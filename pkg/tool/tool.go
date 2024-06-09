package tool

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"
	"golang.org/x/oauth2"

	"github.com/charlieegan3/tool-static-site/pkg/tool/middlewares"
	"github.com/charlieegan3/toolbelt/pkg/apis"
)

type StaticSite struct {
	host string

	oauth2Config    *oauth2.Config
	oidcProvider    *oidc.Provider
	idTokenVerifier *oidc.IDTokenVerifier

	sites map[string]site

	sitesContents   map[string]*AferoHTTPFileSystem
	sitesContentsMu sync.RWMutex

	siteLastAccessTimes map[string]time.Time
	siteLastAccessMu    sync.RWMutex
}

type site struct {
	Token           string   `json:"token"`
	Repo            string   `json:"repo"`
	Branch          string   `json:"branch"`
	PermittedEmails []string `json:"permitted_emails"`
}

func (s *StaticSite) Name() string {
	return "static-site"
}

func (s *StaticSite) FeatureSet() apis.FeatureSet {
	return apis.FeatureSet{
		HTTP:     true,
		HTTPHost: true,
		Config:   true,
	}
}

func (s *StaticSite) SetConfig(config map[string]any) error {

	if s.sites == nil {
		s.sites = make(map[string]site)
	}
	if s.sitesContents == nil {
		s.sitesContents = make(map[string]*AferoHTTPFileSystem)
	}
	if s.siteLastAccessTimes == nil {
		s.siteLastAccessTimes = make(map[string]time.Time)
	}

	var ok bool

	cfg := gabs.Wrap(config)

	path := "web.host"
	s.host, ok = cfg.Path(path).Data().(string)
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	path = "auth.provider_url"
	providerURL, ok := cfg.Path(path).Data().(string)
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	var err error
	s.oidcProvider, err = oidc.NewProvider(context.TODO(), providerURL)
	if err != nil {
		return fmt.Errorf("failed to create oidc provider: %w", err)
	}

	s.oauth2Config = &oauth2.Config{
		Endpoint: s.oidcProvider.Endpoint(),
	}

	path = "auth.client_id"
	s.oauth2Config.ClientID, ok = cfg.Path(path).Data().(string)
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	path = "auth.client_secret"
	s.oauth2Config.ClientSecret, ok = cfg.Path(path).Data().(string)
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	path = "web.https"
	isHttps, ok := cfg.Path(path).Data().(bool)
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	scheme := "https://"
	if !isHttps {
		scheme = "http://"
	}

	s.oauth2Config.RedirectURL = scheme + s.host + "/admin/auth/callback"

	// offline_access is required for refresh tokens
	s.oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "offline_access"}

	s.idTokenVerifier = s.oidcProvider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})

	path = "sites"
	sites, ok := cfg.Path(path).Data().(map[string]interface{})
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	sitesBs, err := json.Marshal(sites)
	if err != nil {
		return fmt.Errorf("failed to marshal sites config: %v", err)
	}

	err = json.Unmarshal(sitesBs, &s.sites)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sites config: %v", err)
	}

	return nil
}

func (s *StaticSite) Jobs() ([]apis.Job, error) { return []apis.Job{}, nil }

func (s *StaticSite) HTTPAttach(router *mux.Router) error {
	router.StrictSlash(true)
	router.Use(middlewares.InitMiddlewareAuth(
		s.oauth2Config,
		s.idTokenVerifier,
		"/admin/",
	))
	router.PathPrefix("/admin/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	for name, data := range s.sites {
		subRouter := router.PathPrefix(fmt.Sprintf("/%s/", name)).Subrouter()

		subRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			email, ok := r.Context().Value("email").(string)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			fmt.Println(email)

			if !slices.Contains(data.PermittedEmails, email) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// fetch the contents from memory or from the source
			s.sitesContentsMu.RLock()
			contents, ok := s.sitesContents[name]
			s.sitesContentsMu.RUnlock()
			if !ok {
				var err error
				contents, err = downloadSite(data.Repo, data.Branch, data.Token)
				if err != nil {
					http.Error(w, fmt.Sprintf("failed to download site: %v", err), http.StatusInternalServerError)
					return
				}

				s.sitesContentsMu.Lock()
				s.sitesContents[name] = contents
				s.sitesContentsMu.Unlock()
			}

			requestFile := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/%s", name))

			req, err := http.NewRequest("GET", strings.TrimPrefix(requestFile, "/"), nil)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("failed to create request"))
			}

			http.FileServer(contents).ServeHTTP(w, req)

			s.siteLastAccessMu.Lock()
			s.siteLastAccessTimes[name] = time.Now()
			s.siteLastAccessMu.Unlock()
		})

		// redirect /name to /name/
		router.HandleFunc(fmt.Sprintf("/%s", name), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("/%s/", name), http.StatusMovedPermanently)
		})
	}

	// run cleaner in bg
	go func() {
		for {
			time.Sleep(5 * time.Minute)

			s.siteLastAccessMu.RLock()
			for name, lastAccess := range s.siteLastAccessTimes {
				if time.Since(lastAccess) > 10*time.Minute {
					s.sitesContentsMu.Lock()
					delete(s.sitesContents, name)
					s.sitesContentsMu.Unlock()
				}
			}
			s.siteLastAccessMu.RUnlock()
		}
	}()

	return nil
}
func (s *StaticSite) HTTPHost() string {
	return s.host
}
func (s *StaticSite) HTTPPath() string { return "" }

func (s *StaticSite) ExternalJobsFuncSet(f func(job apis.ExternalJob) error) {}

func (s *StaticSite) DatabaseSet(db *sql.DB) {}

func (s *StaticSite) DatabaseMigrations() (*embed.FS, string, error) {
	return nil, "", nil
}

type AferoHTTPFileSystem struct {
	fs afero.Fs
}

func (a AferoHTTPFileSystem) Open(name string) (http.File, error) {
	file, err := a.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return file.(http.File), nil
}

func downloadSite(repo, branch, token string) (*AferoHTTPFileSystem, error) {
	client := &http.Client{}

	url := fmt.Sprintf("https://api.github.com/repos/%s/zipball/%s", repo, branch)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	bodyBs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	fs := afero.NewMemMapFs()

	reader, err := zip.NewReader(bytes.NewReader(bodyBs), int64(len(bodyBs)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %v", err)
	}

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		f, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file in zip: %v", err)
		}
		defer f.Close()

		parts := strings.Split(file.Name, "/")
		trimmedName := strings.Join(parts[1:], "/")

		memFile, err := fs.Create("/" + trimmedName)
		if err != nil {
			return nil, fmt.Errorf("failed to create file in memfs: %v", err)
		}
		defer memFile.Close()

		_, err = io.Copy(memFile, f)
		if err != nil {
			return nil, fmt.Errorf("failed to copy file content: %v", err)
		}
	}

	return &AferoHTTPFileSystem{fs}, nil
}
