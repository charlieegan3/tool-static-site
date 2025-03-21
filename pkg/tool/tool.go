package tool

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/gorilla/mux"
	"github.com/spf13/afero"

	"github.com/charlieegan3/toolbelt/pkg/apis"
)

type StaticSite struct {
	host string

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

func (*StaticSite) Name() string {
	return "static-site"
}

func (*StaticSite) FeatureSet() apis.FeatureSet {
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

	var err error

	path = "sites"

	sites, ok := cfg.Path(path).Data().(map[string]interface{})
	if !ok {
		return fmt.Errorf("config value %s not set", path)
	}

	sitesBs, err := json.Marshal(sites)
	if err != nil {
		return fmt.Errorf("failed to marshal sites config: %w", err)
	}

	err = json.Unmarshal(sitesBs, &s.sites)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sites config: %w", err)
	}

	return nil
}

func (*StaticSite) Jobs() ([]apis.Job, error) { return []apis.Job{}, nil }

func (s *StaticSite) HTTPAttach(router *mux.Router) error {
	router.StrictSlash(true)

	for name, data := range s.sites {
		subRouter := router.PathPrefix(fmt.Sprintf("/%s/", name)).Subrouter()

		subRouter.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email := r.Header.Get("X-Email")
			if email == "" {
				http.Error(w, "unauthorized: no user", http.StatusUnauthorized)

				return
			}

			if !slices.Contains(data.PermittedEmails, email) {
				fmt.Println("permitted_emails", data.PermittedEmails)
				fmt.Println("email", email)
				http.Error(w, "unauthorized: unknown user", http.StatusUnauthorized)

				return
			}

			requestFile := strings.TrimPrefix(r.URL.Path, "/"+name)

			// fetch the contents from memory or from the source
			s.sitesContentsMu.RLock()
			contents, ok := s.sitesContents[name]
			s.sitesContentsMu.RUnlock()

			if !ok || requestFile == "/refresh" {
				var err error

				contents, err = downloadSite(r.Context(), data.Repo, data.Branch, data.Token)
				if err != nil {
					http.Error(w, fmt.Sprintf("failed to download site: %v", err), http.StatusInternalServerError)

					return
				}

				s.sitesContentsMu.Lock()
				s.sitesContents[name] = contents
				s.sitesContentsMu.Unlock()
			}

			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimPrefix(requestFile, "/"), nil)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				_, err := w.Write([]byte("failed to create request"))
				if err != nil {
					http.Error(w, "failed to write response", http.StatusInternalServerError)
				}
			}

			http.FileServer(contents).ServeHTTP(w, req)

			s.siteLastAccessMu.Lock()
			s.siteLastAccessTimes[name] = time.Now()
			s.siteLastAccessMu.Unlock()
		})

		// redirect /name to /name/
		router.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("/%s/", name), http.StatusMovedPermanently)
		})

		router.PathPrefix("/robots.txt").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")

			_, err := w.Write([]byte("User-agent: *\nDisallow: /"))
			if err != nil {
				http.Error(w, "failed to write response", http.StatusInternalServerError)
			}
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

func (*StaticSite) HTTPPath() string { return "" }

func (*StaticSite) ExternalJobsFuncSet(_ func(job apis.ExternalJob) error) {}

func (*StaticSite) DatabaseSet(_ *sql.DB) {}

func (*StaticSite) DatabaseMigrations() (*embed.FS, string, error) {
	return nil, "", nil
}

type AferoHTTPFileSystem struct {
	fs afero.Fs
}

func (a AferoHTTPFileSystem) Open(name string) (http.File, error) {
	file, err := a.fs.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	f, ok := file.(http.File)
	if !ok {
		return nil, errors.New("failed to convert file to http.File")
	}

	return f, nil
}

func downloadSite(ctx context.Context, repo, branch, token string) (*AferoHTTPFileSystem, error) {
	client := &http.Client{}

	url := fmt.Sprintf("https://api.github.com/repos/%s/zipball/%s", repo, branch)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	fs := afero.NewMemMapFs()

	reader, err := zip.NewReader(bytes.NewReader(bodyBs), int64(len(bodyBs)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		f, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file in zip: %w", err)
		}
		defer f.Close()

		parts := strings.Split(file.Name, "/")
		trimmedName := strings.Join(parts[1:], "/")

		memFile, err := fs.Create("/" + trimmedName)
		if err != nil {
			return nil, fmt.Errorf("failed to create file in memfs: %w", err)
		}
		defer memFile.Close()

		//nolint gosec
		_, err = io.Copy(memFile, f)
		if err != nil {
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}
	}

	return &AferoHTTPFileSystem{fs}, nil
}
