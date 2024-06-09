package middlewares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

func InitMiddlewareAuth(
	oauth2Config *oauth2.Config,
	idTokenVerifier *oidc.IDTokenVerifier,
	adminPath string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if r.URL.Path == adminPath+"auth/callback" {
				handleAuthCallback(w, r, oauth2Config, idTokenVerifier, adminPath)
				return
			}

			token, err := r.Cookie("token")
			if err != nil && err == http.ErrNoCookie {
				refreshed := handleTokenRefresh(w, r, oauth2Config, adminPath)

				if refreshed {
					next.ServeHTTP(w, r)
					return
				}

				stateToken, err := generateStateToken()
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				s := state{
					Destination: r.URL.String(),
					Token:       stateToken,
				}

				stateBs, err := json.Marshal(s)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				setCookie(w, "state_token", base64.RawURLEncoding.EncodeToString([]byte(s.Token)), "/", time.Time{})

				http.Redirect(w, r, oauth2Config.AuthCodeURL(base64.RawURLEncoding.EncodeToString(stateBs)), http.StatusFound)
				return
			}

			email, err := verifyIDToken(r, idTokenVerifier, token.Value)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), "email", email),
			))
		})
	}
}

type state struct {
	Destination string `json:"destination"`
	Token       string `json:"token"`
}

func generateStateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setCookie(w http.ResponseWriter, name, value, path string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Secure:   true,
		SameSite: http.SameSiteDefaultMode,
		Path:     path,
		HttpOnly: true,
		Expires:  expiry,
	})
}

func verifyIDToken(r *http.Request, idTokenVerifier *oidc.IDTokenVerifier, tokenValue string) (string, error) {
	idToken, err := idTokenVerifier.Verify(r.Context(), tokenValue)
	if err != nil {
		return "", err
	}

	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %w", err)
	}

	if !claims.Verified {
		return "", fmt.Errorf("unauthorized")
	}

	return claims.Email, nil
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request, oauth2Config *oauth2.Config, idTokenVerifier *oidc.IDTokenVerifier, adminPath string) {
	if r.URL.Query().Get("state") == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	stateBs, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var s state
	err = json.Unmarshal(stateBs, &s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stateTokenCookie, err := r.Cookie("state_token")
	if err != nil {
		http.Error(w, "invalid state token", http.StatusInternalServerError)
		return
	}

	if base64.RawURLEncoding.EncodeToString([]byte(s.Token)) != stateTokenCookie.Value {
		http.Error(w, "invalid state token", http.StatusInternalServerError)
		return
	}

	oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "failed to get id token", http.StatusInternalServerError)
		return
	}

	_, err = verifyIDToken(r, idTokenVerifier, rawIDToken)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	setCookie(w, "token", rawIDToken, "/", oauth2Token.Expiry)

	if oauth2Token.RefreshToken != "" {
		setCookie(w, "refresh_token", oauth2Token.RefreshToken, "/", time.Now().Add(14*24*time.Hour))
	}

	setCookie(w, "state_token", "", "/", time.Unix(0, 0))

	http.Redirect(w, r, s.Destination, http.StatusFound)
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request, oauth2Config *oauth2.Config, adminPath string) bool {
	refreshToken, err := r.Cookie("refresh_token")
	if err != nil {
		return false
	}

	oauth2Token := &oauth2.Token{RefreshToken: refreshToken.Value}

	newToken, err := oauth2Config.TokenSource(r.Context(), oauth2Token).Token()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}

	setCookie(w, "token", newToken.AccessToken, "/", newToken.Expiry)

	if newToken.RefreshToken != "" {
		setCookie(w, "refresh_token", newToken.RefreshToken, "/", time.Now().Add(14*24*time.Hour))
	}

	return true
}
