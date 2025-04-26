package auth

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"ipv6-proxy/db"
)

type Authenticator struct {
	DB *db.DB
}

func NewAuthenticator(database *db.DB) *Authenticator {
	return &Authenticator{
		DB: database,
	}
}

func (a *Authenticator) Authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		auth = r.Header.Get("Authorization")
	}

	if auth == "" {
		log.Printf("[AUTH] No auth header found")
		return "", false
	}

	authParts := strings.SplitN(auth, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		log.Printf("[AUTH] Invalid auth format: %s", auth)
		return "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		log.Printf("[AUTH] Error decoding credentials: %v", err)
		return "", false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		log.Printf("[AUTH] Invalid credential format")
		return "", false
	}

	username := credentials[0]
	password := credentials[1]

	log.Printf("[AUTH] Authenticating user: %s with password: %s", username, password)

	if !a.DB.VerifyPassword(username, password) {
		log.Printf("[AUTH] Password verification failed for user: %s", username)
		return "", false
	}

	log.Printf("[AUTH] Successfully authenticated user: %s", username)
	return username, true
}

func (a *Authenticator) ValidateAPIKey(apiKey string) bool {
	return a.DB.ValidateAPIKey(apiKey)
}

func (a *Authenticator) MiddlewareFunc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[AUTH-MIDDLEWARE] Processing %s request to %s", r.Method, r.URL.String())
		
		if strings.HasPrefix(r.URL.Path, "/manage") {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			if !a.ValidateAPIKey(apiKey) {
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			log.Printf("[AUTH] API key authentication successful")
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == http.MethodConnect {
			log.Printf("[AUTH-CONNECT] Processing CONNECT request for: %s", r.RequestURI)
		}

		username, authenticated := a.Authenticate(r)
		if !authenticated {
			log.Printf("[AUTH] Authentication failed, sending 407 response")
			w.Header().Set("Proxy-Authenticate", `Basic realm="IPv6 Proxy"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}

		if !a.DB.CanMakeRequest(username) {
			log.Printf("[AUTH] Thread limit exceeded for user: %s", username)
			http.Error(w, "Thread limit exceeded", http.StatusTooManyRequests)
			return
		}

		a.DB.AddRequest(username)

		ctx := context.WithValue(r.Context(), "username", username)
		r = r.WithContext(ctx)
		
		log.Printf("[AUTH] Authentication successful for user: %s, proceeding to handler", username)

		next.ServeHTTP(w, r)
	})
} 