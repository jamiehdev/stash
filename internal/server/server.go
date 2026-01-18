package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"stash/internal/store"
)

const maxBodySize = 1 << 20 // 1MB

type Server struct {
	store  *store.Store
	mux    *http.ServeMux
	static http.Handler
}

type CreateRequest struct {
	Content         string `json:"content"`
	TTL             int    `json:"ttl"`
	DeleteTokenHash string `json:"delete_token_hash"`
}

type CreateResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GetResponse struct {
	Content   string    `json:"content"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(s *store.Store, staticFS http.FileSystem) *Server {
	srv := &Server{
		store: s,
		mux:   http.NewServeMux(),
	}
	if staticFS != nil {
		srv.static = http.FileServer(staticFS)
	}
	srv.setupRoutes()
	return srv
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("POST /api/paste", s.handleCreate)
	s.mux.HandleFunc("GET /api/paste/{id}", s.handleGet)
	s.mux.HandleFunc("DELETE /api/paste/{id}", s.handleDelete)
	s.mux.HandleFunc("GET /app.js", s.handleStatic)
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /p/{id}", s.handleIndex)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.static == nil {
		http.NotFound(w, r)
		return
	}
	s.static.ServeHTTP(w, r)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(s.mux).ServeHTTP(w, r)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	content, err := base64.RawURLEncoding.DecodeString(req.Content)
	if err != nil {
		// try standard base64
		content, err = base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			http.Error(w, "invalid content encoding", http.StatusBadRequest)
			return
		}
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 3600 // default 1 hour
	}
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

	id, err := s.store.Create(content, req.DeleteTokenHash, expiresAt)
	if err != nil {
		http.Error(w, "failed to create paste", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CreateResponse{
		ID:        id,
		ExpiresAt: expiresAt,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	paste, err := s.store.Get(id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if paste == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetResponse{
		Content:   base64.RawURLEncoding.EncodeToString(paste.Content),
		ExpiresAt: paste.ExpiresAt,
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := r.URL.Query().Get("token")

	paste, err := s.store.Get(id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if paste == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// hash the token and compare
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	if paste.DeleteHash != tokenHash {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := s.store.Delete(id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if s.static == nil {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html><body>stash</body></html>"))
		return
	}
	r.URL.Path = "/index.html"
	s.static.ServeHTTP(w, r)
}
