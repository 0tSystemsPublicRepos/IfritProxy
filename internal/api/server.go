package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type APIServer struct {
	db     *database.SQLiteDB
	addr   string
	token  string
	mu     sync.RWMutex
}

func NewAPIServer(addr string, token string, db *database.SQLiteDB) *APIServer {
	return &APIServer{
		db:    db,
		addr:  addr,
		token: token,
	}
}

func (s *APIServer) Start() error {
	http.HandleFunc("/api/v1/health", s.handleHealth)
	http.HandleFunc("/api/v1/attacks", s.handleAttacks)
	http.HandleFunc("/api/v1/auth/verify", s.handleAuthVerify)

	fmt.Printf("API Server starting on %s\n", s.addr)
	return http.ListenAndServe(s.addr, s)
}

func (s *APIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Authenticate
	if !s.authenticate(r) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Route to handler
	http.DefaultServeMux.ServeHTTP(w, r)
}

func (s *APIServer) authenticate(r *http.Request) bool {
	token := r.Header.Get("Authorization")
	return token == "Bearer "+s.token
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"db":         "connected",
		"version":    "0.1",
		"timestamp":  int64(0),
	})
}

func (s *APIServer) handleAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'ip' parameter"})
		return
	}

	attacks, err := s.db.GetAttacksByIP(ip, 100)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"attacks": attacks,
		"total":   len(attacks),
	})
}

func (s *APIServer) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token := req["token"]
	isValid := token == s.token

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"valid": isValid})
}
