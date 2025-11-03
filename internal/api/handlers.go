package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type APIServer struct {
	listenAddr string
	apiKey     string
	db         *database.SQLiteDB
}

func NewAPIServer(listenAddr, apiKey string, db *database.SQLiteDB) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		apiKey:     apiKey,
		db:         db,
	}
}

func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/attacks", s.corsMiddleware(s.handleGetAttacks))
	mux.HandleFunc("/api/attackers", s.corsMiddleware(s.handleGetAttackers))
	mux.HandleFunc("/api/patterns", s.corsMiddleware(s.handleGetPatterns))
	mux.HandleFunc("/api/stats", s.corsMiddleware(s.handleGetStats))
	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))

	return http.ListenAndServe(s.listenAddr, mux)
}

func (s *APIServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (s *APIServer) handleGetAttacks(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	attacks, err := s.db.GetAttackInstances(limit)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if attacks == nil {
		attacks = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attacks)
}

func (s *APIServer) handleGetAttackers(w http.ResponseWriter, r *http.Request) {
	attackers, err := s.db.GetAttackerProfiles()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if attackers == nil {
		attackers = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attackers)
}

func (s *APIServer) handleGetPatterns(w http.ResponseWriter, r *http.Request) {
	patterns, err := s.db.GetAllPatterns()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if patterns == nil {
		patterns = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(patterns)
}

func (s *APIServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"status": "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}
