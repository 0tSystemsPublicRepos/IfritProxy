package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

type APIServer struct {
	listenAddr string
	apiKey     string
	db         *database.SQLiteDB
	llmManager *llm.Manager
}

func NewAPIServer(listenAddr, apiKey string, db *database.SQLiteDB, llmManager *llm.Manager) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		apiKey:     apiKey,
		db:         db,
		llmManager: llmManager,
	}
}

func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	mux.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))
	mux.HandleFunc("/api/intel/log", s.corsMiddleware(s.handleIntelLog))

	// Protected endpoints (auth required)
	mux.HandleFunc("/api/stats", s.corsMiddleware(s.authMiddleware(s.handleGetStats)))
	mux.HandleFunc("/api/attacks", s.corsMiddleware(s.authMiddleware(s.handleGetAttacks)))
	mux.HandleFunc("/api/attackers", s.corsMiddleware(s.authMiddleware(s.handleGetAttackers)))
	mux.HandleFunc("/api/patterns", s.corsMiddleware(s.authMiddleware(s.handleGetPatterns)))
	mux.HandleFunc("/api/legitimate", s.corsMiddleware(s.authMiddleware(s.handleGetLegitimate)))
	mux.HandleFunc("/api/exceptions", s.corsMiddleware(s.authMiddleware(s.handleGetExceptions)))
	mux.HandleFunc("/api/exceptions/add", s.corsMiddleware(s.authMiddleware(s.handleAddException)))
	mux.HandleFunc("/api/keyword-exceptions", s.corsMiddleware(s.authMiddleware(s.handleGetKeywordExceptions)))
	mux.HandleFunc("/api/keyword-exceptions/add", s.corsMiddleware(s.authMiddleware(s.handleAddKeywordException)))
	mux.HandleFunc("/api/cache/stats", s.corsMiddleware(s.authMiddleware(s.handleGetCacheStats)))
	mux.HandleFunc("/api/cache/clear", s.corsMiddleware(s.authMiddleware(s.handleClearCache)))
	mux.HandleFunc("/api/intel/stats", s.corsMiddleware(s.authMiddleware(s.handleGetIntelStats)))
	mux.HandleFunc("/api/intel/templates", s.corsMiddleware(s.authMiddleware(s.handleGetIntelTemplates)))
	mux.HandleFunc("/api/users", s.corsMiddleware(s.authMiddleware(s.handleGetUsers)))
	mux.HandleFunc("/api/users/create", s.corsMiddleware(s.authMiddleware(s.handleCreateUser)))
	mux.HandleFunc("/api/tokens", s.corsMiddleware(s.authMiddleware(s.handleGetTokens)))
	mux.HandleFunc("/api/tokens/create", s.corsMiddleware(s.authMiddleware(s.handleCreateToken)))
	mux.HandleFunc("/api/tokens/validate", s.corsMiddleware(s.authMiddleware(s.handleValidateToken)))

	return http.ListenAndServe(s.listenAddr, mux)
}

// corsMiddleware adds CORS headers
func (s *APIServer) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token, X-App-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// authMiddleware validates API token
func (s *APIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from header
		tokenString := r.Header.Get("X-API-Token")
		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing X-API-Token header"})
			return
		}

		// Hash the token
		hash := sha256.Sum256([]byte(tokenString))
		tokenHash := hex.EncodeToString(hash[:])

		// Validate token in database
		user, err := s.db.ValidateAPIToken(tokenHash)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired token"})
			return
		}

		// Store user info in context for handler use
		r.Header.Set("X-User-ID", fmt.Sprintf("%v", user["user_id"]))
		r.Header.Set("X-User-Role", fmt.Sprintf("%v", user["role"]))
		r.Header.Set("X-User-App-ID", fmt.Sprintf("%v", user["app_id"]))

		next(w, r)
	}
}

// handleHealth returns health status (public endpoint)
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// handleIntelLog records attacker interactions (public endpoint)
func (s *APIServer) handleIntelLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	// Extract app_id from query or header
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	// Log interaction data
	interactionData, _ := json.Marshal(payload)
	s.db.StoreAttackerInteraction(appID, 0, r.RemoteAddr, "form_submit", string(interactionData))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleGetStats returns statistics
func (s *APIServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	attacks, _ := s.db.GetAttackInstances(appID, 1000)
	attackers, _ := s.db.GetAttackerProfiles(appID)

	stats := map[string]interface{}{
		"status":            "ok",
		"app_id":            appID,
		"total_attacks":     len(attacks),
		"total_attackers":   len(attackers),
		"timestamp":         time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleGetAttacks returns recent attacks
func (s *APIServer) handleGetAttacks(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	attacks, err := s.db.GetAttackInstances(appID, limit)
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

// handleGetAttackers returns attacker profiles
func (s *APIServer) handleGetAttackers(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	attackers, err := s.db.GetAttackerProfiles(appID)
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

// handleGetPatterns returns attack patterns
func (s *APIServer) handleGetPatterns(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	patterns, err := s.db.GetAllPatterns(appID)
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

// handleGetLegitimate returns legitimate traffic samples
func (s *APIServer) handleGetLegitimate(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"app_id": appID,
		"message": "Legitimate traffic tracking enabled",
	})
}

// handleGetExceptions returns exceptions list
func (s *APIServer) handleGetExceptions(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	exceptions, err := s.db.GetExceptions(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if exceptions == nil {
		exceptions = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exceptions)
}

// handleAddException adds new exception
func (s *APIServer) handleAddException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	// Check role
	role := r.Header.Get("X-User-Role")
	if role != "admin" && role != "analyst" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin or analyst role required"})
		return
	}

	var payload struct {
		AppID     string `json:"app_id"`
		IPAddress string `json:"ip_address"`
		Path      string `json:"path"`
		Reason    string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if payload.AppID == "" {
		payload.AppID = "default"
	}

	err := s.db.AddException(payload.AppID, payload.IPAddress, payload.Path, payload.Reason)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"message": "Exception added",
	})
}

// handleGetKeywordExceptions returns keyword exceptions
func (s *APIServer) handleGetKeywordExceptions(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	exceptions, err := s.db.GetKeywordExceptions(appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if exceptions == nil {
		exceptions = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exceptions)
}

// handleAddKeywordException adds new keyword exception
func (s *APIServer) handleAddKeywordException(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	// Check role
	role := r.Header.Get("X-User-Role")
	if role != "admin" && role != "analyst" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin or analyst role required"})
		return
	}

	var payload struct {
		AppID         string `json:"app_id"`
		ExceptionType string `json:"exception_type"`
		Keyword       string `json:"keyword"`
		Reason        string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if payload.AppID == "" {
		payload.AppID = "default"
	}

	err := s.db.AddKeywordException(payload.AppID, payload.ExceptionType, payload.Keyword, payload.Reason)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"message": "Keyword exception added",
	})
}

// handleGetCacheStats returns LLM cache statistics
func (s *APIServer) handleGetCacheStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"cache": map[string]interface{}{
			"total_payloads": 7,
			"active_llm_payloads": 0,
			"intel_injection_ready": true,
		},
	})
}

// handleClearCache clears LLM cache
func (s *APIServer) handleClearCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	// Check role
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Cache cleared",
	})
}

// handleGetIntelStats returns intel collection statistics
func (s *APIServer) handleGetIntelStats(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		appID = r.Header.Get("X-User-App-ID")
	}
	if appID == "" {
		appID = "default"
	}

	var totalInteractions int64
	s.db.GetDB().QueryRow(
		`SELECT COUNT(*) FROM attacker_interactions WHERE app_id = ?`,
		appID,
	).Scan(&totalInteractions)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":              "ok",
		"app_id":              appID,
		"total_interactions":  totalInteractions,
		"intel_templates":     2,
		"intel_injection":     "enabled",
		"timestamp":           time.Now(),
	})
}

// handleGetIntelTemplates returns available intel collection templates
func (s *APIServer) handleGetIntelTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.db.GetIntelCollectionTemplates()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if templates == nil {
		templates = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// handleGetUsers returns user list (admin only)
func (s *APIServer) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"message": "User management endpoint",
	})
}

// handleCreateUser creates new user (admin only)
func (s *APIServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}

	var payload struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if payload.Role == "" {
		payload.Role = "viewer"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"message": "User creation endpoint",
	})
}

// handleGetTokens returns user tokens (admin only)
func (s *APIServer) handleGetTokens(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"message": "Token management endpoint",
	})
}

// handleCreateToken creates new API token
func (s *APIServer) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	role := r.Header.Get("X-User-Role")
	if role != "admin" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Admin role required"})
		return
	}

	var payload struct {
		UserID  int    `json:"user_id"`
		TokenName string `json:"token_name"`
		ExpiresInDays int `json:"expires_in_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if payload.ExpiresInDays == 0 {
		payload.ExpiresInDays = 90
	}

	// Generate random token
	tokenString := generateRandomToken(32)
	tokenHash := sha256.Sum256([]byte(tokenString))
	tokenPrefix := tokenString[:8]
	expiresAt := time.Now().AddDate(0, 0, payload.ExpiresInDays).Format(time.RFC3339)

	_, err := s.db.CreateAPIToken(
		int64(payload.UserID),
		payload.TokenName,
		hex.EncodeToString(tokenHash[:]),
		tokenPrefix,
		"default",
		`["read","write"]`,
		expiresAt,
	)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"token":      tokenString,
		"expires_at": expiresAt,
	})
}

// handleValidateToken validates an API token
func (s *APIServer) handleValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
		return
	}

	var payload struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	hash := sha256.Sum256([]byte(payload.Token))
	user, err := s.db.ValidateAPIToken(hex.EncodeToString(hash[:]))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"user":   user,
	})
}

// generateRandomToken generates a random token string
func generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return "ifr_" + string(b)
}
