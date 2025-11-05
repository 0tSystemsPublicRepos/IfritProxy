package execution

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type ExecutionModeHandler struct {
	mode   string
	config *config.ExecutionModeConfig
	db     *database.SQLiteDB
}

func NewExecutionModeHandler(cfg *config.ExecutionModeConfig, db *database.SQLiteDB) *ExecutionModeHandler {
	return &ExecutionModeHandler{
		mode:   cfg.Mode,
		config: cfg,
		db:     db,
	}
}

// IsOnboardingMode returns true if in onboarding mode
func (e *ExecutionModeHandler) IsOnboardingMode() bool {
	return e.mode == "onboarding"
}

// IsNormalMode returns true if in normal mode
func (e *ExecutionModeHandler) IsNormalMode() bool {
	return e.mode == "normal"
}

// IsLearningMode returns true if in learning mode
func (e *ExecutionModeHandler) IsLearningMode() bool {
	return e.mode == "learning"
}

// HandleOnboardingRequest handles request in onboarding mode
// If auto-whitelist is enabled, adds the request path to exceptions
func (e *ExecutionModeHandler) HandleOnboardingRequest(method, path string) error {
	log.Printf("[ONBOARDING] Processing: %s %s", method, path)
	if !e.IsOnboardingMode() {
		log.Printf("[ONBOARDING] Not in onboarding mode, skipping")
		return nil
	}

	if !e.config.OnboardingAutoWhitelist {
		log.Printf("[ONBOARDING] Auto-whitelist disabled, skipping")
		return nil
	}

	// Add path to exceptions table to whitelist for future requests
	// Using path (method + URL) instead of IP since IPs change
	err := e.addPathToExceptions(method, path)
	if err != nil {
		log.Printf("Error adding path to exceptions: %v", err)
		return err
	}

	// Log to onboarding traffic file
	e.logOnboardingTraffic(method, path)

	return nil	
}

// addPathToExceptions adds path (method + URL) to exceptions whitelist in database
// This way, the exception applies to the request type, not specific IPs
func (e *ExecutionModeHandler) addPathToExceptions(method, path string) error {
	if e.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Create a unique identifier for this request pattern (method + path)
	// This exception applies to ANY IP making this request
	reason := fmt.Sprintf("auto-added in onboarding mode - %s", time.Now().Format("2006-01-02 15:04:05"))
	
	err := e.db.AddException("*", path, reason)
	if err != nil {
		log.Printf("Error adding path to exceptions: %v", err)
		return err
	}

	log.Printf("[ONBOARDING] Auto-whitelisted path in DB: %s %s", method, path)
	return nil
}

// logOnboardingTraffic logs request to onboarding traffic file
func (e *ExecutionModeHandler) logOnboardingTraffic(method, path string) {
	if e.config.OnboardingLogFile == "" {
		return
	}

	// Ensure log directory exists
	logDir := filepath.Dir(e.config.OnboardingLogFile)
	os.MkdirAll(logDir, 0755)

	// Open file in append mode
	file, err := os.OpenFile(e.config.OnboardingLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening onboarding log: %v", err)
		return
	}
	defer file.Close()

	// Write log entry
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] %s %s\n", timestamp, method, path)
	file.WriteString(entry)
}

// GetModeInfo returns information about current execution mode
func (e *ExecutionModeHandler) GetModeInfo() map[string]interface{} {
	return map[string]interface{}{
		"mode":                      e.mode,
		"onboarding_auto_whitelist": e.config.OnboardingAutoWhitelist,
		"onboarding_duration_days":  e.config.OnboardingDurationDays,
		"onboarding_log_file":       e.config.OnboardingLogFile,
	}
}
