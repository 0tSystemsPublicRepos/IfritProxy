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
func (e *ExecutionModeHandler) HandleOnboardingRequest(method, path, appID string) error {
	log.Printf("[ONBOARDING] app_id=%s | Processing: %s %s", appID, method, path)
	if !e.IsOnboardingMode() {
		log.Printf("[ONBOARDING] app_id=%s | Not in onboarding mode, skipping", appID)
		return nil
	}

	if !e.config.OnboardingAutoWhitelist {
		log.Printf("[ONBOARDING] app_id=%s | Auto-whitelist disabled, skipping", appID)
		return nil
	}

	// Add path to exceptions table to whitelist for future requests
	// Using "*" for IP to match any IP for that path
	err := e.addPathToExceptions(appID, method, path)
	if err != nil {
		log.Printf("Error adding path to exceptions for app_id=%s: %v", appID, err)
		return err
	}

	// Log to onboarding traffic file
	e.logOnboardingTraffic(appID, method, path)

	return nil
}

// addPathToExceptions adds path to exceptions whitelist in database
func (e *ExecutionModeHandler) addPathToExceptions(appID, method, path string) error {
	if e.db == nil {
		return fmt.Errorf("database not initialized")
	}

	// Create a unique identifier for this request pattern (method + path)
	// This exception applies to ANY IP making this request
	reason := fmt.Sprintf("auto-added in onboarding mode - %s", time.Now().Format("2006-01-02 15:04:05"))

	err := e.db.AddException(appID, "*", path, reason)
	if err != nil {
		log.Printf("Error adding path to exceptions for app_id=%s: %v", appID, err)
		return err
	}

	log.Printf("[ONBOARDING] app_id=%s | Auto-whitelisted path in DB: %s %s", appID, method, path)
	return nil
}

// logOnboardingTraffic logs request to onboarding traffic file
func (e *ExecutionModeHandler) logOnboardingTraffic(appID, method, path string) {
	if e.config.OnboardingLogFile == "" {
		return
	}

	// Create app-specific log file
	logDir := filepath.Dir(e.config.OnboardingLogFile)
	logFilename := fmt.Sprintf("onboarding_%s.log", appID)
	logFilePath := filepath.Join(logDir, logFilename)

	// Ensure log directory exists
	os.MkdirAll(logDir, 0755)

	// Open file in append mode
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening onboarding log for app_id=%s: %v", appID, err)
		return
	}
	defer file.Close()

	// Write log entry
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("[%s] [%s] %s %s\n", timestamp, appID, method, path)
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
