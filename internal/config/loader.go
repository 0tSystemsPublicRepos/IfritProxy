package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// === DATABASE ABSTRACTION LAYER ===

type DatabaseConfig struct {
	Type           string               `json:"type"`                    // "sqlite", "mysql", "postgresql"
	SQLite         SQLiteConfig         `json:"sqlite,omitempty"`
	MySQL          MySQLConfig          `json:"mysql,omitempty"`
	PostgreSQL     PostgreSQLConfig     `json:"postgresql,omitempty"`
	ConnectionPool ConnectionPoolConfig `json:"connection_pool,omitempty"`
}

type SQLiteConfig struct {
	Path        string `json:"path"`
	JournalMode string `json:"journal_mode"`
	Synchronous string `json:"synchronous"`
}

type MySQLConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Database       string `json:"database"`
	MaxConnections int    `json:"max_connections"`
	SSL            bool   `json:"ssl"`
}

type PostgreSQLConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Database       string `json:"database"`
	SSLMode        string `json:"ssl_mode"`
	MaxConnections int    `json:"max_connections"`
}

type ConnectionPoolConfig struct {
	Enabled               bool   `json:"enabled"`
	MaxIdleConnections    int    `json:"max_idle_connections"`
	MaxOpenConnections    int    `json:"max_open_connections"`
	ConnectionMaxLifetime string `json:"connection_max_lifetime"`
}

// === MULTI-APP SUPPORT ===

type AppConfig struct {
	ProxyTarget string `json:"proxy_target"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

type ServerConfig struct {
	ListenAddr    string    `json:"listen_addr"`
	APIListenAddr string    `json:"api_listen_addr"`
	MultiAppMode  bool      `json:"multi_app_mode"`
	AppIDHeader   string    `json:"app_id_header"`
	AppIDFallback string    `json:"app_id_fallback"`
	ProxyTarget   string    `json:"proxy_target"` // Default target for single-app mode
	TLS           TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// === API AUTHENTICATION ===

type APIConfig struct {
	ListenAddr     string                    `json:"listen_addr"`
	Authentication APIAuthenticationConfig   `json:"authentication"`
	RateLimiting   APIRateLimitingConfig     `json:"rate_limiting"`
}

type APIAuthenticationConfig struct {
	Enabled         bool   `json:"enabled"`
	TokenHeader     string `json:"token_header"`
	RequireAuth     bool   `json:"require_auth"`
	TokenExpiryDays int    `json:"token_expiry_days"`
}

type APIRateLimitingConfig struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
}

// === DASHBOARD ===

type DashboardConfig struct {
	Enabled        bool                `json:"enabled"`
	ListenAddr     string              `json:"listen_addr"`
	Authentication DashboardAuthConfig `json:"authentication"`
}

type DashboardAuthConfig struct {
	Enabled     bool   `json:"enabled"`
	TokenHeader string `json:"token_header"`
}

// === MAIN CONFIG STRUCTURE ===

type Config struct {
	Server            ServerConfig          `json:"server"`
	Database          DatabaseConfig        `json:"database"`
	Apps              map[string]AppConfig  `json:"apps"`
	API               APIConfig             `json:"api"`
	Dashboard         DashboardConfig       `json:"dashboard"`
	LLM               LLMConfig             `json:"llm"`
	Detection         DetectionConfig       `json:"detection"`
	ExecutionMode     ExecutionModeConfig   `json:"execution_mode"`
	Anonymization     AnonymizationConfig   `json:"anonymization"`
	PayloadManagement PayloadManagement     `json:"payload_management"`
	System            SystemConfig          `json:"system"`
}

type LLMConfig struct {
	Primary string       `json:"primary"`
	Claude  ClaudeConfig `json:"claude"`
	GPT     GPTConfig    `json:"gpt"`
}

type ClaudeConfig struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

type GPTConfig struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

type DetectionConfig struct {
	Mode             string   `json:"mode"`              // "detection" or "allowlist"
	EnableLocalRules bool     `json:"enable_local_rules"`
	EnableLLM        bool     `json:"enable_llm"`
	LLMOnlyOn        []string `json:"llm_only_on"`
	WhitelistIPs     []string `json:"whitelist_ips"`
	WhitelistPaths   []string `json:"whitelist_paths"`
SkipBodyCheckOnWhitelist bool   `json:"skip_body_check_on_whitelist"`
}

type ExecutionModeConfig struct {
	Mode                   string `json:"mode"`
	OnboardingAutoWhitelist bool   `json:"onboarding_auto_whitelist"`
	OnboardingDurationDays int    `json:"onboarding_duration_days"`
	OnboardingLogFile      string `json:"onboarding_log_file"`
}

type AnonymizationConfig struct {
	Enabled          bool     `json:"enabled"`
	Strategy         string   `json:"strategy"`
	StoreOriginal    bool     `json:"store_original"`
	SensitiveHeaders []string `json:"sensitive_headers"`
}

type PayloadManagement struct {
	EnableIntelCollection    bool                   `json:"enable_intel_collection"`
	IntelCollectionPayloadID int                    `json:"intel_collection_payload_id"`
	CacheLLMPayloadsToDb     bool                   `json:"cache_llm_payloads_to_db"`
	GenerateDynamicPayload   bool                   `json:"generate_dynamic_payload"`
	DynamicLLMCacheTTL       int                    `json:"dynamic_llm_cache_ttl"`
	UseDBPayloads            bool                   `json:"use_db_payloads"`
	DefaultResponses         map[string]interface{} `json:"default_responses"`
}

type SystemConfig struct {
	HomeDir  string `json:"home_dir"`
	LogDir   string `json:"log_dir"`
	LogLevel string `json:"log_level"`
	Debug    bool   `json:"debug"`
}

// === LOADER FUNCTIONS ===

func Load(configPath string) (*Config, error) {
	var data []byte
	var err error

	if configPath != "" {
		data, err = ioutil.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		// Try common locations
		locations := []string{
			"./config/default.json",
			"./config/default.yaml",
			"./config/default.yml",
			"/etc/ifrit/config.json",
			"/etc/ifrit/config.yaml",
			os.Getenv("IFRIT_CONFIG"),
		}

		for _, loc := range locations {
			if loc == "" {
				continue
			}
			if d, err := ioutil.ReadFile(loc); err == nil {
				data = d
				fmt.Printf("Loaded config from: %s\n", loc)
				break
			}
		}
	}

	// If no config found, use defaults
	if data == nil {
		fmt.Println("No config file found, using defaults")
		return getDefaults(), nil
	}

	// Parse JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Printf("Warning: Failed to parse config: %v, using defaults\n", err)
		return getDefaults(), nil
	}

	applyDefaults(&config)
	expandEnvVars(&config)

	return &config, nil
}

// expandEnvVars replaces ${VAR_NAME} with environment variables
func expandEnvVars(cfg *Config) {
	cfg.LLM.Claude.APIKey = os.ExpandEnv(cfg.LLM.Claude.APIKey)
	cfg.LLM.GPT.APIKey = os.ExpandEnv(cfg.LLM.GPT.APIKey)
	cfg.Database.SQLite.Path = os.ExpandEnv(cfg.Database.SQLite.Path)
	cfg.Database.MySQL.Password = os.ExpandEnv(cfg.Database.MySQL.Password)
	cfg.Database.PostgreSQL.Password = os.ExpandEnv(cfg.Database.PostgreSQL.Password)
}

func getDefaults() *Config {
	cfg := &Config{
		Server: ServerConfig{
			ListenAddr:    ":8080",
			APIListenAddr: ":8443",
			MultiAppMode:  false,
			AppIDHeader:   "X-App-ID",
			AppIDFallback: "default",
			ProxyTarget:   "http://localhost:80",
			TLS: TLSConfig{
				Enabled:  true,
				CertFile: "/app/config/certs/server.crt",
				KeyFile:  "/app/config/certs/server.key",
			},
		},
		Database: DatabaseConfig{
			Type: "sqlite",
			SQLite: SQLiteConfig{
				Path:        "./data/ifrit.db",
				JournalMode: "WAL",
				Synchronous: "NORMAL",
			},
			MySQL: MySQLConfig{
				Host:           "localhost",
				Port:           3306,
				Username:       "ifrit_user",
				Password:       "${DB_PASSWORD}",
				Database:       "ifrit",
				MaxConnections: 20,
				SSL:            false,
			},
			PostgreSQL: PostgreSQLConfig{
				Host:           "localhost",
				Port:           5432,
				Username:       "ifrit_user",
				Password:       "${DB_PASSWORD}",
				Database:       "ifrit",
				SSLMode:        "disable",
				MaxConnections: 20,
			},
			ConnectionPool: ConnectionPoolConfig{
				Enabled:               true,
				MaxIdleConnections:    5,
				MaxOpenConnections:    25,
				ConnectionMaxLifetime: "1h",
			},
		},
		Apps: map[string]AppConfig{
			"app1": {
				ProxyTarget: "http://localhost:3000",
				Enabled:     true,
				Description: "Main API",
			},
			"app2": {
				ProxyTarget: "http://localhost:4000",
				Enabled:     true,
				Description: "Admin Panel",
			},
		},
		API: APIConfig{
			ListenAddr: ":8443",
			Authentication: APIAuthenticationConfig{
				Enabled:         true,
				TokenHeader:     "X-API-Token",
				RequireAuth:     true,
				TokenExpiryDays: 90,
			},
			RateLimiting: APIRateLimitingConfig{
				Enabled:           true,
				RequestsPerMinute: 100,
			},
		},
		Dashboard: DashboardConfig{
			Enabled:    true,
			ListenAddr: ":5601",
			Authentication: DashboardAuthConfig{
				Enabled:     true,
				TokenHeader: "X-Dashboard-Token",
			},
		},
		LLM: LLMConfig{
			Primary: "claude",
			Claude: ClaudeConfig{
				APIKey: "${CLAUDE_API_KEY}",
				Model:  "claude-3-5-haiku-20241022",
			},
			GPT: GPTConfig{
				APIKey: "${OPENAI_API_KEY}",
				Model:  "gpt-4o-mini",
			},
		},
		Detection: DetectionConfig{
			Mode:             "detection",
			EnableLocalRules: true,
			EnableLLM:        true,
			LLMOnlyOn:        []string{"POST", "PUT", "DELETE"},
			WhitelistIPs:     []string{},
			WhitelistPaths:   []string{},
		},
		ExecutionMode: ExecutionModeConfig{
			Mode:                   "onboarding",
			OnboardingAutoWhitelist: true,
			OnboardingDurationDays: 7,
			OnboardingLogFile:      "./logs/onboarding_traffic.log",
		},
		Anonymization: AnonymizationConfig{
			Enabled:       true,
			Strategy:      "hybrid",
			StoreOriginal: true,
			SensitiveHeaders: []string{
				"Authorization",
				"Cookie",
				"X-API-Key",
				"X-Auth-Token",
			},
		},
		PayloadManagement: PayloadManagement{
			EnableIntelCollection:    true,
			IntelCollectionPayloadID: 1,
			CacheLLMPayloadsToDb:     true,
			GenerateDynamicPayload:   false,
			DynamicLLMCacheTTL:       86400,
			UseDBPayloads:            true,
			DefaultResponses: map[string]interface{}{
				"reconnaissance": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Not found"},
					"status_code": 404,
				},
				"sql_injection": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Forbidden"},
					"status_code": 403,
				},
				"xss": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Invalid input", "message": "XSS prevention enabled"},
					"status_code": 400,
				},
				"credential_stuffing": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Invalid credentials", "message": "Account locked after 3 attempts"},
					"status_code": 401,
				},
				"blocked_by_allowlist": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Forbidden"},
					"status_code": 403,
				},
				"fallback": map[string]interface{}{
					"content":     map[string]interface{}{"error": "Internal server error"},
					"status_code": 500,
				},
			},
		},
		System: SystemConfig{
			HomeDir:  "./",
			LogDir:   "./logs",
			LogLevel: "info",
		},
	}

	applyDefaults(cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.APIListenAddr == "" {
		cfg.Server.APIListenAddr = ":8443"
	}
	if cfg.Server.ProxyTarget == "" {
		cfg.Server.ProxyTarget = "http://localhost:80"
	}
	if cfg.Server.AppIDHeader == "" {
		cfg.Server.AppIDHeader = "X-App-ID"
	}
	if cfg.Server.AppIDFallback == "" {
		cfg.Server.AppIDFallback = "default"
	}

	// Database defaults
	if cfg.Database.Type == "" {
		cfg.Database.Type = "sqlite"
	}
	if cfg.Database.SQLite.Path == "" {
		cfg.Database.SQLite.Path = "./data/ifrit.db"
	}
	if cfg.Database.SQLite.JournalMode == "" {
		cfg.Database.SQLite.JournalMode = "WAL"
	}
	if cfg.Database.SQLite.Synchronous == "" {
		cfg.Database.SQLite.Synchronous = "NORMAL"
	}
	if cfg.Database.MySQL.Port == 0 {
		cfg.Database.MySQL.Port = 3306
	}
	if cfg.Database.PostgreSQL.Port == 0 {
		cfg.Database.PostgreSQL.Port = 5432
	}
	if cfg.Database.ConnectionPool.MaxIdleConnections == 0 {
		cfg.Database.ConnectionPool.MaxIdleConnections = 5
	}
	if cfg.Database.ConnectionPool.MaxOpenConnections == 0 {
		cfg.Database.ConnectionPool.MaxOpenConnections = 25
	}

	// API defaults
	if cfg.API.ListenAddr == "" {
		cfg.API.ListenAddr = ":8443"
	}
	if cfg.API.Authentication.TokenHeader == "" {
		cfg.API.Authentication.TokenHeader = "X-API-Token"
	}
	if cfg.API.Authentication.TokenExpiryDays == 0 {
		cfg.API.Authentication.TokenExpiryDays = 90
	}
	if cfg.API.RateLimiting.RequestsPerMinute == 0 {
		cfg.API.RateLimiting.RequestsPerMinute = 100
	}

	// Dashboard defaults
	if cfg.Dashboard.ListenAddr == "" {
		cfg.Dashboard.ListenAddr = ":5601"
	}
	if cfg.Dashboard.Authentication.TokenHeader == "" {
		cfg.Dashboard.Authentication.TokenHeader = "X-Dashboard-Token"
	}

	// LLM defaults
	if cfg.LLM.Primary == "" {
		cfg.LLM.Primary = "claude"
	}
	if cfg.LLM.Claude.Model == "" {
		cfg.LLM.Claude.Model = "claude-3-5-haiku-20241022"
	}

	// Detection defaults
	if cfg.Detection.Mode == "" {
		cfg.Detection.Mode = "detection"
	}
	if len(cfg.Detection.LLMOnlyOn) == 0 {
		cfg.Detection.LLMOnlyOn = []string{"POST", "PUT", "DELETE"}
	}

	// Execution mode defaults
	if cfg.ExecutionMode.Mode == "" {
		cfg.ExecutionMode.Mode = "onboarding"
	}
	if cfg.ExecutionMode.OnboardingDurationDays == 0 {
		cfg.ExecutionMode.OnboardingDurationDays = 7
	}
	if cfg.ExecutionMode.OnboardingLogFile == "" {
		cfg.ExecutionMode.OnboardingLogFile = "./logs/onboarding_traffic.log"
	}

	// Anonymization defaults
	if cfg.Anonymization.Strategy == "" {
		cfg.Anonymization.Strategy = "hybrid"
	}
	if len(cfg.Anonymization.SensitiveHeaders) == 0 {
		cfg.Anonymization.SensitiveHeaders = []string{
			"Authorization",
			"Cookie",
			"X-API-Key",
			"X-Auth-Token",
		}
	}

	// Payload management defaults
	if cfg.PayloadManagement.DynamicLLMCacheTTL == 0 {
		cfg.PayloadManagement.DynamicLLMCacheTTL = 86400
	}
	if cfg.PayloadManagement.DefaultResponses == nil {
		cfg.PayloadManagement.DefaultResponses = map[string]interface{}{
			"fallback": map[string]interface{}{
				"content":     map[string]interface{}{"error": "Internal server error"},
				"status_code": 500,
			},
		}
	}

	// System defaults
	if cfg.System.HomeDir == "" {
		cfg.System.HomeDir = "./"
	}
	if cfg.System.LogLevel == "" {
		cfg.System.LogLevel = "info"
	}

	// Create directories
	os.MkdirAll(cfg.System.LogDir, 0755)
	os.MkdirAll(filepath.Dir(cfg.Database.SQLite.Path), 0755)
}
