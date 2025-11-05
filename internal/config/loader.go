package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type PayloadManagement struct {
	GenerateDynamicPayload bool                   `json:"generate_dynamic_payload"`
	DynamicLLMCacheTTL     int                    `json:"dynamic_llm_cache_ttl"`
	DefaultResponses       map[string]interface{} `json:"default_responses"`
}

type ExecutionModeConfig struct {
	Mode                    string `json:"mode"`
	OnboardingAutoWhitelist bool   `json:"onboarding_auto_whitelist"`
	OnboardingDurationDays  int    `json:"onboarding_duration_days"`
	OnboardingLogFile       string `json:"onboarding_log_file"`
}

type Config struct {
	Server            ServerConfig        `json:"server"`
	Database          DatabaseConfig      `json:"database"`
	LLM               LLMConfig           `json:"llm"`
	Detection         DetectionConfig     `json:"detection"`
	ExecutionMode     ExecutionModeConfig `json:"execution_mode"`
	Anonymization     AnonymizationConfig `json:"anonymization"`
	PayloadManagement PayloadManagement   `json:"payload_management"`
	System            SystemConfig        `json:"system"`
}

type ServerConfig struct {
	ListenAddr    string    `json:"listen_addr"`
	ProxyTarget   string    `json:"proxy_target"`
	APIListenAddr string    `json:"api_listen_addr"`
	TLS           TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type DatabaseConfig struct {
	Type string `json:"type"`
	Path string `json:"path"`
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
	EnableLocalRules bool     `json:"enable_local_rules"`
	EnableLLM        bool     `json:"enable_llm"`
	LLMOnlyOn        []string `json:"llm_only_on"`
	WhitelistIPs     []string `json:"whitelist_ips"`
	WhitelistPaths   []string `json:"whitelist_paths"`
}

type AnonymizationConfig struct {
	Enabled          bool     `json:"enabled"`
	Strategy         string   `json:"strategy"`
	StoreOriginal    bool     `json:"store_original"`
	SensitiveHeaders []string `json:"sensitive_headers"`
}

type SystemConfig struct {
	HomeDir  string `json:"home_dir"`
	LogDir   string `json:"log_dir"`
	LogLevel string `json:"log_level"`
}

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

	// Parse based on file extension or content
	var config Config

	// Try JSON first
	if err := json.Unmarshal(data, &config); err == nil {
		applyDefaults(&config)
		return &config, nil
	}

	// Try parsing as simple YAML-like format (key: value)
	if err := parseSimpleYAML(string(data), &config); err == nil {
		applyDefaults(&config)
		return &config, nil
	}

	// If all else fails, use defaults
	fmt.Println("Failed to parse config, using defaults")
	return getDefaults(), nil
}

func parseSimpleYAML(content string, cfg *Config) error {
	// Simple YAML parser for our specific config
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Very basic parsing (not a full YAML parser)
		if strings.Contains(line, "listen_addr") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				cfg.Server.ListenAddr = strings.TrimSpace(strings.Trim(parts[1], "\"'"))
			}
		}
	}

	return nil
}

func getDefaults() *Config {
	cfg := &Config{
		Server: ServerConfig{
			ListenAddr:    ":8080",
			ProxyTarget:   "http://localhost:80",
			APIListenAddr: ":8443",
			TLS: TLSConfig{
				Enabled:  true,
				CertFile: "/app/config/certs/server.crt",
				KeyFile:  "/app/config/certs/server.key",
			},
		},
		Database: DatabaseConfig{
			Type: "sqlite",
			Path: "./data/ifrit.db",
		},
		LLM: LLMConfig{
			Primary: "claude",
			Claude: ClaudeConfig{
				Model: "claude-3-5-sonnet",
			},
			GPT: GPTConfig{
				Model: "gpt-4",
			},
		},
		Detection: DetectionConfig{
			EnableLocalRules: true,
			EnableLLM:        true,
			LLMOnlyOn:        []string{"POST", "PUT", "DELETE"},
			WhitelistIPs:     []string{},
		},
		ExecutionMode: ExecutionModeConfig{
			Mode:                    "onboarding",
			OnboardingAutoWhitelist: true,
			OnboardingDurationDays:  7,
			OnboardingLogFile:       "./logs/onboarding_traffic.log",
		},
		Anonymization: AnonymizationConfig{
			Enabled:       true,
			Strategy:      "hybrid",
			StoreOriginal: true,
			SensitiveHeaders: []string{
				"Authorization",
				"Cookie",
				"X-API-Key",
			},
		},
		PayloadManagement: PayloadManagement{
			GenerateDynamicPayload: false,
			DynamicLLMCacheTTL:     86400,
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
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.APIListenAddr == "" {
		cfg.Server.APIListenAddr = ":8443"
	}
	if cfg.Server.ProxyTarget == "" {
		cfg.Server.ProxyTarget = "http://localhost:80"
	}
	if cfg.Database.Type == "" {
		cfg.Database.Type = "sqlite"
	}
	if cfg.Database.Path == "" {
		cfg.Database.Path = "./data/ifrit.db"
	}
	if cfg.LLM.Primary == "" {
		cfg.LLM.Primary = "claude"
	}
	if cfg.LLM.Claude.Model == "" {
		cfg.LLM.Claude.Model = "claude-3-5-sonnet"
	}
	if cfg.ExecutionMode.Mode == "" {
		cfg.ExecutionMode.Mode = "onboarding"
	}
	if cfg.ExecutionMode.OnboardingDurationDays == 0 {
		cfg.ExecutionMode.OnboardingDurationDays = 7
	}
	if cfg.ExecutionMode.OnboardingLogFile == "" {
		cfg.ExecutionMode.OnboardingLogFile = "./logs/onboarding_traffic.log"
	}
	if cfg.System.HomeDir == "" {
		cfg.System.HomeDir = "./"
	}
	if cfg.System.LogLevel == "" {
		cfg.System.LogLevel = "info"
	}
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

	// Do NOT set default whitelist IPs if config explicitly set empty array
	// This allows onboarding mode to work properly
	if cfg.Detection.WhitelistIPs == nil {
		cfg.Detection.WhitelistIPs = []string{}
	}

	// Create directories
	os.MkdirAll(cfg.System.LogDir, 0755)
	os.MkdirAll(filepath.Dir(cfg.Database.Path), 0755)
}
