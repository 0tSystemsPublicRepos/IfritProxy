package config

// ThreatIntelligenceConfig holds threat intelligence settings
type ThreatIntelligenceConfig struct {
	Enabled               bool                   `json:"enabled"`
	CacheTTLHours         int                    `json:"cache_ttl_hours"`
	EnrichmentWorkers     int                    `json:"enrichment_workers"`
	APIs                  ThreatIntelligenceAPIs `json:"apis"`
	RiskScoreWeights      RiskScoreWeights       `json:"risk_score_weights"`
	ThreatLevelThresholds ThreatLevelThresholds  `json:"threat_level_thresholds"`
}

type ThreatIntelligenceAPIs struct {
	AbuseIPDB  AbuseIPDBConfig  `json:"abuseipdb"`
	VirusTotal VirusTotalConfig `json:"virustotal"`
	IPInfo     IPInfoConfig     `json:"ipinfo"`
}

type AbuseIPDBConfig struct {
	Enabled        bool   `json:"enabled"`
	APIKey         string `json:"api_key"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type VirusTotalConfig struct {
	Enabled        bool   `json:"enabled"`
	APIKey         string `json:"api_key"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type IPInfoConfig struct {
	Enabled        bool   `json:"enabled"`
	APIKey         string `json:"api_key"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type RiskScoreWeights struct {
	AbuseIPDBScore       float64 `json:"abuseipdb_score"`
	VirusTotalDetections float64 `json:"virustotal_detections"`
	IPInfoRisk           float64 `json:"ipinfo_risk"`
}

type ThreatLevelThresholds struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// NotificationsConfig holds notification settings
type NotificationsConfig struct {
	Enabled   bool                  `json:"enabled"`
	Providers NotificationProviders `json:"providers"`
	Rules   NotificationRulesConfig `json:"rules"`
}

type NotificationProviders struct {
	Email  EmailProviderConfig  `json:"email"`
	Slack  SlackProviderConfig  `json:"slack"`
	Twilio TwilioProviderConfig `json:"twilio"`
}

type EmailProviderConfig struct {
	Enabled      bool   `json:"enabled"`
	SMTPHost     string `json:"smtp_host"`
	SMTPPort     int    `json:"smtp_port"`
	SMTPUsername string `json:"smtp_username"`
	SMTPPassword string `json:"smtp_password"`
	FromAddress  string `json:"from_address"`
}

type SlackProviderConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
}

type TwilioProviderConfig struct {
	Enabled    bool   `json:"enabled"`
	AccountSID string `json:"account_sid"`
	AuthToken  string `json:"auth_token"`
	FromNumber string `json:"from_number"`
	ToNumber   string `json:"to_number"`
}

// WebhooksConfig holds webhook settings
type WebhooksConfig struct {
	Enabled           bool `json:"enabled"`
	RetryCount        int  `json:"retry_count"`
	RetryDelaySeconds int  `json:"retry_delay_seconds"`
	TimeoutSeconds    int  `json:"timeout_seconds"`
}

// NotificationRulesConfig holds notification filtering rules
type NotificationRulesConfig struct {
	AlertOnCritical bool `json:"alert_on_critical"`
	AlertOnHigh     bool `json:"alert_on_high"`
	AlertOnMedium   bool `json:"alert_on_medium"`
	AlertOnLow      bool `json:"alert_on_low"`
}
