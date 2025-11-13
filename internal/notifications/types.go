package notifications

import (
	"time"
)

type NotificationProvider interface {
	Send(notification *Notification) error
	Name() string
	IsEnabled() bool
}

type Notification struct {
	AppID           string
	ThreatLevel     string
	RiskScore       int
	SourceIP        string
	Country         string
	AttackType      string
	Path            string
	Method          string
	Timestamp       time.Time
	AbuseIPDBScore  float64
	AbuseIPDBReports int
	VirusTotalMalicious int
	VirusTotalSuspicious int
}

type WebhookPayload struct {
	Event            string                 `json:"event"`
	Timestamp        time.Time              `json:"timestamp"`
	AppID            string                 `json:"app_id"`
	ThreatLevel      string                 `json:"threat_level"`
	RiskScore        int                    `json:"risk_score"`
	SourceIP         string                 `json:"source_ip"`
	Country          string                 `json:"country"`
	AttackType       string                 `json:"attack_type"`
	Path             string                 `json:"path"`
	Method           string                 `json:"method"`
	AbuseIPDB        map[string]interface{} `json:"abuse_ipdb,omitempty"`
	VirusTotal       map[string]interface{} `json:"virustotal,omitempty"`
	IPInfo           map[string]interface{} `json:"ipinfo,omitempty"`
}

type EmailPayload struct {
	To      string
	Subject string
	Body    string
	HTML    bool
}

type SlackPayload struct {
	Channel     string
	Username    string
	IconEmoji   string
	Attachments []SlackAttachment `json:"attachments"`
}

type SlackAttachment struct {
	Color      string       `json:"color"`
	Title      string       `json:"title"`
	TitleLink  string       `json:"title_link"`
	Text       string       `json:"text"`
	Fields     []SlackField `json:"fields"`
	Timestamp  int64        `json:"ts"`
	ImageURL   string       `json:"image_url,omitempty"`
	ThumbURL   string       `json:"thumb_url,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type TwilioPayload struct {
	To   string
	From string
	Body string
}
