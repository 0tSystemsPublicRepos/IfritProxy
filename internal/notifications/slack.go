package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
)

type SlackProvider struct {
	config *config.SlackProviderConfig
	client *http.Client
}

func NewSlackProvider(cfg *config.SlackProviderConfig) *SlackProvider {
	return &SlackProvider{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (sp *SlackProvider) Name() string {
	return "slack"
}

func (sp *SlackProvider) IsEnabled() bool {
	return sp.config.Enabled && sp.config.WebhookURL != "" && sp.config.WebhookURL != "${SLACK_WEBHOOK_URL}"
}

// Send sends Slack notification
func (sp *SlackProvider) Send(notification *Notification) error {
	if !sp.IsEnabled() {
		return nil
	}

	payload := sp.buildSlackPayload(notification)

	err := sp.sendToSlack(payload)
	if err != nil {
		log.Printf("[SLACK] ✗ Failed to send Slack message: %v", err)
		return err
	}

	log.Printf("[SLACK] ✓ Slack message sent successfully (threat: %s/%d)", notification.ThreatLevel, notification.RiskScore)
	return nil
}

// sendToSlack sends webhook message to Slack
func (sp *SlackProvider) sendToSlack(payload interface{}) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", sp.config.WebhookURL, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IFRIT/1.0")

	resp, err := sp.client.Do(req)
	if err != nil {
		return fmt.Errorf("Slack webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Slack webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// buildSlackPayload constructs Slack message payload
func (sp *SlackProvider) buildSlackPayload(notification *Notification) map[string]interface{} {
	// Determine color based on threat level
	color := "#36a64f" // Green
	emoji := ":information_source:"
	if notification.ThreatLevel == "CRITICAL" {
		color = "#ff0000" // Red
		emoji = ":rotating_light:"
	} else if notification.ThreatLevel == "HIGH" {
		color = "#ff6600" // Orange
		emoji = ":warning:"
	} else if notification.ThreatLevel == "MEDIUM" {
		color = "#ffaa00" // Dark Orange
		emoji = ":warning:"
	} else if notification.ThreatLevel == "LOW" {
		color = "#00aa00" // Green
		emoji = ":green_circle:"
	}

	// Build fields
	fields := []map[string]interface{}{
		{
			"title": "Threat Level",
			"value": fmt.Sprintf("%s %s", emoji, notification.ThreatLevel),
			"short": true,
		},
		{
			"title": "Risk Score",
			"value": fmt.Sprintf("%d/100", notification.RiskScore),
			"short": true,
		},
		{
			"title": "Attack Type",
			"value": notification.AttackType,
			"short": true,
		},
		{
			"title": "Source IP",
			"value": fmt.Sprintf("`%s`", notification.SourceIP),
			"short": true,
		},
		{
			"title": "Country",
			"value": notification.Country,
			"short": true,
		},
		{
			"title": "HTTP Method",
			"value": notification.Method,
			"short": true,
		},
		{
			"title": "Target Path",
			"value": fmt.Sprintf("`%s`", notification.Path),
			"short": false,
		},
		{
			"title": "Timestamp",
			"value": notification.Timestamp.Format("2006-01-02 15:04:05 MST"),
			"short": false,
		},
	}

	// Add AbuseIPDB info if available
	if notification.AbuseIPDBReports > 0 {
		fields = append(fields, map[string]interface{}{
			"title": "AbuseIPDB Score",
			"value": fmt.Sprintf("%.1f%% (%d reports)", notification.AbuseIPDBScore, notification.AbuseIPDBReports),
			"short": true,
		})
	}

	// Add VirusTotal info if available
	if notification.VirusTotalMalicious > 0 || notification.VirusTotalSuspicious > 0 {
		fields = append(fields, map[string]interface{}{
			"title": "VirusTotal",
			"value": fmt.Sprintf("Malicious: %d, Suspicious: %d", notification.VirusTotalMalicious, notification.VirusTotalSuspicious),
			"short": true,
		})
	}

	// Build attachment
	attachment := map[string]interface{}{
		"fallback": fmt.Sprintf("IFRIT Alert: %s threat (%d/100) from %s", notification.ThreatLevel, notification.RiskScore, notification.SourceIP),
		"color":    color,
		"title":    fmt.Sprintf("%s IFRIT Threat Alert - %s", emoji, notification.ThreatLevel),
		"fields":   fields,
		"ts":       notification.Timestamp.Unix(),
	}

	// Build final payload
	payload := map[string]interface{}{
		"username":    "IFRIT Threat Intelligence",
		"icon_emoji":  ":shield:",
		"attachments": []map[string]interface{}{attachment},
	}

	return payload
}
