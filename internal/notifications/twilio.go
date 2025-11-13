package notifications

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"io"	

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
)

type TwilioProvider struct {
	config *config.TwilioProviderConfig
	client *http.Client
}

func NewTwilioProvider(cfg *config.TwilioProviderConfig) *TwilioProvider {
	return &TwilioProvider{
		config: cfg,
		client: &http.Client{},
	}
}

func (tp *TwilioProvider) Name() string {
	return "twilio"
}

func (tp *TwilioProvider) IsEnabled() bool {
	return tp.config.Enabled && tp.config.AccountSID != "" && tp.config.AuthToken != ""
}

// Send sends SMS notification via Twilio
func (tp *TwilioProvider) Send(notification *Notification) error {
	if !tp.IsEnabled() {
		return nil
	}

	if tp.config.FromNumber == "" {
		log.Printf("[TWILIO] No sender phone number configured")
		return fmt.Errorf("no sender phone number configured")
	}

	// Build SMS message
	message := tp.buildSMSMessage(notification)

	// Send SMS
	err := tp.sendSMS(tp.config.ToNumber, message)
	if err != nil {
		log.Printf("[TWILIO] ✗ Failed to send SMS: %v", err)
		return err
	}

	log.Printf("[TWILIO] ✓ SMS sent successfully (threat: %s/%d)", notification.ThreatLevel, notification.RiskScore)
	return nil
}

// sendSMS sends SMS via Twilio API
func (tp *TwilioProvider) sendSMS(toNumber, message string) error {
	// Twilio API endpoint
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", tp.config.AccountSID)

	// Prepare form data
	data := url.Values{}
	data.Set("From", tp.config.FromNumber)
	data.Set("To", toNumber)
	data.Set("Body", message)

	// Create request
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(tp.config.AccountSID, tp.config.AuthToken)

	// Send request
	resp, err := tp.client.Do(req)
	if err != nil {
		return fmt.Errorf("SMS request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[TWILIO] API Response (%d): %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("Twilio API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// buildSMSMessage constructs SMS message (160 chars limit)
func (tp *TwilioProvider) buildSMSMessage(notification *Notification) string {
	threatEmoji := "⚠️"
	if notification.ThreatLevel == "CRITICAL" {
		threatEmoji = "🚨"
	} else if notification.ThreatLevel == "HIGH" {
		threatEmoji = "⛔"
	}

	message := fmt.Sprintf(
		"%s IFRIT Alert: %s threat (%d/100) from %s. Attack: %s on %s. Time: %s",
		threatEmoji,
		notification.ThreatLevel,
		notification.RiskScore,
		notification.SourceIP,
		notification.AttackType,
		notification.Path,
		notification.Timestamp.Format("15:04 MST"),
	)

	// Truncate to 160 chars if needed
	if len(message) > 160 {
		message = message[:157] + "..."
	}

	return message
}
