package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"database/sql"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type WebhookProvider struct {
	config *config.WebhooksConfig
	db     *database.SQLiteDB
	client *http.Client
}

func NewWebhookProvider(cfg *config.WebhooksConfig, db *database.SQLiteDB) *WebhookProvider {
	return &WebhookProvider{
		config: cfg,
		db:     db,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}

func (wp *WebhookProvider) Name() string {
	return "webhook"
}

func (wp *WebhookProvider) IsEnabled() bool {
	return wp.config.Enabled
}

// Send fires webhook to configured endpoints
func (wp *WebhookProvider) Send(notification *Notification) error {
	if !wp.IsEnabled() {
		return nil
	}

	// Build webhook payload
	payload := wp.buildWebhookPayload(notification)

	// Get all active webhooks for this app
	webhooks, err := wp.getActiveWebhooks(notification.AppID)
	if err != nil {
		log.Printf("[WEBHOOK] Error fetching webhooks: %v", err)
		return err
	}

	if len(webhooks) == 0 {
		log.Printf("[WEBHOOK] No active webhooks configured for app_id: %s", notification.AppID)
		return nil
	}

	// Fire each webhook
	for _, webhook := range webhooks {
		go wp.fireWebhook(webhook, payload, notification)
	}

	return nil
}

// fireWebhook sends webhook with retry logic
func (wp *WebhookProvider) fireWebhook(webhook map[string]interface{}, payload *WebhookPayload, notification *Notification) {
	webhookID := int64(webhook["id"].(int64))
	endpoint := webhook["endpoint"].(string)
	authType := webhook["auth_type"].(string)
	authValue := webhook["auth_value"].(string)

	payloadJSON, _ := json.Marshal(payload)

	var lastErr error
	for attempt := 1; attempt <= wp.config.RetryCount; attempt++ {
		err := wp.sendWebhookRequest(endpoint, authType, authValue, payloadJSON)
		if err == nil {
			log.Printf("[WEBHOOK] ✓ Webhook %d fired successfully to %s (threat: %s/%d)", webhookID, endpoint, notification.ThreatLevel, notification.RiskScore)
			wp.recordWebhookFire(webhookID, "success", "")
			return
		}

		lastErr = err
		log.Printf("[WEBHOOK] Attempt %d/%d failed for webhook %d: %v", attempt, wp.config.RetryCount, webhookID, err)

		if attempt < wp.config.RetryCount {
			time.Sleep(time.Duration(wp.config.RetryDelaySeconds) * time.Second)
		}
	}

	log.Printf("[WEBHOOK] ✗ Webhook %d failed after %d attempts: %v", webhookID, wp.config.RetryCount, lastErr)
	wp.recordWebhookFire(webhookID, "failed", lastErr.Error())
}

// sendWebhookRequest makes HTTP request to webhook endpoint
func (wp *WebhookProvider) sendWebhookRequest(endpoint, authType, authValue string, payload []byte) error {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IFRIT-Webhook/1.0")

	// Add authentication if configured
	if authType == "bearer" && authValue != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authValue))
	} else if authType == "apikey" && authValue != "" {
		req.Header.Set("X-API-Key", authValue)
	} else if authType == "basic" && authValue != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", authValue))
	}

	resp, err := wp.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// buildWebhookPayload constructs the webhook payload
func (wp *WebhookProvider) buildWebhookPayload(notification *Notification) *WebhookPayload {
	payload := &WebhookPayload{
		Event:       "threat_detected",
		Timestamp:   notification.Timestamp,
		AppID:       notification.AppID,
		ThreatLevel: notification.ThreatLevel,
		RiskScore:   notification.RiskScore,
		SourceIP:    notification.SourceIP,
		Country:     notification.Country,
		AttackType:  notification.AttackType,
		Path:        notification.Path,
		Method:      notification.Method,
	}

	// Add AbuseIPDB data
	if notification.AbuseIPDBScore > 0 || notification.AbuseIPDBReports > 0 {
		payload.AbuseIPDB = map[string]interface{}{
			"confidence_score": notification.AbuseIPDBScore,
			"reports":          notification.AbuseIPDBReports,
		}
	}

	// Add VirusTotal data
	if notification.VirusTotalMalicious > 0 || notification.VirusTotalSuspicious > 0 {
		payload.VirusTotal = map[string]interface{}{
			"malicious":  notification.VirusTotalMalicious,
			"suspicious": notification.VirusTotalSuspicious,
		}
	}

	return payload
}

// getActiveWebhooks retrieves all active webhooks for an app
func (wp *WebhookProvider) getActiveWebhooks(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, endpoint, auth_type, auth_value
		FROM webhooks_config
		WHERE app_id = ? AND enabled = 1
	`
	
	rows, err := wp.db.GetDB().Query(query, appID)
	if err != nil {
		log.Printf("[WEBHOOK] Database query error: %v", err)
		return nil, err
	}
	defer rows.Close()

	var webhooks []map[string]interface{}
	for rows.Next() {
		var id int64
		var endpoint, authType string
		var authValue sql.NullString
		
		if err := rows.Scan(&id, &endpoint, &authType, &authValue); err != nil {
			log.Printf("[WEBHOOK] Row scan error: %v", err)
			continue
		}

		authVal := ""
		if authValue.Valid {
			authVal = authValue.String
		}

		log.Printf("[WEBHOOK] Found webhook: id=%d endpoint=%s auth_type=%s", id, endpoint, authType)
		webhooks = append(webhooks, map[string]interface{}{
			"id":        id,
			"endpoint":  endpoint,
			"auth_type": authType,
			"auth_value": authVal,
		})
	}

	if len(webhooks) == 0 {
		log.Printf("[WEBHOOK] No active webhooks found for app_id: %s", appID)
	} else {
		log.Printf("[WEBHOOK] Found %d active webhook(s) for app_id: %s", len(webhooks), appID)
	}

	return webhooks, rows.Err()
}


// recordWebhookFire logs webhook fire attempt
func (wp *WebhookProvider) recordWebhookFire(webhookID int64, status, errorMsg string) {
	// This could be extended to store webhook fire history in database
	// For now, just log it
	if status == "success" {
		log.Printf("[WEBHOOK] Fire recorded: webhook_id=%d status=success", webhookID)
	} else {
		log.Printf("[WEBHOOK] Fire recorded: webhook_id=%d status=failed error=%s", webhookID, errorMsg)
	}
}
