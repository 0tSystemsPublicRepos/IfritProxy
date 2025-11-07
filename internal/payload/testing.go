package payload

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

// TestPayload validates a payload before saving
func (pm *PayloadManager) TestPayload(template PayloadTemplate) (bool, []string) {
	var errors []string

	// Validate required fields
	if template.Name == "" {
		errors = append(errors, "Payload name is required")
	}

	if template.AttackType == "" {
		errors = append(errors, "Attack type is required")
	}

	if template.Content == "" {
		errors = append(errors, "Payload content is required")
	}

	if template.HTTPStatusCode < 100 || template.HTTPStatusCode > 599 {
		errors = append(errors, "HTTP status code must be between 100 and 599")
	}

	if template.Priority < 1 || template.Priority > 100 {
		errors = append(errors, "Priority must be between 1 and 100")
	}

	// Validate payload type
	validTypes := map[string]bool{"fixed": true, "conditional": true, "dynamic": true}
	if !validTypes[template.PayloadType] {
		errors = append(errors, "Payload type must be 'fixed', 'conditional', or 'dynamic'")
	}

	// Validate content type
	validContentTypes := map[string]bool{
		"application/json":       true,
		"text/plain":             true,
		"text/html":              true,
		"application/xml":        true,
		"text/xml":               true,
		"application/javascript": true,
	}
	if !validContentTypes[template.ContentType] {
		errors = append(errors, "Content type not in approved list")
	}

	return len(errors) == 0, errors
}

// TestPayloadDelivery simulates payload delivery and validates response
func (pm *PayloadManager) TestPayloadDelivery(ctx AttackerContext, cfg *config.PayloadManagement, llmMgr *llm.Manager) (bool, string) {
	start := time.Now()

	payload, err := pm.GetPayloadForAttack(ctx, cfg, llmMgr)
	if err != nil {
		return false, "Error retrieving payload: " + err.Error()
	}

	elapsed := time.Since(start)

	// Validate response
	if payload == nil {
		return false, "No payload returned"
	}

	// Check response time is reasonable
	if elapsed > 5*time.Second {
		return false, fmt.Sprintf("Payload retrieval took too long: %v", elapsed)
	}

	return true, fmt.Sprintf("Payload delivered successfully in %v", elapsed)
}

// ValidatePayloadContent checks if payload content is safe
func (pm *PayloadManager) ValidatePayloadContent(content, contentType string) (bool, []string) {
	var errors []string

	// Check for suspicious patterns that might leak real data
	suspiciousPatterns := []string{
		"127.0.0.1",   // localhost
		"localhost",   // localhost
		"/etc/shadow", // real file
		"/var/log",    // real path
		"root:",       // real user
	}

	for _, pattern := range suspiciousPatterns {
		if content == pattern {
			errors = append(errors, "Payload contains suspicious pattern: "+pattern)
		}
	}

	// Validate JSON if content type is JSON
	if contentType == "application/json" {
		var obj interface{}
		if err := json.Unmarshal([]byte(content), &obj); err != nil {
			errors = append(errors, "Invalid JSON in payload: "+err.Error())
		}
	}

	return len(errors) == 0, errors
}
