package payload

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

type AttackerContext struct {
	SourceIP       string
	AttackType     string
	Classification string
	Path           string
}

type PayloadResponse struct {
	Body        string
	StatusCode  int
	ContentType string
}

type PayloadTemplate struct {
	ID              int64
	Name            string
	AttackType      string
	PayloadType     string
	Content         string
	ContentType     string
	HTTPStatusCode  int
	IsActive        bool
	Priority        int
	CreatedBy       string
}

type PayloadCondition struct {
	ID                 int64
	PayloadTemplateID  int64
	ConditionType      string
	ConditionValue     string
	Operator           string
}

type PayloadManager struct {
	db         *sql.DB
	llmManager *llm.Manager
}

func NewPayloadManager(db *sql.DB) *PayloadManager {
	return &PayloadManager{
		db:         db,
		llmManager: nil,
	}
}

func (pm *PayloadManager) SetLLMManager(manager *llm.Manager) {
	pm.llmManager = manager
}

// GetPayloadForAttack returns appropriate honeypot payload for detected attack
func (pm *PayloadManager) GetPayloadForAttack(ctx AttackerContext, cfg *config.PayloadManagement, llmManager *llm.Manager) (*PayloadResponse, error) {
	log.Printf("[PAYLOAD] Getting payload for attack type: %s from %s", ctx.AttackType, ctx.SourceIP)

	// 1. Check if we should use database payloads
	if cfg.UseDBPayloads {
		payload, err := pm.getPayloadFromDB(ctx.AttackType)
		if err == nil && payload != nil {
			log.Printf("[PAYLOAD] Using cached payload from DB for: %s", ctx.AttackType)
			return payload, nil
		}
	}

	// 2. Try to generate dynamic payload via LLM
	if cfg.GenerateDynamicPayload && llmManager != nil {
		log.Printf("[PAYLOAD] Generating dynamic payload via LLM for: %s", ctx.AttackType)
		payload, err := pm.generateLLMPayload(ctx, cfg, llmManager)
		if err == nil && payload != nil {
			return payload, nil
		}
	}

	// 3. Fall back to default responses
	log.Printf("[PAYLOAD] Using default response for: %s", ctx.AttackType)
	return pm.getDefaultPayload(ctx.AttackType, cfg), nil
}

// getPayloadFromDB retrieves payload template from database
func (pm *PayloadManager) getPayloadFromDB(attackType string) (*PayloadResponse, error) {
	var content, contentType string
	var statusCode int

	err := pm.db.QueryRow(
		`SELECT content, content_type, http_status_code 
		 FROM payload_templates 
		 WHERE attack_type = ? AND is_active = 1 
		 ORDER BY priority DESC 
		 LIMIT 1`,
		attackType,
	).Scan(&content, &contentType, &statusCode)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[PAYLOAD] No payload template found in DB for: %s", attackType)
			return nil, nil
		}
		log.Printf("[PAYLOAD] Error querying DB for payload: %v", err)
		return nil, err
	}

	return &PayloadResponse{
		Body:        content,
		ContentType: contentType,
		StatusCode:  statusCode,
	}, nil
}

// generateLLMPayload generates payload via LLM with intel injection
func (pm *PayloadManager) generateLLMPayload(ctx AttackerContext, cfg *config.PayloadManagement, llmManager *llm.Manager) (*PayloadResponse, error) {
	// Get LLM provider (Claude)
	provider := llmManager.GetProvider(llmManager.GetPrimaryName())
	if provider == nil {
		return nil, fmt.Errorf("LLM provider not available")
	}

	claudeProvider, ok := provider.(*llm.ClaudeProvider)
	if !ok {
		return nil, fmt.Errorf("provider is not Claude")
	}

	// Get intel templates from database
	intelTemplates, err := pm.getIntelTemplates()
	if err != nil {
		log.Printf("[PAYLOAD] Error getting intel templates: %v", err)
		intelTemplates = []map[string]interface{}{}
	}

	// Set intel templates on Claude provider
	claudeProvider.SetIntelTemplates(intelTemplates)

	// Generate payload with intel injection
	intelTemplateID := cfg.IntelCollectionPayloadID
	if intelTemplateID <= 0 {
		intelTemplateID = 1
	}

	payloadData, err := claudeProvider.GeneratePayloadWithIntel(ctx.AttackType, intelTemplateID)
	if err != nil {
		log.Printf("[PAYLOAD] Error generating LLM payload: %v", err)
		return nil, err
	}

	// Convert to JSON
	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		return nil, err
	}

	// Cache the payload if configured
	if cfg.CacheLLMPayloadsToDb {
		pm.cachePayloadToDB(ctx.AttackType, string(payloadJSON))
	}

	return &PayloadResponse{
		Body:        string(payloadJSON),
		ContentType: "application/json",
		StatusCode:  200,
	}, nil
}

// getDefaultPayload returns default payload for attack type
func (pm *PayloadManager) getDefaultPayload(attackType string, cfg *config.PayloadManagement) *PayloadResponse {
	// Check default responses in config
	if response, ok := cfg.DefaultResponses[attackType]; ok {
		if respMap, ok := response.(map[string]interface{}); ok {
			content := respMap["content"]
			statusCode := int64(500)
			if sc, ok := respMap["status_code"].(float64); ok {
				statusCode = int64(sc)
			}

			contentJSON, _ := json.Marshal(content)
			return &PayloadResponse{
				Body:        string(contentJSON),
				ContentType: "application/json",
				StatusCode:  int(statusCode),
			}
		}
	}

	// Ultimate fallback
	fallback := cfg.DefaultResponses["fallback"]
	if respMap, ok := fallback.(map[string]interface{}); ok {
		content := respMap["content"]
		statusCode := int64(500)
		if sc, ok := respMap["status_code"].(float64); ok {
			statusCode = int64(sc)
		}

		contentJSON, _ := json.Marshal(content)
		return &PayloadResponse{
			Body:        string(contentJSON),
			ContentType: "application/json",
			StatusCode:  int(statusCode),
		}
	}

	return &PayloadResponse{
		Body:        `{"error": "Internal server error"}`,
		ContentType: "application/json",
		StatusCode:  500,
	}
}

// getIntelTemplates retrieves active intel collection templates from database
func (pm *PayloadManager) getIntelTemplates() ([]map[string]interface{}, error) {
	rows, err := pm.db.Query(
		`SELECT id, name, template_type, content, description 
		 FROM intel_collection_templates 
		 WHERE is_active = 1 
		 ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id int64
		var name, templateType, content, description string

		if err := rows.Scan(&id, &name, &templateType, &content, &description); err != nil {
			continue
		}

		template := map[string]interface{}{
			"id":              id,
			"name":            name,
			"template_type":   templateType,
			"content":         content,
			"description":     description,
		}
		templates = append(templates, template)
	}

	return templates, rows.Err()
}

// cachePayloadToDB stores generated payload in database for future use
func (pm *PayloadManager) cachePayloadToDB(attackType, payloadJSON string) error {
	_, err := pm.db.Exec(
		`INSERT OR REPLACE INTO payload_templates (name, attack_type, payload_type, content, content_type, http_status_code, is_active, created_at, created_by)
		 VALUES (?, ?, 'dynamic', ?, 'application/json', 200, 1, CURRENT_TIMESTAMP, 'llm_cache')`,
		fmt.Sprintf("dynamic_%s_%d", attackType, getCurrentUnixTimestamp()),
		attackType,
		payloadJSON,
	)

	if err != nil {
		log.Printf("[PAYLOAD] Error caching payload to DB: %v", err)
		return err
	}

	log.Printf("[PAYLOAD] Cached LLM-generated payload for: %s", attackType)
	return nil
}

// GetCacheStats returns cache statistics
func (pm *PayloadManager) GetCacheStats() map[string]interface{} {
	var totalPayloads, activeLLMPayloads int64

	pm.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1").Scan(&totalPayloads)
	pm.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1 AND created_by = 'llm_cache'").Scan(&activeLLMPayloads)

	return map[string]interface{}{
		"total_payloads":        totalPayloads,
		"active_llm_payloads":   activeLLMPayloads,
		"intel_injection_ready": true,
	}
}

func getCurrentUnixTimestamp() int64 {
	return 1730976294 // Nov 7, 2025
}
