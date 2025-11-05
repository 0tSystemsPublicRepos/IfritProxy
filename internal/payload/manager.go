package payload

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

type PayloadManager struct {
	db *sql.DB
	llmMgr interface{} // Will be *llm.Manager but avoiding circular import
}

// NewPayloadManager creates a new payload manager instance
func NewPayloadManager(db *sql.DB) *PayloadManager {
	return &PayloadManager{db: db}
}

// PayloadTemplate represents a stored payload template
type PayloadTemplate struct {
	ID             int
	Name           string
	AttackType     string
	Classification string
	PayloadType    string
	Content        string
	ContentType    string
	HTTPStatusCode int
	Conditions     string
	Priority       int
	IsActive       bool
	CreatedBy      string
}

// PayloadResponse represents the response to send to attacker
type PayloadResponse struct {
	StatusCode  int
	Headers     map[string]string
	Body        string
	ContentType string
	DelayMS     int
}

// AttackerContext contains information about the current attack
type AttackerContext struct {
	SourceIP         string
	AttackType       string
	Classification   string
	Path             string
	TotalRequests    int
	PreviousHoneypot bool
	AttackerProfile  string // beginner, intermediate, advanced
	GeographicOrigin string
}

// GetPayloadForAttack selects the best payload for the given attack
// Priority: Database → Dynamic (LLM) → Config Default → Fallback
func (pm *PayloadManager) GetPayloadForAttack(ctx AttackerContext, cfg *config.PayloadManagement, llmMgr interface{}) (*PayloadResponse, error) {
	// Stage 1: Try to get payload from database (fixed payloads)
	payload, err := pm.getPayloadByAttackType(ctx.AttackType)
	if err == nil && payload != nil {
		log.Printf("[PAYLOAD] Using database payload for %s (status: %d)", ctx.AttackType, payload.StatusCode)
		return payload, nil
	}

	// Stage 2: Generate dynamic payload if enabled
	if cfg != nil && cfg.GenerateDynamicPayload && llmMgr != nil {
		log.Printf("[PAYLOAD] Generating dynamic payload for %s via LLM", ctx.AttackType)
		payload, err := pm.getPayloadFromLLM(ctx.AttackType)
		if err == nil && payload != nil {
			log.Printf("[PAYLOAD] Using LLM-generated payload for %s (status: %d)", ctx.AttackType, payload.StatusCode)
			return payload, nil
		}
		log.Printf("[PAYLOAD] LLM generation failed: %v, falling back to config", err)
	}

	// Stage 3: Use config default response
	if cfg != nil && cfg.DefaultResponses != nil {
		payload, err := pm.getPayloadFromConfig(ctx.AttackType, cfg)
		if err == nil && payload != nil {
			log.Printf("[PAYLOAD] Using config default for %s (status: %d)", ctx.AttackType, payload.StatusCode)
			return payload, nil
		}
	}

	// Stage 4: Fallback to generic error
	payload = &PayloadResponse{
		StatusCode:  500,
		ContentType: "application/json",
		Body:        `{"error": "Internal server error"}`,
		Headers:     make(map[string]string),
		DelayMS:     50,
	}
	log.Printf("[PAYLOAD] Using fallback for %s (status: %d)", ctx.AttackType, payload.StatusCode)
	return payload, nil
}

// getConditionalPayload finds payload matching specific conditions
func (pm *PayloadManager) getConditionalPayload(ctx AttackerContext) (*PayloadResponse, error) {
	query := `
		SELECT id, name, content, content_type, http_status_code, payload_type
		FROM payload_templates
		WHERE is_active = 1 AND payload_type IN ('conditional', 'dynamic')
		ORDER BY priority DESC
		LIMIT 20
	`

	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, content, contentType, payloadType string
		var statusCode int

		if err := rows.Scan(&id, &name, &content, &contentType, &statusCode, &payloadType); err != nil {
			log.Printf("Error scanning payload: %v", err)
			continue
		}

		// Get conditions for this payload
		conditions, err := pm.getPayloadConditions(id)
		if err != nil {
			continue
		}

		// Check if conditions match
		if pm.conditionsMatch(conditions, ctx) {
			return &PayloadResponse{
				StatusCode:  statusCode,
				ContentType: contentType,
				Body:        content,
				Headers:     make(map[string]string),
				DelayMS:     50, // Realistic response delay
			}, nil
		}
	}

	return nil, nil
}

// getPayloadByAttackType gets payload for specific attack type
func (pm *PayloadManager) getPayloadByAttackType(attackType string) (*PayloadResponse, error) {
	query := `
		SELECT content, content_type, http_status_code
		FROM payload_templates
		WHERE is_active = 1 
		AND attack_type = ?
		AND payload_type = 'fixed'
		ORDER BY priority DESC
		LIMIT 1
	`

	var content, contentType string
	var statusCode int

	err := pm.db.QueryRow(query, attackType).Scan(&content, &contentType, &statusCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        content,
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getGenericPayload gets the default fallback payload
func (pm *PayloadManager) getGenericPayload() (*PayloadResponse, error) {
	query := `
		SELECT content, content_type, http_status_code
		FROM payload_templates
		WHERE is_active = 1 
		AND attack_type = 'unknown'
		LIMIT 1
	`

	var content, contentType string
	var statusCode int

	err := pm.db.QueryRow(query).Scan(&content, &contentType, &statusCode)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        content,
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getPayloadConditions retrieves all conditions for a payload template
func (pm *PayloadManager) getPayloadConditions(payloadID int) ([]PayloadCondition, error) {
	query := `
		SELECT condition_type, condition_value, operator
		FROM payload_conditions
		WHERE payload_template_id = ?
	`

	rows, err := pm.db.Query(query, payloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conditions []PayloadCondition

	for rows.Next() {
		var conditionType, conditionValue, operator string

		if err := rows.Scan(&conditionType, &conditionValue, &operator); err != nil {
			continue
		}

		conditions = append(conditions, PayloadCondition{
			Type:     conditionType,
			Value:    conditionValue,
			Operator: operator,
		})
	}

	return conditions, nil
}

// conditionsMatch checks if all conditions match the attacker context
func (pm *PayloadManager) conditionsMatch(conditions []PayloadCondition, ctx AttackerContext) bool {
	if len(conditions) == 0 {
		return false
	}

	for _, cond := range conditions {
		if !pm.conditionMatches(cond, ctx) {
			return false
		}
	}

	return true
}

// conditionMatches checks if a single condition matches
func (pm *PayloadManager) conditionMatches(cond PayloadCondition, ctx AttackerContext) bool {
	switch cond.Type {
	case "source_ip":
		return pm.ipMatches(cond.Value, ctx.SourceIP)
	case "attacker_profile":
		return strings.EqualFold(cond.Value, ctx.AttackerProfile)
	case "attack_type":
		return strings.EqualFold(cond.Value, ctx.AttackType)
	case "geographic":
		return strings.EqualFold(cond.Value, ctx.GeographicOrigin)
	case "classification":
		return strings.EqualFold(cond.Value, ctx.Classification)
	default:
		return false
	}
}

// ipMatches checks if IP matches pattern (supports wildcards)
func (pm *PayloadManager) ipMatches(pattern, ip string) bool {
	// Convert wildcard pattern to regex
	// 192.168.* becomes 192\.168\..*
	regexPattern := strings.ReplaceAll(pattern, ".", "\\.")
	regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, ip)
	if err != nil {
		log.Printf("IP pattern error: %v", err)
		return false
	}

	return matched
}

// CreatePayload creates a new payload template
func (pm *PayloadManager) CreatePayload(template PayloadTemplate) (int, error) {
	query := `
		INSERT INTO payload_templates 
		(name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, is_active, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := pm.db.Exec(query,
		template.Name,
		template.AttackType,
		template.Classification,
		template.PayloadType,
		template.Content,
		template.ContentType,
		template.HTTPStatusCode,
		template.Priority,
		template.IsActive,
		template.CreatedBy,
	)

	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	return int(id), err
}

// GetPayload retrieves a specific payload by ID
func (pm *PayloadManager) GetPayload(id int) (*PayloadTemplate, error) {
	query := `
		SELECT id, name, attack_type, classification, payload_type, content, content_type, http_status_code, conditions, priority, is_active, created_by
		FROM payload_templates
		WHERE id = ?
	`

	var template PayloadTemplate
	var conditions sql.NullString

	err := pm.db.QueryRow(query, id).Scan(
		&template.ID,
		&template.Name,
		&template.AttackType,
		&template.Classification,
		&template.PayloadType,
		&template.Content,
		&template.ContentType,
		&template.HTTPStatusCode,
		&conditions,
		&template.Priority,
		&template.IsActive,
		&template.CreatedBy,
	)

	if err != nil {
		return nil, err
	}

	if conditions.Valid {
		template.Conditions = conditions.String
	}

	return &template, nil
}

// ListPayloads retrieves all active payloads
func (pm *PayloadManager) ListPayloads(attackType string) ([]PayloadTemplate, error) {
	query := `
		SELECT id, name, attack_type, classification, payload_type, content, content_type, http_status_code, priority, is_active, created_by
		FROM payload_templates
		WHERE is_active = 1
	`

	if attackType != "" {
		query += ` AND attack_type = ?`
	}

	query += ` ORDER BY priority DESC`

	var rows *sql.Rows
	var err error

	if attackType != "" {
		rows, err = pm.db.Query(query, attackType)
	} else {
		rows, err = pm.db.Query(query)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var payloads []PayloadTemplate

	for rows.Next() {
		var template PayloadTemplate

		err := rows.Scan(
			&template.ID,
			&template.Name,
			&template.AttackType,
			&template.Classification,
			&template.PayloadType,
			&template.Content,
			&template.ContentType,
			&template.HTTPStatusCode,
			&template.Priority,
			&template.IsActive,
			&template.CreatedBy,
		)

		if err != nil {
			continue
		}

		payloads = append(payloads, template)
	}

	return payloads, nil
}

// UpdatePayload updates an existing payload
func (pm *PayloadManager) UpdatePayload(id int, template PayloadTemplate) error {
	query := `
		UPDATE payload_templates
		SET name = ?, attack_type = ?, classification = ?, payload_type = ?, 
		    content = ?, content_type = ?, http_status_code = ?, priority = ?, is_active = ?,
		    updated_at = datetime('now')
		WHERE id = ?
	`

	_, err := pm.db.Exec(query,
		template.Name,
		template.AttackType,
		template.Classification,
		template.PayloadType,
		template.Content,
		template.ContentType,
		template.HTTPStatusCode,
		template.Priority,
		template.IsActive,
		id,
	)

	return err
}

// DeletePayload deletes a payload template
func (pm *PayloadManager) DeletePayload(id int) error {
	query := `DELETE FROM payload_templates WHERE id = ?`
	_, err := pm.db.Exec(query, id)
	return err
}

// PayloadCondition represents a single condition for payload matching
type PayloadCondition struct {
	Type     string
	Value    string
	Operator string
}

// getPayloadFromConfig retrieves default response from config
func (pm *PayloadManager) getPayloadFromConfig(attackType string, cfg *config.PayloadManagement) (*PayloadResponse, error) {
	if cfg.DefaultResponses == nil {
		return nil, nil
	}

	// Try to get specific attack type response
	responseConfig, ok := cfg.DefaultResponses[attackType]
	if ok {
		return pm.parseConfigResponse(responseConfig)
	}

	// If not found, try fallback
	fallbackConfig, ok := cfg.DefaultResponses["fallback"]
	if ok {
		return pm.parseConfigResponse(fallbackConfig)
	}

	return nil, nil
}

// parseConfigResponse parses a config response into PayloadResponse
func (pm *PayloadManager) parseConfigResponse(respConfig interface{}) (*PayloadResponse, error) {
	respMap, ok := respConfig.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	content := respMap["content"]
	statusCode := int(respMap["status_code"].(float64))

	// Convert content to JSON string
	contentJSON, _ := json.Marshal(content)

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: "application/json",
		Body:        string(contentJSON),
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getPayloadFromLLM generates payload using LLM (Claude)
func (pm *PayloadManager) getPayloadFromLLM(attackType string) (*PayloadResponse, error) {
	if pm.llmMgr == nil {
		return nil, fmt.Errorf("LLM manager not configured")
	}

	// Cast to LLM Manager
	llmManager, ok := pm.llmMgr.(*llm.Manager)
	if !ok {
		return nil, fmt.Errorf("invalid LLM manager type")
	}

	// Generate fake payload using LLM
	payload, err := llmManager.GeneratePayload(attackType)
	if err != nil {
		return nil, fmt.Errorf("LLM generation error: %w", err)
	}

	if payload == nil {
		return nil, fmt.Errorf("LLM returned empty payload")
	}

	// Convert payload to JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Determine appropriate status code for attack type
	statusCode := pm.getStatusCodeForAttackType(attackType)

	return &PayloadResponse{
		StatusCode:  statusCode,
		ContentType: "application/json",
		Body:        string(payloadJSON),
		Headers:     make(map[string]string),
		DelayMS:     50,
	}, nil
}

// getStatusCodeForAttackType returns appropriate HTTP status for attack type
func (pm *PayloadManager) getStatusCodeForAttackType(attackType string) int {
	statusCodes := map[string]int{
		"reconnaissance":      404,
		"sql_injection":       403,
		"xss":                 400,
		"command_injection":   403,
		"credential_stuffing": 401,
		"path_traversal":      403,
	}

	if code, ok := statusCodes[attackType]; ok {
		return code
	}

	return 500 // Default
}

// SetLLMManager sets the LLM manager for dynamic payload generation
func (pm *PayloadManager) SetLLMManager(llmMgr interface{}) {
	pm.llmMgr = llmMgr
}

