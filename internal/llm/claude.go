package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
)

type ClaudeProvider struct {
	apiKey           string
	model            string
	anonEngine       *anonymization.AnonymizationEngine
	intelTemplates   []map[string]interface{}
}

type ClaudeRequest struct {
	Model       string         `json:"model"`
	MaxTokens   int            `json:"max_tokens"`
	Messages    []ClaudeMessage `json:"messages"`
}

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func NewClaudeProvider(apiKey, model string) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey:         apiKey,
		model:          model,
		intelTemplates: []map[string]interface{}{},
	}
}

func (cp *ClaudeProvider) GetName() string {
	return "claude"
}

func (cp *ClaudeProvider) SetAnonymizationEngine(engine *anonymization.AnonymizationEngine) {
	cp.anonEngine = engine
}

func (cp *ClaudeProvider) SetIntelTemplates(templates []map[string]interface{}) {
	cp.intelTemplates = templates
}

func (cp *ClaudeProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	// Note: Anonymization happens at a higher level before calling LLM
	// For now, we use requestData as-is

	prompt := fmt.Sprintf(`You are a security threat detection AI. Analyze this HTTP request and determine if it's malicious.

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Respond with ONLY valid JSON in this format:
{
  "is_attack": boolean,
  "attack_type": "string or null",
  "classification": "string or null",
  "confidence": number (0-1),
  "reason": "string"
}

Be strict. Return true only for clear attacks.`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
	)

	claudeReq := ClaudeRequest{
		Model:     cp.model,
		MaxTokens: 256,
		Messages: []ClaudeMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	reqBody, _ := json.Marshal(claudeReq)
	httpReq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", cp.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		log.Printf("Failed to parse Claude response: %v", err)
		return nil, err
	}

	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude")
	}

 	// Parse the JSON response
var result AnalysisResult
if err := json.Unmarshal([]byte(claudeResp.Content[0].Text), &result); err != nil {
    log.Printf("Failed to parse Claude analysis: %v. Raw: %s", err, claudeResp.Content[0].Text)
    return nil, err
}

	
	return &result, nil
}

func (cp *ClaudeProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"status":    "success",
		"message":   "Request processed",
		"data":      map[string]interface{}{},
		"timestamp": getCurrentTimestamp(),
	}

	// Add attack-specific responses
	switch attackType {
	case "sql_injection":
		payload = map[string]interface{}{
			"error": "Invalid query",
			"code":  1064,
		}
	case "xss":
		payload = map[string]interface{}{
			"error":   "Invalid input",
			"message": "XSS prevention enabled",
		}
	case "path_traversal":
		payload = map[string]interface{}{
			"error":   "Access denied",
			"message": "Path traversal detected",
		}
	case "reconnaissance":
		payload = map[string]interface{}{
			"error": "Not found",
		}
	}

	return payload, nil
}

// GeneratePayloadWithIntel creates payload with intel collection tracking
func (cp *ClaudeProvider) GeneratePayloadWithIntel(attackType string, intelTemplateID int) (map[string]interface{}, error) {
	// Get base payload
	basePayload, err := cp.GeneratePayload(attackType)
	if err != nil {
		return nil, err
	}

	// If no intel templates configured, return base payload
	if len(cp.intelTemplates) == 0 {
		return basePayload, nil
	}

	// Find the intel template to inject
	var selectedTemplate map[string]interface{}
	if intelTemplateID > 0 && intelTemplateID <= len(cp.intelTemplates) {
		selectedTemplate = cp.intelTemplates[intelTemplateID-1]
	} else if len(cp.intelTemplates) > 0 {
		selectedTemplate = cp.intelTemplates[0]
	}

	if selectedTemplate == nil {
		return basePayload, nil
	}

	// Create enhanced payload with intel collection
	enhancedPayload := map[string]interface{}{
		"status":  "ok",
		"message": "Request processed successfully",
		"data":    basePayload,
		"meta": map[string]interface{}{
			"timestamp": getCurrentTimestamp(),
			"intel_id":  intelTemplateID,
		},
	}

	// For HTML/JavaScript responses, inject tracking
	if templateType, ok := selectedTemplate["template_type"].(string); ok && templateType == "javascript" {
		if content, ok := selectedTemplate["content"].(string); ok {
			enhancedPayload["_tracking"] = content
			log.Printf("[INTEL] Injected JavaScript tracking into payload for attack type: %s", attackType)
		}
	}

	return enhancedPayload, nil
}

func getCurrentTimestamp() string {
	return "2025-11-07T18:24:54Z"
}
