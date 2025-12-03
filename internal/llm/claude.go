package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
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

func (cp *ClaudeProvider) GetIntelTemplates() []map[string]interface{} {
	return cp.intelTemplates
}

func (cp *ClaudeProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
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
		logging.Error("Failed to parse Claude response: %v", err)
		return nil, err
	}

	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude")
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(claudeResp.Content[0].Text), &result); err != nil {
		logging.Error("Failed to parse Claude analysis: %v. Raw: %s", err, claudeResp.Content[0].Text)
		return nil, err
	}

	return &result, nil
}

func (cp *ClaudeProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
	return cp.GeneratePayloadWithContext(attackType, "", "")
}

func (cp *ClaudeProvider) GeneratePayloadWithContext(attackType, path, method string) (map[string]interface{}, error) {
	prompt := cp.buildPayloadPrompt(attackType, path, method)

	claudeReq := ClaudeRequest{
		Model:     cp.model,
		MaxTokens: 512,
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logging.Error("[PAYLOAD] Failed to call Claude API for payload generation: %v", err)
		return cp.getFallbackPayload(attackType), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var claudeResp ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		logging.Error("[PAYLOAD] Failed to parse Claude response: %v", err)
		return cp.getFallbackPayload(attackType), nil
	}

	if len(claudeResp.Content) == 0 {
		logging.Error("[PAYLOAD] Empty response from Claude")
		return cp.getFallbackPayload(attackType), nil
	}

	responseText := claudeResp.Content[0].Text
	
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(responseText), &payload); err != nil {
		logging.Error("[PAYLOAD] Failed to parse generated payload JSON: %v. Raw: %s", err, responseText)
		return cp.getFallbackPayload(attackType), nil
	}

	logging.Info("[PAYLOAD] Successfully generated dynamic payload for attack type: %s", attackType)
	return payload, nil
}

func (cp *ClaudeProvider) buildPayloadPrompt(attackType, path, method string) string {
	basePrompt := `You are a cybersecurity deception system. Generate a realistic but FAKE HTTP response payload that would deceive an attacker.

CRITICAL RULES:
1. Response must be valid JSON only
2. Data must appear realistic but be completely fabricated
3. Include appropriate error messages or data for the attack type
4. Add realistic timestamps, IDs, and metadata
5. Make the attacker think they're succeeding (to waste their time)
6. NEVER include actual sensitive data
7. Vary the response - don't use generic templates

Attack Type: %s
Endpoint Path: %s
HTTP Method: %s

ATTACK-SPECIFIC GUIDELINES:
`

	switch attackType {
	case "SQL Injection":
		basePrompt += `- Generate fake database error messages OR fake query results
- Include realistic table names, column names, row counts
- Add SQL error codes (e.g., 1064, 1146, 1054)
- Include fake database version info
- Example structure: {"error": "SQL syntax error", "code": 1064, "query": "...", "affected_rows": 0}`

	case "Local File Inclusion", "Path Traversal":
		basePrompt += `- Generate fake file contents or permission errors
- Include realistic file paths, permissions, timestamps
- Add fake file metadata (size, owner, modified date)
- Example: {"error": "Permission denied", "file": "/etc/passwd", "message": "Access restricted to root only"}`

	case "XSS", "Cross-Site Scripting":
		basePrompt += `- Show input validation errors or sanitized output
- Include fake CSRF tokens, session IDs
- Add security headers information
- Example: {"error": "Invalid input detected", "sanitized": true, "security_token": "..."}`

	case "Template Injection", "SSTI":
		basePrompt += `- Generate fake template rendering output
- Include template engine errors or processed results
- Add fake variable names and values
- Example: {"template": "processed", "output": "...", "variables": {...}}`

	case "Prototype Pollution":
		basePrompt += `- Show object property manipulation results
- Include fake prototype chain info
- Add JavaScript object structures
- Example: {"object": {...}, "prototype": {...}, "properties": [...]}`

	case "Command Injection", "RCE":
		basePrompt += `- Generate fake command execution results
- Include realistic command output, exit codes
- Add fake process IDs, timestamps
- Example: {"output": "command executed", "exit_code": 0, "pid": 1234, "user": "www-data"}`

	case "XXE", "XML External Entity":
		basePrompt += `- Show XML parsing errors or fake parsed content
- Include DTD validation messages
- Add fake entity resolution info
- Example: {"error": "External entity not allowed", "parser": "libxml2", "line": 4}`

	case "Reconnaissance", "Directory Traversal":
		basePrompt += `- Generate 404 errors or minimal fake directory listings
- Include fake server info (version, OS)
- Add misleading paths and files
- Example: {"error": "Not Found", "path": "...", "suggestions": [...]}`

	default:
		basePrompt += `- Generate a generic but convincing error or success response
- Include realistic status messages and metadata
- Add timestamps and request IDs
- Example: {"status": "error", "message": "Request failed", "code": 400}`
	}

	basePrompt += `

OUTPUT FORMAT:
Return ONLY valid JSON. No markdown, no explanations, no code blocks. Just the JSON payload.

Generate the deception payload now:`

	return fmt.Sprintf(basePrompt, attackType, path, method)
}

func (cp *ClaudeProvider) getFallbackPayload(attackType string) map[string]interface{} {
	payload := map[string]interface{}{
		"status":    "success",
		"message":   "Request processed",
		"data":      map[string]interface{}{},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	switch attackType {
	case "SQL Injection":
		payload = map[string]interface{}{
			"error": "You have an error in your SQL syntax",
			"code":  1064,
			"query": "SELECT * FROM users WHERE id = '1'",
		}
	case "XSS", "Cross-Site Scripting":
		payload = map[string]interface{}{
			"error":   "Invalid input",
			"message": "XSS prevention enabled",
			"token":   fmt.Sprintf("csrf_%x", time.Now().UnixNano()),
		}
	case "Local File Inclusion", "Path Traversal":
		payload = map[string]interface{}{
			"error":   "Permission denied",
			"file":    "/etc/passwd",
			"message": "Access restricted",
		}
	case "Template Injection":
		payload = map[string]interface{}{
			"error":    "Template rendering failed",
			"template": "user_profile.html",
			"line":     12,
		}
	case "Prototype Pollution":
		payload = map[string]interface{}{
			"status": "updated",
			"object": map[string]interface{}{
				"constructor": "Object",
				"__proto__":   map[string]interface{}{},
			},
		}
	case "Reconnaissance":
		payload = map[string]interface{}{
			"error":  "Not found",
			"status": 404,
		}
	}

	return payload
}

func (cp *ClaudeProvider) GeneratePayloadWithIntel(attackType string, intelTemplateID int) (map[string]interface{}, error) {
	basePayload, err := cp.GeneratePayload(attackType)
	if err != nil {
		return nil, err
	}

	if len(cp.intelTemplates) == 0 {
		return basePayload, nil
	}

	var selectedTemplate map[string]interface{}
	if intelTemplateID > 0 && intelTemplateID <= len(cp.intelTemplates) {
		selectedTemplate = cp.intelTemplates[intelTemplateID-1]
	} else if len(cp.intelTemplates) > 0 {
		selectedTemplate = cp.intelTemplates[0]
	}

	if selectedTemplate == nil {
		return basePayload, nil
	}

	enhancedPayload := map[string]interface{}{
		"status":  "ok",
		"message": "Request processed successfully",
		"data":    basePayload,
		"meta": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"intel_id":  intelTemplateID,
		},
	}

	if templateType, ok := selectedTemplate["template_type"].(string); ok && templateType == "javascript" {
		if content, ok := selectedTemplate["content"].(string); ok {
			enhancedPayload["_tracking"] = content
			logging.Info("[INTEL] Injected JavaScript tracking into payload for attack type: %s", attackType)
		}
	}

	return enhancedPayload, nil
}
