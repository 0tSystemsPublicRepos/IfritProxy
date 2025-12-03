package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type GeminiProvider struct {
	apiKey         string
	model          string
	anonEngine     *anonymization.AnonymizationEngine
	intelTemplates []map[string]interface{}
}

type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	return &GeminiProvider{
		apiKey:         apiKey,
		model:          model,
		intelTemplates: []map[string]interface{}{},
	}
}

func (gp *GeminiProvider) GetName() string {
	return "gemini"
}

func (gp *GeminiProvider) SetAnonymizationEngine(engine *anonymization.AnonymizationEngine) {
	gp.anonEngine = engine
}

func (gp *GeminiProvider) SetIntelTemplates(templates []map[string]interface{}) {
	gp.intelTemplates = templates
}

func (gp *GeminiProvider) GetIntelTemplates() []map[string]interface{} {
	return gp.intelTemplates
}

func (gp *GeminiProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`You are a security threat detection AI. Analyze this HTTP request and determine if it's malicious.

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Respond ONLY with a valid JSON object in this exact format:
{
  "is_attack": boolean,
  "attack_type": "string or null",
  "classification": "string or null",
  "confidence": number (0-1),
  "reason": "string"
}

Do NOT include any text outside the JSON object. Your entire response MUST be a single, valid JSON object.
Be strict. Return true only for clear attacks.`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
	)

	geminiReq := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{
						Text: prompt,
					},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(geminiReq)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", gp.model, gp.apiKey)

	logging.Debug("[GEMINI] Making request to: %s (model: %s)", url, gp.model)

	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		logging.Error("[GEMINI] HTTP error: %v", err)
		return nil, fmt.Errorf("failed to call Gemini API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	logging.Debug("[GEMINI] HTTP Status: %d", resp.StatusCode)
	logging.Debug("[GEMINI] Raw response body: %s", string(body))

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		logging.Error("[GEMINI] Failed to parse Gemini response: %v", err)
		return nil, err
	}

	logging.Debug("[GEMINI] Response candidates count: %d", len(geminiResp.Candidates))
	if len(geminiResp.Candidates) > 0 {
		logging.Debug("[GEMINI] First candidate content parts: %d", len(geminiResp.Candidates[0].Content.Parts))
		if len(geminiResp.Candidates[0].Content.Parts) > 0 {
			logging.Debug("[GEMINI] First part text length: %d", len(geminiResp.Candidates[0].Content.Parts[0].Text))
		}
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		logging.Error("[GEMINI] Empty response - candidates=%d", len(geminiResp.Candidates))
		logging.Debug("[GEMINI] Full response object: %+v", geminiResp)
		return nil, fmt.Errorf("empty response from Gemini")
	}

	responseText := geminiResp.Candidates[0].Content.Parts[0].Text

	responseText = strings.TrimPrefix(responseText, "```json\n")
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimSuffix(responseText, "\n```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	logging.Debug("[GEMINI] Raw response (after markdown strip): %s", responseText)

	var result AnalysisResult
	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		logging.Error("[GEMINI] Failed to parse JSON analysis: %v. Raw: %s", err, responseText)
		return nil, err
	}

	result.TokensUsed = geminiResp.UsageMetadata.PromptTokenCount + geminiResp.UsageMetadata.CandidatesTokenCount

	logging.Info("[GEMINI] Analysis complete - is_attack=%v, attack_type=%s, confidence=%.2f", result.IsAttack, result.AttackType, result.Confidence)

	return &result, nil
}

func (gp *GeminiProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
	return gp.GeneratePayloadWithContext(attackType, "", "")
}

func (gp *GeminiProvider) GeneratePayloadWithContext(attackType, path, method string) (map[string]interface{}, error) {
	prompt := gp.buildPayloadPrompt(attackType, path, method)

	geminiReq := GeminiRequest{
		Contents: []GeminiContent{
			{
				Parts: []GeminiPart{
					{
						Text: prompt,
					},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(geminiReq)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", gp.model, gp.apiKey)

	httpReq, _ := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logging.Error("[GEMINI][PAYLOAD] Failed to call Gemini API for payload generation: %v", err)
		return gp.getFallbackPayload(attackType), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	logging.Debug("[GEMINI][PAYLOAD] HTTP Status: %d", resp.StatusCode)

	var geminiResp GeminiResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		logging.Error("[GEMINI][PAYLOAD] Failed to parse Gemini response: %v", err)
		return gp.getFallbackPayload(attackType), nil
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		logging.Error("[GEMINI][PAYLOAD] Empty response from Gemini")
		return gp.getFallbackPayload(attackType), nil
	}

	responseText := geminiResp.Candidates[0].Content.Parts[0].Text

	responseText = strings.TrimPrefix(responseText, "```json\n")
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimSuffix(responseText, "\n```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(responseText), &payload); err != nil {
		logging.Error("[GEMINI][PAYLOAD] Failed to parse generated payload JSON: %v. Raw: %s", err, responseText)
		return gp.getFallbackPayload(attackType), nil
	}

	logging.Info("[GEMINI][PAYLOAD] Successfully generated dynamic payload for attack type: %s", attackType)
	return payload, nil
}

func (gp *GeminiProvider) buildPayloadPrompt(attackType, path, method string) string {
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

func (gp *GeminiProvider) getFallbackPayload(attackType string) map[string]interface{} {
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

func (gp *GeminiProvider) GeneratePayloadWithIntel(attackType string, intelTemplateID int) (map[string]interface{}, error) {
	basePayload, err := gp.GeneratePayload(attackType)
	if err != nil {
		return nil, err
	}

	if len(gp.intelTemplates) == 0 {
		return basePayload, nil
	}

	var selectedTemplate map[string]interface{}
	if intelTemplateID > 0 && intelTemplateID <= len(gp.intelTemplates) {
		selectedTemplate = gp.intelTemplates[intelTemplateID-1]
	} else if len(gp.intelTemplates) > 0 {
		selectedTemplate = gp.intelTemplates[0]
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
