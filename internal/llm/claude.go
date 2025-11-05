package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
)

type ClaudeProvider struct {
	apiKey              string
	model               string
	client              *http.Client
	cache               *AnalysisCache
	anonymizationEngine *anonymization.AnonymizationEngine
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []claudeMessage `json:"messages"`
	System    string          `json:"system"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// NewClaudeProvider creates provider without cache (backwards compatible)
func NewClaudeProvider(apiKey, model string) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:               NewAnalysisCache(24 * time.Hour),
		anonymizationEngine: nil,
	}
}

// NewClaudeProviderWithCache creates provider with shared cache
func NewClaudeProviderWithCache(apiKey, model string, cache *AnalysisCache) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:               cache,
		anonymizationEngine: nil,
	}
}

// NewClaudeProviderWithAnonymization creates provider with anonymization engine
func NewClaudeProviderWithAnonymization(apiKey, model string, cache *AnalysisCache, anonEngine *anonymization.AnonymizationEngine) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey:              apiKey,
		model:               model,
		client:              &http.Client{Timeout: 30 * time.Second},
		cache:               cache,
		anonymizationEngine: anonEngine,
	}
}

// SetAnonymizationEngine allows setting anonymization engine after creation
func (c *ClaudeProvider) SetAnonymizationEngine(engine *anonymization.AnonymizationEngine) {
	c.anonymizationEngine = engine
}

func (c *ClaudeProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	// Check cache first
	if cached, found := c.cache.Get(requestData); found {
		c.cache.Hit(requestData)
		log.Printf("[CACHE HIT] Reusing Claude analysis for %s %s\n", requestData["method"], requestData["path"])
		return cached, nil
	}

	if c.apiKey == "" {
		return &AnalysisResult{
			IsAttack:   false,
			Confidence: 0,
			Reasoning:  "Claude API key not configured",
		}, nil
	}

	// Stage 1: Anonymize the request data before sending to Claude
	var anonResult *anonymization.AnonymizationResult
	if c.anonymizationEngine != nil {
		anonResult = c.anonymizationEngine.AnonymizeRequestData(requestData)
		log.Printf("[ANON] Anonymization: %d fields redacted", anonResult.RedactionCount)
		log.Printf("[ANON] Original: %s %s", requestData["method"], requestData["path"])
		log.Printf("[ANON] Anonymized: %s", anonResult.AnonymizedRequest)
	} else {
		// No anonymization - fallback
		anonResult = &anonymization.AnonymizationResult{
			AnonymizedRequest: fmt.Sprintf("%s %s", requestData["method"], requestData["path"]),
			OriginalRequest:   fmt.Sprintf("%s %s", requestData["method"], requestData["path"]),
			RedactedFields:    make(map[string]string),
			RedactionCount:    0,
		}
		log.Printf("[ANON] Anonymization engine not configured - sending raw data")
	}

	// Stage 2: Build prompt with anonymized data
	prompt := c.buildPrompt(requestData, anonResult)

	// Create the request
	reqBody := claudeRequest{
		Model:     c.model,
		MaxTokens: 500,
		System:    "You are a security expert analyzing HTTP requests for malicious intent. Respond in JSON format only.",
		Messages: []claudeMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	// Make the request
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Claude API error: %d - %s", resp.StatusCode, string(body))
	}

	// Parse response
	var claudeResp claudeResponse
	if err := json.NewDecoder(resp.Body).Decode(&claudeResp); err != nil {
		return nil, err
	}

	// Extract text from response
	if len(claudeResp.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude")
	}

	responseText := claudeResp.Content[0].Text

	// Parse the JSON response
	result := c.parseResponse(responseText)
	result.TokensUsed = claudeResp.Usage.InputTokens + claudeResp.Usage.OutputTokens

	// Store in cache for future use
	c.cache.Set(requestData, result)
	log.Printf("[CLAUDE] Analyzed %s %s (confidence: %.2f, %d fields redacted, now cached)\n",
		requestData["method"], requestData["path"], result.Confidence, anonResult.RedactionCount)

	return result, nil
}

func (c *ClaudeProvider) buildPrompt(requestData map[string]string, anonResult *anonymization.AnonymizationResult) string {
	return fmt.Sprintf(`
Analyze this HTTP request for malicious intent:

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Anonymization Status: %d sensitive fields redacted from headers/auth
Keep in mind that some sensitive authentication headers may be redacted for privacy.
Focus on attack patterns and suspicious behavior in the visible data.

Determine if this is a malicious request. Respond with ONLY a JSON object (no markdown, no extra text):
{
  "is_attack": boolean,
  "attack_type": string or null,
  "classification": string or null,
  "confidence": number between 0 and 1,
  "reasoning": string
}

Attack types: sql_injection, xss, path_traversal, command_injection, reconnaissance, credential_stuffing, other, or null
Classifications: reconnaissance, exploitation, post_exploitation, or other
`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
		anonResult.RedactionCount,
	)
}

func (c *ClaudeProvider) parseResponse(responseText string) *AnalysisResult {
	var result struct {
		IsAttack       bool    `json:"is_attack"`
		AttackType     string  `json:"attack_type"`
		Classification string  `json:"classification"`
		Confidence     float64 `json:"confidence"`
		Reasoning      string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		// Try to extract JSON from the response (Claude might add explanation)
		start := bytes.Index([]byte(responseText), []byte("{"))
		end := bytes.LastIndex([]byte(responseText), []byte("}"))
		if start != -1 && end != -1 {
			jsonStr := responseText[start : end+1]
			json.Unmarshal([]byte(jsonStr), &result)
		}
	}

	return &AnalysisResult{
		IsAttack:       result.IsAttack,
		AttackType:     result.AttackType,
		Classification: result.Classification,
		Confidence:     result.Confidence,
		Reasoning:      result.Reasoning,
	}
}

func (c *ClaudeProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
	payloads := map[string]map[string]interface{}{
		"sql_injection": {
			"data": []map[string]interface{}{
				{"id": 1, "email": "admin@internal.local", "role": "admin"},
				{"id": 2, "email": "user@internal.local", "role": "user"},
			},
			"total": 2,
		},
		"xss": {
			"error":   "Invalid input",
			"message": "XSS prevention enabled",
		},
		"path_traversal": {
			"error":  "Access denied",
			"status": 403,
		},
		"command_injection": {
			"output": "Command not found",
			"status": 127,
		},
		"reconnaissance": {
			"error":  "Not found",
			"status": 404,
		},
		"credential_stuffing": {
			"error": "Invalid credentials",
			"message": "Account locked after 3 attempts",
		},
	}

	if payload, ok := payloads[attackType]; ok {
		return payload, nil
	}

	return map[string]interface{}{
		"error": "Internal server error",
	}, nil
}

func (c *ClaudeProvider) GetName() string {
	return "claude"
}
