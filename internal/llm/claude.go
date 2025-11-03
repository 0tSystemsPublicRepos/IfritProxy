package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type ClaudeProvider struct {
	apiKey string
	model  string
	client *http.Client
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	Messages  []claudeMessage  `json:"messages"`
	System    string           `json:"system"`
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

func NewClaudeProvider(apiKey, model string) *ClaudeProvider {
	return &ClaudeProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *ClaudeProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	if c.apiKey == "" {
		return &AnalysisResult{
			IsAttack:   false,
			Confidence: 0,
			Reasoning:  "Claude API key not configured",
		}, nil
	}

	// Build the prompt
	prompt := c.buildPrompt(requestData)

	// Create the request
	reqBody := claudeRequest{
		Model:     c.model,
		MaxTokens: 500,
		System:    "You are a security expert analyzing HTTP requests for malicious intent. Respond in JSON format.",
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

	return result, nil
}

func (c *ClaudeProvider) buildPrompt(requestData map[string]string) string {
	return fmt.Sprintf(`
Analyze this HTTP request for malicious intent:

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Determine if this is a malicious request. Respond with a JSON object containing:
{
  "is_attack": boolean,
  "attack_type": string or null,
  "classification": string or null,
  "confidence": number between 0 and 1,
  "reasoning": string
}

Attack types include: sql_injection, xss, path_traversal, command_injection, reconnaissance, credential_stuffing, other, or null if benign.
Classifications: reconnaissance, exploitation, post_exploitation, or other.
`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
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
