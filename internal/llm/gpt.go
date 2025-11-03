package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type GPTProvider struct {
	apiKey string
	model  string
	client *http.Client
}

type gptMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type gptRequest struct {
	Model       string       `json:"model"`
	Messages    []gptMessage `json:"messages"`
	Temperature float64      `json:"temperature"`
	MaxTokens   int          `json:"max_tokens"`
}

type gptResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func NewGPTProvider(apiKey, model string) *GPTProvider {
	return &GPTProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (g *GPTProvider) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	if g.apiKey == "" {
		return &AnalysisResult{
			IsAttack:   false,
			Confidence: 0,
			Reasoning:  "GPT API key not configured",
		}, nil
	}

	// Build the prompt
	prompt := g.buildPrompt(requestData)

	// Create the request
	reqBody := gptRequest{
		Model:       g.model,
		Temperature: 0.3,
		MaxTokens:   500,
		Messages: []gptMessage{
			{
				Role:    "system",
				Content: "You are a security expert analyzing HTTP requests for malicious intent. Respond in JSON format only.",
			},
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
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.apiKey))

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call GPT API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GPT API error: %d - %s", resp.StatusCode, string(body))
	}

	// Parse response
	var gptResp gptResponse
	if err := json.NewDecoder(resp.Body).Decode(&gptResp); err != nil {
		return nil, err
	}

	// Extract text from response
	if len(gptResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from GPT")
	}

	responseText := gptResp.Choices[0].Message.Content

	// Parse the JSON response
	result := g.parseResponse(responseText)
	result.TokensUsed = gptResp.Usage.PromptTokens + gptResp.Usage.CompletionTokens

	return result, nil
}

func (g *GPTProvider) buildPrompt(requestData map[string]string) string {
	return fmt.Sprintf(`
Analyze this HTTP request for malicious intent:

Method: %s
Path: %s
Query: %s
Headers: %s
Body: %s

Determine if this is a malicious request. Respond with ONLY a JSON object containing:
{
  "is_attack": boolean,
  "attack_type": string or null,
  "classification": string or null,
  "confidence": number between 0 and 1,
  "reasoning": string
}

Attack types: sql_injection, xss, path_traversal, command_injection, reconnaissance, credential_stuffing, other, null
Classifications: reconnaissance, exploitation, post_exploitation, other
`,
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
	)
}

func (g *GPTProvider) parseResponse(responseText string) *AnalysisResult {
	var result struct {
		IsAttack       bool    `json:"is_attack"`
		AttackType     string  `json:"attack_type"`
		Classification string  `json:"classification"`
		Confidence     float64 `json:"confidence"`
		Reasoning      string  `json:"reasoning"`
	}

	if err := json.Unmarshal([]byte(responseText), &result); err != nil {
		// Try to extract JSON from the response
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

func (g *GPTProvider) GeneratePayload(attackType string) (map[string]interface{}, error) {
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

func (g *GPTProvider) GetName() string {
	return "gpt"
}
