package llm

import (
	"fmt"
)

type Manager struct {
	primary   Provider
	fallback  Provider
	primaryName string
}

func NewManager(primaryProvider, primaryKey, primaryModel, fallbackProvider, fallbackKey, fallbackModel string) *Manager {
	var primary Provider
	var fallback Provider

	// Initialize primary provider
	switch primaryProvider {
	case "claude":
		primary = NewClaudeProvider(primaryKey, primaryModel)
	case "gpt":
		primary = NewGPTProvider(primaryKey, primaryModel)
	default:
		primary = NewClaudeProvider(primaryKey, "claude-3-5-sonnet")
	}

	// Initialize fallback provider
	switch fallbackProvider {
	case "claude":
		fallback = NewClaudeProvider(fallbackKey, fallbackModel)
	case "gpt":
		fallback = NewGPTProvider(fallbackKey, fallbackModel)
	default:
		fallback = nil
	}

	return &Manager{
		primary:   primary,
		fallback:  fallback,
		primaryName: primaryProvider,
	}
}

func (m *Manager) AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error) {
	// Try primary provider first
	result, err := m.primary.AnalyzeRequest(requestData)
	if err == nil && result != nil {
		return result, nil
	}

	// If primary fails and we have a fallback, try that
	if m.fallback != nil {
		fmt.Printf("Primary LLM provider failed, trying fallback...\n")
		result, err := m.fallback.AnalyzeRequest(requestData)
		if err == nil && result != nil {
			return result, nil
		}
	}

	// Both failed or no result
	if err != nil {
		return nil, fmt.Errorf("all LLM providers failed: %w", err)
	}

	return nil, fmt.Errorf("no valid response from LLM providers")
}

func (m *Manager) GeneratePayload(attackType string) (map[string]interface{}, error) {
	return m.primary.GeneratePayload(attackType)
}

func (m *Manager) GetPrimaryName() string {
	return m.primaryName
}
