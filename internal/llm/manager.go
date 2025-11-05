package llm

import (
	"fmt"
	"time"
)

type Manager struct {
	primary   Provider
	fallback  Provider
	primaryName string
	cache     *AnalysisCache
}

func NewManager(primaryProvider, primaryKey, primaryModel, fallbackProvider, fallbackKey, fallbackModel string) *Manager {
	var primary Provider
	var fallback Provider

	// Initialize cache (shared for all providers)
	cache := NewAnalysisCache(24 * time.Hour)

	// Initialize primary provider
	switch primaryProvider {
	case "claude":
		primary = NewClaudeProviderWithCache(primaryKey, primaryModel, cache)
	case "gpt":
		primary = NewGPTProvider(primaryKey, primaryModel)
	default:
		primary = NewClaudeProviderWithCache(primaryKey, "claude-3-5-sonnet", cache)
	}

	// Initialize fallback provider
	switch fallbackProvider {
	case "claude":
		fallback = NewClaudeProviderWithCache(fallbackKey, fallbackModel, cache)
	case "gpt":
		fallback = NewGPTProvider(fallbackKey, fallbackModel)
	default:
		fallback = nil
	}

	return &Manager{
		primary:     primary,
		fallback:    fallback,
		primaryName: primaryProvider,
		cache:       cache,
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

// GetCacheStats returns cache statistics for monitoring
func (m *Manager) GetCacheStats() map[string]interface{} {
	return m.cache.Stats()
}

// ClearCache clears all cached entries
func (m *Manager) ClearCache() {
	m.cache.Clear()
}

// GetProvider returns a specific provider by name
func (m *Manager) GetProvider(name string) interface{} {
	switch name {
	case "claude", "primary":
		return m.primary
	case "fallback":
		return m.fallback
	default:
		return nil
	}
}


