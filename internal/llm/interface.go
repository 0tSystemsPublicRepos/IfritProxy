package llm

import (
	"net/http"
)

type Provider interface {
	AnalyzeRequest(req *http.Request, sanitizedData map[string]string) (*AnalysisResult, error)
	GeneratePayload(attackType string) (map[string]interface{}, error)
	GetName() string
}

type AnalysisResult struct {
	IsAttack       bool
	AttackType     string
	Classification string
	Confidence     float64
	Reasoning      string
}

type ProviderConfig struct {
	APIKey string
	Model  string
}
