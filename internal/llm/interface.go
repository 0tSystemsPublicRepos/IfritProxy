package llm

type Provider interface {
	AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error)
	GeneratePayload(attackType string) (map[string]interface{}, error)
	GetName() string
}

type AnalysisResult struct {
	IsAttack       bool    `json:"is_attack"`
	AttackType     string  `json:"attack_type"`
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Reasoning      string  `json:"reason"`
	TokensUsed     int     `json:"tokens_used"`
}

type ProviderConfig struct {
	APIKey string
	Model  string
}
