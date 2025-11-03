package llm

type Provider interface {
	AnalyzeRequest(requestData map[string]string) (*AnalysisResult, error)
	GeneratePayload(attackType string) (map[string]interface{}, error)
	GetName() string
}

type AnalysisResult struct {
	IsAttack       bool
	AttackType     string
	Classification string
	Confidence     float64
	Reasoning      string
	TokensUsed     int
}

type ProviderConfig struct {
	APIKey string
	Model  string
}
