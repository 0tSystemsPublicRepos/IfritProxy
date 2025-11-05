package detection

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
)

type DetectionEngine struct {
	localRules     []*Rule
	whitelistIPs   map[string]bool
	whitelistPaths []*regexp.Regexp
	db             *database.SQLiteDB
	llmManager     *llm.Manager
	anonEngine     *anonymization.AnonymizationEngine
}

type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Methods  []string
	Severity string
}

type DetectionResult struct {
	IsAttack        bool
	AttackType      string
	Classification  string
	Confidence      float64
	Signature       string
	DetectionStage  int
	PayloadTemplate string
	ResponseCode    int
}

func NewDetectionEngine(whitelistIPs []string, whitelistPaths []string, db *database.SQLiteDB, llmManager *llm.Manager, anonEngine *anonymization.AnonymizationEngine) *DetectionEngine {
	engine := &DetectionEngine{
		whitelistIPs: make(map[string]bool),
		db:           db,
		llmManager:   llmManager,
		anonEngine:   anonEngine,
	}

	for _, ip := range whitelistIPs {
		engine.whitelistIPs[ip] = true
	}

	for _, path := range whitelistPaths {
		if re, err := regexp.Compile(path); err == nil {
			engine.whitelistPaths = append(engine.whitelistPaths, re)
		}
	}

	engine.initLocalRules()
	return engine
}

func (de *DetectionEngine) initLocalRules() {
	de.localRules = []*Rule{
		{
			Name:     "path_traversal",
			Pattern:  regexp.MustCompile(`\.\./`),
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Severity: "critical",
		},
		{
			Name:     "path_traversal_backslash",
			Pattern:  regexp.MustCompile(`\.\.\\`),
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Severity: "critical",
		},
		{
			Name:     "sql_injection",
			Pattern:  regexp.MustCompile(`(?i)(UNION|SELECT|DROP|DELETE|INSERT|UPDATE)\s+(FROM|INTO|WHERE)`),
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Severity: "critical",
		},
		{
			Name:     "sql_injection_or",
			Pattern:  regexp.MustCompile(`(?i)'\s*OR\s*'`),
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Severity: "critical",
		},
		{
			Name:     "xss_attempt",
			Pattern:  regexp.MustCompile(`<script|javascript:|onerror=|onload=`),
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Severity: "high",
		},
	}
}

func (de *DetectionEngine) CheckExceptions(r *http.Request, clientIP string) bool {
	// Check if this IP is whitelisted
	if de.whitelistIPs[clientIP] {
		return true
	}

	// Check path-based whitelist patterns
	for _, pathRegex := range de.whitelistPaths {
		if pathRegex.MatchString(r.URL.Path) {
			return true
		}
	}

	// Check database exceptions table
	// Query for either specific IP or wildcard ("*")
	var exists bool
	err := de.db.GetDB().QueryRow(
		`SELECT EXISTS(
			SELECT 1 FROM exceptions 
			WHERE enabled = 1 
			AND path = ? 
			AND (ip_address = ? OR ip_address = '*')
		)`,
		r.URL.Path,
		clientIP,
	).Scan(&exists)

	if err == nil && exists {
		return true
	}

	return false
}

func (de *DetectionEngine) CheckLocalRules(r *http.Request) *DetectionResult {
	for _, rule := range de.localRules {
		methodMatch := false
		for _, m := range rule.Methods {
			if m == r.Method {
				methodMatch = true
				break
			}
		}

		if !methodMatch {
			continue
		}

		fullRequest := r.URL.Path + "?" + r.URL.RawQuery
		if rule.Pattern.MatchString(fullRequest) {
			signature := de.GenerateSignature(r)
			return &DetectionResult{
				IsAttack:       true,
				AttackType:     rule.Name,
				Classification: "local_rule",
				Confidence:     1.0,
				Signature:      signature,
				DetectionStage: 2,
			}
		}
	}

	return nil
}

func (de *DetectionEngine) CheckDatabasePatterns(r *http.Request) *DetectionResult {
	patterns, err := de.db.GetAllPatterns()
	if err != nil {
		log.Printf("[DEBUG] Error getting patterns: %v", err)
		return nil
	}

	log.Printf("[DEBUG] Checking %d patterns for %s %s", len(patterns), r.Method, r.URL.Path)

	for _, pattern := range patterns {
		pathPattern := pattern["path_pattern"].(string)
		method := pattern["http_method"].(string)
		attackType := pattern["attack_type"].(string)

		// Check method first
		if method != r.Method {
			continue
		}

		// Check path
		log.Printf("[DEBUG] Pattern match check: method=%s path=%s vs request path=%s", method, pathPattern, r.URL.Path)

		if pathPattern == r.URL.Path {
			log.Printf("[DEBUG] ✓ MATCH FOUND: %s %s", method, pathPattern)
			return &DetectionResult{
				IsAttack:        true,
				AttackType:      attackType,
				Classification:  pattern["attack_classification"].(string),
				Confidence:      pattern["confidence"].(float64),
				Signature:       de.GenerateSignature(r),
				DetectionStage:  3,
				PayloadTemplate: pattern["payload_template"].(string),
				ResponseCode:    int(pattern["response_code"].(int64)),
			}
		}
	}

	log.Printf("[DEBUG] ✗ No pattern match found for %s %s", r.Method, r.URL.Path)
	return nil
}

// Stage 4: LLM Analysis for unknown requests
func (de *DetectionEngine) CheckLLMAnalysis(r *http.Request) *DetectionResult {
	if de.llmManager == nil {
		return nil
	}

	// Extract request data for LLM
	requestData := de.ExtractRequestData(r)

	// Call LLM
	result, err := de.llmManager.AnalyzeRequest(requestData)
	if err != nil {
		fmt.Printf("LLM analysis error: %v\n", err)
		return nil
	}

	if !result.IsAttack {
		return nil
	}

	// Store the result in database for future learning
	payload, _ := de.llmManager.GeneratePayload(result.AttackType)
	payloadJSON, _ := json.Marshal(payload)
	de.db.StoreAttackPattern(
		de.GenerateSignature(r),
		result.AttackType,
		result.Classification,
		r.Method,
		r.URL.Path,
		string(payloadJSON),
		200,
		"llm",
		result.Confidence,
	)

	return &DetectionResult{
		IsAttack:        true,
		AttackType:      result.AttackType,
		Classification:  result.Classification,
		Confidence:      result.Confidence,
		Signature:       de.GenerateSignature(r),
		DetectionStage:  4,
		PayloadTemplate: string(payloadJSON),
		ResponseCode:    200,
	}
}

func (de *DetectionEngine) GenerateSignature(r *http.Request) string {
	data := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, r.URL.RawQuery)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (de *DetectionEngine) ExtractRequestData(r *http.Request) map[string]string {
	data := make(map[string]string)

	data["method"] = r.Method
	data["path"] = r.URL.Path
	data["query"] = r.URL.RawQuery

	// Extract ALL headers (including sensitive ones)
	// Anonymization engine will redact sensitive headers before sending to LLM
	headerStr := ""
	for key, values := range r.Header {
		headerStr += fmt.Sprintf("%s: %s; ", key, strings.Join(values, ","))
	}
	data["headers"] = headerStr

	// Extract body
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		data["body"] = string(bodyBytes)
	}

	return data
}
