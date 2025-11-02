package detection

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type DetectionEngine struct {
	localRules     []*Rule
	whitelistIPs   map[string]bool
	whitelistPaths []*regexp.Regexp
	db             *database.SQLiteDB
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

func NewDetectionEngine(whitelistIPs []string, whitelistPaths []string, db *database.SQLiteDB) *DetectionEngine {
	engine := &DetectionEngine{
		whitelistIPs: make(map[string]bool),
		db:           db,
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
	if de.whitelistIPs[clientIP] {
		return true
	}

	for _, pathRegex := range de.whitelistPaths {
		if pathRegex.MatchString(r.URL.Path) {
			return true
		}
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
	// Get all patterns from database and check if path matches
	patterns, err := de.db.GetAllPatterns()
	if err != nil {
		return nil
	}

	for _, pattern := range patterns {
		pathPattern := pattern["path_pattern"].(string)
		method := pattern["http_method"].(string)

		// Check if method matches
		if method != r.Method {
			continue
		}

		// Check if path matches exactly
		if pathPattern == r.URL.Path {
			return &DetectionResult{
				IsAttack:        true,
				AttackType:      pattern["attack_type"].(string),
				Classification:  pattern["attack_classification"].(string),
				Confidence:      pattern["confidence"].(float64),
				Signature:       de.GenerateSignature(r),
				DetectionStage:  3,
				PayloadTemplate: pattern["payload_template"].(string),
				ResponseCode:    int(pattern["response_code"].(int64)),
			}
		}
	}

	return nil
}

func (de *DetectionEngine) GenerateSignature(r *http.Request) string {
	data := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, r.URL.RawQuery)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (de *DetectionEngine) ExtractSuspiciousContent(r *http.Request) map[string]string {
	content := make(map[string]string)

	content["method"] = r.Method
	content["path"] = r.URL.Path
	content["query"] = r.URL.RawQuery

	suspiciousHeaders := []string{"Authorization", "Cookie", "X-API-Key"}
	for _, header := range suspiciousHeaders {
		if val := r.Header.Get(header); val != "" {
			content[strings.ToLower(header)] = "[REDACTED]"
		}
	}

	return content
}
