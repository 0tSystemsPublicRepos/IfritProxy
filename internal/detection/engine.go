package detection

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"net/url"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

type DetectionEngine struct {
	mode           string
	localRules     []*Rule
	whitelistIPs   map[string]bool
	whitelistPaths []*regexp.Regexp
	db             database.DatabaseProvider
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
	PatternID       int64 
	PayloadTemplate string
	ResponseCode    int
}

// SetDatabase sets the database provider for the detection engine
func (e *DetectionEngine) SetDatabase(db database.DatabaseProvider) {
	e.db = db
}

func NewDetectionEngine(mode string, whitelistIPs []string, whitelistPaths []string, db database.DatabaseProvider, llmManager *llm.Manager, anonEngine *anonymization.AnonymizationEngine) *DetectionEngine {	
	engine := &DetectionEngine{
		mode:           mode,
		whitelistIPs:   make(map[string]bool),
		db:             db,
		llmManager:     llmManager,
		anonEngine:     anonEngine,
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

// CheckExceptions checks if request is whitelisted (with app_id support)
func (de *DetectionEngine) CheckExceptions(r *http.Request, clientIP, appID string) bool {
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

	exists, err := de.db.CheckException(appID, r.URL.Path, clientIP)
	if err == nil && exists {
		return true
	}	
	return false
}



// CheckLocalRules checks request against local regex rules (with app_id support)
func (de *DetectionEngine) CheckLocalRules(r *http.Request, appID string, skipBodyCheckOnWhitelist bool) *DetectionResult {
	logging.Debug("[STAGE1] app_id=%s | CheckLocalRules called for: %s %s", appID, r.Method, r.URL.Path)
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

		// Build complete request string for pattern matching
		fullRequest := r.URL.Path
		if r.URL.RawQuery != "" {
			// Decode the query string so patterns can match URL-encoded attacks
			decodedQuery, err := url.QueryUnescape(r.URL.RawQuery)
			if err != nil {
				decodedQuery = r.URL.RawQuery // fallback to raw if decode fails
			}
			fullRequest += "?" + decodedQuery
		}

		// Add headers (space-separated for pattern matching)
		for key, values := range r.Header {
			fullRequest += " " + key + ":" + strings.Join(values, ",")
		}

		// Add body if present
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
			fullRequest += " " + string(bodyBytes)
		}

		if rule.Pattern.MatchString(fullRequest) {
			// Check keyword exceptions before returning attack
			if de.shouldSkipKeywordCheck(r, appID) && skipBodyCheckOnWhitelist {
				logging.Debug("[KEYWORD_SKIP] app_id=%s | Skipping %s due to exception (skipBodyCheck=%v)", appID, rule.Name, skipBodyCheckOnWhitelist)
				continue
			}

			// If skipBodyCheck is false, continue analysis even if path is whitelisted
			if de.shouldSkipKeywordCheck(r, appID) && !skipBodyCheckOnWhitelist {
				logging.Debug("[KEYWORD_CHECK] app_id=%s | Path whitelisted but checking %s (skipBodyCheck=false)", appID, rule.Name)
			}

			signature := de.GenerateSignature(r)
			logging.Debug("[STAGE1] Pattern '%s' matched in full request", rule.Name)
			return &DetectionResult{
				IsAttack:       true,
				AttackType:     rule.Name,
				Classification: "local_rule",
				Confidence:     1.0,
				Signature:      signature,
				DetectionStage: 1,
			}
		}
	}
	logging.Debug("[STAGE1] app_id=%s | No local rule matched, returning nil", appID)
	return nil
}


// CheckDatabasePatterns checks request against database patterns (ENHANCED)
func (de *DetectionEngine) CheckDatabasePatterns(r *http.Request, appID string, skipBodyCheckOnWhitelist bool) *DetectionResult {
	logging.Debug("[STAGE2] app_id=%s | CheckDatabasePatterns called for: %s %s", appID, r.Method, r.URL.Path)
	
	patterns, err := de.db.GetAllPatterns(appID)
	if err != nil {
		logging.Error("[STAGE2] app_id=%s | Error fetching patterns: %v", appID, err)
		return nil
	}
	logging.Debug("[STAGE2] app_id=%s | Fetched %d patterns from database", appID, len(patterns))

	for _, pattern := range patterns {
		// Extract pattern fields
		pathPattern := pattern["path_pattern"].(string)
		method := pattern["http_method"].(string)
		attackType := pattern["attack_type"].(string)
		
		// Get new fields (with nil checks)
		patternType := "exact" // default
		if pt, ok := pattern["pattern_type"].(string); ok && pt != "" {
			patternType = pt
		}
		
		headerPattern := ""
		if hp, ok := pattern["header_pattern"].(string); ok {
			headerPattern = hp
		}
		
		bodyPattern := ""
		if bp, ok := pattern["body_pattern"].(string); ok {
			bodyPattern = bp
		}
		
		queryPattern := ""
		if qp, ok := pattern["query_pattern"].(string); ok {
			queryPattern = qp
		}

		// Check method first
		if method != "" && method != r.Method {
			continue
		}

		// Check if should skip due to keyword exception
		if de.shouldSkipKeywordCheck(r, appID) && skipBodyCheckOnWhitelist {
			logging.Debug("[KEYWORD_SKIP] app_id=%s | Skipping pattern check due to exception (skipBodyCheck=%v)", appID, skipBodyCheckOnWhitelist)
			continue
		}

		// If skipBodyCheck is false, continue analysis even if path is whitelisted
		if de.shouldSkipKeywordCheck(r, appID) && !skipBodyCheckOnWhitelist {
			logging.Debug("[KEYWORD_CHECK] app_id=%s | Path whitelisted but checking pattern (skipBodyCheck=false)", appID)
		}

		// Match based on pattern type
		pathMatched := false
		
		switch patternType {
		case "exact":
			pathMatched = (pathPattern == r.URL.Path)
			logging.Debug("[STAGE2] app_id=%s | EXACT match: '%s' == '%s' -> %v", appID, pathPattern, r.URL.Path, pathMatched)
			
		case "prefix":
			// Must match: /api/admin == /api/admin OR /api/admin/ is prefix of /api/admin/users
			pathMatched = (pathPattern == r.URL.Path) || 
			             strings.HasPrefix(r.URL.Path, pathPattern+"/")
			logging.Debug("[STAGE2] app_id=%s | PREFIX match: '%s' prefix of '%s' -> %v", appID, pathPattern, r.URL.Path, pathMatched)
			
		case "regex":
			if re, err := regexp.Compile(pathPattern); err == nil {
				pathMatched = re.MatchString(r.URL.Path)
				logging.Debug("[STAGE2] app_id=%s | REGEX match: '%s' regex '%s' -> %v", appID, pathPattern, r.URL.Path, pathMatched)
			} else {
				logging.Error("[STAGE2] app_id=%s | Invalid regex pattern: %s", appID, pathPattern)
			}
			
		case "contains":
			pathMatched = strings.Contains(r.URL.Path, pathPattern)
			logging.Debug("[STAGE2] app_id=%s | CONTAINS match: '%s' contains '%s' -> %v", appID, r.URL.Path, pathPattern, pathMatched)
		}

		if !pathMatched {
			continue
		}

		// Check query pattern if specified
		if queryPattern != "" && r.URL.RawQuery != "" {
			queryMatched := false
			if re, err := regexp.Compile(queryPattern); err == nil {
				queryMatched = re.MatchString(r.URL.RawQuery)
			} else {
				queryMatched = strings.Contains(r.URL.RawQuery, queryPattern)
			}
			if !queryMatched {
				logging.Debug("[STAGE2] app_id=%s | Query pattern not matched, skipping", appID)
				continue
			}
			logging.Debug("[STAGE2] app_id=%s | Query pattern matched", appID)
		}

		// Check header pattern if specified
		if headerPattern != "" {
			headerMatched := false
			headerRegex, err := regexp.Compile(headerPattern)
			
			for key, values := range r.Header {
				headerStr := key + ":" + strings.Join(values, ",")
				if err == nil {
					if headerRegex.MatchString(headerStr) {
						headerMatched = true
						logging.Debug("[STAGE2] app_id=%s | Header pattern matched: %s", appID, headerStr)
						break
					}
				} else {
					if strings.Contains(headerStr, headerPattern) {
						headerMatched = true
						logging.Debug("[STAGE2] app_id=%s | Header contains pattern: %s", appID, headerStr)
						break
					}
				}
			}
			
			if !headerMatched {
				logging.Debug("[STAGE2] app_id=%s | Header pattern not matched, skipping", appID)
				continue
			}
		}

		// Check body pattern if specified
		if bodyPattern != "" && r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
			bodyStr := string(bodyBytes)
			
			bodyMatched := false
			if re, err := regexp.Compile(bodyPattern); err == nil {
				bodyMatched = re.MatchString(bodyStr)
			} else {
				bodyMatched = strings.Contains(bodyStr, bodyPattern)
			}
			
			if !bodyMatched {
				logging.Debug("[STAGE2] app_id=%s | Body pattern not matched, skipping", appID)
				continue
			}
			logging.Debug("[STAGE2] app_id=%s | Body pattern matched", appID)
		}

		// All checks passed - this is an attack!
		logging.Info("[STAGE2] app_id=%s | Attack detected: %s (pattern_type: %s)", appID, attackType, patternType)
		
		return &DetectionResult{
			IsAttack:        true,
			AttackType:      attackType,
			Classification:  pattern["attack_classification"].(string),
			Confidence:      pattern["confidence"].(float64),
			Signature:       de.GenerateSignature(r),
			DetectionStage:  2,
			PatternID:       pattern["id"].(int64),
			PayloadTemplate: pattern["payload_template"].(string),
			ResponseCode:    getIntFromInterface(pattern["response_code"]),
		}
	}

	return nil
}

// getIntFromInterface safely converts interface{} to int (handles both int and int64)
func getIntFromInterface(val interface{}) int {
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}


// CheckLegitimateCache checks if request is in legitimate cache (STAGE 3)
func (de *DetectionEngine) CheckLegitimateCache(r *http.Request, appID string, skipBodyCheckOnWhitelist bool) (bool, error) {
	// If path is whitelisted and skipBodyCheck is true, consider it legitimate
	if de.shouldSkipKeywordCheck(r, appID) && skipBodyCheckOnWhitelist {
		logging.Debug("[STAGE3] ✓ CACHE HIT: app_id=%s | Request is legitimate (whitelisted path)", appID)
		return true, nil
	}

	// Generate signatures
	pathSig := de.generatePathSignature(r)
	bodySig := de.generateBodySignature(r)
	headersSig := de.generateHeadersSignature(r)

	logging.Debug("[STAGE3] app_id=%s | Checking legitimate cache: pathSig=%s bodySig=%s", appID, pathSig, bodySig)

	// Check if exists in legitimate_requests table
	exists, err := de.db.GetLegitimateRequest(appID, pathSig, bodySig, headersSig)
	if err != nil {
		logging.Error("[STAGE3] Error checking legitimate cache: %v", err)
		return false, err
	}

	if exists {
		logging.Debug("[STAGE3] ✓ CACHE HIT: app_id=%s | Request is legitimate (cached)", appID)
		return true, nil
	}

	logging.Debug("[STAGE3] ✗ CACHE MISS: app_id=%s | Request not in cache, need LLM analysis", appID)
	return false, nil
}

// StoreLegitimateRequest stores validated request in cache
func (de *DetectionEngine) StoreLegitimateRequest(r *http.Request, appID string) error {
	pathSig := de.generatePathSignature(r)
	bodySig := de.generateBodySignature(r)
	headersSig := de.generateHeadersSignature(r)

	err := de.db.StoreLegitimateRequest(appID, r.Method, r.URL.Path, pathSig, bodySig, headersSig)
	if err != nil {
		logging.Error("[STAGE3] Error storing legitimate request: %v", err)
		return err
	}

	logging.Debug("[STAGE3] ✓ Stored legitimate request in cache: app_id=%s", appID)
	return nil
}


// CheckLLMAnalysis performs LLM analysis for unknown requests (with app_id support)
func (de *DetectionEngine) CheckLLMAnalysis(r *http.Request, appID string, skipBodyCheckOnWhitelist bool) *DetectionResult {
        if de.llmManager == nil {
                return nil
        }

        // Check keyword exceptions before calling LLM
        if de.shouldSkipKeywordCheck(r, appID) && skipBodyCheckOnWhitelist {
                logging.Debug("[KEYWORD_SKIP] app_id=%s | Skipping LLM analysis due to exception (skipBodyCheck=%v)", appID, skipBodyCheckOnWhitelist)
                return nil
        }

        // If skipBodyCheck is false, continue analysis even if path is whitelisted
        if de.shouldSkipKeywordCheck(r, appID) && !skipBodyCheckOnWhitelist {
                logging.Debug("[KEYWORD_CHECK] app_id=%s | Path whitelisted but checking body/headers (skipBodyCheck=false)", appID)
        }

        // Extract request data for LLM
        requestData := de.ExtractRequestData(r)

        // Call LLM
        result, err := de.llmManager.AnalyzeRequest(requestData)
        if err != nil {
                logging.Error("[LLM ERROR] app_id=%s | Analysis error: %v", appID, err)
                return nil
        }
                
        if !result.IsAttack {   
                // LLM says it's legitimate - store in cache for future
                de.StoreLegitimateRequest(r, appID)
                return nil
        }

        // Store the result in database for future learning (with app_id)
	payload, _ := de.llmManager.GeneratePayload(result.AttackType)
	payloadJSON, _ := json.Marshal(payload)
	de.db.StoreAttackPatternEnhanced(
		appID,
		de.GenerateSignature(r),
		result.AttackType,
		result.Classification,
		r.Method,
		r.URL.Path,
		string(payloadJSON),
		200,
		"llm",
		result.Confidence,
		"prefix",  // default pattern type for LLM-detected patterns
		"",        // header_pattern (could be extracted from LLM analysis in future)
		"",        // body_pattern
		"",        // query_pattern
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


// shouldSkipKeywordCheck checks if request should skip keyword exception filtering
func (de *DetectionEngine) shouldSkipKeywordCheck(r *http.Request, appID string) bool {
	exceptions, err := de.db.GetKeywordExceptions(appID)
	if err != nil {
		return false
	}

	// Check path for keyword exceptions
	for _, exc := range exceptions {
		excType := exc["exception_type"].(string)
		keyword := exc["keyword"].(string)

		if excType == "path" && strings.Contains(r.URL.Path, keyword) {
			logging.Debug("[KEYWORD_EXCEPTION] app_id=%s | Path contains exception keyword: %s", appID, keyword)
			return true
		}
	}

	// Check body for keyword exceptions
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		bodyStr := string(bodyBytes)

		for _, exc := range exceptions {
			excType := exc["exception_type"].(string)
			keyword := exc["keyword"].(string)

			if excType == "body_field" && strings.Contains(bodyStr, keyword) {
				logging.Debug("[KEYWORD_EXCEPTION] app_id=%s | Body contains exception keyword: %s", appID, keyword)
				return true
			}
		}
	}

	// Check headers for keyword exceptions
	for _, exc := range exceptions {
		excType := exc["exception_type"].(string)
		keyword := exc["keyword"].(string)

		if excType == "header" {
			for headerName, headerValues := range r.Header {
				for _, headerValue := range headerValues {
					if strings.Contains(headerName, keyword) || strings.Contains(headerValue, keyword) {
						logging.Debug("[KEYWORD_EXCEPTION] app_id=%s | Header contains exception keyword: %s", appID, keyword)
						return true
					}
				}
			}
		}
	}

	return false
}

// GenerateSignature creates a hash signature of the request
func (de *DetectionEngine) GenerateSignature(r *http.Request) string {
	data := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, r.URL.RawQuery)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generatePathSignature generates signature for path only
func (de *DetectionEngine) generatePathSignature(r *http.Request) string {
	hash := md5.Sum([]byte(r.Method + "|" + r.URL.Path))
	return hex.EncodeToString(hash[:])
}

// generateBodySignature generates signature for request body
func (de *DetectionEngine) generateBodySignature(r *http.Request) string {
	body := ""
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		body = string(bodyBytes)
	}
	
	// Include query parameters in signature
	if r.URL.RawQuery != "" {
		body += "|QUERY:" + r.URL.RawQuery
	}
	
	hash := md5.Sum([]byte(body))
	return hex.EncodeToString(hash[:])
}


// generateHeadersSignature generates signature for important headers
func (de *DetectionEngine) generateHeadersSignature(r *http.Request) string {
	importantHeaders := []string{"Content-Type", "Authorization", "User-Agent"}
	headerStr := ""
	for _, header := range importantHeaders {
		headerStr += r.Header.Get(header) + "|"
	}
	hash := md5.Sum([]byte(headerStr))
	return hex.EncodeToString(hash[:])
}

// ExtractRequestData extracts relevant data from request for LLM analysis
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
