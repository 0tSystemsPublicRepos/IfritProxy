package anonymization

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type AnonymizationEngine struct {
	enabled          bool
	strategy         string
	storeOriginal    bool
	sensitiveHeaders []string
	patterns         map[string]*regexp.Regexp
}

type AnonymizationResult struct {
	AnonymizedRequest string            // Request sent to LLM
	OriginalRequest   string            // Original request (stored in DB)
	RedactedFields    map[string]string // What was redacted and how
	RedactionCount    int               // How many fields redacted
}

func NewAnonymizationEngine(enabled bool, strategy string, storeOriginal bool, sensitiveHeaders []string) *AnonymizationEngine {
	engine := &AnonymizationEngine{
		enabled:          enabled,
		strategy:         strategy,
		storeOriginal:    storeOriginal,
		sensitiveHeaders: sensitiveHeaders,
		patterns:         make(map[string]*regexp.Regexp),
	}

	// Compile common sensitive data patterns
	engine.patterns["jwt_token"] = regexp.MustCompile(`Bearer\s+[A-Za-z0-9_-]+`)
	engine.patterns["api_key"] = regexp.MustCompile(`(api[_-]?key|api[_-]?secret)\s*[:=]\s*[A-Za-z0-9_-]+`)
	engine.patterns["email"] = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+`)

	return engine
}

// AnonymizeRequest removes sensitive data from HTTP request
func (ae *AnonymizationEngine) AnonymizeRequest(r *http.Request) *AnonymizationResult {
	result := &AnonymizationResult{
		RedactedFields: make(map[string]string),
	}

	if !ae.enabled {
		result.AnonymizedRequest = r.RequestURI
		result.OriginalRequest = r.RequestURI
		return result
	}

	// Store original
	result.OriginalRequest = r.RequestURI
	anonymized := r.RequestURI

	// Stage 1: Redact sensitive headers
	redactedHeaders := ae.redactHeaders(r)
	result.RedactedFields = redactedHeaders
	result.RedactionCount = len(redactedHeaders)

	// Stage 2: Apply anonymization strategy
	switch ae.strategy {
	case "hybrid":
		// Redact sensitive headers AND patterns
		for _, header := range ae.sensitiveHeaders {
			if r.Header.Get(header) != "" {
				log.Printf("[ANON] Redacting header: %s", header)
				anonymized = strings.ReplaceAll(
					anonymized,
					r.Header.Get(header),
					"[REDACTED_"+strings.ToUpper(header)+"]",
				)
			}
		}

		// Redact patterns in body/query string
		for patternName, pattern := range ae.patterns {
			if pattern.MatchString(anonymized) {
				log.Printf("[ANON] Redacting pattern: %s", patternName)
				anonymized = pattern.ReplaceAllString(
					anonymized,
					"[REDACTED_"+strings.ToUpper(patternName)+"]",
				)
				result.RedactionCount++
			}
		}

	case "header-only":
		// Only redact sensitive headers
		for _, header := range ae.sensitiveHeaders {
			if r.Header.Get(header) != "" {
				log.Printf("[ANON] Redacting header: %s", header)
				anonymized = strings.ReplaceAll(
					anonymized,
					r.Header.Get(header),
					"[REDACTED_"+strings.ToUpper(header)+"]",
				)
			}
		}
	}

	result.AnonymizedRequest = anonymized

	if result.RedactionCount > 0 {
		log.Printf("[ANON] Anonymization complete: %d fields redacted", result.RedactionCount)
	}

	return result
}

// AnonymizeRequestData anonymizes request data map (for LLM analysis)
func (ae *AnonymizationEngine) AnonymizeRequestData(requestData map[string]string) *AnonymizationResult {
	result := &AnonymizationResult{
		RedactedFields: make(map[string]string),
	}

	if !ae.enabled {
		result.AnonymizedRequest = fmt.Sprintf("%s %s", requestData["method"], requestData["path"])
		result.OriginalRequest = fmt.Sprintf("%s %s", requestData["method"], requestData["path"])
		return result
	}

	// Store original
	originalStr := fmt.Sprintf("%s %s Query:%s Headers:%s Body:%s",
		requestData["method"],
		requestData["path"],
		requestData["query"],
		requestData["headers"],
		requestData["body"],
	)
	result.OriginalRequest = originalStr

	// Start with original data
	anonymized := originalStr

	// Redact sensitive headers from headers field (case-insensitive)
	headersField := requestData["headers"]
	for _, header := range ae.sensitiveHeaders {
		// Create case-insensitive pattern for header matching
		// Match "HeaderName:" anywhere in the headers field
		headerPattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(header) + `:\s*[^;]*`)
		matches := headerPattern.FindAllString(headersField, -1)
		if len(matches) > 0 {
			log.Printf("[ANON] Redacting sensitive header: %s (%d occurrences)", header, len(matches))
			headersField = headerPattern.ReplaceAllString(
				headersField,
				"[REDACTED_"+strings.ToUpper(strings.ReplaceAll(header, "-", "_"))+"]",
			)
			result.RedactedFields[header] = "[REDACTED]"
			result.RedactionCount += len(matches)
		}
	}

	// Update anonymized with redacted headers
	anonymized = strings.Replace(anonymized, requestData["headers"], headersField, 1)

	// Redact patterns in body and query string
	switch ae.strategy {
	case "hybrid":
		// Apply pattern-based redaction
		for patternName, pattern := range ae.patterns {
			matches := pattern.FindAllString(anonymized, -1)
			if len(matches) > 0 {
				log.Printf("[ANON] Redacting pattern '%s': %d occurrences", patternName, len(matches))
				anonymized = pattern.ReplaceAllString(
					anonymized,
					"[REDACTED_"+strings.ToUpper(patternName)+"]",
				)
				result.RedactedFields[patternName] = fmt.Sprintf("%d occurrences", len(matches))
				result.RedactionCount += len(matches)
			}
		}

	case "header-only":
		// Only redact headers, not body patterns
		log.Printf("[ANON] Using header-only strategy")
	}

	result.AnonymizedRequest = anonymized
	return result
}

// redactHeaders returns map of sensitive headers that were found
func (ae *AnonymizationEngine) redactHeaders(r *http.Request) map[string]string {
	redacted := make(map[string]string)

	for _, header := range ae.sensitiveHeaders {
		value := r.Header.Get(header)
		if value != "" {
			// Store what was redacted (for audit)
			redacted[header] = "[REDACTED]"
		}
	}

	return redacted
}

// ShouldRedact returns true if a value should be redacted
func (ae *AnonymizationEngine) ShouldRedact(fieldName string) bool {
	for _, sensitive := range ae.sensitiveHeaders {
		if strings.EqualFold(fieldName, sensitive) {
			return true
		}
	}
	return false
}

// GetRedactionStatus returns human-readable status
func (ae *AnonymizationEngine) GetRedactionStatus(result *AnonymizationResult) string {
	if result.RedactionCount == 0 {
		return "No sensitive data found"
	}
	return fmt.Sprintf("Redacted %d sensitive fields", result.RedactionCount)
}
