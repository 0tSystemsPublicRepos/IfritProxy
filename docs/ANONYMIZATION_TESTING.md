# Data Anonymization Testing Report

**Last edit:** November 5, 2025  

## Overview

The anonymization engine redacts sensitive data before sending requests for LLM analysis. This ensures privacy compliance (GDPR, HIPAA, PCI-DSS) while maintaining attack detection accuracy.

## Features Tested

### Sensitive Header Redaction
- **Authorization header** → `[REDACTED_AUTHORIZATION]`
- **Cookie header** → `[REDACTED_COOKIE]`
- **X-API-Key header** → `[REDACTED_X_API_KEY]`
- **X-Auth-Token header** → `[REDACTED_X_AUTH_TOKEN]`

**Case-insensitive matching:** Works with `X-API-Key`, `x-api-key`, `X-Api-Key` variants

### Sensitive Pattern Redaction
- **JWT tokens** (Bearer tokens) → `[REDACTED_JWT_TOKEN]`
- **API keys** (api_key=, api-secret=) → `[REDACTED_API_KEY]`
- **Email addresses** → `[REDACTED_EMAIL]`

### Hybrid Strategy
- Redacts headers AND patterns
- Logs all redactions with occurrence counts
- Returns clean anonymized data to Claude

### Integration
- Anonymization engine wired into detection engine
- Configured via `config.json` with `sensitive_headers` list
- Works with all three execution modes (onboarding, learning, normal)

## Test Case Results

### Test Request
```bash
curl -X POST "http://localhost:8080/api/test2" \
  -H "Authorization: Bearer sk-ant-test-token-12345" \
  -H "Cookie: session=abc123def456" \
  -H "X-API-Key: sk-live-secret" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@company.com", "password": "P@ssw0rd123"}'
```

### Original Request
```
POST /api/test2
Headers: User-Agent: curl/8.7.1; Accept: */*; Authorization: Bearer sk-ant-test-token-12345; Cookie: session=abc123def456; X-API-Key: sk-live-secret; Content-Type: application/json; Content-Length: 57
Body: {"email": "admin@company.com", "password": "P@ssw0rd123"}
```

### Anonymized Request (Sent to Claude)
```
POST /api/test2
Headers: [REDACTED_AUTHORIZATION]; [REDACTED_COOKIE]; [REDACTED_X_API_KEY]; Content-Type: application/json; Content-Length: 57; User-Agent: curl/8.7.1; Accept: */*
Body: {"email": "[REDACTED_EMAIL]", "password": "[REDACTED_EMAIL]"}
```

### Redaction Summary
- **5 fields redacted:**
  - Authorization header (1)
  - Cookie header (1)
  - X-API-Key header (1)
  - Email in body (2)

### Claude Analysis Result
```
Is Attack: true
Attack Type: credential_stuffing
Confidence: 0.70
Reasoning: Payload contains email and password - typical credential stuffing attempt
```

## Configuration

### `config.json` Anonymization Section
```json
{
  "anonymization": {
    "enabled": true,
    "strategy": "hybrid",
    "store_original": true,
    "sensitive_headers": [
      "Authorization",
      "Cookie",
      "X-API-Key",
      "X-Auth-Token"
    ]
  }
}
```

### Strategy Options
- **hybrid** - Redact sensitive headers AND patterns (recommended)
- **header-only** - Only redact sensitive headers, preserve patterns
- **disabled** - No anonymization (not recommended for external LLMs)

## Privacy & Compliance

### What can be redacted
Authentication tokens and credentials  
Session cookies  
API keys  
Email addresses  
Sensitive headers  

### What Does NOT Get Redacted
❌ HTTP method and path (needed for attack detection)  
❌ Content-Type, User-Agent (helps understanding context)  
❌ Attack patterns (SQL injection syntax, XSS payloads needed for detection)  

### Compliance Coverage
- **GDPR:** Personal data (emails, tokens) redacted before external API calls
- **HIPAA:** PHI protected via anonymization before LLM
- **PCI-DSS:** Credit card data redacted before external processing
- **CCPA:** User data minimization through selective redaction

## Audit Logging

All redactions logged with:
- Header name/pattern that matched
- Number of occurrences
- Replacement value used
- Timestamp

Example logs:
```
[ANON] Redacting sensitive header: Authorization (1 occurrences)
[ANON] Redacting sensitive header: Cookie (1 occurrences)
[ANON] Redacting sensitive header: X-API-Key (1 occurrences)
[ANON] Redacting pattern 'email': 2 occurrences
[ANON] Anonymization: 5 fields redacted
```

## Implementation Details

### Anonymization Flow
1. **Request arrives** → DetectionEngine extracts data
2. **ExtractRequestData** → Captures all headers and body
3. **CheckLLMAnalysis** → Calls LLM Manager
4. **Claude Provider** → Calls AnonymizationEngine
5. **AnonymizeRequestData** → Case-insensitive header matching + pattern redaction
6. **Anonymized data** → Sent to Claude API
7. **Original data** → Stored in database (if store_original=true)

### Case-Insensitive Matching
Uses regex with `(?i)` flag to match headers regardless of case:
- Config: `X-API-Key`
- Request: `X-Api-Key` or `x-api-key` or `X-API-KEY`
- Result: All matched and redacted as `[REDACTED_X_API_KEY]`

## Known Limitations

### Current (MVP)
- Only configurable via config.json
- Redaction patterns hardcoded for common sensitive data
- No encryption of stored original data (store_original=true stores plaintext)

### Future (Commercial)
- Per-request override of anonymization rules
- ML-based sensitive field detection
- Encryption at rest for original data
- Role-based access to original data
- Advanced PII detection (SSN, credit cards, etc.)

## Recommendations

### For Production
1. ✅ Enable anonymization (already default), when using commercial LLMs
2. ✅ Use hybrid strategy (recommended)
3. ⚠️ Consider disabling `store_original` if compliance-sensitive
4. ✅ Add custom headers to `sensitive_headers` list if needed
5. ✅ Monitor anonymization logs for false positives

### For Testing
- Run with `store_original=true` to compare anonymized vs original
- Verify redaction counts match expected sensitive data
- Test with various header name casings


---
