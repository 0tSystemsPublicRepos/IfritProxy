# Data Anonymization Testing Report

**Version:** 0.1.1  
**Last Updated:** November 7, 2025

---

## Overview

The anonymization engine redacts sensitive data before sending requests to external LLMs (currently Anthropic Claude). This ensures privacy compliance (GDPR, HIPAA, PCI-DSS, CCPA) while maintaining attack detection accuracy.

**Key principle:** Sensitive data stays local. Only necessary threat indicators are sent to Claude.

---

## Features Tested

### Sensitive Header Redaction

**Headers redacted (case-insensitive):**
- `Authorization` → `[REDACTED_AUTHORIZATION]`
- `Cookie` → `[REDACTED_COOKIE]`
- `X-API-Key` → `[REDACTED_X_API_KEY]`
- `X-Auth-Token` → `[REDACTED_X_AUTH_TOKEN]`
- Custom headers (configurable)

**Case-insensitive matching:**
Works with all variants: `X-API-Key`, `x-api-key`, `X-Api-Key`, `X-API-KEY`

### Sensitive Pattern Redaction

**Patterns redacted (regex-based):**
- JWT tokens (Bearer prefix) → `[REDACTED_JWT_TOKEN]`
- API keys (api_key=, api-secret=) → `[REDACTED_API_KEY]`
- Email addresses → `[REDACTED_EMAIL]`

### Hybrid Strategy

- Redacts headers AND patterns
- Logs all redactions with occurrence counts
- Returns clean anonymized data to Claude
- Original data optionally stored locally (if `store_original: true`)

### Integration Points

- Anonymization engine wired into detection engine
- Configured via `config.json` with `sensitive_headers` list
- Works with all three execution modes (onboarding, learning, normal)
- Automatically applied before LLM analysis (Stage 4)


### Important: Balancing Privacy and Detection

While anonymization protects sensitive data, it creates a trade-off: redacting too much information can reduce attack detection accuracy. For example, if attackers deliberately target sensitive headers (like `Authorization`) that are redacted before reaching Claude, the LLM may not recognize the attack pattern without the actual sensitive value.

**Recommendation:** Unless you are using a loca LLM for detection, please carefully evaluate what data to redact based on threat model:
- **High privacy requirement:** Redact aggressively (GDPR/HIPAA compliance priority)
- **High security requirement:** Redact minimally (detection accuracy priority)
- **Balanced approach:** Redact only truly sensitive data (credentials, tokens), preserve patterns that help detection

In future versions (0.2+), I plan to implement **context-aware anonymization** that will:
- Detect when attackers specifically target redacted fields
- Use LLM analysis to infer attack patterns from redaction signatures
- Apply ML-based sensitive field detection for better balance
- Provide configurable redaction strategies per threat type

For now, if you notice false negatives (attacks not detected), consider adjusting your `sensitive_headers` list or switching to `strategy: header-only` for higher detection accuracy.

---

## Test Case Results

### Test Request
```bash
