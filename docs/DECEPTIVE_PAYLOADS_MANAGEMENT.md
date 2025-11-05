# Payload Management System

## Overview

Payload Management controls what fake responses IFRIT sends when attacks are detected. Instead of blocking or passing through attacks, IFRIT returns deceptive honeypot responses to confuse attackers while gathering intelligence.

The system intelligently selects responses using a four-stage fallback mechanism, balancing realism with cost efficiency.

---

## How It Works

### The Four-Stage Selection Process

When an attack is detected, IFRIT selects the response in this order:

```
Attack Detected (e.g., SQL injection on /api/search)
    ↓
Stage 1: Database Patterns?
    └─ Learned pattern exists? → Return stored payload ✓
    
Stage 2: LLM Generation? (if enabled)
    └─ Generate realistic response via Claude ✓
    
Stage 3: Config Defaults?
    └─ Attack type defined in config? → Return it ✓
    
Stage 4: Fallback
    └─ Return generic 500 error (fallback error/response can be customized as well)
```

### Stage 1: Database Patterns (Learning)

IFRIT learns attack patterns and caches responses for future use.

**First time attack is detected:**
- Detection engine identifies attack type and path
- LLM generates or config default provides response
- Pattern stored in `attack_patterns` table with payload
- Response returned to attacker

**Subsequent identical attacks:**
- Database pattern matches immediately
- Cached payload returned (no API calls, <10ms)
- No processing needed

**Example:**
```
Request 1: POST /api/users with "1 OR 1=1"
  → Detected: sql_injection
  → Stored in DB: pattern for POST /api/users
  → Payload: {"data": [...fake users...], "total": 2}

Request 2: POST /api/users with same SQL injection
  → Database match found instantly
  → Returns same payload from cache
  → No Claude API call (cost saved!)
```

### Stage 2: LLM Dynamic Generation

When `generate_dynamic_payload: true`, Claude generates realistic responses for new attack types.

**How it works:**
- Attack doesn't match database pattern
- Config check: `generate_dynamic_payload`
- If enabled: Call Claude with attack type
- Claude generates fake response (SQL records, error message, etc.)
- Response cached in database for future use

**Characteristics:**
- ~3 seconds per generation (Claude API call)
- Creates realistic, contextual responses
- Automatically cached after first use
- Can be disabled for instant responses (but less realistic)

**Example generated payloads:**
```
SQL Injection → 
{
  "data": [
    {"id": 1, "email": "admin@internal.local", "role": "admin"},
    {"id": 2, "email": "user@internal.local", "role": "user"}
  ],
  "total": 2
}

XSS Attempt →
{
  "error": "Invalid input detected",
  "message": "XSS prevention enabled"
}

Command Injection →
{
  "error": "Forbidden",
  "message": "Command execution not allowed"
}
```

### Stage 3: Config Defaults

Pre-configured fallback responses in `config/default.json` for known attack types.

**Response time:** <5ms (no API calls)

**Example:**
```json
"default_responses": {
  "sql_injection": {
    "content": {"error": "Forbidden"},
    "status_code": 403
  },
  "credential_stuffing": {
    "content": {"error": "Invalid credentials", "message": "Account locked after 3 attempts"},
    "status_code": 401
  }
}
```

### Stage 4: Fallback

Generic error when no match found at any stage, the fallback message can be set in the config.

```
HTTP/1.1 500 Internal Server Error
{"error": "Internal server error"}
```

---

## Configuration

### Basic Setup (No Dynamic Generation)

Minimal configuration - fast but less realistic:

```json
{
  "payload_management": {
    "generate_dynamic_payload": false,
    "dynamic_llm_cache_ttl": 86400,
    "default_responses": {
      "fallback": {
        "content": {"error": "Internal server error"},
        "status_code": 500
      }
    }
  }
}
```

### Recommended Setup (With Dynamic Generation)

Example configuration - realistic and cost-efficient:

```json
{
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 86400,
    "default_responses": {
      "reconnaissance": {
        "content": {"error": "Not found"},
        "status_code": 404
      },
      "sql_injection": {
        "content": {"error": "Forbidden"},
        "status_code": 403
      },
      "xss": {
        "content": {"error": "Invalid input", "message": "XSS prevention enabled"},
        "status_code": 400
      },
      "credential_stuffing": {
        "content": {"error": "Invalid credentials", "message": "Account locked after 3 attempts"},
        "status_code": 401
      },
      "path_traversal": {
        "content": {"error": "Forbidden"},
        "status_code": 403
      },
      "command_injection": {
        "content": {"error": "Forbidden"},
        "status_code": 403
      },
      "fallback": {
        "content": {"error": "Internal server error"},
        "status_code": 500
      }
    }
  }
}
```

### Configuration Parameters

**`generate_dynamic_payload`** (boolean)
- `true`: LLM generates payloads for new attack types (recommended)
- `false`: Only use config defaults and fallback (faster, less realistic)

**`dynamic_llm_cache_ttl`** (seconds)
- Default: `86400` (24 hours)
- How long to keep generated payloads cached
- Set to `0` to disable caching (not recommended)

**`default_responses`** (object)
- Map of attack_type → response configuration
- Each response has:
  - `content`: JSON object or string to return
  - `status_code`: HTTP status (200-599)

---

## Database Schema

Payloads are stored in the `attack_patterns` table:

```sql
CREATE TABLE attack_patterns (
  id INTEGER PRIMARY KEY,
  attack_type TEXT,              -- e.g., "sql_injection", "xss"
  attack_signature TEXT,         -- Pattern that triggered detection
  http_method TEXT,              -- GET, POST, etc.
  path_pattern TEXT,             -- /api/users, /login, etc.
  payload_template TEXT,         -- JSON response to send (stored here!)
  response_code INTEGER,         -- HTTP status code (200-599)
  times_seen INTEGER,            -- How many times detected
  first_seen TIMESTAMP,          -- When first detected
  last_seen TIMESTAMP,           -- Most recent detection
  created_by TEXT,               -- "claude", "config", "manual"
  claude_confidence FLOAT        -- LLM confidence (0.0-1.0)
);
```

**Key column: `payload_template`**
- Contains the JSON response to send
- Populated by:
  1. Claude (if dynamic generation enabled)
  2. Config defaults (if no Claude generation)
  3. Manual CLI insertion (advanced users)

---

## Caching Mechanism

IFRIT caches payloads to reduce API calls and response time.

### How Caching Works

```
Attack Detected
    ↓
Check database for pattern match
    ├─ Found? → Return cached payload ✓ (<10ms)
    └─ Not found:
        ├─ LLM enabled? → Generate payload ✓ (~3s)
        ├─ Generate → Store in database ✓
        ├─ Future identical attacks → Use cache ✓
        └─ Not enabled? → Use config default ✓ (<5ms)
```

### Cost Optimization

**Without caching:**
- 100 attacks = 100 Claude API calls
- Cost: ~$0.30

**With caching:**
- Hour 1: 100 attacks, 30 unique patterns → 30 API calls ($0.09)
- Hour 2: 100 attacks, same patterns → 0 API calls ($0.00)
- **Result: 90%+ cost reduction after learning phase**

### Cache Management

Check cache stats:
```bash
curl http://localhost:8443/api/cache/stats
```

Response:
```json
{
  "status": "ok",
  "cache": {
    "cached_payloads": 45,
    "cache_size": 1000
  }
}
```

Clear cache (if needed):
```bash
curl -X POST http://localhost:8443/api/cache/clear
```

---

## Managing Payloads via CLI

### View Learned Patterns

List all learned attack patterns:
```bash
./ifrit-cli pattern list
```

Output:
```
ID  TYPE              METHOD  PATTERN         SEEN  LAST SEEN
1   sql_injection     POST    /api/users      12    2025-11-05 21:38:15
2   credential_stuff  POST    /api/login      45    2025-11-05 21:39:00
3   xss               POST    /api/comment    3     2025-11-05 21:35:22
```

### View Specific Pattern (With Payload)

```bash
./ifrit-cli pattern view 1
```

Output:
```
Pattern #1
==========
Type:              sql_injection
Classification:    injection
Signature:         1 UNION SELECT
HTTP Method:       POST
Path Pattern:      /api/users
Response Code:     403
Times Seen:        12
Created By:        claude
Claude Confidence: 0.95
First Seen:        2025-11-05 21:36:42
Last Seen:         2025-11-05 21:38:15
Payload Template:  {"data": [{"id": 1, "email": "admin@internal.local", "role": "admin"}, {"id": 2, "email": "user@internal.local", "role": "user"}], "total": 2}
```

### Add Manual Payload

For advanced users who want to manually define payloads:

```bash
./ifrit-cli pattern add sql_injection "1 OR 1=1"
```

This creates a new pattern (payload comes from config defaults).

### Remove Payload

Delete a learned pattern:

```bash
./ifrit-cli pattern remove 1
```

---

## Limitations

### Current (MVP)

✅ Four-stage fallback working correctly  
✅ LLM generates realistic payloads  
✅ Automatic caching and learning  
✅ Config-based customization  
✅ CLI management of patterns  
✅ Cost optimization via caching  

### Not Implemented (Future)

❌ Conditional payloads based on attacker profile  
❌ Payload randomization per request  
❌ Response time simulation  
❌ Per-request payload override  
❌ Encrypted payload storage  
❌ Payload versioning/rollback  

### Known Constraints

- **Response time:** First dynamic generation ~3 seconds (Claude API)
- **Cache size:** Limited to 1000 payloads in memory
- **Customization:** Limited to config.json or manual CLI/database edits
- **No payload editing:** Can only delete and re-add (not update)
- **LLM context:** Claude sees anonymized request data only

---

## Security Considerations

### Data Privacy

**Sensitive data that gets anonymized before payload generation:**
- Authentication tokens
- Session cookies
- API keys
- Email addresses
- Passwords

**Claude receives only:**
- HTTP method and path
- Attack pattern/signature
- Attack type (detected)
- Content-Type, User-Agent

**Claude does NOT receive:**
- Credentials
- Personal information
- Real user data
- Sensitive headers

### Payload Safety

- Generated payloads are **fake/honeypot only**
- No real data exposed to attackers
- Responses designed to deceive, not harm
- No executable code in responses
- All payloads are JSON (safe for parsing)

---

## Troubleshooting

### Issue: Always returning fallback (500)

**Symptoms:**
```
[PAYLOAD] Using fallback for unknown_attack (status: 500)
```

**Cause:** Attack type not in database, LLM disabled, not in config defaults

**Solution:**
1. Check `generate_dynamic_payload` is `true` OR
2. Add attack type to `default_responses` in config

### Issue: LLM generation not working

**Symptoms:**
```
[PAYLOAD] LLM payload generation not yet implemented
```

**Cause:** LLM manager not configured or API key missing

**Solution:**
1. Verify Claude API key in config
2. Check `generate_dynamic_payload: true`
3. Verify LLM manager initialized in logs

### Issue: Slow initial responses

**Symptoms:** First request ~3 seconds, subsequent <10ms

**Expected:** This is normal! First request triggers Claude generation, subsequent requests use cache.

**Solution:** If too slow, set `generate_dynamic_payload: false` to use config defaults only.

### Issue: Database growing too large

**Symptoms:** Many learned patterns consuming space

**Solution:**
```bash
# Clear specific patterns
./ifrit-cli pattern remove [id]

# Or clear all and restart
rm data/ifrit.db
```

---

## Best Practices

### For Development
```json
{
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 3600
  }
}
```

### For Production
```json
{
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 86400,
    "default_responses": { ... comprehensive list ... }
  }
}
```

### For Cost Optimization
- Keep `generate_dynamic_payload: true` - caching saves 95% of API calls
- Monitor cache via `/api/cache/stats`
- Periodically clean old patterns: `./ifrit-cli pattern list | filter old`

### For Maximum Realism
- Enable dynamic generation
- Allow sufficient cache TTL (86400+ seconds)
- Add comprehensive defaults for common attack types
- Monitor LLMs (if used) confidence scores
