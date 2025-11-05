# IFRIT Proxy - Complete Feature Documentation

## Table of Contents
1. [Execution Modes](#execution-modes)
2. [Detection Pipeline](#detection-pipeline)
3. [Configuration Options](#configuration-options)
4. [CLI Commands](#cli-commands)
5. [REST API](#rest-api)
6. [Database Schema](#database-schema)

---

## Execution Modes

IFRIT supports three execution modes, each designed for different deployment scenarios.

### 1. Normal Mode (Production)

**Purpose:** Full threat detection with honeypot responses

**Behavior:**
- All incoming requests processed through 4-stage detection pipeline
- Malicious requests blocked and returned with deceptive responses
- Legitimate traffic forwarded to backend
- Real-time learning from new attack patterns
- Claude/GPT integration for unknown attack analysis

**Configuration:**
```json
{
  "execution_mode": {
    "mode": "normal"
  }
}
```

**Use Case:** Production deployments after security baseline established

---

### 2. Learning Mode (Monitoring)

**Purpose:** Observe traffic without blocking

**Behavior:**
- All requests logged to database and file
- No honeypot blocking - all traffic passes through
- Security team reviews logged traffic manually
- Can classify requests as attack/legitimate
- Used to establish baseline of legitimate traffic

**Configuration:**
```json
{
  "execution_mode": {
    "mode": "learning"
  }
}
```

**Use Case:** Initial deployment, understanding normal traffic patterns

---

### 3. Onboarding Mode (Fast Adoption)

**Purpose:** Automatic baseline creation with zero configuration

**Behavior:**
- First request to a path is analyzed
- If malicious, path is automatically whitelisted
- ALL subsequent requests to that path pass through
- Traffic logged for review
- Designed for rapid deployment without false positives

**Configuration:**
```json
{
  "execution_mode": {
    "mode": "onboarding",
    "onboarding_auto_whitelist": true,
    "onboarding_duration_days": 7,
    "onboarding_log_file": "./logs/onboarding_traffic.log"
  }
}
```

**Use Case:** 
- Week 1 of deployment
- Zero false positives guarantee
- Automatic baseline learning
- Transition to Normal mode after 7 days

**Onboarding Mode Details:**

When a request arrives in onboarding mode:

1. Request flows through 4-stage detection pipeline
2. If detected as attack:
   - Path is added to exceptions table with wildcard IP (`*`)
   - Request is forwarded to backend (not blocked)
   - Traffic logged to `onboarding_traffic.log`
3. Subsequent requests to same path:
   - Caught in Stage 0 (CheckExceptions)
   - Passed through immediately (no detection overhead)
4. Security team reviews log file
5. Manual adjustments can be made via CLI

**Key Advantage:** Security team can gradually restrict rules instead of dealing with false positives

---

## Detection Pipeline

IFRIT uses a 4-stage detection pipeline for maximum accuracy and performance.

### Stage 0: Exception Checking (Whitelist)

**Purpose:** Fast-track legitimate traffic

**Process:**
- Checks `exceptions` database table
- Matches against both IP-specific and path-specific rules
- Supports wildcard IPs (`*`) for path-based whitelisting

**Syntax:**
- `ip_address = "192.168.1.100"` → Only this IP passes
- `ip_address = "*"` → Any IP passes for this path
- Can combine both rules for same path

**Performance:** < 1ms (database lookup)

**Example:**
```
Exception: IP=*, PATH=/.env, REASON=onboarding mode
→ GET /.env from ANY IP passes through
```

---

### Stage 1: Local Rules (Fast Pattern Matching)

**Purpose:** Catch obvious attacks instantly

**Detection Method:**
- In-memory pattern matching
- High-confidence keywords (e.g., `' OR '1'='1'`, `<script>`)
- No database queries

**Performance:** < 0.5ms

**Example Detections:**
- SQL injection keywords
- XSS script tags
- Path traversal patterns
- Command injection operators

**Cost:** $0 (local processing)

---

### Stage 2: Database Patterns (Learned Attacks)

**Purpose:** Block known attack signatures

**Detection Method:**
- Query `attack_patterns` table
- Match HTTP method + path
- Returns stored deception payload

**Process:**
1. Request signature generated: `METHOD:PATH`
2. Query database for matching pattern
3. If found, return deception response
4. If not found, continue to Stage 3

**Performance:** 2-5ms (database query with index)

**Cost:** $0 (local database, no API calls)

---

### Stage 3: LLM Analysis (Unknown Attacks)

**Purpose:** Analyze new/unknown attack patterns

**Detection Method:**
- Send sanitized request to Claude or GPT
- LLM classifies as attack/legitimate
- Learn new patterns from response

**Triggered For:**
- POST, PUT, DELETE requests (by default, configurable)
- Requests not matching Stages 1-2

**Process:**
1. Anonymization engine redacts sensitive data
2. Request sent to LLM API
3. LLM returns: `{ is_attack: true/false, confidence: 0.0-1.0, attack_type: "..." }`
4. If attack, pattern stored in database
5. Deception response generated

**Performance:** 500-2000ms (API latency)

**Cost:** $0.0001-0.001 per request (Claude Haiku pricing)

**Caching:** Identical requests cached for 24 hours (reduces API calls 70-90%)

---

## Configuration Options

### Complete config.json Example
```json
{
  "server": {
    "listen_addr": ":8080",
    "proxy_target": "http://localhost:80",
    "api_listen_addr": ":8443",
    "tls": {
      "enabled": true,
      "cert_file": "/app/config/certs/server.crt",
      "key_file": "/app/config/certs/server.key"
    }
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-...",
      "model": "claude-3-5-haiku-20241022"
    },
    "gpt": {
      "api_key": "",
      "model": "gpt-4o-mini"
    }
  },
  "detection": {
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "whitelist_ips": [],
    "whitelist_paths": []
  },
  "execution_mode": {
    "mode": "onboarding",
    "onboarding_auto_whitelist": true,
    "onboarding_duration_days": 7,
    "onboarding_log_file": "./logs/onboarding_traffic.log"
  },
  "anonymization": {
    "enabled": true,
    "strategy": "hybrid",
    "store_original": true,
    "sensitive_headers": ["Authorization", "Cookie", "X-API-Key", "X-Auth-Token"]
  },
  "system": {
    "home_dir": "./",
    "log_dir": "./logs",
    "log_level": "info"
  }
}
```

### Configuration Reference

#### server.listen_addr
- **Type:** String
- **Default:** `:8080`
- **Description:** Address and port for proxy to listen on
- **Example:** `:8080`, `0.0.0.0:8080`

#### server.proxy_target
- **Type:** String
- **Default:** `http://localhost:80`
- **Description:** Backend application address
- **Example:** `http://localhost:80`, `http://app-server:3000`

#### server.api_listen_addr
- **Type:** String
- **Default:** `:8443`
- **Description:** Address for management API
- **Example:** `:8443`, `127.0.0.1:8443`

#### server.tls.enabled
- **Type:** Boolean
- **Default:** `true`
- **Description:** Enable TLS for proxy
- **Note:** Requires cert_file and key_file

#### database.type
- **Type:** String
- **Default:** `sqlite`
- **Description:** Database type (currently only SQLite supported)

#### database.path
- **Type:** String
- **Default:** `./data/ifrit.db`
- **Description:** Path to SQLite database file

#### llm.primary
- **Type:** String
- **Default:** `claude`
- **Options:** `claude`, `gpt`
- **Description:** Primary LLM provider for analysis

#### llm.claude.api_key
- **Type:** String
- **Description:** Anthropic API key (get from console.anthropic.com)
- **Required if:** `llm.primary = "claude"`

#### llm.claude.model
- **Type:** String
- **Default:** `claude-3-5-haiku-20241022`
- **Description:** Claude model version to use

#### detection.enable_local_rules
- **Type:** Boolean
- **Default:** `true`
- **Description:** Enable Stage 1 (local pattern matching)

#### detection.enable_llm
- **Type:** Boolean
- **Default:** `true`
- **Description:** Enable Stage 3 (LLM analysis)

#### detection.llm_only_on
- **Type:** Array of strings
- **Default:** `["POST", "PUT", "DELETE"]`
- **Description:** Only use LLM for these HTTP methods
- **Rationale:** GET requests are usually reconnaissance, less need for LLM

#### detection.whitelist_ips
- **Type:** Array of strings
- **Default:** `[]`
- **Description:** IPs to bypass detection entirely
- **Example:** `["127.0.0.1", "10.0.0.0/8"]`

#### detection.whitelist_paths
- **Type:** Array of strings
- **Default:** `[]`
- **Description:** Path patterns to bypass detection
- **Example:** `["/health", "/metrics"]`

#### execution_mode.mode
- **Type:** String
- **Options:** `normal`, `learning`, `onboarding`
- **Default:** `onboarding`
- **Description:** Execution mode

#### execution_mode.onboarding_auto_whitelist
- **Type:** Boolean
- **Default:** `true`
- **Description:** Automatically whitelist detected attack paths

#### execution_mode.onboarding_duration_days
- **Type:** Integer
- **Default:** `7`
- **Description:** Reminder duration for onboarding phase

#### execution_mode.onboarding_log_file
- **Type:** String
- **Default:** `./logs/onboarding_traffic.log`
- **Description:** File to log onboarding traffic

#### anonymization.enabled
- **Type:** Boolean
- **Default:** `true`
- **Description:** Anonymize sensitive data before sending to LLM

#### anonymization.strategy
- **Type:** String
- **Default:** `hybrid`
- **Options:** `hybrid`, `token`, `mask`
- **Description:** Anonymization strategy

#### anonymization.store_original
- **Type:** Boolean
- **Default:** `true`
- **Description:** Store original (non-anonymized) data in database

#### anonymization.sensitive_headers
- **Type:** Array of strings
- **Description:** HTTP headers to anonymize before LLM API calls

---

## CLI Commands

Complete `ifrit-cli` command reference.

### Pattern Management
```bash
# List all attack patterns
ifrit-cli pattern list

# View specific pattern details
ifrit-cli pattern view <id>

# Add new pattern
ifrit-cli pattern add <attack_type> <signature>

# Remove pattern
ifrit-cli pattern remove <id>
```

**Output Example:**
```
ID  TYPE               METHOD  PATTERN           SEEN  LAST SEEN
1   reconnaissance     GET     /.env             0     2025-11-05T14:16:29Z
2   reconnaissance     GET     /.env.local       0     2025-11-05T14:16:29Z
3   sql_injection      GET     ?id=1' OR '1'='1' 5     2025-11-05T15:30:00Z
```

### Attack Management
```bash
# List recent attacks
ifrit-cli attack list

# View attack details
ifrit-cli attack view <id>

# Show attack statistics
ifrit-cli attack stats

# Attacks from specific IP
ifrit-cli attack by-ip <ip_address>

# Attacks on specific path
ifrit-cli attack by-path <path>
```

### Attacker Profiles
```bash
# List all attacker profiles
ifrit-cli attacker list

# View attacker details
ifrit-cli attacker view <id>

# Search attacker by IP
ifrit-cli attacker search <ip_address>

# Remove attacker profile
ifrit-cli attacker remove <id>
```

### Exception Management (Whitelists)
```bash
# List all exceptions
ifrit-cli exception list

# View exception details
ifrit-cli exception view <id>

# Add exception (use * for wildcard)
ifrit-cli exception add <ip> <path>

# Remove exception
ifrit-cli exception remove <id>

# Enable exception
ifrit-cli exception enable <id>

# Disable exception
ifrit-cli exception disable <id>
```

**Examples:**
```bash
# Whitelist specific IP on all paths
ifrit-cli exception add 192.168.1.100 "*"

# Whitelist all IPs on specific path
ifrit-cli exception add "*" "/health"

# Whitelist specific IP on specific path
ifrit-cli exception add 192.168.1.100 "/admin"
```

### Database Operations
```bash
# Show database statistics
ifrit-cli db stats

# Show database schema
ifrit-cli db schema
```

---

## REST API

Management API running on `api_listen_addr` (default: `:8443`).

### Authentication

All API endpoints require token authentication via header:
```
Authorization: Bearer <token>
```

Token is configured in environment or config file (TBD).

### Endpoints

#### GET /api/patterns

List all attack patterns.

**Response:**
```json
{
  "patterns": [
    {
      "id": 1,
      "attack_type": "reconnaissance",
      "http_method": "GET",
      "path_pattern": "/.env",
      "times_seen": 0,
      "last_seen": "2025-11-05T14:16:29Z"
    }
  ],
  "total": 55
}
```

#### GET /api/attacks

List recent attacks.

**Query Parameters:**
- `limit` (default: 50)
- `offset` (default: 0)

**Response:**
```json
{
  "attacks": [
    {
      "id": 1,
      "pattern_id": 1,
      "source_ip": "192.168.1.100",
      "method": "GET",
      "path": "/.env",
      "timestamp": "2025-11-05T15:48:39Z"
    }
  ],
  "total": 42
}
```

#### GET /api/exceptions

List all exceptions.

**Response:**
```json
{
  "exceptions": [
    {
      "id": 1,
      "ip_address": "*",
      "path": "/.env",
      "reason": "auto-added in onboarding mode",
      "enabled": true,
      "created_at": "2025-11-05T14:48:39Z"
    }
  ],
  "total": 1
}
```

#### GET /api/cache/stats

Cache statistics.

**Response:**
```json
{
  "cache": {
    "cached_entries": 2,
    "total_hits": 0,
    "ttl_seconds": 86400
  },
  "status": "ok"
}
```

#### POST /api/cache/clear

Clear all cached entries.

**Response:**
```json
{
  "cleared": 2,
  "status": "ok"
}
```

---

## Database Schema

### attack_patterns

Stores known attack signatures and learned patterns.
```sql
CREATE TABLE attack_patterns (
  id INTEGER PRIMARY KEY,
  attack_signature TEXT UNIQUE,
  attack_type TEXT,
  attack_classification TEXT,
  http_method TEXT,
  path_pattern TEXT,
  payload_template TEXT,
  response_code INTEGER,
  times_seen INTEGER,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  created_by TEXT,
  claude_confidence REAL
);
```

### attack_instances

Records of individual attacks detected.
```sql
CREATE TABLE attack_instances (
  id INTEGER PRIMARY KEY,
  pattern_id INTEGER,
  source_ip TEXT,
  user_agent TEXT,
  requested_path TEXT,
  http_method TEXT,
  returned_honeypot BOOLEAN,
  attacker_accepted BOOLEAN,
  timestamp TIMESTAMP
);
```

### attacker_profiles

Profiles of unique attackers.
```sql
CREATE TABLE attacker_profiles (
  id INTEGER PRIMARY KEY,
  source_ip TEXT UNIQUE,
  total_requests INTEGER,
  successful_probes INTEGER,
  attack_types TEXT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP
);
```

### exceptions

Whitelisted IPs and paths.
```sql
CREATE TABLE exceptions (
  id INTEGER PRIMARY KEY,
  ip_address TEXT,
  path TEXT,
  reason TEXT,
  created_at TIMESTAMP,
  enabled BOOLEAN,
  UNIQUE(ip_address, path)
);
```

---

## Behavior Examples

### Example 1: Onboarding Mode - First Week

**Day 1:**
```
GET /.env from 192.168.1.5
  → Detected as "reconnaissance"
  → Added to exceptions: IP=*, PATH=/.env
  → Request forwarded to backend
  → Logged to onboarding_traffic.log

GET /.env from 203.0.113.42
  → Caught in exceptions (Stage 0)
  → Passed through immediately
  → No detection overhead
```

**Day 2-7:**
- Similar patterns added to exceptions automatically
- Security team reviews `onboarding_traffic.log`
- If needed, can manually edit exceptions via CLI

**Day 8:**
- Switch to `"mode": "normal"`
- Exceptions remain active
- Full detection pipeline enabled
- Previously seen attacks blocked with honeypot

### Example 2: Normal Mode - Production
```
GET /.env from 203.0.113.42
  → Stage 0: Not in exceptions → continue
  → Stage 1: Local rules → no match → continue
  → Stage 2: Database patterns → MATCH found!
  → Return 403 with fake payload
  → Log: reconnaissance attack detected
```

### Example 3: Learning Mode - Baseline
```
POST /api/search with malicious payload
  → All stages skipped
  → Request forwarded to backend
  → Logged to database
  → Security team reviews later
```

---

## Performance Characteristics

| Stage | Detection Method | Time | Cost |
|-------|-----------------|------|------|
| 0 | Exception whitelist | < 1ms | $0 |
| 1 | Local rules | < 0.5ms | $0 |
| 2 | Database patterns | 2-5ms | $0 |
| 3 | LLM analysis | 500-2000ms | $0.0001-0.001 |

**With caching:** 70-90% reduction in LLM API calls after first week

---

Last edit: November 5, 2025
