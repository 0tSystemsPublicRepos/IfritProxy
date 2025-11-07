# IFRIT Proxy

**Intelligent Threat Deception**

IFRIT is an intelligent deception proxy that transforms every attack into threat intelligence. It sits between attackers and production infrastructure, intercepting malicious requests and making real-time decisions: return fake data to confuse the attacker, or pass legitimate traffic through unchanged.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Overview

IFRIT operates as intelligent middleware between the internet and production applications. When a request arrives, IFRIT makes a real-time decision: pass it through to the legitimate backend or serve a honeypot response.

The decision-making process follows a **multi-stage pipeline**:

1. **Stage 0: Whitelist Check** - Does this IP/path have an exception? → Pass through
2. **Stage 1: Local Rules** - Does this match obvious attack patterns? → Honeypot
3. **Stage 2: Database Patterns** - Have we seen this attack before? → Honeypot (cached)
4. **Stage 3: LLM Analysis** - Is this a novel attack? → Ask AI → Honeypot

**Throughout this process:**
- Sensitive data is anonymized before reaching local/external LLMs (currently supports Anthropic Claude)
- Attack patterns are learned and stored for future reference
- Attacker profiles are built based on behavior
- All requests generate detailed logs for threat intelligence

Legitimate users access the real backend. Attackers receive deceptive honeypot responses. Your organization profiles every threat while maintaining zero data leakage.

---

## Key Features

### Real-Time Threat Detection

Four-stage pipeline detects attacks without requiring infrastructure changes:

- **Whitelist exceptions** - Critical paths bypass honeypot (with optional body check override)
- **Local rules** - Instant pattern matching (no API calls)
- **Database patterns** - Learned attacks cached locally (<10ms)
- **LLM analysis** - Novel threats analyzed by Claude/GPT

### Intelligent Learning

Each attack analyzed becomes a learned pattern:

- First attack: LLM generates honeypot (~3 seconds)
- Subsequent attacks: Database cache (<10ms)
- **Result: 95% cost reduction after learning phase**

### Two Detection Modes

**Detection Mode (Default)**
- Smart threat analysis
- Optional whitelist for exceptions
- All other traffic analyzed
- Use for: Standard deployments

**Allowlist Mode (New)**
- Only whitelisted IPs/paths allowed
- Everything else blocked
- Zero false positives
- Use for: VPN-only, admin portals, strict zero-trust

See [DETECTION_MODES.md](docs/DETECTION_MODES.md) for detailed comparison.

### Three Execution Modes

**Onboarding Mode**
- Auto-learns legitimate traffic patterns
- Zero blocking
- 7-day default duration
- Auto-whitelists discovered legitimate paths

**Learning Mode**
- All traffic passes through
- Full logging for manual review
- No blocking

**Normal Mode**
- Full detection and honeypot responses
- Real-time learning
- Production-ready

### Payload Management System

Intelligent honeypot response selection:

- **Stage 1: Database** - Use learned payloads (cached)
- **Stage 2: LLM** - AI generates realistic responses (currently supports Anthropic Claude only)
- **Stage 3: Config** - Fallback to configured defaults
- **Stage 4: Fallback** - Generic error if nothing matches

### Whitelist Override Flag

**New in 0.1.1:** Control whether whitelisted paths bypass body/header checks:
```json
{
  "detection": {
    "skip_body_check_on_whitelist": false
  }
}
```

- `true` (default): Whitelisted paths skip ALL checks (fastest)
- `false`: Whitelisted paths still check body/headers (catches malicious payloads in clean paths)

### Data Anonymization

Sensitive data is redacted before sending to external LLMs:

**Redacted:**
- Authentication tokens and credentials
- Session cookies
- API keys
- Email addresses
- Personal information

**Preserved (needed for detection):**
- HTTP method and path
- Attack patterns (SQL injection syntax, path traversal, etc.)
- Content-Type and User-Agent

**Compliance:**
- GDPR: PII anonymized before external API calls
- HIPAA: PHI protected
- PCI-DSS: Credit card data redacted
- CCPA: User data minimization

### CLI Management Tool

Complete command-line interface:
```bash
# View attacks
./ifrit-cli attack list
./ifrit-cli attack view 1
./ifrit-cli attack stats
./ifrit-cli attack by-ip 192.168.1.1
./ifrit-cli attack by-path /api/users

# Manage patterns
./ifrit-cli pattern list
./ifrit-cli pattern view 1
./ifrit-cli pattern add sql_injection "1 OR 1=1"
./ifrit-cli pattern remove 1

# View attacker profiles
./ifrit-cli attacker list
./ifrit-cli attacker view 1
./ifrit-cli attacker search 192.168.1.1

# Manage exceptions (whitelist)
./ifrit-cli exception list
./ifrit-cli exception add 10.0.0.1 /health
./ifrit-cli exception remove 1

# Manage keyword exceptions (body check override)
./ifrit-cli keyword list
./ifrit-cli keyword add path health
./ifrit-cli keyword remove 1

# Database operations
./ifrit-cli db stats
./ifrit-cli db schema
```

### REST API

JSON API for integrations:
```bash
# Get recent attacks
curl http://localhost:8443/api/attacks

# Get attacker profiles
curl http://localhost:8443/api/attackers

# Get learned patterns
curl http://localhost:8443/api/patterns

# Get cache statistics
curl http://localhost:8443/api/cache/stats

# Clear cache
curl -X POST http://localhost:8443/api/cache/clear
```

### Threat Intelligence

Actionable intelligence from attack analysis:

- **Attack classification** - Type, severity, technique
- **Attacker profiles** - IP, first seen, last seen, total requests
- **Pattern database** - Learned signatures with confidence scores
- **Timeline tracking** - Attacker progression and tool evolution

---

## How It Works

### Request Flow
```
Incoming Request
    ↓
[Stage 0] Whitelist Check
├─ Is IP whitelisted? → ALLOW ✓
├─ Is path whitelisted? → Check skip_body_check_on_whitelist flag
│  ├─ true: ALLOW ✓
│  └─ false: Continue to detection
└─ Continue to Stage 1
    ↓
[Stage 1] Local Rules
├─ Matches obvious attack signature? → HONEYPOT ✓
└─ Continue to Stage 2
    ↓
[Stage 2] Database Patterns
├─ Matches learned pattern? → HONEYPOT ✓
└─ Continue to Stage 3
    ↓
[Stage 3] LLM Analysis 
├─ AI confirms it's an attack? → HONEYPOT ✓
└─ Not an attack
    ↓
[Forward] Legitimate Traffic
└─ Pass to backend ✓
```

### Payload Selection

When an attack is detected, the response is selected by priority:
```
Attack Detected (e.g., sql_injection)
    ↓
[1] Database: Any stored payload? → Use it ✓
    ↓
[2] LLM: Generate dynamic deception response? → AI LLM creates response ✓
    ↓
[3] Config: Attack type in defaults? → Use it ✓
    ↓
[4] Fallback: Generic error → 500 response ✓ (or whatever response is configured)
```

### Learning Process
```
Hour 1: 100 attacks, 40 unique types
├─ Detect → 40 LLM calls → $0.02 cost
├─ Store patterns in DB
└─ Honeypot responses cached

Hour 2: 100 attacks, same 40 types
├─ Database pattern matches → 0 LLM calls
├─ Cached responses used
└─ $0.00 cost (100% savings)
```

---

## Architecture

### Components

**Reverse Proxy Engine**
- Listens on configured port (8080/8443 - customizable)
- Routes traffic to backend or honeypot
- Written in Go for high performance
- TLS/HTTPS support

**Detection Engine**
- Four-stage pipeline decision logic
- Whitelist exception checking with skip flag
- Local rule pattern matching
- LLM integration for novel threats
- Data anonymization before external APIs

**Payload Management**
- Intelligent response selection
- Database caching of learned payloads
- LLM-based dynamic generation
- Config-based defaults
- Graceful fallback

**Learning Engine**
- Captures attack signatures
- Stores learned patterns in database
- Tracks confidence scores
- Builds attacker profiles

**Data Layer**
- SQLite database (local, no external deps)
- Stores exceptions, patterns, attacks, profiles, keyword exceptions
- Fast pattern matching optimized queries

**REST API & CLI**
- Query interface for all data
- Pattern management
- Exception/whitelist management
- Statistics and analytics

---

## Configuration

All configuration through JSON (`config/default.json`). No code changes needed.

### Detection Modes

**Detection Mode (Default)**
```json
{
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": [],
    "whitelist_paths": []
  }
}
```

**Allowlist Mode (Strict)**
```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": ["192.168.1.100", "192.168.1.102"],
    "whitelist_paths": ["/health", "/status"]
  }
}
```

### Execution Modes
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

Options: `onboarding`, `learning`, `normal`

### Payload Management
```json
{
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 86400,
    "default_responses": {
      "sql_injection": {
        "content": {"error": "Forbidden"},
        "status_code": 403
      }
    }
  }
}
```

### Anonymization
```json
{
  "anonymization": {
    "enabled": true,
    "strategy": "hybrid",
    "store_original": true,
    "sensitive_headers": [
      "Authorization",
      "Cookie",
      "X-API-Key"
    ]
  }
}
```

### Debug Logging
```json
{
  "system": {
    "debug": false
  }
}
```

Set `true` to enable debug logs (verbose output), `false` for production (clean logs).

---

## Documentation

- **[START_HERE.md](docs/START_HERE.md)** - Quick navigation guide
- **[INSTALLATION.md](docs/INSTALLATION.md)** - Detailed setup instructions
- **[DETECTION_MODES.md](docs/DETECTION_MODES.md)** - Detection vs Allowlist modes
- **[DECEPTIVE_PAYLOADS_MANAGEMENT.md](docs/DECEPTIVE_PAYLOADS_MANAGEMENT.md)** - Honeypot response system
- **[ANONYMIZATION_TESTING.md](docs/ANONYMIZATION_TESTING.md)** - Data privacy details
- **[FEATURES.md](docs/FEATURES.md)** - Complete feature list

---

## Contributing

IFRIT is developed openly on GitHub under Apache License 2.0.

**Contributions welcome:**
- New LLM providers (GPT, Llama, etc.)
- SIEM integrations (Wazuh, Splunk, ELK)
- Payload templates for new attack types
- Detection improvements and pattern refinements
- Documentation and examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

IFRIT Proxy is licensed under [Apache License 2.0](LICENSE).

---

## Support

**Security Issues + Bug reports + Ideas or general inquiries**
- Email: [ifrit@0t.systems](mailto:ifrit@0t.systems)

---

## Acknowledgments

Built with Go, SQLite, Claude AI, and the security community's collective threat intelligence.

**Version:** 0.1.1  
**Status:** MVP  
**Last Updated:** November 7, 2025
