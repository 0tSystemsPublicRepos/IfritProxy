# Threat Intelligence Implementation Guide

## Overview

IFRIT now includes an **async threat intelligence enrichment system** that automatically enriches attacker IPs with data from AbuseIPDB, VirusTotal, and IPinfo APIs.

**Key Features:**
-  Async background enrichment (non-blocking)
-  24-hour caching to reduce API calls by 90%
-  3 parallel worker goroutines
-  Intelligent risk scoring (0-100)
-  Multi-API enrichment (AbuseIPDB, VirusTotal, IPinfo)
-  CLI commands for querying threat data
-  SQLite persistence

---

## Architecture

### Components

#### 1. Enricher (`internal/threat_intelligence/enricher.go`)
Handles individual IP enrichment:
- Queries AbuseIPDB, VirusTotal, IPinfo in parallel
- Calculates weighted risk scores
- Stores results in database
- Implements cache checking

#### 2. Manager (`internal/threat_intelligence/manager.go`)
Manages enrichment workers:
- Spawns 3 worker goroutines
- Manages job queue (buffer: 1000 jobs)
- Implements retry logic with exponential backoff
- Graceful shutdown handling

#### 3. Database Layer (`internal/database/sqlite.go`)
New methods:
- `StoreThreatIntelligence()` - Save enriched data
- `GetThreatIntelligence()` - Retrieve threat intel for IP
- `GetTopThreatsByRiskScore()` - Get top attackers
- `IsThreatIntelligenceCached()` - Check cache validity

#### 4. Configuration (`internal/config/threat_intelligence.go`)
Config structures for:
- AbuseIPDB, VirusTotal, IPinfo API settings
- Risk score weights
- Threat level thresholds
- Enrichment worker count

---

## Data Flow
```
Attack Detected (Stage 1-4)
    ↓
Logged & Stored
    ↓
Async Enrichment Triggered
    ├→ Worker picks from queue
    ├→ Check cache (24h TTL)
    ├→ Query 3 APIs in parallel
    ├→ Calculate risk score
    └→ Store in database
    
Risk Score Calculation:
  - AbuseIPDB score (40% weight)
  - VirusTotal detections (35% weight)
  - IPinfo risk (25% weight)
  = Total risk score 0-100

Threat Levels:
  - CRITICAL: 80-100
  - HIGH: 60-79
  - MEDIUM: 40-59
  - LOW: 0-39
```

---

## Configuration

### Enable/Disable in `config/default.json`
```json
{
  "threat_intelligence": {
    "enabled": true,
    "cache_ttl_hours": 24,
    "enrichment_workers": 3,
    "apis": {
      "abuseipdb": {
        "enabled": true,
        "api_key": "${ABUSEIPDB_API_KEY}",
        "timeout_seconds": 10
      },
      "virustotal": {
        "enabled": true,
        "api_key": "${VIRUSTOTAL_API_KEY}",
        "timeout_seconds": 10
      },
      "ipinfo": {
        "enabled": true,
        "api_key": "${IPINFO_API_KEY}",
        "timeout_seconds": 10
      }
    },
    "risk_score_weights": {
      "abuseipdb_score": 0.4,
      "virustotal_detections": 0.35,
      "ipinfo_risk": 0.25
    },
    "threat_level_thresholds": {
      "critical": 80,
      "high": 60,
      "medium": 40,
      "low": 0
    }
  }
}
```

### Get API Keys

**AbuseIPDB:**
- Visit: https://www.abuseipdb.com/
- Sign up for free account
- Generate API key in Account → API

**VirusTotal:**
- Visit: https://www.virustotal.com/
- Sign up for free account
- Get API key from User Account → API key

**IPinfo:**
- Visit: https://ipinfo.io/
- Sign up for free account
- Get token from Account → API Tokens

---

## CLI Commands

### List All Enriched Threats
```bash
./ifrit-cli threat list
```

Output:
```
ID  IP ADDRESS      RISK SCORE  THREAT LEVEL  COUNTRY  ATTACKS  UPDATED
1   203.0.113.5     92          CRITICAL      CN       15       2025-11-13T11:24:07Z
2   192.0.2.100     45          MEDIUM        RU       8        2025-11-13T11:23:15Z
```

### View Specific Threat
```bash
./ifrit-cli threat view 203.0.113.5
```

Output:
```
Threat Intelligence for 203.0.113.5
==========================
ID:                  1
Risk Score:          92/100 (CRITICAL)
Country:             China
Organization:        Example ISP

AbuseIPDB Data
  Confidence Score:  87.5
  Reports:           23

VirusTotal Data
  Malicious:         5
  Suspicious:        2

Privacy/Hosting
  Type:              hosting

Detection Stats
  Total Attacks:     15
  Last Attack:       2025-11-13T11:24:07Z

Cache Info
  Enriched:          2025-11-13T11:20:00Z
  Cache Until:       2025-11-14T11:20:00Z
```

### Top Threats by Risk Score
```bash
./ifrit-cli threat top 5
```

Output:
```
Top 5 Threats by Risk Score
RANK  IP ADDRESS      RISK SCORE  THREAT LEVEL  COUNTRY  ATTACKS
1     203.0.113.5     92          CRITICAL      CN       15
2     192.0.2.50      78          HIGH          RU       12
3     198.51.100.25   65          HIGH          KP       8
```

### Threat Statistics
```bash
./ifrit-cli threat stats
```

Output:
```
Threat Intelligence Statistics
===============================
Total Enriched IPs:   42
Average Risk Score:   58.3

Threat Level Distribution
  🔴 CRITICAL:        8
  🟠 HIGH:            12
  🟡 MEDIUM:          18
  🟢 LOW:             4

Status: Active enrichment workers running
Cache TTL: 24 hours
```

---

## Database Schema

### threat_intelligence Table
```sql
CREATE TABLE threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    source_ip TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    
    -- AbuseIPDB data
    abuseipdb_score REAL,
    abuseipdb_reports INTEGER,
    abuseipdb_last_reported TEXT,
    
    -- VirusTotal data
    virustotal_malicious INTEGER,
    virustotal_suspicious INTEGER,
    virustotal_harmless INTEGER,
    virustotal_undetected INTEGER,
    
    -- IPinfo data
    ipinfo_country TEXT,
    ipinfo_org TEXT,
    ipinfo_privacy_type TEXT,
    is_vpn BOOLEAN DEFAULT 0,
    is_proxy BOOLEAN DEFAULT 0,
    is_hosting BOOLEAN DEFAULT 0,
    is_tor BOOLEAN DEFAULT 0,
    
    -- Metadata
    threat_level TEXT,
    enriched_at TIMESTAMP,
    cached_until TIMESTAMP,
    last_attack_at TIMESTAMP,
    total_attacks INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(app_id, source_ip),
    FOREIGN KEY(app_id) REFERENCES attacker_profiles(app_id)
);
```

---

## Integration Points

### 1. Main Application (`cmd/ifrit/main.go`)
- Initialized after payload manager
- Started before API server
- Gracefully stopped on shutdown
- Enrichment triggered on attack detection (all stages)

### 2. Detection Engine
Enrichment triggered when:
- Stage 1: Local rule detected
- Stage 2: Database pattern matched
- Stage 3: (N/A - legitimate)
- Stage 4: LLM analysis confirmed attack
- Allowlist: Non-whitelisted request blocked

### 3. Async Behavior
```go
// Non-blocking enrichment trigger
go tiManager.EnqueueEnrichment(appID, clientIP)
```

Benefits:
- Zero latency impact on proxy
- Requests process normally
- Enrichment happens in background
- Cache hits within 24 hours

---

## Performance

### Typical Response Times

| Operation | Time | Notes |
|-----------|------|-------|
| Cache hit (in database) | <1ms | Fast lookup |
| Cache hit (memory) | <1ms | Would require in-memory cache |
| LLM-generated enrichment | ~3s | First-time enrichment |
| API query (parallel) | ~1-3s | Per-worker, 3 workers in parallel |
| Database store | <10ms | Persists to SQLite |

### Cost Optimization

**Week 1 (New deployment):**
- 1000 attacks, 200 unique IPs
- ~200 API calls (60 AbuseIPDB + 60 VT + 60 IPinfo)
- Cost: ~$2-5

**Week 2-4 (Cache hits):**
- 1000 attacks, same 200 IPs
- ~0 API calls (all cached)
- Cost: $0

**Result: 95%+ cost reduction after initial learning**

---

## Troubleshooting

### Workers not starting

**Symptom:** "Starting X enrichment workers" not in logs

**Solution:**
```bash
# Check config
cat config/default.json | grep -A5 threat_intelligence

# Verify enabled
"enabled": true
```

### API keys not working

**Test AbuseIPDB:**
```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  -d ipAddress=1.2.3.4 \
  -d maxAgeInDays=90 \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

**Check logs:**
```bash
tail -f logs/ifrit.log | grep THREAT_INTEL
```

### High database size

**Check threat_intelligence rows:**
```bash
sqlite3 data/ifrit.db "SELECT COUNT(*) FROM threat_intelligence;"
```

**Clear old data (older than 30 days):**
```bash
sqlite3 data/ifrit.db "DELETE FROM threat_intelligence WHERE updated_at < datetime('now', '-30 days');"
```

---

## Future Enhancements

**Planned for 0.2:**
- [ ] Notifications on high-risk IP attacks
- [ ] Webhook triggers for CRITICAL threats
- [ ] Dashboard integration for threat intel
- [ ] GraphQL API for threat queries
- [ ] Geo-blocking based on risk
- [ ] Custom threat scoring algorithms
- [ ] Threat intel export (JSON/CSV)
- [ ] Integration with external SIEM (Splunk, ELK)

**Long-term (0.3+):**
- [ ] Machine learning for risk prediction
- [ ] Behavioral analysis
- [ ] Correlation with attack patterns
- [ ] Threat actor profiling
- [ ] Automated response policies

---

## API Reference

### Go Code Example
```go
// Initialize enricher
tiManager := threat_intelligence.NewManager(&cfg.ThreatIntelligence, db)
tiManager.Start()

// Enqueue enrichment (non-blocking)
go tiManager.EnqueueEnrichment("default", "203.0.113.5")

// Query threat intel
intel, _ := db.GetThreatIntelligence("default", "203.0.113.5")
// Returns: map[string]interface{} with all threat data

// Get top threats
threats, _ := db.GetTopThreatsByRiskScore("default", 10)

// Graceful shutdown
tiManager.Stop()
```

---

## Statistics & Metrics

After one week of operation, you should see:
- **Enriched IPs:** 50-200
- **Cache Hit Rate:** 80%+
- **Average Risk Score:** 40-60
- **API Calls Reduced:** 90%+
- **Database Size Impact:** +5-10MB

---

## Support & Issues

For issues or feature requests:
- Email: ifrit@0t.systems
---

**Last Updated:** November 13, 2025
