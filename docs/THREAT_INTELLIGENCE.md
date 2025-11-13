# Threat Intelligence System

## Overview

IFRIT's Threat Intelligence system enriches detected attacks with data from multiple third-party APIs to calculate risk scores and threat levels. This enables intelligent threat assessment and rule-based alert filtering.

## Architecture

### Threat Enrichment Pipeline
```
Attack Detected
    ↓
Enqueue Job → Worker Pool (3 workers)
    ↓
Parallel API Calls:
  - AbuseIPDB (IP reputation)
  - VirusTotal (malware detection)
  - IPInfo (geolocation & privacy detection)
    ↓
Risk Score Calculation (0-100)
    ↓
Threat Level Assignment (LOW/MEDIUM/HIGH/CRITICAL)
    ↓
Database Storage (24h cache)
    ↓
Dashboard & API Access
```

### Configuration

Located in `config/default.json`:
```json
"threat_intelligence": {
  "enabled": true,
  "cache_ttl_hours": 24,
  "enrichment_workers": 3,
  "apis": {
    "abuseipdb": {
      "enabled": true,
      "api_key": "YOUR_API_KEY",
      "timeout_seconds": 10
    },
    "virustotal": {
      "enabled": true,
      "api_key": "YOUR_API_KEY",
      "timeout_seconds": 10
    },
    "ipinfo": {
      "enabled": true,
      "api_key": "YOUR_API_KEY",
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
```

## Risk Score Calculation

The risk score (0-100) is calculated using a weighted formula:
```
Risk Score = (AbuseIPDB × 0.40) + (VirusTotal × 0.35) + (IPInfo × 0.25)
```

### Components

**1. AbuseIPDB (40% weight)**
- IP reputation score (0-100)
- Number of abuse reports
- Higher score = more malicious

**2. VirusTotal (35% weight)**
- Number of malware detections
- Calculated as: (malicious_detections / 2) × 100 (capped at 100)
- Indicates malware/C2 infrastructure

**3. IPInfo (25% weight)**
- VPN detection
- Proxy detection
- Hosting provider detection
- Tor exit node detection
- Higher risk if privacy tools detected

### Threat Level Thresholds

| Threat Level | Risk Score | Action |
|---|---|---|
| CRITICAL | 80-100 | Alert immediately |
| HIGH | 60-79 | Alert (if configured) |
| MEDIUM | 40-59 | Log only |
| LOW | 0-39 | Log only |

## API Integration

### AbuseIPDB

**Purpose:** IP reputation and abuse history

**Endpoint:** `https://api.abuseipdb.com/api/v2/check`

**Rate Limit:** 4,000 requests/day (free tier)

**Data Retrieved:**
- `abuseConfidenceScore`: 0-100
- `totalReports`: Number of abuse reports
- `usageType`: datacenter, residential, etc.

### VirusTotal

**Purpose:** Malware and threat detection

**Endpoint:** `https://www.virustotal.com/api/v3/ip_addresses/{ip}`

**Rate Limit:** 4 requests/minute (free tier)

**Data Retrieved:**
- `last_dns_records`: DNS history
- `last_https_certificate`: Certificate info
- Malicious vote count from security vendors

### IPInfo

**Purpose:** Geolocation and privacy detection

**Endpoint:** `https://ipinfo.io/{ip}`

**Rate Limit:** 50,000 requests/month (free tier)

**Data Retrieved:**
- `country`: Country code
- `city`: City name
- `privacy`: VPN/Proxy detection
- `hosting`: Hosting provider detection

## Database Schema
```sql
CREATE TABLE threat_intelligence (
    id INTEGER PRIMARY KEY,
    app_id TEXT,
    source_ip TEXT,
    risk_score INTEGER,
    threat_level TEXT,
    abuseipdb_score REAL,
    abuseipdb_reports INTEGER,
    virustotal_malicious INTEGER,
    virustotal_suspicious INTEGER,
    ipinfo_country TEXT,
    ipinfo_city TEXT,
    is_vpn BOOLEAN,
    is_proxy BOOLEAN,
    is_hosting BOOLEAN,
    is_tor BOOLEAN,
    enriched_at TIMESTAMP,
    cached_until TIMESTAMP,
    total_attacks INTEGER,
    UNIQUE(app_id, source_ip),
    FOREIGN KEY(app_id, source_ip) REFERENCES attacker_profiles(app_id, source_ip)
);
```

## CLI Commands

### List Threat Intelligence
```bash
./ifrit threat list [--limit 50] [--app-id default]
```

Output:
```
IP              Risk  Level   Country  Reports  Malicious
1.2.3.4         75    HIGH    US       45       3
5.6.7.8         32    LOW     CN       2        0
```

### View IP Details
```bash
./ifrit threat view 1.2.3.4 [--app-id default]
```

Output:
```
IP Address:     1.2.3.4
Risk Score:     75 / 100
Threat Level:   HIGH
Country:        United States
City:           New York

AbuseIPDB:
  Score:        58.0
  Reports:      45
  
VirusTotal:
  Malicious:    3
  Suspicious:   1
  
IPInfo:
  VPN:          false
  Proxy:        false
  Hosting:      true
  Tor:          false

Cached Until:   2025-11-14 16:20:00 UTC
```

### Top Threats
```bash
./ifrit threat top [--limit 10] [--app-id default]
```

Output:
```
Rank  IP           Risk   Level     Country
1     192.168.1.1  95     CRITICAL  RU
2     10.0.0.1     82     CRITICAL  CN
3     172.16.0.1   71     HIGH      KP
```

### Statistics
```bash
./ifrit threat stats [--app-id default]
```

Output:
```
Total IPs Enriched:    1,245
CRITICAL Threats:      12
HIGH Threats:          45
MEDIUM Threats:        234
LOW Threats:           954

Average Risk Score:    42
Highest Risk Score:    98 (1.2.3.4)
```

## API Endpoints

### List Threat Intelligence
```bash
GET /api/threat-intel/list?limit=50&app_id=default
```

Response:
```json
[
  {
    "ip_address": "1.2.3.4",
    "risk_score": 75,
    "threat_level": "HIGH",
    "abuseipdb_score": 58,
    "abuseipdb_reports": 45,
    "virustotal_malicious": 3,
    "virustotal_suspicious": 1,
    "country": "US",
    "last_seen": "2025-11-13T16:20:00Z"
  }
]
```

### View IP Details
```bash
GET /api/threat-intel/view?ip=1.2.3.4&app_id=default
```

Response:
```json
{
  "ip_address": "1.2.3.4",
  "risk_score": 75,
  "threat_level": "HIGH",
  "abuseipdb_score": 58.0,
  "abuseipdb_reports": 45,
  "virustotal_malicious": 3,
  "virustotal_suspicious": 1,
  "ipinfo_country": "US",
  "ipinfo_city": "New York",
  "is_vpn": false,
  "is_proxy": false,
  "is_hosting": true,
  "is_tor": false,
  "last_seen": "2025-11-13T16:20:00Z",
  "created_at": "2025-11-10T10:00:00Z"
}
```

### Top Threats
```bash
GET /api/threat-intel/top?limit=10&app_id=default
```

Response:
```json
[
  {
    "ip_address": "1.2.3.4",
    "risk_score": 95,
    "threat_level": "CRITICAL",
    "abuseipdb_reports": 156,
    "virustotal_malicious": 8,
    "country": "RU",
    "last_seen": "2025-11-13T16:20:00Z"
  }
]
```

### Threat Statistics
```bash
GET /api/threat-intel/stats?app_id=default
```

Response:
```json
{
  "total_ips": 1245,
  "critical": 12,
  "high": 45,
  "medium": 234,
  "low": 954,
  "timestamp": "2025-11-13T16:20:00Z"
}
```

## Caching

- **TTL:** 24 hours (configurable)
- **Storage:** SQLite database
- **Bypass:** Automatic refresh on new attacks
- **Cost Benefit:** 90% reduction in API calls after learning period

## Performance

### Enrichment Speed

- Average time per IP: 2-3 seconds
- Parallel processing: 3 workers
- Non-blocking: Attacks blocked while enrichment happens in background

### Database Performance

- Indexed on: `(app_id, source_ip)`, `risk_score`, `cached_until`
- Query time: < 10ms for lookup
- Storage: ~2KB per IP record

## Troubleshooting

### No data enriched

1. Check API keys configured in `config/default.json`
2. Verify APIs are enabled
3. Check logs: `[THREAT_INTEL]` entries

### Slow enrichment

1. May be API rate limiting
2. Check API timeout settings
3. Reduce workers if needed

### High API costs

1. Enable caching (24h TTL)
2. Disable unused APIs
3. Use free tier APIs only

## Best Practices

1. **API Keys:** Store in environment variables, not config
2. **Rate Limiting:** Monitor API quota usage
3. **Caching:** Leverage 24h cache for repeated IPs
4. **Monitoring:** Check `[THREAT_INTEL]` logs regularly
5. **Updates:** Keep threat data fresh by enabling auto-enrichment

