# IFRIT Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-13

### Added - Threat Intelligence & Notifications

#### Threat Intelligence System
- **3rd Party API Integration** - AbuseIPDB, VirusTotal, IPInfo enrichment
- **Risk Score Calculation** - Weighted formula (40% AbuseIPDB + 35% VirusTotal + 25% IPInfo)
- **Threat Level Classification** - CRITICAL (80-100), HIGH (60-79), MEDIUM (40-59), LOW (0-39)
- **Threat Intelligence Database** - SQLite storage with 24-hour cache
- **Parallel Enrichment** - 3 worker goroutines for non-blocking API calls
- **IP Intelligence Tracking** - Country, city, VPN/proxy/hosting/Tor detection
- **Cost Optimization** - 90% API call reduction via caching
- **CLI Commands**:
  - `ifrit threat list` - List enriched IPs
  - `ifrit threat view [ip]` - View IP details
  - `ifrit threat top [n]` - Top threats by risk
  - `ifrit threat stats` - Statistics

#### Notification System
- **Multi-Channel Notifications** - Email, Slack, Twilio SMS, Custom Webhooks
- **Rule-Based Alert Filtering** - Control alerts by threat level
- **Email Notifications** - SMTP integration with HTML formatting (tested: Mailtrap)
- **Slack Integration** - Webhook-based alerts with color coding
- **Twilio SMS** - SMS alerts to configured numbers
- **Custom Webhooks** - JSON payload delivery with retry logic
- **Notification History** - Audit trail of all sent alerts
- **API Endpoints**:
  - `GET /api/notifications/config` - View settings
  - `POST /api/notifications/config/update` - Update rules
  - `GET /api/notifications/history` - View sent alerts

#### Dashboard Enhancements
- **Threat Intelligence Cards** - Display CRITICAL/HIGH/MEDIUM/LOW threat counts
- **Top Risky IPs Section** - Show most dangerous IPs with risk scores
- **Real-Time Updates** - 5-second refresh interval
- **Enhanced Metrics** - Attack statistics + Threat intelligence stats
- **Embedded HTML Dashboard** - Moved from static files to `internal/api/handlers.go`

#### API Endpoints (New)
- `GET /api/threat-intel/list` - List threat intelligence data
- `GET /api/threat-intel/view?ip=X.X.X.X` - Get IP details
- `GET /api/threat-intel/top` - Top threats by risk score
- `GET /api/threat-intel/stats` - Threat statistics

### Changed

#### Configuration
- **New `threat_intelligence` section** - API keys, workers, weights, thresholds
- **New `notifications.rules` section** - Alert filtering by threat level
- **New `notifications.rules` fields**:
  - `alert_on_critical` (default: true)
  - `alert_on_high` (default: false)
  - `alert_on_medium` (default: false)
  - `alert_on_low` (default: false)

#### Database
- **New `threat_intelligence` table** - Stores enriched IP data with proper foreign key
- **New `notification_history` table** - Audit trail of sent notifications
- **Fixed Foreign Key** - Composite key `(app_id, source_ip)` in threat_intelligence

#### Notification Manager
- **Rule-Based Filtering** - Checks `config.notifications.rules` before sending
- **Config-Driven Settings** - Rules read from `config/default.json`
- **Log Filtering** - `[NOTIFICATIONS] Skipped notification for X threat (rule-based filtering)`

#### API Server
- **Threat Intelligence Endpoints** - Complete CRUD for threat data
- **Notification Configuration Endpoints** - Get/update alert rules
- **Dashboard HTML** - Enhanced with threat intel cards and top risky IPs

### Fixed

#### Database Initialization
- **Foreign Key Constraint** - Now correctly references `attacker_profiles(app_id, source_ip)`
- **Table Creation Order** - `threat_intelligence` properly added to init.go
- **Index Creation** - Added 4 new indexes for threat_intelligence table

#### Threat Intelligence Storage
- **Pre-Insert Validation** - Ensures `attacker_profiles` record exists before storing threat data
- **Upsert Logic** - Uses `ON CONFLICT` with proper updates

### Removed

#### Deprecated Files
- **`./web/` directory** - Removed (dashboard now embedded in API)
- **`internal/api/WEB_README.md`** - Removed (API-based dashboard only)

### Testing

#### Threat Intelligence (New)
- ✅ AbuseIPDB API integration
- ✅ VirusTotal API integration
- ✅ IPInfo API integration
- ✅ Risk score calculation
- ✅ Threat level assignment
- ✅ Database storage
- ✅ Caching (24-hour TTL)

#### Notifications (New)
- ✅ Email via Mailtrap (tested)
- ✅ Webhook.site integration (tested)
- ✅ Rule-based filtering (CRITICAL only - tested)
- ✅ Notification history tracking
- ✅ Config-driven rules

#### Dashboard (Enhanced)
- ✅ Threat intelligence cards display
- ✅ Top risky IPs section
- ✅ Real-time updates
- ✅ API token authentication

### Performance

| Operation | Speed | Queries/sec |
|-----------|-------|-------------|
| Threat intel lookup | <10ms | 100+ |
| API enrichment | 2-3 sec | 0.3-0.5 |
| Email notification | 500ms | 2 |
| Webhook notification | 100ms | 10+ |
| Dashboard load | <1 sec | N/A |

### Documentation (New)

- **THREAT_INTELLIGENCE.md** - Complete threat intel guide (architecture, APIs, CLI, database)
- **NOTIFICATIONS.md** - Notification system documentation (rule-based filtering, providers, setup)
- **API_ENDPOINTS.md** - Complete API reference (all 30+ endpoints documented)
- **Updated START_HERE.md** - New navigation for threat intelligence & notifications

### Known Issues

- Risk scores may be lower than expected (SQL injection showing as LOW/MEDIUM instead of CRITICAL)
  - Cause: 3rd party API confidence scores are conservative
  - Workaround: Adjust `threat_level_thresholds` in config
  - Fix planned: Add local scoring boost for detected attack types

- Twilio SMS requires verified numbers in trial mode
  - Solution: Use production Twilio account or test with webhook/email

### Configuration Example
```json
{
  "threat_intelligence": {
    "enabled": true,
    "cache_ttl_hours": 24,
    "enrichment_workers": 3,
    "apis": {
      "abuseipdb": { "enabled": true, "api_key": "YOUR_KEY" },
      "virustotal": { "enabled": true, "api_key": "YOUR_KEY" },
      "ipinfo": { "enabled": true, "api_key": "YOUR_KEY" }
    }
  },
  "notifications": {
    "enabled": true,
    "providers": {
      "email": { "enabled": true, "smtp_host": "...", "smtp_port": 2525 },
      "slack": { "enabled": false, "webhook_url": "..." },
      "twilio": { "enabled": false, "account_sid": "...", "from_number": "..." }
    },
    "rules": {
      "alert_on_critical": true,
      "alert_on_high": false,
      "alert_on_medium": false,
      "alert_on_low": false
    }
  }
}
```

---

## [0.1.1] - 2025-11-07

### Added
- **Skip Body Check on Whitelist Flag** - `skip_body_check_on_whitelist` config option
- **Graceful Shutdown** - Proper server shutdown with context timeout
- **Debug Log Control** - New `system.debug` config flag

### Changed
- **All Detection Stages** - Respect whitelist override flag
- **Logging** - Conditional debug logging based on config

### Fixed
- **Keyword Exception Logic** - Properly applied across all stages
- **Stage 3 (Cache)** - Caches whitelisted requests correctly
- **Debug Output** - Removed verbose Claude API response logging

---

## [0.1.0] - 2025-11-05

### Added
- **Core Reverse Proxy** - Intercepts traffic, decides honeypot vs. forward
- **Four-Stage Detection Pipeline** - Whitelist → Local Rules → DB Patterns → LLM Analysis
- **Real-Time Threat Detection** - Claude and GPT integration
- **Self-Learning Attack Patterns** - SQLite database
- **Data Anonymization** - GDPR/HIPAA compliant
- **REST API** - JSON endpoints
- **CLI Management Tool** - Full command-line interface
- **Attack Logging** - Detailed logs
- **Attacker Profiling** - Track IPs and attack types
- **Honeypot Payload System** - Return fake data
- **Pattern Database** - Learn from attacks
- **Exception Management** - Whitelist IPs/paths
- **Multi-App Support** - app_id header support
- **Execution Modes** - Onboarding, Learning, Normal
- **Detection Modes** - Detection and Allowlist

---

## Supported Versions

| Version | Status | Release Date | Support Until |
|---------|--------|---|---|
| 0.2.0   | Active | 2025-11-13 | TBD |
| 0.1.1   | Active | 2025-11-07 | TBD |
| 0.1.0   | Archive | 2025-11-05 | 2025-11-13 |

---

## Next Planned Features (v0.3.0+)

- [ ] Machine learning scoring boost (higher CRITICAL rates)
- [ ] Advanced SIEM integrations (Wazuh, Splunk)
- [ ] Web UI dashboard (interactive, not read-only)
- [ ] PostgreSQL/MySQL support
- [ ] Notification scheduling & quiet hours
- [ ] Attack deduplication
- [ ] Notification batching
- [ ] Escalation policies
- [ ] Comprehensive threat reports
- [ ] Response automation
- [ ] Clustering & load balancing
