# IFRIT Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Allowlist Mode** - Strict access control with whitelist-only traffic (everything else blocked)
- **Detection Modes** - Two modes: Detection (smart analysis) and Allowlist (strict control)
- **Payload Management System** - Intelligent honeypot response selection with 4-stage fallback
- **LLM Dynamic Payload Generation** - Claude generates realistic honeypot responses on-the-fly
- **Payload Caching** - 90% cost reduction after learning phase (first attack: Claude, repeat: cache)
- **Data Anonymization Engine** - Case-insensitive header redaction, PII tokenization, compliance support
- **CLI Manager Tool** - Complete database operations from terminal
- **Pattern Management** - Add, view, remove learned attack patterns
- **Attacker Profile Viewing** - Track attacker behavior, first seen, last seen, attack types
- **Exception/Whitelist Management** - Via CLI and database
- **Comprehensive Attack Filtering** - Query by IP, path, type, time range
- **REST API** - Attack stats, pattern queries, cache management, health checks
- **Execution Modes** - Onboarding (auto-learn), Learning (log only), Normal (production)
- **Threat Intelligence Output** - Attack logs, pattern database, attacker profiles

### Changed
- **Detection Pipeline** - Now 4 stages: Whitelist → Local Rules → Database Patterns → LLM Analysis
- **Payload Response System** - From static to intelligent selection (DB → LLM → Config → Fallback)
- **Database Schema** - Enhanced with payload_template column for honeypot caching
- **Configuration** - Added detection.mode, payload_management, anonymization sections
- **Detection Engine** - Now supports both Detection and Allowlist modes
- **Anonymization** - Improved with case-insensitive matching, regex patterns, audit logging
- **Main Handler** - Integrated payload management into all detection stages
- **Logging** - Added [ALLOWLIST], [PAYLOAD], [ANON] prefixes for visibility

### Fixed
- **Detection Engine** - Proper mode parameter propagation
- **Payload Selection** - Fixed LLM manager type casting for dynamic generation
- **Config Loading** - Added PayloadManagement struct with proper defaults
- **Database Patterns** - Now correctly matched in Stage 2
- **Header Redaction** - Case-insensitive matching for Authorization, Cookie, X-API-Key
- **Status Code Handling** - Proper HTTP status codes from payload configuration

### Deprecated
- Static-only honeypot responses (now dynamic with fallback)

## [0.1.0] - 2025-11-05

### Added
- **Core Reverse Proxy** - Intercepts traffic, decides honeypot vs. forward
- **Four-Stage Detection Pipeline**
  - Stage 0: Whitelist exceptions (whitelisted IPs/paths bypass detection)
  - Stage 1: Local rules (obvious attack signatures)
  - Stage 2: Database patterns (learned attacks from previous detection)
  - Stage 3: LLM analysis (Claude/GPT for novel threats)
- **Real-Time Threat Detection** - Claude and GPT integration
- **Self-Learning Attack Patterns** - SQLite database stores learned signatures
- **Data Anonymization** - Sensitive headers/data redacted before external APIs (GDPR/HIPAA compliant)
- **Read-Only Web Dashboard** - Real-time attack feeds, attacker profiles, system health
- **REST API** - JSON endpoints for integrations and queries
- **CLI Management Tool** - Full command-line interface for all operations
- **Attack Logging** - Detailed logs with timestamp, IP, path, type, stage detected
- **Attacker Profiling** - Tracks unique IPs, attack types, frequency, sophistication
- **Honeypot Payload System** - Returns fake data to confuse attackers
- **Pattern Database** - Stores learned attack signatures with confidence scores
- **Exception Management** - Whitelist IPs and paths that bypass detection
- **Configuration** - Full JSON configuration (no code changes needed)
- **Docker Support** - Docker and docker-compose deployment
- **Systemd Support** - Linux service deployment
- **TLS/HTTPS Support** - Configurable certificates

### Features
- Instant detection (Stage 1-2: <10ms)
- Learning capability (each attack analyzed becomes a learned pattern)
- Cost optimization (90% API call reduction after learning)
- Zero infrastructure changes (drop-in reverse proxy)
- Privacy-first (anonymization before external APIs)
- Complete audit trail (all attacks logged with context)
- Extensible architecture (new LLM providers, SIEM integrations)

### Performance
- Whitelist exceptions: <1ms
- Local rules: <5ms
- Database pattern match: <10ms
- LLM analysis: ~3 seconds
- Typical learned pattern reuse: <10ms (90% of attacks)

### Known Limitations
- Zero-day exploits require LLM analysis (~3s delay)
- Compromised credentials bypass honeypot layer
- LLM misclassification possible (use conservative defaults)
- Single point of failure (does not replace network IDS)
- Single instance learns locally only (aggregation requires community contribution)

---

**Next Major Version Goals:**
- Multi-database support (MySQL, PostgreSQL, others)
- Advanced SIEM integrations (Wazuh, Splunk, ELK)
- Conditional payloads based on attacker profile
- Web UI for dashboard (not read-only basic dashboard)
- Payload randomization and evolution
- Local machine learning for analysis & Attacker profiling
- Commercial edition with enhanced features, enterprise integration & load balancing/clustering
