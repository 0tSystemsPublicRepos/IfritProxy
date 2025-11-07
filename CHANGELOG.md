# IFRIT Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-11-07

### Added
- **Skip Body Check on Whitelist Flag** - `skip_body_check_on_whitelist` config option allows checking request body/headers even when path is whitelisted
- **Graceful Shutdown** - Proper server shutdown with context timeout and signal handling
- **Debug Log Control** - New `system.debug` config flag to enable/disable debug logging (keeps production logs clean)
- **Enhanced Detection Pipeline** - All stages now respect the whitelist override flag

### Changed
- **All Detection Stages** - All stages now accept and respect `skip_body_check_on_whitelist` flag
- **Main Handler** - Graceful shutdown handler using http.Server instead of blocking ListenAndServe
- **Logging** - Conditional debug logging based on `system.debug` config (removes verbose output)
- **Claude Provider** - Removed raw response logging (cleaned up logs)
- **Detection Engine** - Flag propagated through all detection methods

### Fixed
- **Keyword Exception Logic** - Now properly applies `skip_body_check_on_whitelist` flag to all stages:
  - Stage 1 (Local Rules): Respects flag
  - Stage 2 (Database Patterns): Respects flag
  - Stage 3 (Legitimate Cache): Respects flag and returns early if whitelisted
  - Stage 4 (LLM Analysis): Respects flag
- **Stage 3 (Cache)** - Now properly caches whitelisted requests when flag=true
- **Debug Output** - No verbose Claude API response logging in logs
- **Main.go Formatting** - Fixed malformed debug log statements

### Testing (Phase 1.1 - Complete)
-  Stage 1 (Local Rules) - XSS attack detection and honeypot response
-  Stage 2 (Database Patterns) - SQL injection detection with keyword exceptions
-  Stage 3 (Legitimate Cache) - Request caching with whitelist override
-  Stage 4 (LLM Analysis) - Dynamic payload generation
-  Flag=true behavior - All stages skip when path whitelisted
-  Flag=false behavior - All stages check body/headers even if path whitelisted
-  Multi-app support - app_id propagated through all stages
-  Graceful shutdown - Ctrl+C handling with proper cleanup
-  Keyword exceptions - Working across all detection stages

### Performance
- Whitelist exceptions (flag=true): <1ms
- Local rules: <5ms
- Database pattern match: <10ms
- LLM analysis: ~3 seconds (first time), <10ms (cached)

### Known Issues
- None identified as of now

---

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
- **REST API** - JSON endpoints for integrations and queries
- **CLI Management Tool** - Full command-line interface for all operations
- **Attack Logging** - Detailed logs with timestamp, IP, path, type, stage detected
- **Attacker Profiling** - Tracks unique IPs, attack types, frequency, sophistication
- **Honeypot Payload System** - Returns fake data to confuse attackers
- **Pattern Database** - Stores learned attack signatures with confidence scores
- **Exception Management** - Whitelist IPs and paths that bypass detection
- **Configuration** - Full JSON configuration (no code changes needed)
- **Multi-App Support** - app_id header support for multi-tenant deployments
- **Execution Modes** - Onboarding (auto-learn), Learning (log only), Normal (production)
- **Detection Modes** - Detection (smart analysis) and Allowlist (strict control)
- **Payload Management** - Intelligent honeypot response selection with 4-stage fallback
- **LLM Dynamic Payload Generation** - Claude generates realistic honeypot responses

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

## Supported Versions

| Version | Status | Support Until |
|---------|--------|---------------|
| 0.1.x   | Active | TBD           |

---

**Next Major Version Goals:**
- Multi-database support (MySQL, PostgreSQL, others)
- Advanced SIEM integrations (Wazuh, Splunk, ELK)
- Conditional payloads based on attacker profile
- Web UI for dashboard (not read-only basic dashboard)
- Payload randomization and evolution
- Local machine learning for analysis & Attacker profiling
- enterprise edition with enhanced features, more integrations & load balancing/clustering
