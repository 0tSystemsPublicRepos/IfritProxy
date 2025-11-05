# IFRIT Proxy - START HERE

Welcome! This file will guide you through the complete IFRIT Proxy documentation package.

## Quick Navigation by Role

### I'm a Manager/Executive
Read: `docs/FEATURES.md` - Execution Modes section (5 minutes)

### I'm a Security Team Lead  
Read: `docs/FEATURES.md` (20 minutes)

### I'm Setting Up IFRIT
Read: `docs/INSTALLATION.md` (15 minutes)

### I'm a Developer/Contributor
Read: `docs/ifrit_architecture.md` (30-40 minutes)

## Key Concepts (2-Minute Summary)

IFRIT Proxy is an intelligent reverse proxy that sits between attackers and your real infrastructure.

When an attack comes in, IFRIT makes a smart decision: Is this obviously malicious? Is it a pattern we've seen before? Or do we need to ask Claude/GPT?

If it's an attack, IFRIT serves fake data back to the attacker (fake credentials, fake database records, etc.). This tricks the attacker while revealing their tools and techniques.

IFRIT learns continuously. Each attack analyzed becomes a learned pattern. After one week, 80% of attacks are caught instantly from the local database without external API calls.

## Three Execution Modes

### Onboarding Mode (Week 1)
- Auto-detects attacks
- Auto-whitelists paths
- Zero false positives
- Automatic baseline creation

### Learning Mode (Optional)
- All traffic passes through
- Logged for manual review
- No blocking

### Normal Mode (Production)
- Full detection pipeline
- Honeypot responses
- Real-time learning
- Claude/GPT integration

## Quick Start
```bash
# 1. Clone
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit

# 2. Configure (add your Claude API key)
cp config/default.json.example config/default.json
nano config/default.json

# 3. Build
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli

# 4. Run
./ifrit

# 5. Test
curl http://localhost:8080/.env
ifrit-cli exception list
```

See `docs/INSTALLATION.md` for detailed setup.

## Documentation Map

- **FEATURES.md** - All features, CLI commands, REST API, configuration
- **INSTALLATION.md** - Setup for macOS, Linux, Docker
- **ifrit_architecture.md** - Technical deep dive (existing)
- **ifrit_documentation.md** - Comprehensive overview (existing)

## Execution Mode Guide

### Choose Your Mode

| Mode | Use Case | False Positives | Setup Time |
|------|----------|-----------------|-----------|
| Onboarding | First deployment | 0% | < 5 min |
| Learning | Baseline creation | N/A | 1-2 weeks |
| Normal | Production | ~5% | After onboarding |

### Recommended Path

1. **Days 1-7:** Onboarding mode
   - Auto-learns your traffic
   - Zero blocking
   - Review `logs/onboarding_traffic.log`

2. **Day 8:** Switch to Normal mode
   - All detection enabled
   - Honeypot responses
   - Full threat intelligence

## Key Features

✅ **4-Stage Detection Pipeline**
- Stage 0: Whitelist exceptions
- Stage 1: Local rules (instant)
- Stage 2: Database patterns (learned)
- Stage 3: LLM analysis (Claude/GPT)

✅ **Onboarding Mode**
- Auto-whitelist detection
- Zero configuration needed
- Automatic baseline

✅ **Complete CLI**
- Manage patterns, attacks, attackers
- Whitelist/exception management
- Database statistics

✅ **REST API**
- Pattern queries
- Attack statistics
- Cache management

✅ **Threat Intelligence**
- Attack classification
- Attacker profiling
- Pattern learning

## Next Steps

1. **Read INSTALLATION.md** - Set up IFRIT
2. **Read FEATURES.md** - Understand all capabilities
3. **Deploy in Onboarding Mode** - Start learning
4. **Monitor for 1 week** - Review traffic
5. **Switch to Normal Mode** - Full protection

## Support

- **GitHub:** github.com/0tSystemsPublicRepos/ifrit
- **Issues:** github.com/0tSystemsPublicRepos/ifrit/issues
- **Email:** ifrit@0t.systems

---

**Status:** MVP v0.1 (November 2025)  
**License:** Apache 2.0  
**Python:** Not required (pure Go)  
**Database:** SQLite (local, no external dependencies)
