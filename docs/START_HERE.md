# 🔥FRIT Proxy - START HERE

Welcome! This file will guide you through the complete IFRIT Documentation package.

## What is IFRIT? (2-Minute Overview)

IFRIT is an intelligent reverse proxy that sits between attackers and your infrastructure.

When an attack comes in, IFRIT makes a smart decision:
- Is this obviously malicious? → Block with honeypot
- Is it a pattern we've seen before? → Block with cached response
- Do we need to ask Claude/GPT? → Analyze and block
- Is it legitimate? → Pass through

If it's an attack, IFRIT serves **fake data** back to the attacker (fake credentials, fake database records, etc.). This tricks the attacker while revealing their tools and techniques.

IFRIT learns continuously. Each attack analyzed becomes a learned pattern. After one week, 80% of attacks are caught instantly from the local database without external API calls.

---

## Navigation Guide

### I want to understand IFRIT quickly
**Read:** `docs/FEATURES.md` - Complete feature list (10 minutes)

### I'm setting up IFRIT for the first time
**Read:** `docs/INSTALLATION.md` - Setup instructions (15 minutes)

### I need to choose between Detection and Allowlist mode
**Read:** `docs/DETECTION_MODES.md` - Detailed comparison (10 minutes)

### I want to understand the honeypot response system
**Read:** `docs/DECEPTIVE_PAYLOADS_MANAGEMENT.md` - Payload management (15 minutes)

### I'm concerned about privacy and data handling
**Read:** `docs/ANONYMIZATION_TESTING.md` - Anonymization details (10 minutes)

### I want to contribute or understand the architecture
**Read:** `README.md` - Architecture section (20 minutes)

### I have a security concern
**Read:** `SECURITY.md` - Security policy and reporting (10 minutes)

---

## Key Concepts (5-Minute Summary)

### Three Execution Modes

**Onboarding Mode** (Days 1-7 of deployment)
- Auto-detects attacks
- Auto-whitelists legitimate paths
- Zero false positives
- Automatic baseline creation
- Best for: New deployment

**Learning Mode** (Optional)
- All traffic passes through
- Logged for manual review
- No automatic whitelisting
- Best for: Manual analysis

**Normal Mode** (Production)
- Full detection pipeline enabled
- Honeypot responses for attacks
- Real-time pattern learning
- Claude/GPT integration
- Best for: Active threat defense

### Two Detection Modes

**Detection Mode** (Default)
- Smart threat analysis
- Learns attack patterns
- Optional whitelist for exceptions
- ~5% false positive rate possible
- Best for: Standard deployments

**Allowlist Mode** (New in 0.1.1)
- Strict access control
- Only whitelisted IPs/paths allowed
- Everything else blocked
- Zero false positives (by design)
- Best for: VPN-only, admin portals, strict zero-trust

### Four-Stage Detection Pipeline
```
Stage 0: Whitelist Check
├─ Is IP whitelisted? → ALLOW ✓
├─ Is path whitelisted? → CHECK FLAG
│  ├─ skip_body_check_on_whitelist=true → ALLOW ✓
│  └─ skip_body_check_on_whitelist=false → Continue
└─ Continue to Stage 1

Stage 1: Local Rules
├─ Matches obvious attack? → HONEYPOT ✓
└─ Continue to Stage 2

Stage 2: Database Patterns
├─ Matches learned pattern? → HONEYPOT ✓
└─ Continue to Stage 3

Stage 3: LLM Analysis
├─ Claude/GPT confirms attack? → HONEYPOT ✓
└─ Is legitimate → Forward to backend ✓
```

### New in 0.1.1: Skip Body Check Flag

Control whether whitelisted paths still get checked:
```json
{
  "detection": {
    "skip_body_check_on_whitelist": false
  }
}
```

- `true`: Whitelisted paths skip ALL checks (fastest)
- `false`: Whitelisted paths still check body/headers (catches malicious payloads)

**Example use case:** Path `/health` is whitelisted, but still detect if body contains SQL injection

---

## Quick Start (10 minutes)

### 1. Clone Repository
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
```

### 2. Configure
```bash
cp config/default.json.example config/default.json
```

Edit `config/default.json` and add your Claude API key:
```json
{
  "llm": {
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE"
    }
  }
}
```

### 3. Build
```bash
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

### 4. Run
```bash
./ifrit
```

Server starts on `:8080` (proxy) and `:8443` (API).

### 5. Test
```bash
# In another terminal:
curl http://localhost:8080/.env

# Check CLI
./ifrit-cli exception list
```

---

## Recommended Deployment Path

### Week 1: Onboarding Phase
1. Start in **Onboarding Mode** (default)
2. All traffic passes through, attacks logged
3. IFRIT auto-whitelists legitimate paths
4. Review `logs/onboarding_traffic.log`
5. Zero impact on users

### Week 2: Review & Adjust
1. Review learned patterns: `./ifrit-cli pattern list`
2. Check attacker profiles: `./ifrit-cli attacker list`
3. Verify whitelisted paths are correct
4. Add any manual exceptions needed

### Week 3+: Switch to Normal Mode
1. Update config: `"mode": "normal"`
2. Full detection enabled
3. Honeypot responses for attacks
4. Real-time pattern learning
5. Production-ready

---

## Documentation Map

| Document | Purpose | Read Time |
|----------|---------|-----------|
| **FEATURES.md** | Complete feature list | 10 min |
| **INSTALLATION.md** | Setup instructions | 15 min |
| **DETECTION_MODES.md** | Detection vs Allowlist modes | 10 min |
| **DECEPTIVE_PAYLOADS_MANAGEMENT.md** | Honeypot response system | 15 min |
| **ANONYMIZATION_TESTING.md** | Data privacy details | 10 min |
| **README.md** | Project overview & architecture | 20 min |
| **SECURITY.md** | Security policy & reporting | 10 min |

---

## Common Questions

### Q: How long does it take to get started?
**A:** 10 minutes. Clone, configure API key, build, run.

### Q: Do I need to modify my application code?
**A:** No. IFRIT is a reverse proxy - zero code changes needed.

### Q: Will IFRIT block legitimate traffic?
**A:** Not in Onboarding Mode. Use that for 1 week to establish baseline. After that, ~5% false positive rate in Detection Mode, 0% in Allowlist Mode.

### Q: How much does it cost?
**A:** Free to deploy. If it helps you, consider: ⭐ starring on GitHub, contributing, or [buying us a coffee ☕](mailto:ifrit@0t.systems). Optional Claude API costs: ~$0.30 for first week of learning, then 90% savings via caching. 

### Q: Can I run multiple IFRIT instances?
**A:** Yes, with shared database (not fully tested, need network-mounted SQLite or PostgreSQL support coming soon).

### Q: What if Claude/GPT is down?
**A:** IFRIT falls back to config defaults and whitelist mode. Still protects against known patterns.

### Q: How is my data handled?
**A:** Sensitive data (tokens, credentials, emails) is anonymized before sending to Claude. See ANONYMIZATION_TESTING.md.

### Q: Can I use IFRIT with other security tools?
**A:** Yes. IFRIT works alongside IDS/IPS, WAF, firewalls, etc. It's complementary, not a replacement.

---

## Execution Mode Decision Tree
```
Starting fresh deployment?
├─ YES → Use Onboarding Mode for 1 week
│        └─ After 1 week → Switch to Normal Mode
│
└─ NO → Choose based on use case:
         ├─ Need strict access control? → Allowlist Mode
         ├─ Want smart threat analysis? → Detection Mode
         └─ Testing/learning? → Learning Mode
```

---

## Detection Mode Decision Tree
```
How strict do you need to be?
├─ Very strict (VPN-only, admin portal) → Allowlist Mode
├─ Standard (web app, public endpoints) → Detection Mode
└─ Learning (need baseline first) → Onboarding Mode
```

---

## Performance Expectations

| Operation | Speed | Example |
|-----------|-------|---------|
| Whitelist check | <1ms | 1000 requests/sec |
| Local rules | <5ms | 200 requests/sec |
| DB pattern match | <10ms | 100 requests/sec |
| LLM analysis | ~3 seconds | 0.3 requests/sec |
| Learned pattern reuse | <10ms | 100 requests/sec |

**Real-world:** 95% of requests use learned patterns (<10ms). Only 5% of new attacks trigger LLM (~3s).

---

## Support & Help

### Documentation
- All docs in `docs/` directory
- README.md for overview
- FEATURES.md for complete feature list

### Issues & Bugs
- Email: ifrit@0t.systems

### Security Issues
- **NEVER** use public issues for security reports
- Email: ifrit@0t.systems
- Response time: 24-36 hours

---

## Next Steps (Choose One)

###  I want to understand features first
→ Read **FEATURES.md**

###  I want to get running immediately
→ Read **INSTALLATION.md**

###  I want to understand security
→ Read **SECURITY.md** then **ANONYMIZATION_TESTING.md**

###  I want to configure properly
→ Read **DETECTION_MODES.md** then **INSTALLATION.md**

###  I want to understand the big picture
→ Read **README.md** (Architecture section)

---

## Status & Version

- **Version   :** 0.1.1 (MVP)
- **Last edit :** November 7, 2025
- **Status    :** Active Development
- **License   :** Apache 2.0

---

**Happy defending 🔥**
