# Detection Modes

**Version:** 0.1.1  
**Last Updated:** November 7, 2025

IFRIT supports two different security modes: **Detection Mode** (default) and **Allowlist Mode**. Choose the mode that matches your security requirements.

---

## Detection Mode (Default)

**Use when:** You want smart threat detection with minimal false positives and flexibility.

### How It Works

All traffic is analyzed by the detection pipeline:
```
Request arrives
    ↓
Is IP/path whitelisted? → YES → Check skip_body_check_on_whitelist flag
                              ├─ true → Allow through ✓
                              └─ false → Continue to detection
                        → NO → Continue to detection
    ↓
Stage 1: Check local rules → Attack? → Block with honeypot ✓
    ↓
Stage 2: Check learned patterns → Attack? → Block with honeypot ✓
    ↓
Stage 3: LLM analysis (POST/PUT/DELETE) → Attack? → Block with honeypot ✓
    ↓
Legitimate traffic → Forward to backend ✓
```

### Configuration
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

### Whitelist (Optional)

Bypass detection for trusted IPs or paths:
```json
{
  "detection": {
    "mode": "detection",
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50"
    ],
    "whitelist_paths": [
      "/health",
      "/status",
      "^/metrics.*"
    ]
  }
}
```

**Whitelisted IPs:** ALL paths allowed  
**Whitelisted paths:** Allowed from ANY IP

### Skip Body Check Flag (New in 0.1.1)

Control whether whitelisted paths still get checked:
```json
{
  "detection": {
    "skip_body_check_on_whitelist": false
  }
}
```

**Behavior:**
- `true` (default): Whitelisted paths skip ALL checks (fastest, original behavior)
- `false`: Whitelisted paths still check body/headers (catches malicious payloads in clean paths)

**Example use case:** Path `/health` is whitelisted, but still detect if body contains SQL injection

### Use Cases

- Standard web application deployment
- Detect attacks + learn patterns automatically
- Some traffic exceptions needed (health checks, metrics)
- False positive tolerance acceptable (~5%)
- Cost-conscious (learns after first week, then 90% savings)

---

## Allowlist Mode

**Use when:** You need strict access control - only authorized traffic allowed.

### How It Works

Only whitelisted traffic is allowed. Everything else is blocked with a honeypot response:
```
Request arrives
    ↓
Is IP/path whitelisted? → YES → Allow through ✓
                        → NO → Block request
                              Return fantasy response (via payload management)
```

### Configuration
```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50",
      "203.0.113.0"
    ],
    "whitelist_paths": [
      "/health",
      "/status"
    ]
  }
}
```

### How Allowlist Works

**Whitelisted IP** (e.g., `192.168.1.100`):
- ALL paths allowed
- No detection needed
- Instant response (<1ms)

**Whitelisted path** (e.g., `/health`):
- Allowed from ANY IP
- No detection needed
- Instant response (<1ms)

**Non-whitelisted request** (e.g., `203.0.113.5` to `/api/users`):
- Blocked immediately
- Returns fake response (from `blocked_by_allowlist` in payload config)
- Logged as attack
- Response time: <10ms

### Blocked Request Response

When a non-whitelisted request arrives, IFRIT returns:

**If `generate_dynamic_payload: true`:**
```
LLM generates realistic fake response
Status: 403 Forbidden (or configured)
Body: Contextual error message
```

**If `generate_dynamic_payload: false`:**
```
Config default response
Status: 403 Forbidden (or configured)
Body: {"error": "Forbidden"}
(this response can be customized)
```

### Use Cases

- VPN-only access (internal network only)
- Admin portal (IP restricted)
- API gateway (authorized clients only)
- Strict zero-trust network policy
- Honeypot for unauthorized access
- Compliance requirement (no public exposure)

---

## Comparison

| Feature | Detection Mode | Allowlist Mode |
|---------|----------------|----------------|
| **Default action** | Analyze traffic | Block traffic |
| **Whitelisted IPs** | Bypass detection | Allow all paths |
| **Whitelisted paths** | Allow from any IP | Allow from any IP |
| **Non-whitelisted** | 4-stage detection pipeline | Immediate block |
| **False positives** | Possible (~5%) | None (by design) |
| **False negatives** | Rare (<1%) | None (all unknown = blocked) |
| **Setup complexity** | Low | Very low |
| **Learning capability** | Yes | No (allowlist static) |
| **Response time (typical)** | <10ms (95% cached) | <1ms (all allowlist) |
| **Response time (novel attack)** | ~3 seconds (LLM) | <1ms (always blocked) |
| **Best for** | Web apps, public APIs | VPN, admin portals |

---

## Configuration Examples

### Example 1: Standard Detection (Most Users)
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

**Result:** Smart threat detection, learns patterns, blocks attacks

**Traffic flow:**
- 95% requests: Cached patterns detection (<10ms)
- 5% requests: Novel attacks (LLM analysis ~3s)
- All attacks: Honeypot response

---

### Example 2: Detection with Admin Bypass
```json
{
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": [
      "192.168.1.100",
      "10.0.0.50"
    ],
    "whitelist_paths": [
      "/health",
      "/status",
      "^/metrics.*"
    ]
  }
}
```

**Result:** 
- Admin IPs bypass all detection
- Health/metrics endpoints always allowed from any IP
- All other traffic analyzed
- Production-ready

**Traffic flow:**
- Admin IPs: Bypass detection (<1ms)
- Health/metrics: Bypass detection (<1ms)
- Other traffic: Full detection pipeline

---

### Example 3: Strict Allowlist (VPN Only)
```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "10.0.0.0/24"
    ],
    "whitelist_paths": []
  }
}
```

**Result:** 
- Only internal network (10.0.0.0/24) allowed
- Everything else blocked
- Zero false positives

**Traffic flow:**
- Internal IPs: Allow all paths (<1ms)
- External IPs: Block everything (<1ms)
- All blocked requests: Logged as attacks

---

### Example 4: Allowlist with Public Endpoints
```json
{
  "detection": {
    "mode": "allowlist",
    "whitelist_ips": [
      "192.168.1.100"
    ],
    "whitelist_paths": [
      "/api/health",
      "/api/status",
      "^/public/.*"
    ]
  }
}
```

**Result:**
- Admin IP (192.168.1.100) can access everything
- Allowed IP(s) can access `/api/health`, `/api/status`, `/public/*`
- Everything else blocked

**Traffic flow:**
- Admin/internal IPs: All paths allowed (<1ms)
- Public endpoints: Any IP allowed (<1ms)
- Other paths from external IPs: Block (<1ms)

---

### Example 5: Hybrid - Detection with Body Check Override
```json
{
  "detection": {
    "mode": "detection",
    "skip_body_check_on_whitelist": true,
    "whitelist_paths": [
      "/health",
      "/metrics"
    ]
  }
}
```

vs.
```json
{
  "detection": {
    "mode": "detection",
    "skip_body_check_on_whitelist": false,
    "whitelist_paths": [
      "/health",
      "/metrics"
    ]
  }
}
```

**Difference:**
- `true`: `/health` bypasses ALL checks (fastest)
- `false`: `/health` bypasses path detection but still checks body/headers

**Use case:** `/health` is clean, but still want to catch malicious bodies

---

## Switching Modes

### From Detection to Allowlist
```bash
# Stop IFRIT
pkill ifrit

# Edit config/default.json
nano config/default.json

# Change mode
sed -i '' 's/"mode": "detection"/"mode": "allowlist"/' config/default.json

# Add your whitelisted IPs/paths
# Example:
# "whitelist_ips": ["192.168.1.100"],
# "whitelist_paths": ["/health"]

# Restart
./ifrit
```

### From Allowlist to Detection
```bash
# Stop IFRIT
pkill ifrit

# Edit config/default.json
nano config/default.json

# Change mode
sed -i '' 's/"mode": "allowlist"/"mode": "detection"/' config/default.json

# Restart
./ifrit
```

**Data preservation:** All learned patterns are preserved when switching modes. Database is not cleared.

---

## Monitoring Blocked Requests

### View Blocked Requests in Allowlist Mode
```bash
# CLI - show all attacks (includes blocked requests)
./ifrit-cli attack list

# Show attacks from specific IP
./ifrit-cli attack by-ip 203.0.113.5

# Show attacks on specific path
./ifrit-cli attack by-path /api/admin

# Get attack statistics
./ifrit-cli attack stats
```

### Check Logs
```bash
# Watch logs in real-time
tail -f logs/ifrit.log | grep ALLOWLIST

# Count blocked requests
grep "ALLOWLIST" logs/ifrit.log | wc -l

# Show blocked requests from last hour
grep "ALLOWLIST" logs/ifrit.log | tail -100
```

### Typical Output
```
2025-11-07 22:11:04 [ALLOWLIST] app_id=default | Blocking non-whitelisted request from 203.0.113.5 to POST /api/users
2025-11-07 22:11:05 [ALLOWLIST] app_id=default | Blocking non-whitelisted request from 203.0.113.6 to GET /admin
2025-11-07 22:11:06 [ALLOWLIST] app_id=default | Blocking non-whitelisted request from 203.0.113.7 to DELETE /api/config
```

---

## Best Practices

### For Detection Mode

1. **Start with no whitelist** - Let IFRIT learn your traffic
2. **Monitor first week** - Check logs for false positives
3. **Add exceptions gradually** - Whitelist only necessary paths/IPs
4. **Review learned patterns** - `./ifrit-cli pattern list`
5. **Adjust `skip_body_check_on_whitelist`** - Based on your threat model
   - `true` (faster): If whitelisted paths are truly safe
   - `false` (safer): If whitelisted paths might contain attacks

### For Allowlist Mode

1. **List all IPs** - Be explicit about what's allowed
2. **Use IP ranges** - `10.0.0.0/24` instead of individual IPs
3. **Keep paths minimal** - Only public endpoints if needed
4. **Document exceptions** - Why is this IP/path whitelisted?
5. **Review blocked requests** - Ensure no legitimate traffic is blocked

### Transition Path (Recommended)
```
Week 1: Onboarding Mode
├─ Auto-learn traffic
├─ Auto-whitelist paths
└─ Zero blocking

Week 2-3: Detection Mode
├─ Review learned patterns
├─ Adjust whitelists
└─ Monitor for false positives

Week 4+: Production Mode
├─ If strict requirements → Allowlist Mode
└─ If standard requirements → Detection Mode
```

---

## Troubleshooting

### All requests blocked in allowlist mode?

**Check if you've added your own IP to whitelist:**
```json
"whitelist_ips": ["YOUR.IP.HERE"]
```

**Test locally:**
```bash
# Access from localhost
curl http://127.0.0.1:8080/health

# Check if 127.0.0.1 is whitelisted
./ifrit-cli exception list
```

### Getting false positives in detection mode?

**Add the path to whitelist:**
```json
"whitelist_paths": ["/your/false/positive/path"]
```

**Or adjust the skip flag:**
```json
"skip_body_check_on_whitelist": true
```

### Need to allow specific IP but block one path?

**Use detection mode with selective whitelist:**
```json
{
  "detection": {
    "mode": "detection",
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": ["192.168.1.100"],
    "whitelist_paths": []
  }
}
```

Then manually manage that path detection separately.

### High false positive rate?

**In Detection Mode:**
1. Review logs: `grep "STAGE" logs/ifrit.log`
2. Identify problematic paths
3. Add to `whitelist_paths`
4. Or lower LLM confidence threshold (future feature)

---

## Performance Comparison

| Scenario | Detection Mode | Allowlist Mode |
|----------|---|---|
| Whitelist hit (cached pattern) | <10ms | <1ms |
| Novel attack (LLM analysis) | ~3s | N/A (blocked) |
| Non-whitelisted attack | ~3s | <1ms |
| Legitimate traffic | <10ms | <1ms |

**Throughput:**
- Detection Mode: ~1000 requests/sec (typical)
- Allowlist Mode: ~10,000 requests/sec (whitelist only)

---

## Migration Guide

### From WAF to IFRIT (Detection Mode)
```
Current: WAF (rules-based blocking)
Goal: IFRIT (smart detection + learning)

Step 1: Add IFRIT in front of WAF
  ├─ IFRIT in Detection Mode
  └─ WAF still active (backup)

Step 2: Monitor for 1 week
  ├─ Compare IFRIT detection vs WAF
  ├─ Adjust IFRIT whitelist
  └─ Build confidence

Step 3: Disable WAF (optional)
  └─ IFRIT handles all detection
```

### From IP Blocking to IFRIT (Allowlist Mode)
```
Current: Firewall rules (IP blocking)
Goal: IFRIT (honeypot + learning)

Step 1: Configure Allowlist Mode
  ├─ Add trusted IPs to whitelist
  └─ Keep firewall rules for now

Step 2: Monitor IFRIT logs
  ├─ Compare blocked IPs
  ├─ Identify legitimate traffic
  └─ Adjust whitelist

Step 3: Remove firewall rules (optional)
  └─ IFRIT handles all blocking
```

---

## Summary

**Detection Mode:**
-  Flexible, learns patterns
-  Handles novel attacks (LLM)
-  Good balance of security and usability
-  ~5% false positive rate possible

**Allowlist Mode:**
-  Strict, zero false positives
-  Very fast (<1ms)
-  Perfect for restricted environments
-  Requires explicit whitelisting

**Recommendation for production:**
- New deployments: Start with Detection Mode
- Onboarding mode first, then evaluate
- After 1 week: Choose based on your needs
- Can switch anytime without data loss

---

**Last Updated:** November 7, 2025  
**Version:** 0.1.1
