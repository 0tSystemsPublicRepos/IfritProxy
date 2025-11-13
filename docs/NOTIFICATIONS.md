# Notifications System

## Overview

IFRIT's notification system sends real-time alerts about detected threats to multiple channels (Email, Slack, Twilio SMS, Webhooks) with **rule-based filtering** to control alert volume.

## Architecture

### Notification Pipeline
```
Attack Detected + Threat Intel Enriched
    ↓
Check Notification Rules
    ├─ CRITICAL threat? → Send to all enabled providers
    ├─ HIGH threat? → Skip (disabled by default)
    ├─ MEDIUM threat? → Skip (disabled by default)
    └─ LOW threat? → Skip (disabled by default)
    ↓
Parallel Delivery
    ├─ Email (SMTP)
    ├─ Slack (Webhook)
    ├─ Twilio (SMS API)
    └─ Custom Webhooks
    ↓
Audit Log + History
```

## Configuration

### Notification Rules

Located in `config/default.json`:
```json
"notifications": {
  "enabled": true,
  "providers": {
    "email": { ... },
    "slack": { ... },
    "twilio": { ... }
  },
  "rules": {
    "alert_on_critical": true,
    "alert_on_high": false,
    "alert_on_medium": false,
    "alert_on_low": false
  }
}
```

### Rule Behavior

  ---------------------------------------------------------------------
 | Threat Level | Default | Behavior  	                               |
 |--------------|---------|--------------------------------------------|
 | CRITICAL     | ON      | Always sends alerts                        |
 | HIGH         | OFF     | Alerts suppressed (manual override needed) |
 | MEDIUM       | OFF     | Alerts suppressed (manual override needed) |
 | LOW          | OFF     | Alerts suppressed (manual override needed) |
  ---------------------------------------------------------------------

**To enable HIGH alerts:**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": true,    // ← Change to true
  "alert_on_medium": false,
  "alert_on_low": false
}
```

## Providers

### 1. Email (SMTP)

**Configuration:**
```json
"email": {
  "enabled": true,
  "smtp_host": "sandbox.smtp.mailtrap.io",
  "smtp_port": 2525,
  "smtp_username": "YOUR_USERNAME",
  "smtp_password": "YOUR_PASSWORD",
  "from_address": "alerts@ifrit.local"
}
```

**Supported Hosts:**
- Gmail: `smtp.gmail.com:587` (use app password)
- Mailtrap: `sandbox.smtp.mailtrap.io:2525` (testing)
- SendGrid: `smtp.sendgrid.net:587`
- Custom SMTP server

**Email Content:**
- HTML formatted
- Color-coded threat levels
- Attack details (IP, type, path)
- Risk score and threat intel data
- Recommended actions

**Example:**
```
Subject: 🚨 IFRIT Alert: CRITICAL threat detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IFRIT Threat Alert

CRITICAL Threat Level Detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Score: 85/100

Threat Level: CRITICAL
Attack Type: SQL Injection
Source IP: 192.168.1.100
Country: United States
HTTP Method: POST
Target Path: /api/users
Timestamp: 2025-11-13 16:20:34 CET

AbuseIPDB Score: 78.5% (156 reports)
VirusTotal: Malicious: 5, Suspicious: 2

Recommended Action:
Review the attack details and take appropriate action. 
IFRIT has blocked this request.
```

### 2. Slack

**Configuration:**
```json
"slack": {
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
}
```

**Setup Slack Webhook:**

1. Go to your Slack workspace → Settings → Manage Apps
2. Create New App → From Scratch
3. Name: "IFRIT" → Create App
4. Enable Incoming Webhooks
5. Add New Webhook to Workspace
6. Select channel (e.g., #security)
7. Authorize
8. Copy webhook URL to config

**Message Format:**
- Color-coded severity (Red=CRITICAL, Orange=HIGH)
- Emoji threat indicators
- Formatted fields for easy reading
- Threat intel data integrated

**Example:**
```
🚨 IFRIT Threat Alert - CRITICAL

Threat Level: CRITICAL 🚨
Risk Score: 85/100
Attack Type: SQL Injection
Source IP: `192.168.1.100`
Country: United States
HTTP Method: POST
Target Path: `/api/users`
Timestamp: 2025-11-13 16:20:34 CET

AbuseIPDB Score: 78.5% (156 reports)
VirusTotal: Malicious: 5, Suspicious: 2
```

### 3. Twilio SMS

**Configuration:**
```json
"twilio": {
  "enabled": true,
  "account_sid": "YOUR_ACCOUNT_SID",
  "auth_token": "YOUR_AUTH_TOKEN",
  "from_number": "+1xxxxxxxxx",
  "to_number": "+1xxxxxxxxx"
}
```

**Setup Twilio:**

1. Sign up at https://www.twilio.com
2. Get Account SID and Auth Token from Console
3. Get Twilio phone number
4. Add recipient phone number (verified in trial)
5. Add to config

**SMS Format:**
- Concise (160 chars max)
- Threat level emoji
- Source IP
- Attack type
- Severity indicator

**Example:**
```
🚨 CRITICAL THREAT ALERT
IP: 192.168.1.100
Type: SQL Injection
Risk: 85/100
Action: Blocked
```

### 4. Custom Webhooks

**Configuration:**
```json
"webhooks": {
  "enabled": true,
  "retry_count": 3,
  "retry_delay_seconds": 5,
  "timeout_seconds": 10
}
```

**Payload Format:**
```json
{
  "event": "threat_detected",
  "timestamp": "2025-11-13T16:20:34Z",
  "app_id": "default",
  "threat_level": "CRITICAL",
  "risk_score": 85,
  "source_ip": "192.168.1.100",
  "country": "United States",
  "attack_type": "SQL Injection",
  "path": "/api/users",
  "method": "POST",
  "abuseipdb_score": 78.5,
  "abuseipdb_reports": 156,
  "virustotal_malicious": 5,
  "virustotal_suspicious": 2
}
```

**Setup Custom Webhook:**

1. Store webhook URL in database/config
2. IFRIT POSTs JSON payload on threat detection
3. Webhook receives event
4. Retry 3 times if fails
5. Audit logged to database

## Rule-Based Filtering

### How It Works

1. Attack detected and enriched with threat intel
2. Threat level calculated (LOW/MEDIUM/HIGH/CRITICAL)
3. Manager checks `config/default.json` rules
4. If threat level rule enabled → Send to all providers
5. If threat level rule disabled → Skip notification
6. Decision logged to `[NOTIFICATIONS]` logs

### Example Scenarios

**Scenario 1: Only CRITICAL enabled (default)**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": false,
  "alert_on_medium": false,
  "alert_on_low": false
}
```

Events:
```
CRITICAL SQL Injection → ✅ SEND EMAIL, SLACK, SMS
HIGH XSS → ❌ SKIP (rule disabled)
MEDIUM Recon → ❌ SKIP (rule disabled)
LOW Probe → ❌ SKIP (rule disabled)
```

**Scenario 2: CRITICAL + HIGH enabled**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": true,
  "alert_on_medium": false,
  "alert_on_low": false
}
```

Events:
```
CRITICAL SQL Injection → ✅ SEND
HIGH Credential Stuffing → ✅ SEND
MEDIUM Recon → ❌ SKIP
LOW Probe → ❌ SKIP
```

### API Configuration

Update rules via API:
```bash
POST /api/notifications/config/update
X-API-Token: YOUR_TOKEN

{
  "app_id": "default",
  "alert_on_critical": true,
  "alert_on_high": true,
  "alert_on_medium": false,
  "alert_on_low": false,
  "email_enabled": true,
  "slack_enabled": true,
  "twilio_enabled": false,
  "webhook_enabled": true
}
```

## API Endpoints

### Get Notification Config
```bash
GET /api/notifications/config?app_id=default
X-API-Token: YOUR_TOKEN
```

Response:
```json
{
  "app_id": "default",
  "email_enabled": true,
  "slack_enabled": true,
  "twilio_enabled": false,
  "webhook_enabled": true,
  "alert_rules": {
    "critical": true,
    "high": false,
    "medium": false,
    "low": false
  }
}
```

### Update Notification Config
```bash
POST /api/notifications/config/update
X-API-Token: YOUR_TOKEN

{
  "alert_on_critical": true,
  "alert_on_high": true,
  "alert_on_medium": false,
  "alert_on_low": false
}
```

### Get Notification History
```bash
GET /api/notifications/history?limit=50&app_id=default
X-API-Token: YOUR_TOKEN
```

Response:
```json
[
  {
    "threat_level": "CRITICAL",
    "source_ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "notification_type": "email",
    "status": "success",
    "sent_at": "2025-11-13T16:20:34Z"
  }
]
```

## Logs

All notification activity is logged:
```
[NOTIFICATIONS] Sending notification for threat: CRITICAL/85 from 192.168.1.100
[NOTIFICATIONS] Skipped notification for MEDIUM threat (rule-based filtering)
[EMAIL] ✓ Email sent successfully to 1 recipient(s) (threat: CRITICAL/85)
[SLACK] ✓ Slack message sent successfully (threat: CRITICAL/85)
[TWILIO] ✓ SMS sent successfully to +1xxxxxxxx (threat: CRITICAL/85)
[WEBHOOK] ✓ Webhook fired successfully (threat: CRITICAL/85)
```

## Best Practices

### Alert Fatigue Prevention

1. **Start with CRITICAL only** (default configuration)
2. **Monitor alert volume** for 1 week
3. **Gradually enable HIGH** if needed
4. **Fine-tune thresholds** based on environment
5. **Use separate channels** for different severities

### Recommended Rules by Environment

**Development:**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": true,
  "alert_on_medium": true,
  "alert_on_low": false
}
```

**Staging:**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": true,
  "alert_on_medium": false,
  "alert_on_low": false
}
```

**Production:**
```json
"rules": {
  "alert_on_critical": true,
  "alert_on_high": false,
  "alert_on_medium": false,
  "alert_on_low": false
}
```


## Troubleshooting

### Notifications not sending

1. Check provider is **enabled** in config
2. Verify API keys/credentials correct
3. Check notification rule for threat level
4. Review logs: `[NOTIFICATIONS]` entries
5. Test with triggered CRITICAL attack

### Email not received

1. Check spam folder
2. Verify SMTP credentials
3. Check firewall allows port (587, 2525, etc.)
4. Review `[EMAIL]` logs

### Slack webhook failing

1. Verify webhook URL valid and recent
2. Check channel still exists
3. Verify bot permissions
4. Test webhook manually: `curl -X POST -H 'Content-type: application/json' --data '{"text":"Test"}' YOUR_WEBHOOK_URL`

### SMS not received

1. Verify phone number correct and verified in Twilio
2. Check account has credits
3. Verify region supports SMS
4. Review `[TWILIO]` logs

### Too many alerts

1. Disable rules for HIGH/MEDIUM/LOW
2. Keep only CRITICAL enabled
3. Adjust threat level thresholds if needed
4. Check attack patterns - may need rate limiting
