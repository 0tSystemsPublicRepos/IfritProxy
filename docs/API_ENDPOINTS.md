# API Endpoints Reference

## Authentication

All protected endpoints require the `X-API-Token` header:
```bash
curl -H "X-API-Token: ifr_YOUR_TOKEN" http://localhost:8443/api/endpoint
```

## Base URL
```
http://localhost:8443
```

## Public Endpoints

### Health Check

Check if IFRIT is running.
```
GET /api/health
```

**Response:**
```json
{
  "status": "healthy"
}
```

---

### Intel Log (Attacker Interaction Logging)

Log attacker interactions for intelligence collection.
```
POST /api/intel/log
Content-Type: application/json

{
  "email": "attacker@example.com",
  "password": "password123",
  "custom_field": "value"
}
```

**Response:**
```json
{
  "status": "ok"
}
```

---

## Protected Endpoints (Require Authentication)

All endpoints below require `X-API-Token` header.

---

## Attack & Detection Endpoints

### Get Statistics

Overall attack statistics.
```
GET /api/stats?app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `app_id` (optional): Application ID, defaults to "default"

**Response:**
```json
{
  "status": "ok",
  "app_id": "default",
  "total_attacks": 1245,
  "total_attackers": 89,
  "timestamp": "2025-11-13T16:20:34Z"
}
```

---

### Get Recent Attacks

List recent detected attacks.
```
GET /api/attacks?limit=100&app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `limit` (optional): Number of results (1-1000), default: 100
- `app_id` (optional): Application ID, default: "default"

**Response:**
```json
[
  {
    "id": 1,
    "app_id": "default",
    "source_ip": "192.168.1.100",
    "attack_type": "SQL Injection",
    "requested_path": "/api/users",
    "http_method": "POST",
    "detection_stage": 4,
    "timestamp": "2025-11-13T16:20:34Z"
  }
]
```

---

### Get Attacker Profiles

List unique attackers and their attack patterns.
```
GET /api/attackers?app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `app_id` (optional): Application ID, default: "default"

**Response:**
```json
[
  {
    "id": 1,
    "app_id": "default",
    "source_ip": "192.168.1.100",
    "total_requests": 45,
    "successful_probes": 3,
    "attack_types": "SQL Injection, XSS",
    "first_seen": "2025-11-10T10:00:00Z",
    "last_seen": "2025-11-13T16:20:34Z"
  }
]
```

---

### Get Attack Patterns

List detected attack patterns.
```
GET /api/patterns?app_id=default
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
[
  {
    "id": 1,
    "app_id": "default",
    "attack_type": "SQL Injection",
    "attack_signature": "1 OR 1=1",
    "http_method": "POST",
    "path_pattern": "/api/users",
    "times_seen": 45,
    "first_seen": "2025-11-10T10:00:00Z",
    "last_seen": "2025-11-13T16:20:34Z"
  }
]
```

---

## Threat Intelligence Endpoints

### List Threat Intelligence

Get enriched threat data for all IPs.
```
GET /api/threat-intel/list?limit=50&app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `limit` (optional): Max results (1-1000), default: 50
- `app_id` (optional): Application ID, default: "default"

**Response:**
```json
[
  {
    "ip_address": "192.168.1.100",
    "risk_score": 85,
    "threat_level": "CRITICAL",
    "abuseipdb_score": 78.5,
    "abuseipdb_reports": 156,
    "virustotal_malicious": 5,
    "virustotal_suspicious": 2,
    "country": "United States",
    "last_seen": "2025-11-13T16:20:34Z"
  }
]
```

---

### Get Threat Intelligence Detail

Get detailed threat information for a specific IP.
```
GET /api/threat-intel/view?ip=192.168.1.100&app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `ip` (required): IP address to look up
- `app_id` (optional): Application ID, default: "default"

**Response:**
```json
{
  "ip_address": "192.168.1.100",
  "risk_score": 85,
  "threat_level": "CRITICAL",
  "abuseipdb_score": 78.5,
  "abuseipdb_reports": 156,
  "virustotal_malicious": 5,
  "virustotal_suspicious": 2,
  "ipinfo_country": "US",
  "ipinfo_city": "New York",
  "is_vpn": false,
  "is_proxy": false,
  "is_hosting": true,
  "is_tor": false,
  "last_seen": "2025-11-13T16:20:34Z",
  "created_at": "2025-11-10T10:00:00Z"
}
```

---

### Get Top Threats

Get the most dangerous IPs by risk score.
```
GET /api/threat-intel/top?limit=10&app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `limit` (optional): Max results (1-100), default: 10
- `app_id` (optional): Application ID, default: "default"

**Response:**
```json
[
  {
    "ip_address": "192.168.1.100",
    "risk_score": 95,
    "threat_level": "CRITICAL",
    "abuseipdb_reports": 156,
    "virustotal_malicious": 8,
    "country": "RU",
    "last_seen": "2025-11-13T16:20:34Z"
  }
]
```

---

### Get Threat Intelligence Statistics

Get aggregate threat statistics.
```
GET /api/threat-intel/stats?app_id=default
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
{
  "total_ips": 1245,
  "critical": 12,
  "high": 45,
  "medium": 234,
  "low": 954,
  "timestamp": "2025-11-13T16:20:34Z"
}
```

---

## Notification Configuration Endpoints

### Get Notification Configuration

Get current notification settings and rules.
```
GET /api/notifications/config?app_id=default
X-API-Token: YOUR_TOKEN
```

**Requires Role:** admin or analyst

**Response:**
```json
{
  "app_id": "default",
  "email_enabled": true,
  "slack_enabled": true,
  "twilio_enabled": false,
  "webhook_enabled": true,
  "alert_on_critical": true,
  "alert_on_high": false,
  "alert_on_medium": false,
  "alert_on_low": false
}
```

---

### Update Notification Configuration

Modify notification rules and provider settings.
```
POST /api/notifications/config/update
X-API-Token: YOUR_TOKEN
Content-Type: application/json

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

**Requires Role:** admin

**Response:**
```json
{
  "status": "ok",
  "message": "Notification config updated",
  "config": {
    "app_id": "default",
    "alert_on_critical": true,
    "alert_on_high": true,
    ...
  }
}
```

---

### Get Notification History

Get log of sent notifications.
```
GET /api/notifications/history?limit=50&app_id=default
X-API-Token: YOUR_TOKEN
```

**Query Parameters:**
- `limit` (optional): Max results (1-1000), default: 50
- `app_id` (optional): Application ID, default: "default"

**Response:**
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

---

## Exception Management Endpoints

### Get Exceptions

List IP/path exceptions.
```
GET /api/exceptions?app_id=default
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
[
  {
    "id": 1,
    "app_id": "default",
    "ip_address": "127.0.0.1",
    "path": "/health",
    "reason": "Internal monitoring",
    "created_at": "2025-11-10T10:00:00Z"
  }
]
```

---

### Add Exception

Create a new exception for an IP/path combination.
```
POST /api/exceptions/add
X-API-Token: YOUR_TOKEN
Content-Type: application/json

{
  "app_id": "default",
  "ip_address": "192.168.1.50",
  "path": "/api/admin",
  "reason": "Trusted internal network"
}
```

**Requires Role:** admin or analyst

**Response:**
```json
{
  "status": "ok",
  "message": "Exception added"
}
```

---

### Get Keyword Exceptions

List keyword-based exceptions.
```
GET /api/keyword-exceptions?app_id=default
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
[
  {
    "id": 1,
    "app_id": "default",
    "exception_type": "sql_injection",
    "keyword": "UNION SELECT",
    "reason": "False positive in reports",
    "enabled": true
  }
]
```

---

### Add Keyword Exception

Create keyword exception.
```
POST /api/keyword-exceptions/add
X-API-Token: YOUR_TOKEN
Content-Type: application/json

{
  "app_id": "default",
  "exception_type": "xss",
  "keyword": "<script>",
  "reason": "Legitimate use case"
}
```

**Requires Role:** admin or analyst

**Response:**
```json
{
  "status": "ok",
  "message": "Keyword exception added"
}
```

---

## Utility Endpoints

### Get Cache Statistics

Get LLM cache stats.
```
GET /api/cache/stats
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
{
  "status": "ok",
  "cache": {
    "total_payloads": 7,
    "active_llm_payloads": 0,
    "intel_injection_ready": true
  }
}
```

---

### Clear Cache

Clear all cached payloads.
```
POST /api/cache/clear
X-API-Token: YOUR_TOKEN
```

**Requires Role:** admin

**Response:**
```json
{
  "status": "ok",
  "message": "Cache cleared"
}
```

---

### Get Intel Statistics

Get intelligence collection stats.
```
GET /api/intel/stats?app_id=default
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
{
  "status": "ok",
  "app_id": "default",
  "total_interactions": 1245,
  "intel_templates": 2,
  "intel_injection": "enabled",
  "timestamp": "2025-11-13T16:20:34Z"
}
```

---

### Get Intel Templates

Get available intelligence templates.
```
GET /api/intel/templates
X-API-Token: YOUR_TOKEN
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Email Collection",
    "template_type": "form",
    "is_active": true,
    "created_at": "2025-11-10T10:00:00Z"
  }
]
```

---

## Error Responses

All endpoints return appropriate HTTP status codes:

| Status | Meaning |
|---|---|
| 200 | Success |
| 400 | Bad request |
| 401 | Unauthorized (invalid/missing token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found |
| 500 | Server error |

**Error Response Format:**
```json
{
  "error": "Error message describing what went wrong"
}
```

---

## Rate Limiting

API rate limit: **100 requests per minute**

When rate limited, you'll receive:
- Status: 429 (Too Many Requests)
- Response: `{"error": "Rate limit exceeded"}`

---

## Examples

### Get CRITICAL threats and send Slack alert
```bash
# 1. Get top threats
curl -H "X-API-Token: YOUR_TOKEN" \
  http://localhost:8443/api/threat-intel/top?limit=5

# 2. Enable HIGH alerts
curl -X POST -H "X-API-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_on_critical": true,
    "alert_on_high": true,
    "slack_enabled": true
  }' \
  http://localhost:8443/api/notifications/config/update

# 3. View notification history
curl -H "X-API-Token: YOUR_TOKEN" \
  http://localhost:8443/api/notifications/history?limit=10
```

### Dashboard threat intelligence fetch
```javascript
const apiToken = 'YOUR_TOKEN';

// Fetch threat stats
const stats = await fetch('http://localhost:8443/api/threat-intel/stats', {
  headers: { 'X-API-Token': apiToken }
}).then(r => r.json());

// Fetch top threats
const threats = await fetch('http://localhost:8443/api/threat-intel/top?limit=5', {
  headers: { 'X-API-Token': apiToken }
}).then(r => r.json());

console.log(`Total IPs: ${stats.total_ips}`);
console.log(`CRITICAL threats: ${stats.critical}`);
console.log(`Top threat: ${threats[0].ip_address} (${threats[0].risk_score}/100)`);
```

