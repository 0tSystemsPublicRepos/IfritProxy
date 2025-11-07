# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in IFRIT, please email **ifrit@0t.systems** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Do not open public GitHub issues for security vulnerabilities.**

This is an open source project and we'll do our best to:
1. Acknowledge receipt within 24-36 hours
2. Investigate and confirm within 5 business days
3. Develop a fix and plan a release
4. Credit you in the security advisory (if desired)
5. Coordinate disclosure timing with you

---

## Supported Versions

| Version | Status | Support Until | Security Updates |
|---------|--------|---------------|------------------|
| 0.1.x   | Active | TBD           | Yes              |
| 0.0.x   | EOL    | 2025-11-02    | No               |

**Current Version:** 0.1.1 (Released 2025-11-07)

---

## Security Considerations

### For Users

#### API Key Protection

- **Never commit API keys** to version control
- Use environment variables: `export CLAUDE_API_KEY="sk-ant-..."`
- Or use `.env` files (add to `.gitignore`)
- Rotate keys periodically
- Monitor LLM Console for unusual activity

**Secure configuration:**
```bash
# Instead of hardcoding in config.json
export CLAUDE_API_KEY="sk-ant-your-key"

# Reference in config.json
"api_key": "${CLAUDE_API_KEY}"
```

#### Network Security

- **Run with minimal privileges** - Don't run as root
- **Firewall API port (8443)** - Restrict to internal network only
- **Enable TLS/HTTPS** - Use certificates for all traffic
- **Monitor inbound connections** - Alert on suspicious IPs

**Firewall rules:**
```bash
# Allow proxy traffic from internet or based on needs
Allow TCP 8080 from 0.0.0.0/0

# Restrict API to internal only
Allow TCP 8443 from 10.0.0.0/8 only
```

#### Database Security

- **SQLite runs locally** - No external database connections
- **File permissions** - Restrict `data/ifrit.db` to IFRIT user only
- **Backups** - Encrypt database backups

**Secure permissions:**
```bash
chmod 600 data/ifrit.db
chown ifrit:ifrit data/ifrit.db
```

#### Log Security

- **Sensitive data in logs** - Be aware of what's logged
- **Enable anonymization** - Always use `anonymization.enabled: true`
- **Restrict log access** - Only authorized users should read logs
- **Log rotation** - Configure log rotation to prevent disk filling

**Secure logging:**
```bash
# Restrict log file access
chmod 640 logs/ifrit.log
chown ifrit:syslog logs/ifrit.log
```

#### TLS Configuration

- **Use strong certificates** - 2048-bit RSA minimum, 4096-bit recommended
- **Enable HTTPS** - Set `tls.enabled: true`
- **Use modern ciphers** - Disable old TLS versions
- **Certificate renewal** - Automate with Let's Encrypt or similar

**Secure TLS:**
```json
{
  "server": {
    "tls": {
      "enabled": true,
      "cert_file": "/etc/ifrit/certs/server.crt",
      "key_file": "/etc/ifrit/certs/server.key"
    }
  }
}
```

#### Update Strategy

- **Subscribe to releases** - Watch GitHub for security updates
- **Test updates in staging** - Never deploy directly to production
- **Keep dependencies updated** - Run `go mod update` regularly
- **Security scanning** - Use tools like `go list -json -m all | nancy sleuth`

---

### For Developers

#### Code Security

- **Never commit secrets** - No API keys, passwords, or tokens
- **Use parameterized queries** - All database queries use prepared statements
- **Input validation** - Validate all user inputs and API parameters
- **Output encoding** - Encode data before returning to prevent injection
- **Dependency scanning** - Check for known vulnerabilities in dependencies

**Secure coding:**
```go
// Bad 
query := "SELECT * FROM users WHERE id = " + userID

// Good
query := "SELECT * FROM users WHERE id = ?"
db.Query(query, userID)
```

#### Dependency Management

- **Vendor dependencies** - Use `go mod vendor`
- **Security scanning** - Run `go list -json -m all | nancy sleuth`
- **Regular updates** - Keep Go and dependencies current
- **Audit trail** - Track all dependency changes

**Check for vulnerabilities:**
```bash
go list -json -m all | nancy sleuth
```

#### Data Handling

- **Minimize data collection** - Only collect what's necessary
- **Anonymization** - Redact sensitive data before external APIs
- **Encryption** - Encrypt sensitive data at rest
- **Access control** - Limit who can access sensitive data
- **Audit logging** - Log all access to sensitive data

#### Testing Security

- **Unit tests** - Test security-critical functions
- **Integration tests** - Test entire detection pipeline
- **Penetration testing** - Regular security assessments
- **Fuzzing** - Test with malformed inputs
- **Code review** - Security-focused peer review

---

## Data Privacy & Compliance

### What Data We Collect

**IFRIT collects:**
- HTTP requests (method, path, headers, body)
- Attack signatures and patterns
- Attacker IP addresses and profiles (PLUS whatever intelligence collected through deception payloads)
- Attack timestamps and metadata

**IFRIT does NOT collect:**
- User personal information (unless in attack payload - and it totally customizable)
- Authentication credentials (anonymized before external APIs)
- Financial data (redacted before external APIs)
- Session data (anonymized before external APIs)

### Data Retention

- **Attack logs** - Stored indefinitely in SQLite database
- **Learned patterns** - Stored indefinitely (can be deleted manually)
- **Original requests** - Only if `store_original: true` (not recommended)
- **Commercial LLMs API** - As of this version only supports Anthropic, which retains data per their privacy policy

**Data retention configuration:**
```json
{
  "anonymization": {
    "store_original": false
  }
}
```

### Privacy Compliance

#### GDPR (General Data Protection Regulation)

 **Compliant:**
- Personal data anonymized before external APIs
- No tracking of individuals
- Data minimization (only necessary data collected)
- User can request data deletion

 **Caution:**
- Original request data stored if `store_original: true`
- Should use `store_original: false` for GDPR compliance

#### HIPAA (Health Insurance Portability and Accountability Act)

 **Compliant:**
- PHI anonymized before external APIs
- Encryption at rest (use OS-level encryption)
- Access controls via file permissions
- Audit logging of all data access

#### PCI-DSS (Payment Card Industry Data Security Standard)

 **Compliant:**
- Credit card data redacted before external APIs (via anonymization feature)
- No storage of full card numbers
- TLS encryption for data in transit
- Access controls and audit logging

#### CCPA (California Consumer Privacy Act)

 **Compliant:**
- Minimal personal data collection
- Data deletion capability (manual via CLI)
- Transparency about data collection
- No selling or sharing of personal data

### Anonymization Verification

Test that sensitive data is anonymized:
```bash
# Start IFRIT with debug logging
"system": { "debug": true }

# Send request with sensitive data
curl -X POST http://localhost:8080/api/test \
  -H "Authorization: Bearer sk-test-token" \
  -H "Cookie: session=abc123" \
  -d '{"email": "user@example.com"}'

# Check logs - should see redacted data:
# [ANON] Redacting sensitive header: Authorization
# [ANON] Redacting sensitive header: Cookie
# [ANON] Redacting pattern 'email': 1 occurrences
```

---

## Vulnerability Management

### Reporting Process

1. **Send details to ifrit@0t.systems**
   - Do not create public GitHub issue
   - Do not post on social media
   - Do not share in forums

2. **We will acknowledge within 24-36 hours**
   - Confirm receipt
   - Ask any clarifying questions
   - Provide timeline estimate

3. **Development phase (1-2 weeks typical)**
   - Reproduce vulnerability
   - Develop fix
   - Write tests
   - Create security advisory

4. **Coordination phase when applicable**
   - Send you draft advisory
   - Confirm fix works
   - Agree on disclosure date

5. **Release phase**
   - Release fixed version
   - Publish security advisory
   - Credit researcher (if desired)

### Historical Advisories

None currently. IFRIT is under active development as MVP.

---

## Security Testing

### Recommended Tools

**Vulnerability scanning:**
```bash
# Go vulnerability scanning
go list -json -m all | nancy sleuth

# OWASP dependency-check
dependency-check --project IFRIT --scan .

# Trivy (container scanning)
trivy image ifrit:latest
```

**Code security:**
```bash
# Go security scanner
go get github.com/securego/gosec/v2/cmd/gosec
gosec ./...

# Static analysis
go vet ./...
```

**Network security:**
```bash
# Port scanning
nmap localhost

# SSL/TLS testing
testssl.sh https://localhost:8443

# Load testing
ab -n 1000 -c 100 http://localhost:8080/
```

### Self-Assessment Checklist

- [ ] API keys stored in environment variables only
- [ ] Database permissions set to 600
- [ ] TLS/HTTPS enabled for all traffic
- [ ] Firewall restricts API port to internal IPs
- [ ] Anonymization enabled for external LLM calls
- [ ] Debug logging disabled in production
- [ ] Regular dependency updates scheduled
- [ ] Security scanning in CI/CD pipeline
- [ ] Log files have restricted access
- [ ] Backups are encrypted

---

## Known Limitations

### Security Limitations

1. **Single point of failure** - IFRIT does not replace network IDS/IPS
2. **Zero-day exploits** - Novel attacks require LLM analysis (~3s delay)
3. **Compromised credentials** - Valid credentials bypass honeypot layer
4. **LLM misclassification** - Although very unlikely, LLM can misidentify some attacks
5. **SQLite limitations** - No built-in replication or clustering

### Mitigation Strategies

**For single point of failure:**
- Use load balancer for redundancy
- Run multiple IFRIT instances
- Keep upstream IDS/IPS active

**For zero-day exploits:**
- Use conservative default responses
- Monitor logs for suspicious patterns
- Keep LLM model updated

**For compromised credentials:**
- Use multi-factor authentication
- Monitor for unusual account behavior
- Implement rate limiting
- Use credential rotation

**For LLM misclassification:**
- Use allowlist mode for critical paths
- Adjust confidence thresholds
- Override with manual patterns

---

## Bug Bounty

We currently do not have a formal bug bounty program, but we greatly appreciate security research and responsible disclosure.

**We will:**
- Acknowledge all security reports
- Fix confirmed vulnerabilities
- Credit researchers in advisories
- Consider future bounty program as project grows

---

## Security Roadmap

**Planned improvements:**
- [ ] Encrypted database at rest
- [ ] Role-based access control (RBAC)
- [ ] Advanced SIEM integrations
- [ ] Machine learning for false positive reduction
- [ ] Multi-instance clustering support
- [ ] Hardware security module (HSM) integration
- [ ] Formal security audit
- [ ] Bug bounty program

---

## Third-Party Security

### Anthropic Claude API

IFRIT uses Anthropic's Claude API for LLM analysis.

**Security considerations:**
- Sensitive data is anonymized before sending
- Anthropic has SOC 2 Type II certification
- Data is subject to Anthropic's privacy policy
- Review Anthropic's security before deploying

**Link:** https://www.anthropic.com/security

### SQLite

IFRIT uses SQLite for local data storage.

**Security considerations:**
- SQLite is file-based (protect with OS permissions)
- No built-in encryption (use OS-level encryption)
- Restrict database file to IFRIT user only

**Link:** https://www.sqlite.org/

### Go Standard Library

IFRIT is written in Go.

**Security considerations:**
- Uses Go's built-in crypto libraries
- Regular security updates from Go team
- Actively maintained and audited

**Link:** https://golang.org/

---

## Contact & Support

**Security Issues:**
- Email: ifrit@0t.systems
- Response time: 24-36 hours
- Do not use public channels for security issues

**General Support:**
- Email: ifrit@0t.systems

---

## License

This security policy is part of IFRIT Proxy under Apache License 2.0.

---

**Last Updated:** November 7, 2025  
**Version:** 0.1.1
