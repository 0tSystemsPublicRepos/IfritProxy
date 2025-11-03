# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in IFRIT, please email ifrit@0t.systems with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Do not open public GitHub issues for security vulnerabilities.

## Supported Versions

| Version | Status | Support Until |
|---------|--------|---------------|
| 1.x     | Active | TBD           |
| 0.x     | EOL    | 2025-11-02    |

## Security Considerations

### For Operators

- Always run IFRIT with minimal privileges
- Keep LLM API keys secure (use environment variables)
- Enable HTTPS/TLS for all deployments
- Regularly update to the latest version
- Monitor IFRIT logs for suspicious activity
- Use strong authentication on the dashboard

### For Developers

- Never commit secrets or API keys
- Use parameterized queries to prevent SQL injection
- Validate all user inputs
- Keep dependencies updated
- Run security scans regularly

## Bug Bounty

We currently do not have a formal bug bounty program, but we greatly appreciate security research and responsible disclosure.

## Security Advisories

Security advisories will be published on GitHub Releases with the tag `[SECURITY]`.

