# IFRIT Proxy

Intelligent LLM-Based Threat Deception and Detection Platform

IFRIT is an intelligent reverse proxy that acts as a deception layer between attackers and production infrastructure. It intercepts malicious requests, analyzes them using Claude or GPT, and serves fabricated responses designed to confuse attackers while gathering threat intelligence.

## Overview

IFRIT operates as an intelligent middleware between the internet and production applications. When a request arrives, IFRIT makes a real-time decision: pass it through to the legitimate backend or serve a fabricated honeypot response.

The decision-making process follows a four-step workflow. First, IFRIT checks if the request matches known exceptions (whitelisted IPs, critical paths). Legitimate traffic passes through unchanged.

Second, for unknown requests, IFRIT queries its local SQLite database for previously learned attack patterns. If the request signature matches a known malicious pattern, IFRIT generates a realistic fake response and returns it to the attacker.

Third, if the request is unknown and learning is enabled, IFRIT sends a sanitized version of the request to Claude or GPT with context about the application stack. The LLM analyzes whether the request represents an attack.

Fourth, if the LLM confirms an attack, IFRIT requests a fabricated payload appropriate to the attack type. For reconnaissance probing .env files, it generates fake credentials. For SQL injection attempts, it returns fake database records. This pattern is saved to the database for future reference.

Throughout this process, data anonymization occurs. Sensitive headers (Authorization, Cookie) are redacted before sending to LLMs. User emails and passwords are tokenized. Attack patterns like path traversal and SQL injection syntax are preserved because they are precisely what the LLM needs to detect threats.

All requests, whether legitimate or malicious, pass through but generate different responses. Legitimate users access the real backend. Attackers receive honeypot responses. The organization tracks every probe, learns from it, and profiles the attacker.

## Quick Start

### Installation

Download the latest release for your platform from the GitHub releases page.
```bash
# Linux (x86_64)
wget https://github.com/0tSystemsPublicRepos/ifrit/releases/download/v1.0.0/ifrit-linux-amd64
chmod +x ifrit-linux-amd64
./ifrit-linux-amd64

# macOS (Apple Silicon)
wget https://github.com/0tSystemsPublicRepos/ifrit/releases/download/v1.0.0/ifrit-darwin-arm64
chmod +x ifrit-darwin-arm64
./ifrit-darwin-arm64

# Build from source
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
./ifrit
```

### Configuration

Create a YAML configuration file specifying your backend address and LLM provider credentials:
```yaml
server:
  listen_addr: ":8080"
  proxy_target: "http://localhost:3000"
  api_listen_addr: ":8443"

database:
  type: "sqlite"
  path: "data/ifrit.db"

llm:
  primary: "claude"
  claude:
    api_key: "YOUR_CLAUDE_API_KEY"
    model: "claude-3-sonnet"
```

No additional dependencies or infrastructure changes are required. IFRIT works immediately with existing applications.

### Dashboard

The web dashboard is accessible at http://localhost:8080/dashboard after IFRIT starts. It displays real-time attack feeds, attacker profiles, detected patterns, and system health metrics.

## Installation Video

[Terminal installation and setup demonstration]

## Key Capabilities

IFRIT provides real-time threat detection without requiring infrastructure changes. It deploys as a reverse proxy in front of existing applications, requiring only network routing modifications. No changes to backend code are necessary.

The platform learns attack patterns continuously. Each request analyzed by an LLM becomes a learned pattern that improves detection speed and reduces costs. After the first week, most requests are answered from the local database without querying expensive LLM APIs.

IFRIT builds profiles of attackers based on their behavior. It tracks unique source IPs, the attacks they attempt, the frequency of their probes, and whether they return for follow-up attacks after receiving fake data. This creates a timeline of attacker progression and sophistication estimation.

Data privacy is built in. Sensitive data is anonymized before being sent to commercial LLMs. Organizations can control exactly what data leaves their infrastructure. No credentials, personal information, or proprietary details need to reach external APIs.

The platform generates compliance evidence. Attack logs provide auditable proof of active threat detection. Honeypot responses with timestamps demonstrate rapid response to malicious activity. Attacker profiles show security-conscious infrastructure hardening.

IFRIT integrates with existing security tools. It exports data in standard formats, sends alerts to Wazuh or SIEM systems, and provides REST APIs for custom integrations. It works alongside WAFs, IDS systems, and threat intelligence platforms.

## How IFRIT Works

IFRIT operates as a four-stage detection pipeline that processes each incoming request:

Stage one checks if the request matches known exceptions. Whitelisted IPs and critical paths bypass honeypot responses and pass through to the backend unchanged.

Stage two queries the local SQLite database for previously learned attack patterns. If the request signature matches a known malicious pattern, IFRIT generates an appropriate honeypot response instantly without external API calls.

Stage three evaluates local rules based on configuration. Standard attack signatures like SQL injection attempts, path traversal, and common probes are matched against patterns.

Stage four, if the request remains unclassified and learning is enabled, sends a sanitized request to Claude or GPT for analysis. The LLM determines if the request is malicious and recommends an appropriate response.

The detection pipeline is ordered for efficiency. Most legitimate traffic exits at stage one. Known attacks are caught at stage two or three. Only novel requests reach the expensive LLM analysis at stage four. This reduces costs dramatically while maintaining comprehensive threat detection.

[Architecture Diagram]

## CLI Management Tool

IFRIT includes a comprehensive command-line interface for managing all database entities. View, add, remove, and modify entities directly from the terminal without manual database access.

Attack management displays recent attacks, views details, shows statistics, and filters by IP address or attack type. Pattern management lists all learned attack signatures and allows creation of new patterns.

Attacker profile management displays profiles for each detected source IP, showing total requests, attack types, first seen and last seen timestamps, and whether the attacker returned after receiving honeypot data.

Exception management creates whitelisted rules for IPs and paths that should bypass honeypot detection. Database operations provide statistics, schema information, and maintenance functions.
```bash
ifrit-cli attack list
ifrit-cli attack stats
ifrit-cli pattern list
ifrit-cli attacker view 1
ifrit-cli exception add 10.0.0.1 /health
ifrit-cli db stats
```

See the CLI documentation for the complete command reference.

## Architecture

IFRIT consists of four primary components working in concert: the reverse proxy engine, the detection engine, the learning engine, and the data layer.

The reverse proxy engine handles all network traffic. It listens on a configured port (typically 8080/8443), accepts incoming HTTP/HTTPS requests, and either forwards them to backend applications or returns honeypot responses. This component is written in Go for performance and operates at near-native speeds.

The detection engine makes the critical pass-through-or-honeypot decision. It queries the local database for known patterns, evaluates local rules based on configuration, and when necessary, contacts the LLM API for advanced analysis. This engine applies data anonymization before sending requests to external services.

The learning engine captures new threats and stores them for future reference. When an LLM confirms an attack, the engine stores the attack signature, classification, confidence level, and an appropriate fabricated response template. It tracks how many times each pattern appears and whether attackers return after receiving fake data.

The data layer manages SQLite persistence. It stores exceptions (whitelisted IPs/paths), learned attack patterns, individual attack instances, attacker profiles, and LLM analysis results. The schema is optimized for fast pattern matching and detailed threat analysis.

Additionally, IFRIT includes a read-only web dashboard that queries the data layer via a secured REST API. The dashboard shows attack feeds, attacker profiles, pattern statistics, and system health. Authentication uses token-based validation against a file-based key store.

[System Architecture Diagram]

## Configuration

IFRIT is configured entirely through YAML files. No code changes are required to modify behavior. Configuration covers proxy targets and listening addresses, LLM provider selection (Claude or GPT), database paths, alert thresholds, anonymization rules, and honeypot payload templates.

Anonymization rules are highly configurable. Administrators specify which headers are always redacted (Authorization, Cookie), which patterns warrant tokenization (email addresses, user IDs), and which patterns must never be redacted because they represent the attack itself (SQL injection syntax, path traversal strings).

Payload templates can be customized by attack type. When reconnaissance probes for .env files, a specific payload template is used. SQL injection attempts trigger a different payload. This allows organizations to craft realistic responses that match their actual infrastructure patterns.

Exception rules allow legitimate traffic to bypass the honeypot system entirely. Internal monitoring systems, security scanners, and critical APIs can be whitelisted by IP address or URL pattern.

## Threat Intelligence Output

IFRIT generates three primary intelligence outputs: immediate threat alerts, pattern databases, and attacker profiles.

Immediate alerts occur when sophisticated attacks are detected. These can be sent to Wazuh, SIEM systems, Slack, or email. Alert rules are configurable by attack type, severity, source geography, or targeted endpoint.

Pattern databases grow over time. Each attack pattern stored is an investment in future detection speed and cost reduction. After several weeks of operation, most common attacks are detected instantly from the local database without querying LLMs.

Attacker profiles accumulate intelligence about each source IP address. IFRIT tracks first and last seen timestamps, total request counts, successful probe outcomes, attack types attempted, and whether the attacker returned after receiving fake data. This creates a timeline and sophistication profile for each threat actor.

## Deployment

IFRIT is deployed as a standalone Go binary or Docker container. It sits between the internet and production applications, typically replacing the direct IP in DNS or being placed behind a load balancer.

For small deployments, a single IFRIT instance handles all traffic. For high-traffic environments, multiple instances share a centralized SQLite database or commercial database backend (available in commercial edition).

The tool requires minimal configuration. A YAML file specifies the backend application address, LLM provider credentials, and anonymization rules. No external dependencies exist beyond Go runtime libraries.

## Use Cases

Security teams use IFRIT to understand their threat landscape. By analyzing attacker behavior, they discover which attack vectors are most common, what tools are being used, and whether sophisticated actors are targeting their infrastructure.

Incident responders use IFRIT data to correlate attacks. If an attacker probes multiple targets in a network, IFRIT helps identify the same actor across different systems.

Compliance teams use IFRIT evidence to satisfy audit requirements. The detailed logs show active threat detection and rapid response, strengthening security posture documentation.

Threat intelligence analysts use IFRIT patterns to understand emerging attack techniques. Over months of operation, a detailed dataset of reconnaissance patterns, exploitation attempts, and post-exploitation probes accumulates.

## Limitations

IFRIT is most effective against reconnaissance and initial exploitation phases. Once an attacker gains valid credentials or performs a zero-day exploit, the deception layer cannot protect against them.

The system relies on accurate threat classification from LLMs. Misclassification can result in legitimate requests being honeypotted or malicious requests passing through. Conservative defaults and tuning are required.

IFRIT does not replace network intrusion detection or endpoint protection. It is a complementary tool that adds an intelligent deception layer to existing security infrastructure.

The threat intelligence generated is most valuable when aggregated across multiple instances and organizations. A single organization learns from its own attackers, but broader patterns require coordination with the security community.

## Features

Open Source Edition includes reverse proxy with HTTPS/TLS support, real-time threat detection with Claude or GPT, self-learning attack patterns with SQLite database, data anonymization before external API calls, read-only web dashboard with token authentication, REST API for integrations, full YAML configuration, and Docker and systemd deployment.

Commercial Edition includes everything in the open source edition plus multi-database support (MySQL, PostgreSQL), advanced analytics and reporting, multiple user management with RBAC, email and SMS alerts via Twilio, Wazuh and SIEM integrations, compliance reporting (GDPR, HIPAA, PCI-DSS), database encryption at rest, key rotation and HSM support, dedicated support and SLAs, SaaS or self-hosted options, and white-label capabilities.

For commercial licensing, contact sales@0t.systems

## Getting Started

The open source edition is available on GitHub. Deployment takes minutes: download the binary, create a configuration file specifying your backend address and LLM credentials, and start the proxy. The read-only dashboard is immediately accessible for monitoring.

The commercial edition adds multi-database support, advanced analytics, comprehensive SIEM integrations, compliance reporting, and dedicated support.

For organizations prioritizing privacy and control, the open source edition provides a complete threat detection platform. For enterprises requiring full integration with existing security infrastructure, the commercial edition provides additional capabilities and support.

## Contributing

IFRIT is developed openly on GitHub under the Apache License 2.0. Community contributions are welcome, including new LLM providers, SIEM integrations, payload templates, and detection improvements.

See CONTRIBUTING.md for guidelines on how to contribute code, documentation, or threat patterns.

Threat patterns discovered by the community are shared through the project repository, continuously improving detection capabilities for all users.

## Documentation

Complete documentation is available in the docs directory: INSTALLATION.md for setup instructions, ARCHITECTURE.md for technical deep dives, CONFIGURATION.md for all configuration options, CLI.md for command reference, and FEATURES.md for open source vs commercial comparison.

## License

IFRIT Proxy is licensed under the Apache License 2.0. See LICENSE file for details.

## Support

For security vulnerabilities, email security@0t.systems

For issues and feature requests, use GitHub Issues

For commercial inquiries, contact sales@0t.systems

## Links

Website: https://ifrit.0t.systems
GitHub: https://github.com/0tSystemsPublicRepos/ifrit
Releases: https://github.com/0tSystemsPublicRepos/ifrit/releases
Email: security@0t.systems

