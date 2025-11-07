# IFRIT Proxy - Installation & Setup Guide

**Version:** 0.1.1  
**Last Updated:** November 7, 2025

---

## Quick Start (5 minutes)

### Prerequisites
- Go 1.21+
- SQLite3
- Claude API key (from Anthropic)

### 1. Clone Repository
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
```

### 2. Configure
```bash
cp config/default.json.example config/default.json
nano config/default.json
```

Add your Claude API key:
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
PS: also make sure ifrit-cli can access the sqlite.db file!


### 4. Run
```bash
./ifrit
```

Output:
```
..
..
Configuration loaded
Database: ./data/ifrit.db (type: sqlite)
Proxy target: http://localhost:80
LLM Provider: claude

✓ Database initialized
✓ LLM Manager initialized (primary: claude)
✓ Anonymization engine initialized (strategy: hybrid)
✓ Detection engine initialized
  Mode: detection
✓ Payload manager initialized
✓ Execution mode: detection

Starting API server on :8443
Starting proxy server on :8080
..
..

```

### 5. Test
```bash
# Test attack detection
curl http://localhost:8080/?q=<script>alert(1)</script>

# Check CLI
./ifrit-cli exception list
```

---

## Detailed Installation

### macOS

#### Install Go
```bash
brew install go@1.21
```

#### Install Dependencies
```bash
brew install sqlite3
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### Run Locally
```bash
./ifrit
```

#### Optional: Install to System Path
```bash
sudo mv ifrit /usr/local/bin/
sudo mv ifrit-cli /usr/local/bin/

# Then run from anywhere
ifrit
ifrit-cli pattern list
```

---

### Linux (Ubuntu/Debian)

#### Install Go
```bash
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Make permanent
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Install Dependencies
```bash
sudo apt-get update
sudo apt-get install sqlite3
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### Create System User (Recommended)
```bash
sudo useradd -r -s /bin/false ifrit
sudo mkdir -p /opt/ifrit/{data,logs,config}
sudo cp -r . /opt/ifrit/
sudo chown -R ifrit:ifrit /opt/ifrit
```

#### Systemd Service (Optional)

Create `/etc/systemd/system/ifrit.service`:
```ini
[Unit]
Description=IFRIT Proxy - Intelligent Threat Detection
After=network.target
Documentation=https://github.com/0tSystemsPublicRepos/ifrit

[Service]
Type=simple
User=ifrit
Group=ifrit
WorkingDirectory=/opt/ifrit
ExecStart=/opt/ifrit/ifrit
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ifrit
sudo systemctl start ifrit
sudo systemctl status ifrit

# View logs
sudo journalctl -u ifrit -f
```

---

### Linux (RHEL/CentOS/Fedora)

#### Install Go
```bash
sudo dnf install golang
go version
```

#### Install Dependencies
```bash
sudo dnf install sqlite-devel
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### SELinux Considerations (Optional)

If SELinux is enforced:
```bash
sudo semanage fcontext -a -t bin_t "/opt/ifrit/ifrit"
sudo restorecon /opt/ifrit/ifrit
```

---

### Docker

#### Build Image

Create `Dockerfile` (if not included):
```dockerfile
FROM golang:1.21-alpine as builder
WORKDIR /app
COPY . .
RUN go build -o ifrit ./cmd/ifrit
RUN go build -o ifrit-cli ./cmd/ifrit-cli

FROM alpine:latest
RUN apk --no-cache add ca-certificates sqlite
WORKDIR /app
COPY --from=builder /app/ifrit .
COPY --from=builder /app/ifrit-cli .
COPY config/default.json.example config/default.json
EXPOSE 8080 8443
CMD ["./ifrit"]
```

Build:
```bash
docker build -t ifrit:latest .
```

#### Run Container
```bash
docker run -d \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -e IFRIT_PROXY_TARGET="http://backend:3000" \
  --name ifrit \
  ifrit:latest
```

View logs:
```bash
docker logs -f ifrit
```

#### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  ifrit:
    build: .
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      IFRIT_PROXY_TARGET: "http://backend:3000"
      IFRIT_MODE: "detection"
    restart: unless-stopped
    networks:
      - ifrit-network

  backend:
    image: your-app:latest
    networks:
      - ifrit-network
    expose:
      - "3000"

networks:
  ifrit-network:
    driver: bridge
```

Run:
```bash
docker-compose up -d
docker-compose logs -f ifrit
```

Stop:
```bash
docker-compose down
```

---

## Configuration

### File Location
```
config/default.json
```

### Minimal Configuration (Onboarding)
```json
{
  "server": {
    "listen_addr": ":8080",
    "proxy_target": "http://localhost:80"
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "execution_mode": {
    "mode": "onboarding"
  }
}
```

### Production Configuration (Normal Mode)
```json
{
  "server": {
    "listen_addr": "0.0.0.0:8080",
    "api_listen_addr": "127.0.0.1:8443",
    "proxy_target": "http://app-backend:3000",
    "multi_app_mode": false,
    "tls": {
      "enabled": false
    }
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-YOUR-KEY-HERE",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "detection": {
    "mode": "detection",
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "skip_body_check_on_whitelist": false,
    "whitelist_ips": [],
    "whitelist_paths": ["/health", "/metrics"]
  },
  "execution_mode": {
    "mode": "normal"
  },
  "anonymization": {
    "enabled": true,
    "strategy": "hybrid",
    "store_original": false,
    "sensitive_headers": [
      "Authorization",
      "Cookie",
      "X-API-Key"
    ]
  },
  "payload_management": {
    "generate_dynamic_payload": true,
    "dynamic_llm_cache_ttl": 86400
  },
  "system": {
    "log_dir": "./logs",
    "log_level": "info",
    "debug": false
  }
}
```

### Configuration Parameters

#### Server Section
```json
{
  "server": {
    "listen_addr": ":8080",           // Proxy listener
    "api_listen_addr": ":8443",       // API listener
    "proxy_target": "http://...",     // Backend target
    "multi_app_mode": false,          // Multi-app support
    "app_id_header": "X-App-ID",      // App ID header
    "app_id_fallback": "default"      // Default app ID
  }
}
```

#### Detection Section
```json
{
  "detection": {
    "mode": "detection",              // detection or allowlist
    "enable_local_rules": true,       // Stage 1
    "enable_llm": true,               // Stage 3
    "llm_only_on": ["POST", "PUT"],   // LLM for these methods
    "skip_body_check_on_whitelist": false,  // NEW in 0.1.1
    "whitelist_ips": [],              // Whitelisted IPs
    "whitelist_paths": []             // Whitelisted paths
  }
}
```

#### Execution Mode Section
```json
{
  "execution_mode": {
    "mode": "onboarding",             // onboarding, learning, or normal
    "onboarding_auto_whitelist": true,
    "onboarding_duration_days": 7,
    "onboarding_log_file": "./logs/onboarding.log"
  }
}
```

#### Anonymization Section
```json
{
  "anonymization": {
    "enabled": true,                  // Enable anonymization
    "strategy": "hybrid",             // hybrid, header-only, or disabled
    "store_original": false,          // Store original data?
    "sensitive_headers": [            // Headers to redact
      "Authorization",
      "Cookie",
      "X-API-Key"
    ]
  }
}
```

#### System Section
```json
{
  "system": {
    "home_dir": "./",
    "log_dir": "./logs",
    "log_level": "info",              // info, debug, warn, error
    "debug": false                    // Enable debug logging
  }
}
```

### Environment Variables

Override config with environment variables (optional):
```bash
export IFRIT_LISTEN=":9000"
export IFRIT_TARGET="http://backend:8080"
export IFRIT_MODE="normal"
export IFRIT_DEBUG="false"
export CLAUDE_API_KEY="sk-ant-..."
```

---

## Networking Setup

### Single Machine (Development)
```
┌─────────┐
│ Client  │
└────┬────┘
     │ :8080
     ▼
┌──────────────┐
│ IFRIT Proxy  │
└-────┬────────┘
      │ http://localhost:3000
      ▼
┌──────────────┐
│ Backend App  │
└──────────────┘
```

### Behind Load Balancer (Production) - NOT EXTENSIVELY TESTED YET
```
┌─────────┐
│ Internet│
└────┬────┘
     │ :443 (HTTPS)
     ▼
┌──────────────────┐
│ Load Balancer    │
└─-───┬────────────┘
      │
      ├─── IFRIT 1 :8080
      ├─── IFRIT 2 :8080
      └─── IFRIT 3 :8080
          │
          ▼
     ┌──────────────┐
     │ Backend App  │
     └──────────────┘
```

### High Availability (Multi-Instance) - NOT EXTENSIVELY TESTED YET
```
Multiple IFRIT instances sharing database
(requires network-mounted SQLite or PostgreSQL)

┌─────────┐
│ Load    │
│Balancer │
└────┬────┘
     │
     ├─── IFRIT 1 ──┐
     ├─── IFRIT 2 ──┼─── Shared DB (NFS/Network)
     └─── IFRIT 3 ──┘
```

---

## Firewall Configuration

### Inbound Rules
```bash
# Allow proxy traffic from internet
Allow TCP 8080 from 0.0.0.0/0

# Restrict API to internal network only
Allow TCP 8443 from 10.0.0.0/8
Allow TCP 8443 from 192.168.0.0/16
```

### Outbound Rules
```bash
# Allow outbound to Claude API
Allow TCP 443 to api.anthropic.com

# Allow outbound to OpenAI API (if using GPT)
Allow TCP 443 to api.openai.com

# Allow DNS
Allow UDP 53 to 0.0.0.0/0
```

### UFW (Ubuntu Firewall)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (if remote)
sudo ufw allow 22/tcp

# Allow proxy
sudo ufw allow 8080/tcp

# Allow API from internal only
sudo ufw allow from 10.0.0.0/8 to any port 8443

sudo ufw enable
sudo ufw status
```

---

## Verification

### Check Installation
```bash
# Verify Go installation
go version

# Verify SQLite
sqlite3 --version

# Verify binaries built
ls -la ifrit ifrit-cli
```

### Test Proxy
```bash
# Start IFRIT (if not already running)
./ifrit &

# In another terminal - test attack detection
curl http://localhost:8080/.env

# Check exceptions (should see /health added)
./ifrit-cli exception list

# Kill IFRIT
pkill ifrit
```

### Test CLI
```bash
# List patterns
./ifrit-cli pattern list

# Show statistics
./ifrit-cli db stats

# View exceptions
./ifrit-cli exception list
```

### Check Logs
```bash
# View logs
cat logs/ifrit.log

# Watch logs in real-time
tail -f logs/ifrit.log

# Filter for attacks
grep "ATTACK" logs/ifrit.log

# Filter for errors
grep "ERROR" logs/ifrit.log
```

---

## Troubleshooting

### Port Already in Use

**Error:**
```
listen tcp :8080: bind: address already in use
```

**Solution 1: Change port**
```json
{
  "server": {
    "listen_addr": ":9000"
  }
}
```

**Solution 2: Kill existing process**
```bash
lsof -i :8080
kill -9 <PID>
```

**Solution 3: Check what's using port**
```bash
netstat -tlnp | grep 8080
```

### Database Locked

**Error:**
```
database is locked
```

**Solution:**
```bash
# Delete and recreate database
rm data/ifrit.db

# Restart IFRIT
./ifrit
```

### API Key Invalid

**Error:**
```
Error: "API key is invalid"
```

**Checklist:**
1. API key format: starts with `sk-ant-`
2. API key is active in Anthropic console
3. No extra whitespace in config
4. Correct model name: `claude-3-5-haiku-20241022`

**Test API key:**
```bash
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: sk-ant-YOUR-KEY"
```

### LLM Not Responding

**Error:**
```
dial tcp: connection timeout
```

**Checklist:**
1. Internet connection working
2. Firewall allows outbound 443
3. Claude API is accessible
4. Enable debug logging to see full error

### Build Errors

**Error:**
```
go: no such file or directory
```

**Solution:**
```bash
# Install Go first
brew install go@1.21  # macOS
sudo apt install golang-go  # Ubuntu
```

**Error:**
```
module declarations do not match
```

**Solution:**
```bash
# Update dependencies
go mod tidy
go mod download
```

### Permission Denied

**Error:**
```
permission denied: ./ifrit
```

**Solution:**
```bash
chmod +x ifrit ifrit-cli
```

### Database File Permissions

**Error:**
```
permission denied
```

**Solution:**
```bash
# Fix permissions
chmod 600 data/ifrit.db
chown ifrit:ifrit data/ifrit.db  # If running as ifrit user
```

---

## Upgrading IFRIT

### From 0.1.0 to 0.1.1
```bash
# Stop IFRIT
pkill ifrit

# Pull latest code
git pull origin main

# Rebuild
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli

# Database schema automatically migrates on start
./ifrit

# Verify
./ifrit-cli db stats
```

### Configuration Migration

Configuration format is backward compatible. Existing `config/default.json` will work, but you can add new options:
```json
{
  "detection": {
    "skip_body_check_on_whitelist": false  // NEW in 0.1.1
  },
  "system": {
    "debug": false  // NEW in 0.1.1
  }
}
```

---

## Uninstalling IFRIT

### Remove Binaries
```bash
rm ifrit ifrit-cli
```

### Remove System Service (if installed)
```bash
sudo systemctl stop ifrit
sudo systemctl disable ifrit
sudo rm /etc/systemd/system/ifrit.service
sudo systemctl daemon-reload
```

### Remove Data
```bash
rm -rf data/ logs/ config/
```

### Remove User (if created)
```bash
sudo userdel -r ifrit
```

---

## Next Steps

1. **Read FEATURES.md** - Understand all capabilities
2. **Configure for your environment** - Adjust proxy_target, whitelist_paths
3. **Start in Onboarding Mode** - Zero false positives guarantee
4. **Monitor for 1 week** - Let IFRIT learn your traffic
5. **Switch to Normal Mode** - Full detection enabled

See START_HERE.md for more guidance.

---

## Getting Help

- **Docs:** See docs/ directory
- **Email:** ifrit@0t.systems (Please report any bugs/issues in the documentation if any)

---

**Last Updated:** November 7, 2025  
**Version:** 0.1.1
