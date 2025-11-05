# IFRIT Proxy - Installation & Setup Guide

## Quick Start (5 minutes)

### Prerequisites
- Go 1.21+
- SQLite3
- Claude or GPT API key

### 1. Clone Repository
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
```

### 2. Configure
```bash
cp config/default.json.example config/default.json
```

Edit `config/default.json`:
```json
{
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
curl http://localhost:8080/.env
ifrit-cli exception list
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

#### Install to System Path (Optional)
```bash
sudo mv ifrit /usr/local/bin/
sudo mv ifrit-cli /usr/local/bin/
```

---

### Linux (Ubuntu/Debian)

#### Install Go
```bash
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

#### Install Dependencies
```bash
sudo apt-get install sqlite3
```

#### Clone & Build
```bash
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit
go build -o ifrit ./cmd/ifrit
go build -o ifrit-cli ./cmd/ifrit-cli
```

#### System Service (Optional)

Create `/etc/systemd/system/ifrit.service`:
```ini
[Unit]
Description=IFRIT Proxy - Intelligent Threat Detection
After=network.target

[Service]
Type=simple
User=ifrit
WorkingDirectory=/opt/ifrit
ExecStart=/usr/local/bin/ifrit
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ifrit
sudo systemctl start ifrit
sudo systemctl status ifrit
```

---

### Docker

#### Build Image
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
  -e IFRIT_CONFIG=/app/config/default.json \
  --name ifrit \
  ifrit:latest
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
      IFRIT_CONFIG: /app/config/default.json
    restart: unless-stopped
```

Run:
```bash
docker-compose up -d
```

---

## Configuration

### config/default.json Structure

#### Minimal Configuration (Onboarding)
```json
{
  "server": {
    "listen_addr": ":8080",
    "proxy_target": "http://localhost:80"
  },
  "database": {
    "path": "./data/ifrit.db"
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "sk-ant-...",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "execution_mode": {
    "mode": "onboarding"
  }
}
```

#### Production Configuration (Normal Mode)
```json
{
  "server": {
    "listen_addr": "0.0.0.0:8080",
    "proxy_target": "http://app-backend:3000",
    "api_listen_addr": "127.0.0.1:8443",
    "tls": {
      "enabled": true,
      "cert_file": "/etc/ifrit/certs/server.crt",
      "key_file": "/etc/ifrit/certs/server.key"
    }
  },
  "database": {
    "type": "sqlite",
    "path": "./data/ifrit.db" 
  },
  "llm": {
    "primary": "claude",
    "claude": {
      "api_key": "${CLAUDE_API_KEY}",
      "model": "claude-3-5-haiku-20241022"
    }
  },
  "detection": {
    "enable_local_rules": true,
    "enable_llm": true,
    "llm_only_on": ["POST", "PUT", "DELETE"],
    "whitelist_ips": [],
    "whitelist_paths": ["/health", "/metrics"]
  },
  "execution_mode": {
    "mode": "normal"
  },
  "system": {
    "log_dir": "/var/log/ifrit",
    "log_level": "info"
  }
}
```

### Environment Variables

Override config with environment variables:
```bash
export IFRIT_LISTEN=":9000"
export IFRIT_TARGET="http://backend:8080"
export IFRIT_MODE="normal"
export CLAUDE_API_KEY="sk-ant-..."
```

---

## Networking Setup

### Single Machine (Testing)
```
Client → localhost:8080 (IFRIT Proxy) → localhost:80 (Backend App)
```

### Behind Load Balancer (Production)
```
Internet → Load Balancer → IFRIT Proxy (port 8080) → Backend App
```

### High Availability
```
Internet → Load Balancer
            ├→ IFRIT Proxy 1 (shared database)
            ├→ IFRIT Proxy 2 (shared database)
            └→ IFRIT Proxy 3 (shared database)
            ↓
         Shared Database (As of the current open source version with sqlite, NFS or network mounted)
```

---

## Firewall Rules

### Inbound (From Internet)
```
Allow TCP 8080 from 0.0.0.0/0  (Proxy)
Allow TCP 8443 from <internal> (API, restrict to internal network)
```

### Outbound
```
Allow TCP 443 to api.anthropic.com  (Claude API)
Allow TCP 443 to api.openai.com     (GPT API, if using)
```

---

## Verification

### Check Installation
```bash
./ifrit --version
./ifrit-cli --help
```

### Test Proxy
```bash
# Start IFRIT
./ifrit

# In another terminal:
curl -X GET http://localhost:8080/.env

# Check exceptions were added
./ifrit-cli exception list
```

### Test CLI
```bash
# List patterns
ifrit-cli pattern list

# Show statistics
ifrit-cli db stats

# View exceptions
ifrit-cli exception list
```

### Logs

Check logs for any issues:
```bash
tail -f logs/ifrit.log
```

---

## Troubleshooting

### Port Already in Use
```bash
# Change listen port in config.json
"listen_addr": ":9000"

# Or kill existing process
lsof -i :8080
kill -9 <PID>
```

### Database Locked
```bash
# SQLite connection issue
# Delete and recreate:
rm data/ifrit.db
./ifrit
```

### API Key Invalid
```
Error: "API key is invalid"

# Check:
1. API key format (starts with sk-ant- for Claude)
2. API key is active in Anthropic console
3. No extra whitespace in config
```

### LLM Not Responding
```
Error: "dial tcp: connection timeout"

# Check:
1. Internet connection
2. Firewall allows outbound 443
3. Claude/GPT API is accessible
4. Enable log level DEBUG to see full error
```

---

## Next Steps

1. **Read FEATURES.md** - Understand all capabilities
2. **Configure for your environment** - Adjust proxy_target, whitelist_paths
3. **Start in Onboarding Mode** - Zero false positives guarantee
4. **Monitor for 1 week** - Let IFRIT learn your traffic
5. **Switch to Normal Mode** - Full detection enabled

---

## Getting Help

- **Documentation:** See docs/ directory
- **GitHub Issues:** github.com/0tSystemsPublicRepos/ifrit/issues
- **Email:** security@0t.systems

---

Last edit: November 5, 2025

