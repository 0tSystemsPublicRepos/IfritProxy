-- Threat Intelligence Table
-- Stores enriched data from AbuseIPDB, VirusTotal, IPinfo

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    source_ip TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,  -- 0-100 score
    abuseipdb_score REAL,          -- 0-100 from AbuseIPDB
    abuseipdb_reports INTEGER,     -- Number of reports
    abuseipdb_last_reported TEXT,  -- ISO timestamp
    virustotal_malicious INTEGER,  -- Number of malicious detections
    virustotal_suspicious INTEGER, -- Number of suspicious detections
    virustotal_harmless INTEGER,   -- Number of harmless detections
    virustotal_undetected INTEGER, -- Number of undetected
    ipinfo_country TEXT,           -- Country code
    ipinfo_org TEXT,               -- Organization/ISP
    ipinfo_privacy_type TEXT,      -- vpn, proxy, hosting, tor, etc.
    is_vpn BOOLEAN DEFAULT 0,
    is_proxy BOOLEAN DEFAULT 0,
    is_hosting BOOLEAN DEFAULT 0,
    is_tor BOOLEAN DEFAULT 0,
    threat_level TEXT,             -- LOW, MEDIUM, HIGH, CRITICAL
    enriched_at TIMESTAMP,         -- When enrichment completed
    cached_until TIMESTAMP,        -- When cache expires (24h from enriched_at)
    last_attack_at TIMESTAMP,      -- Last time this IP attacked
    total_attacks INTEGER DEFAULT 0, -- Count of attacks from this IP
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(app_id, source_ip),
    FOREIGN KEY(app_id) REFERENCES attacker_profiles(app_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intelligence(app_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_threat_risk_score ON threat_intelligence(app_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threat_cached_until ON threat_intelligence(cached_until);
CREATE INDEX IF NOT EXISTS idx_threat_updated ON threat_intelligence(updated_at DESC);
