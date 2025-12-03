-- IFRIT Proxy Database Schema v0.3.1
-- Initial database structure

-- Core attack pattern storage
CREATE TABLE IF NOT EXISTS attack_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL,
    attack_signature TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    attack_classification TEXT,
    http_method TEXT,
    path_pattern TEXT,
    payload_template TEXT,
    response_code INTEGER DEFAULT 403,
    times_seen INTEGER DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    claude_confidence REAL DEFAULT 0.0,
    header_pattern TEXT,
    body_pattern TEXT,
    query_pattern TEXT,
    pattern_type TEXT DEFAULT 'exact',
    full_request_pattern TEXT,
    UNIQUE(app_id, attack_signature)
);

-- Individual attack instances
CREATE TABLE IF NOT EXISTS attack_instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    pattern_id INTEGER,
    source_ip TEXT,
    user_agent TEXT,
    requested_path TEXT,
    http_method TEXT,
    returned_honeypot BOOLEAN,
    attacker_accepted BOOLEAN,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(pattern_id) REFERENCES attack_patterns(id)
);

-- Attacker profiling
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    source_ip TEXT NOT NULL,
    total_requests INTEGER DEFAULT 0,
    successful_probes INTEGER DEFAULT 0,
    attack_types TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, source_ip)
);

-- Whitelist exceptions
CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    ip_address TEXT NOT NULL,
    path TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    enabled BOOLEAN DEFAULT 1,
    UNIQUE(app_id, ip_address, path)
);

-- LLM API call tracking
CREATE TABLE IF NOT EXISTS llm_api_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    request_fingerprint TEXT,
    llm_provider TEXT,
    was_attack BOOLEAN,
    attack_type TEXT,
    confidence REAL,
    tokens_used INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- PII anonymization log
CREATE TABLE IF NOT EXISTS anonymization_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_instance_id INTEGER,
    field_type TEXT,
    field_name TEXT,
    redaction_action TEXT,
    original_length INTEGER,
    redacted_value TEXT,
    token_mapping TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(attack_instance_id) REFERENCES attack_instances(id)
);

-- Learning mode
CREATE TABLE IF NOT EXISTS learning_mode_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    source_ip TEXT,
    user_agent TEXT,
    http_method TEXT,
    requested_path TEXT,
    request_body TEXT,
    headers TEXT,
    fingerprint TEXT UNIQUE,
    classification TEXT,
    reviewed BOOLEAN DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Legitimate request cache
CREATE TABLE IF NOT EXISTS legitimate_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    http_method TEXT NOT NULL,
    path TEXT NOT NULL,
    path_signature TEXT,
    body_signature TEXT,
    headers_signature TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hit_count INTEGER DEFAULT 1,
    claude_validated BOOLEAN DEFAULT 1,
    UNIQUE(app_id, path_signature, body_signature, headers_signature)
);

-- Keyword exceptions
CREATE TABLE IF NOT EXISTS keyword_exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    exception_type TEXT NOT NULL,
    keyword TEXT NOT NULL,
    reason TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, exception_type, keyword)
);

-- Attacker interactions (honeypot tracking)
CREATE TABLE IF NOT EXISTS attacker_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    attack_instance_id INTEGER,
    source_ip TEXT,
    interaction_type TEXT,
    interaction_data TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(attack_instance_id) REFERENCES attack_instances(id)
);

-- Authentication & Authorization
CREATE TABLE IF NOT EXISTS api_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    UNIQUE(username)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    token_prefix TEXT,
    app_id TEXT DEFAULT 'default',
    permissions TEXT,
    is_active BOOLEAN DEFAULT 1,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    created_by TEXT,
    FOREIGN KEY(user_id) REFERENCES api_users(id),
    UNIQUE(user_id, token_name)
);

-- Configuration
CREATE TABLE IF NOT EXISTS config_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    data_type TEXT,
    is_sensitive BOOLEAN DEFAULT 0,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT,
    UNIQUE(app_id, category, key)
);

-- Keycloak Integration
CREATE TABLE IF NOT EXISTS keycloak_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    realm TEXT NOT NULL,
    auth_server_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id)
);

CREATE TABLE IF NOT EXISTS keycloak_role_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    keycloak_role TEXT NOT NULL,
    ifrit_permissions TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, keycloak_role)
);

CREATE TABLE IF NOT EXISTS service_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    token_name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    token_prefix TEXT,
    keycloak_service_account_id TEXT,
    permissions TEXT,
    is_active BOOLEAN DEFAULT 1,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    UNIQUE(token_hash)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_attack_instances_source_ip ON attack_instances(source_ip);
CREATE INDEX IF NOT EXISTS idx_attack_instances_pattern_id ON attack_instances(pattern_id);
CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns(attack_type);
CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles(source_ip);
CREATE INDEX IF NOT EXISTS idx_learning_requests_ip ON learning_mode_requests(source_ip);
CREATE INDEX IF NOT EXISTS idx_learning_requests_fingerprint ON learning_mode_requests(fingerprint);
CREATE INDEX IF NOT EXISTS idx_app_attack_type ON attack_patterns(app_id, attack_type);
CREATE INDEX IF NOT EXISTS idx_app_attack_instance ON attack_instances(app_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_app_timestamp ON attack_instances(app_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_app_attacker ON attacker_profiles(app_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_app_exception ON exceptions(app_id, ip_address, path);
CREATE INDEX IF NOT EXISTS idx_app_path_body ON legitimate_requests(app_id, path_signature, body_signature);
CREATE INDEX IF NOT EXISTS idx_app_keyword ON keyword_exceptions(app_id, keyword);
CREATE INDEX IF NOT EXISTS idx_app_interaction ON attacker_interactions(app_id, source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_user_active ON api_users(is_active);
CREATE INDEX IF NOT EXISTS idx_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_token_user ON api_tokens(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_token_app ON api_tokens(app_id);
CREATE INDEX IF NOT EXISTS idx_config_app_category ON config_settings(app_id, category);
CREATE INDEX IF NOT EXISTS idx_config_sensitive ON config_settings(is_sensitive);
CREATE INDEX IF NOT EXISTS idx_keycloak_app ON keycloak_config(app_id);
CREATE INDEX IF NOT EXISTS idx_role_mapping_app ON keycloak_role_mappings(app_id, keycloak_role);
CREATE INDEX IF NOT EXISTS idx_service_tokens_app ON service_tokens(app_id);
CREATE INDEX IF NOT EXISTS idx_service_tokens_active ON service_tokens(is_active);
CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash);
