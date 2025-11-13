-- Webhooks Configuration Table
CREATE TABLE IF NOT EXISTS webhooks_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT DEFAULT 'default',
    endpoint TEXT NOT NULL,
    auth_type TEXT,  -- bearer, apikey, basic, none
    auth_value TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(app_id, endpoint)
);

-- Webhook Fire History (optional, for audit trail)
CREATE TABLE IF NOT EXISTS webhook_fire_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id INTEGER,
    app_id TEXT,
    status TEXT,  -- success, failed, timeout
    error_message TEXT,
    response_code INTEGER,
    fired_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(webhook_id) REFERENCES webhooks_config(id),
    FOREIGN KEY(app_id) REFERENCES attacker_profiles(app_id)
);

-- Notification History (for audit trail)
CREATE TABLE IF NOT EXISTS notification_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT,
    provider TEXT,  -- webhook, email, slack, twilio
    threat_level TEXT,
    risk_score INTEGER,
    source_ip TEXT,
    attack_type TEXT,
    status TEXT,  -- success, failed, skipped
    error_message TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(app_id) REFERENCES attacker_profiles(app_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhooks_app ON webhooks_config(app_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks_config(enabled);
CREATE INDEX IF NOT EXISTS idx_webhook_history_app ON webhook_fire_history(app_id);
CREATE INDEX IF NOT EXISTS idx_notification_history_app ON notification_history(app_id);
CREATE INDEX IF NOT EXISTS idx_notification_history_provider ON notification_history(provider);
