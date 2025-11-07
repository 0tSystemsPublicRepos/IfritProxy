package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// InitializeDatabase creates tables and runs migrations
func InitializeDatabase(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	// Create all tables
	if err := createAllTables(db); err != nil {
		return nil, err
	}

	// Run migrations (including seed data)
	if err := RunMigrations(db); err != nil {
		log.Printf("Warning: Migrations failed: %v", err)
		// Don't fail on migration errors
	}

	log.Println("Database initialized successfully")

	// Return wrapped SQLiteDB
	return &SQLiteDB{db: db}, nil
}

// createAllTables creates all required database tables
func createAllTables(db *sql.DB) error {
	log.Println("Creating database tables...")

	tables := []struct {
		name   string
		schema string
	}{
		{
			name: "attack_patterns",
			schema: `CREATE TABLE IF NOT EXISTS attack_patterns (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				attack_signature TEXT,
				attack_type TEXT NOT NULL,
				attack_classification TEXT,
				http_method TEXT,
				path_pattern TEXT,
				payload_template TEXT,
				response_code INTEGER,
				times_seen INTEGER DEFAULT 0,
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				created_by TEXT,
				claude_confidence REAL,
				body_signature TEXT,
				cached_payload TEXT,
				cached_payload_with_intel TEXT,
				llm_generated_at TIMESTAMP,
				llm_cache_hits INTEGER DEFAULT 0,
				
				UNIQUE(app_id, attack_signature)
			)`,
		},
		{
			name: "attack_instances",
			schema: `CREATE TABLE IF NOT EXISTS attack_instances (
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
			)`,
		},
		{
			name: "attacker_profiles",
			schema: `CREATE TABLE IF NOT EXISTS attacker_profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				source_ip TEXT NOT NULL,
				total_requests INTEGER DEFAULT 0,
				successful_probes INTEGER DEFAULT 0,
				attack_types TEXT,
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, source_ip)
			)`,
		},
		{
			name: "exceptions",
			schema: `CREATE TABLE IF NOT EXISTS exceptions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				ip_address TEXT NOT NULL,
				path TEXT NOT NULL,
				reason TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				enabled BOOLEAN DEFAULT 1,
				UNIQUE(app_id, ip_address, path)
			)`,
		},
		{
			name: "llm_api_calls",
			schema: `CREATE TABLE IF NOT EXISTS llm_api_calls (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				request_fingerprint TEXT,
				llm_provider TEXT,
				was_attack BOOLEAN,
				attack_type TEXT,
				confidence REAL,
				tokens_used INTEGER,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`,
		},
		{
			name: "anonymization_log",
			schema: `CREATE TABLE IF NOT EXISTS anonymization_log (
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
			)`,
		},
		{
			name: "payload_templates",
			schema: `CREATE TABLE IF NOT EXISTS payload_templates (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				attack_type TEXT NOT NULL,
				classification TEXT,
				payload_type TEXT NOT NULL,
				content TEXT NOT NULL,
				content_type TEXT DEFAULT 'application/json',
				http_status_code INTEGER DEFAULT 200,
				conditions TEXT,
				priority INTEGER DEFAULT 50,
				is_active BOOLEAN DEFAULT 1,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				created_by TEXT DEFAULT 'system'
			)`,
		},
		{
			name: "payload_conditions",
			schema: `CREATE TABLE IF NOT EXISTS payload_conditions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				payload_template_id INTEGER NOT NULL,
				condition_type TEXT NOT NULL,
				condition_value TEXT NOT NULL,
				operator TEXT DEFAULT '=',
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY(payload_template_id) REFERENCES payload_templates(id) ON DELETE CASCADE
			)`,
		},
		{
			name: "learning_mode_requests",
			schema: `CREATE TABLE IF NOT EXISTS learning_mode_requests (
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
			)`,
		},
		{
			name: "legitimate_requests",
			schema: `CREATE TABLE IF NOT EXISTS legitimate_requests (
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
			)`,
		},
		{
			name: "keyword_exceptions",
			schema: `CREATE TABLE IF NOT EXISTS keyword_exceptions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				exception_type TEXT NOT NULL,
				keyword TEXT NOT NULL,
				reason TEXT,
				enabled BOOLEAN DEFAULT 1,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, exception_type, keyword)
			)`,
		},
		{
			name: "attacker_interactions",
			schema: `CREATE TABLE IF NOT EXISTS attacker_interactions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				app_id TEXT DEFAULT 'default',
				attack_instance_id INTEGER,
				source_ip TEXT,
				interaction_type TEXT,
				interaction_data TEXT,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				FOREIGN KEY(attack_instance_id) REFERENCES attack_instances(id)
			)`,
		},
		{
			name: "intel_collection_templates",
			schema: `CREATE TABLE IF NOT EXISTS intel_collection_templates (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT UNIQUE NOT NULL,
				template_type TEXT,
				content TEXT NOT NULL,
				description TEXT,
				is_active BOOLEAN DEFAULT 1,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP,
				created_by TEXT
			)`,
		},
		{
			name: "api_users",
			schema: `CREATE TABLE IF NOT EXISTS api_users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				email TEXT UNIQUE,
				password_hash TEXT,
				role TEXT DEFAULT 'viewer',
				is_active BOOLEAN DEFAULT 1,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_login TIMESTAMP,
				
				UNIQUE(username)
			)`,
		},
		{
			name: "api_tokens",
			schema: `CREATE TABLE IF NOT EXISTS api_tokens (
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
			)`,
		},
	}

	for _, table := range tables {
		log.Printf("Creating table: %s", table.name)
		if _, err := db.Exec(table.schema); err != nil {
			log.Printf("Error creating table %s: %v", table.name, err)
			return err
		}
	}

	// Create indexes
	if err := createIndexes(db); err != nil {
		return err
	}

	log.Println("All tables and indexes created successfully")
	return nil
}

// createIndexes creates all database indexes
func createIndexes(db *sql.DB) error {
	log.Println("Creating database indexes...")

	indexes := []struct {
		name  string
		query string
	}{
		// Original indexes
		{"idx_attack_instances_source_ip", "CREATE INDEX IF NOT EXISTS idx_attack_instances_source_ip ON attack_instances(source_ip)"},
		{"idx_attack_instances_pattern_id", "CREATE INDEX IF NOT EXISTS idx_attack_instances_pattern_id ON attack_instances(pattern_id)"},
		{"idx_attack_patterns_type", "CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns(attack_type)"},
		{"idx_attacker_profiles_ip", "CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles(source_ip)"},
		{"idx_payload_templates_attack_type", "CREATE INDEX IF NOT EXISTS idx_payload_templates_attack_type ON payload_templates(attack_type)"},
		{"idx_payload_templates_active", "CREATE INDEX IF NOT EXISTS idx_payload_templates_active ON payload_templates(is_active)"},
		{"idx_payload_templates_priority", "CREATE INDEX IF NOT EXISTS idx_payload_templates_priority ON payload_templates(priority DESC)"},
		{"idx_payload_conditions_template", "CREATE INDEX IF NOT EXISTS idx_payload_conditions_template ON payload_conditions(payload_template_id)"},
		{"idx_learning_requests_ip", "CREATE INDEX IF NOT EXISTS idx_learning_requests_ip ON learning_mode_requests(source_ip)"},
		{"idx_learning_requests_fingerprint", "CREATE INDEX IF NOT EXISTS idx_learning_requests_fingerprint ON learning_mode_requests(fingerprint)"},

		// NEW APP_ID INDEXES
		{"idx_app_attack_type", "CREATE INDEX IF NOT EXISTS idx_app_attack_type ON attack_patterns(app_id, attack_type)"},
		{"idx_app_body_hash", "CREATE INDEX IF NOT EXISTS idx_app_body_hash ON attack_patterns(app_id, body_signature)"},
		{"idx_app_attack_instance", "CREATE INDEX IF NOT EXISTS idx_app_attack_instance ON attack_instances(app_id, source_ip)"},
		{"idx_app_timestamp", "CREATE INDEX IF NOT EXISTS idx_app_timestamp ON attack_instances(app_id, timestamp)"},
		{"idx_app_attacker", "CREATE INDEX IF NOT EXISTS idx_app_attacker ON attacker_profiles(app_id, source_ip)"},
		{"idx_app_exception", "CREATE INDEX IF NOT EXISTS idx_app_exception ON exceptions(app_id, ip_address, path)"},
		{"idx_app_path_body", "CREATE INDEX IF NOT EXISTS idx_app_path_body ON legitimate_requests(app_id, path_signature, body_signature)"},
		{"idx_app_keyword", "CREATE INDEX IF NOT EXISTS idx_app_keyword ON keyword_exceptions(app_id, keyword)"},
		{"idx_app_interaction", "CREATE INDEX IF NOT EXISTS idx_app_interaction ON attacker_interactions(app_id, source_ip, timestamp)"},
		{"idx_intel_active", "CREATE INDEX IF NOT EXISTS idx_intel_active ON intel_collection_templates(is_active)"},
		{"idx_user_active", "CREATE INDEX IF NOT EXISTS idx_user_active ON api_users(is_active)"},
		{"idx_token_hash", "CREATE INDEX IF NOT EXISTS idx_token_hash ON api_tokens(token_hash)"},
		{"idx_token_user", "CREATE INDEX IF NOT EXISTS idx_token_user ON api_tokens(user_id, is_active)"},
		{"idx_token_app", "CREATE INDEX IF NOT EXISTS idx_token_app ON api_tokens(app_id)"},
	}

	for _, idx := range indexes {
		log.Printf("Creating index: %s", idx.name)
		if _, err := db.Exec(idx.query); err != nil {
			log.Printf("Error creating index %s: %v", idx.name, err)
			// Don't fail on index errors, they might already exist
		}
	}

	log.Println("All indexes created successfully")
	return nil
}
