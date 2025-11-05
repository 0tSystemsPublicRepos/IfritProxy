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
				attack_signature TEXT UNIQUE,
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
				claude_confidence REAL
			)`,
		},
		{
			name: "attack_instances",
			schema: `CREATE TABLE IF NOT EXISTS attack_instances (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
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
				source_ip TEXT UNIQUE,
				total_requests INTEGER DEFAULT 0,
				successful_probes INTEGER DEFAULT 0,
				attack_types TEXT,
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`,
		},
		{
			name: "exceptions",
			schema: `CREATE TABLE IF NOT EXISTS exceptions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL,
				path TEXT NOT NULL,
				reason TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				enabled BOOLEAN DEFAULT 1,
				UNIQUE(ip_address, path)
			)`,
		},
		{
			name: "llm_api_calls",
			schema: `CREATE TABLE IF NOT EXISTS llm_api_calls (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
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
	}

	for _, table := range tables {
		log.Printf("Creating table: %s", table.name)
		if _, err := db.Exec(table.schema); err != nil {
			log.Printf("Error creating table %s: %v", table.name, err)
			return err
		}
	}

	// Create indexes
	indexes := []struct {
		name  string
		query string
	}{
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
	}

	for _, idx := range indexes {
		log.Printf("Creating index: %s", idx.name)
		if _, err := db.Exec(idx.query); err != nil {
			log.Printf("Error creating index %s: %v", idx.name, err)
			// Don't fail on index errors, they might already exist
		}
	}

	log.Println("All tables and indexes created successfully")
	return nil
}
