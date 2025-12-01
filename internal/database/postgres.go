package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
)

// PostgresProvider implements DatabaseProvider for PostgreSQL
type PostgresProvider struct {
	db     *sql.DB
	config *PostgresConfig
}

// NewPostgresProvider creates a new PostgreSQL database provider
func NewPostgresProvider(config *PostgresConfig) (*PostgresProvider, error) {
	provider := &PostgresProvider{
		config: config,
	}
	
	if err := provider.Connect(); err != nil {
		return nil, err
	}
	
	return provider, nil
}

// Connect establishes connection to PostgreSQL database
func (pp *PostgresProvider) Connect() error {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		pp.config.Host,
		pp.config.Port,
		pp.config.User,
		pp.config.Password,
		pp.config.Database,
		pp.config.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	if pp.config.MaxConnections > 0 {
		db.SetMaxOpenConns(pp.config.MaxConnections)
		db.SetMaxIdleConns(pp.config.MaxConnections / 2)
	}

	pp.db = db
	logging.Info("[PostgreSQL] Connected to database: %s@%s:%d/%s", pp.config.User, pp.config.Host, pp.config.Port, pp.config.Database)
	return nil
}

// Close closes the database connection
func (pp *PostgresProvider) Close() error {
	if pp.db != nil {
		return pp.db.Close()
	}
	return nil
}

// GetDB returns the underlying sql.DB instance
func (pp *PostgresProvider) GetDB() *sql.DB {
	return pp.db
}

// Ping checks if database connection is alive
func (pp *PostgresProvider) Ping() error {
	return pp.db.Ping()
}

// Migrate runs database migrations for PostgreSQL
func (pp *PostgresProvider) Migrate() error {
	// Create all tables
	if err := pp.createAllTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Run data migrations
	if err := pp.runPostgresMigrations(); err != nil {
		logging.Error("Warning: Migrations failed: %v", err)
	}

	logging.Info("[PostgreSQL] Database migration completed")
	return nil
}

// createAllTables creates all PostgreSQL tables
func (pp *PostgresProvider) createAllTables() error {
	logging.Info("[PostgreSQL] Creating database tables...")

	tables := []struct {
		name   string
		schema string
	}{
		{
			name: "attack_patterns",
			schema: `CREATE TABLE IF NOT EXISTS attack_patterns (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				attack_signature TEXT,
				attack_type VARCHAR(255) NOT NULL,
				attack_classification VARCHAR(255),
				http_method VARCHAR(10),
				path_pattern TEXT,
				payload_template TEXT,
				response_code INTEGER,
				times_seen INTEGER DEFAULT 0,
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				created_by VARCHAR(255),
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
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				pattern_id INTEGER,
				source_ip VARCHAR(45),
				user_agent TEXT,
				requested_path TEXT,
				http_method VARCHAR(10),
				returned_honeypot BOOLEAN,
				attacker_accepted BOOLEAN,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY(pattern_id) REFERENCES attack_patterns(id)
			)`,
		},
		{
			name: "attacker_profiles",
			schema: `CREATE TABLE IF NOT EXISTS attacker_profiles (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				source_ip VARCHAR(45) NOT NULL,
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
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				ip_address VARCHAR(45) NOT NULL,
				path TEXT NOT NULL,
				reason TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				enabled BOOLEAN DEFAULT TRUE,
				UNIQUE(app_id, ip_address, path)
			)`,
		},
		{
			name: "llm_api_calls",
			schema: `CREATE TABLE IF NOT EXISTS llm_api_calls (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				request_fingerprint TEXT,
				llm_provider VARCHAR(50),
				was_attack BOOLEAN,
				attack_type VARCHAR(255),
				confidence REAL,
				tokens_used INTEGER,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`,
		},
		{
			name: "anonymization_log",
			schema: `CREATE TABLE IF NOT EXISTS anonymization_log (
				id SERIAL PRIMARY KEY,
				attack_instance_id INTEGER,
				field_type VARCHAR(100),
				field_name VARCHAR(255),
				redaction_action VARCHAR(100),
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
				id SERIAL PRIMARY KEY,
				name VARCHAR(255) NOT NULL UNIQUE,
				attack_type VARCHAR(255) NOT NULL,
				classification VARCHAR(255),
				payload_type VARCHAR(50) NOT NULL,
				content TEXT NOT NULL,
				content_type VARCHAR(100) DEFAULT 'application/json',
				http_status_code INTEGER DEFAULT 200,
				conditions TEXT,
				priority INTEGER DEFAULT 50,
				is_active BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				created_by VARCHAR(255) DEFAULT 'system'
			)`,
		},
		{
			name: "payload_conditions",
			schema: `CREATE TABLE IF NOT EXISTS payload_conditions (
				id SERIAL PRIMARY KEY,
				payload_template_id INTEGER NOT NULL,
				condition_type VARCHAR(100) NOT NULL,
				condition_value TEXT NOT NULL,
				operator VARCHAR(10) DEFAULT '=',
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY(payload_template_id) REFERENCES payload_templates(id) ON DELETE CASCADE
			)`,
		},
		{
			name: "learning_mode_requests",
			schema: `CREATE TABLE IF NOT EXISTS learning_mode_requests (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				source_ip VARCHAR(45),
				user_agent TEXT,
				http_method VARCHAR(10),
				requested_path TEXT,
				request_body TEXT,
				headers TEXT,
				fingerprint TEXT UNIQUE,
				classification VARCHAR(255),
				reviewed BOOLEAN DEFAULT FALSE,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`,
		},
		{
			name: "legitimate_requests",
			schema: `CREATE TABLE IF NOT EXISTS legitimate_requests (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				http_method VARCHAR(10) NOT NULL,
				path TEXT NOT NULL,
				path_signature VARCHAR(255),
				body_signature VARCHAR(255),
				headers_signature VARCHAR(255),
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				hit_count INTEGER DEFAULT 1,
				claude_validated BOOLEAN DEFAULT TRUE,
				
				UNIQUE(app_id, path_signature, body_signature, headers_signature)
			)`,
		},
		{
			name: "keyword_exceptions",
			schema: `CREATE TABLE IF NOT EXISTS keyword_exceptions (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				exception_type VARCHAR(100) NOT NULL,
				keyword VARCHAR(255) NOT NULL,
				reason TEXT,
				enabled BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, exception_type, keyword)
			)`,
		},
		{
			name: "attacker_interactions",
			schema: `CREATE TABLE IF NOT EXISTS attacker_interactions (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				attack_instance_id INTEGER,
				source_ip VARCHAR(45),
				interaction_type VARCHAR(100),
				interaction_data TEXT,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				FOREIGN KEY(attack_instance_id) REFERENCES attack_instances(id)
			)`,
		},
		{
			name: "threat_intelligence",
			schema: `CREATE TABLE IF NOT EXISTS threat_intelligence (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',	
				source_ip VARCHAR(45) NOT NULL,
				risk_score INTEGER DEFAULT 0,
				threat_level VARCHAR(50),
				abuseipdb_score REAL,
				abuseipdb_reports INTEGER,
				abuseipdb_last_reported TEXT,
				virustotal_malicious INTEGER,
				virustotal_suspicious INTEGER,
				virustotal_harmless INTEGER,
				virustotal_undetected INTEGER,
				ipinfo_country VARCHAR(10),
				ipinfo_city VARCHAR(255),
				ipinfo_org TEXT,
				ipinfo_privacy_type VARCHAR(50),
				is_vpn BOOLEAN DEFAULT FALSE,
				is_proxy BOOLEAN DEFAULT FALSE,
				is_hosting BOOLEAN DEFAULT FALSE,
				is_tor BOOLEAN DEFAULT FALSE,
				enriched_at TIMESTAMP,
				cached_until TIMESTAMP,
				last_attack_at TIMESTAMP,
				total_attacks INTEGER DEFAULT 0,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, source_ip)
			)`,
		},
		{
			name: "intel_collection_templates",
			schema: `CREATE TABLE IF NOT EXISTS intel_collection_templates (
				id SERIAL PRIMARY KEY,
				name VARCHAR(255) UNIQUE NOT NULL,
				template_type VARCHAR(100),
				content TEXT NOT NULL,
				description TEXT,
				is_active BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP,
payload_template TEXT,
				created_by VARCHAR(255)
			)`,
		},
		{
			name: "api_users",
			schema: `CREATE TABLE IF NOT EXISTS api_users (
				id SERIAL PRIMARY KEY,
				username VARCHAR(255) UNIQUE NOT NULL,
				email VARCHAR(255) UNIQUE,
				password_hash TEXT,
				role VARCHAR(50) DEFAULT 'viewer',
				is_active BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_login TIMESTAMP
			)`,
		},
		{
			name: "api_tokens",
			schema: `CREATE TABLE IF NOT EXISTS api_tokens (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL,
				token_name VARCHAR(255) NOT NULL,
				token_hash TEXT UNIQUE NOT NULL,
				token_prefix VARCHAR(20),
				app_id VARCHAR(255) DEFAULT 'default',
				permissions TEXT,
				is_active BOOLEAN DEFAULT TRUE,
				last_used TIMESTAMP,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				expires_at TIMESTAMP,
				created_by VARCHAR(255),
				
				FOREIGN KEY(user_id) REFERENCES api_users(id),
				UNIQUE(user_id, token_name)
			)`,
		},
		{
			name: "config_settings",
			schema: `CREATE TABLE IF NOT EXISTS config_settings (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				category VARCHAR(100) NOT NULL,
				key VARCHAR(255) NOT NULL,
				value TEXT NOT NULL,
				data_type VARCHAR(50),
				is_sensitive BOOLEAN DEFAULT FALSE,
				description TEXT,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_by VARCHAR(255),
				
				UNIQUE(app_id, category, key)
			)`,
		},
		{
			name: "keycloak_config",
			schema: `CREATE TABLE IF NOT EXISTS keycloak_config (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				realm VARCHAR(255) NOT NULL,
				auth_server_url VARCHAR(500) NOT NULL,
				client_id VARCHAR(255) NOT NULL,
				client_secret TEXT,
				enabled BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id)
			)`,
		},
		{
			name: "keycloak_role_mappings",
			schema: `CREATE TABLE IF NOT EXISTS keycloak_role_mappings (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				keycloak_role VARCHAR(255) NOT NULL,
				ifrit_permissions TEXT,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, keycloak_role)
			)`,
		},
		{
			name: "service_tokens",
			schema: `CREATE TABLE IF NOT EXISTS service_tokens (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				token_name VARCHAR(255) NOT NULL,
				token_hash TEXT NOT NULL,
				token_prefix VARCHAR(20),
				keycloak_service_account_id VARCHAR(255),
				permissions TEXT,
				is_active BOOLEAN DEFAULT TRUE,
				expires_at TIMESTAMP,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				last_used_at TIMESTAMP,
				
				UNIQUE(token_hash)
			)`,
		},
		{
			name: "webhooks_config",
			schema: `CREATE TABLE IF NOT EXISTS webhooks_config (
				id SERIAL PRIMARY KEY,
				app_id VARCHAR(255) DEFAULT 'default',
				endpoint VARCHAR(500) NOT NULL,
				auth_type VARCHAR(50),
				auth_value TEXT,
				enabled BOOLEAN DEFAULT TRUE,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				
				UNIQUE(app_id, endpoint)
			)`,
		},
	}

	for _, table := range tables {
		logging.Info("[PostgreSQL] Creating table: %s", table.name)
		if _, err := pp.db.Exec(table.schema); err != nil {
			logging.Error("[PostgreSQL] Error creating table %s: %v", table.name, err)
			return err
		}
	}

	// Create indexes
	if err := pp.createIndexes(); err != nil {
		return err
	}

	logging.Info("[PostgreSQL] All tables and indexes created successfully")
	return nil
}

// createIndexes creates all PostgreSQL indexes
func (pp *PostgresProvider) createIndexes() error {
	logging.Info("[PostgreSQL] Creating database indexes...")

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_attack_instances_source_ip ON attack_instances(source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_attack_instances_pattern_id ON attack_instances(pattern_id)",
		"CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns(attack_type)",
		"CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles(source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_payload_templates_attack_type ON payload_templates(attack_type)",
		"CREATE INDEX IF NOT EXISTS idx_payload_templates_active ON payload_templates(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_payload_templates_priority ON payload_templates(priority DESC)",
		"CREATE INDEX IF NOT EXISTS idx_payload_conditions_template ON payload_conditions(payload_template_id)",
		"CREATE INDEX IF NOT EXISTS idx_learning_requests_ip ON learning_mode_requests(source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_learning_requests_fingerprint ON learning_mode_requests(fingerprint)",
		"CREATE INDEX IF NOT EXISTS idx_app_attack_type ON attack_patterns(app_id, attack_type)",
		"CREATE INDEX IF NOT EXISTS idx_app_body_hash ON attack_patterns(app_id, body_signature)",
		"CREATE INDEX IF NOT EXISTS idx_app_attack_instance ON attack_instances(app_id, source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_app_timestamp ON attack_instances(app_id, timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_app_attacker ON attacker_profiles(app_id, source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_app_exception ON exceptions(app_id, ip_address, path)",
		"CREATE INDEX IF NOT EXISTS idx_app_path_body ON legitimate_requests(app_id, path_signature, body_signature)",
		"CREATE INDEX IF NOT EXISTS idx_app_keyword ON keyword_exceptions(app_id, keyword)",
		"CREATE INDEX IF NOT EXISTS idx_app_interaction ON attacker_interactions(app_id, source_ip, timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_intel_active ON intel_collection_templates(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_user_active ON api_users(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_token_hash ON api_tokens(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_token_user ON api_tokens(user_id, is_active)",
		"CREATE INDEX IF NOT EXISTS idx_token_app ON api_tokens(app_id)",
		"CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intelligence(app_id, source_ip)",
		"CREATE INDEX IF NOT EXISTS idx_threat_risk_score ON threat_intelligence(app_id, risk_score DESC)",
		"CREATE INDEX IF NOT EXISTS idx_threat_cached_until ON threat_intelligence(cached_until)",
		"CREATE INDEX IF NOT EXISTS idx_threat_updated ON threat_intelligence(updated_at DESC)",
		"CREATE INDEX IF NOT EXISTS idx_config_app_category ON config_settings(app_id, category)",
		"CREATE INDEX IF NOT EXISTS idx_config_sensitive ON config_settings(is_sensitive)",
		"CREATE INDEX IF NOT EXISTS idx_keycloak_app ON keycloak_config(app_id)",
		"CREATE INDEX IF NOT EXISTS idx_role_mapping_app ON keycloak_role_mappings(app_id, keycloak_role)",
		"CREATE INDEX IF NOT EXISTS idx_service_tokens_app ON service_tokens(app_id)",
		"CREATE INDEX IF NOT EXISTS idx_service_tokens_active ON service_tokens(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_service_tokens_hash ON service_tokens(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_webhooks_app ON webhooks_config(app_id)",
		"CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks_config(enabled)",
	}

	for _, idx := range indexes {
		if _, err := pp.db.Exec(idx); err != nil {
			logging.Error("[PostgreSQL] Error creating index: %v", err)
		}
	}

	logging.Info("[PostgreSQL] All indexes created successfully")
	return nil
}

// runPostgresMigrations runs data seeding for PostgreSQL
func (pp *PostgresProvider) runPostgresMigrations() error {
	// For now, we'll reuse the SQLite migration logic since it's mostly compatible
	// In the future, you can create PostgreSQL-specific migration files
	
	// Seed attack patterns (adapted for PostgreSQL)
	if err := pp.seedAttackPatterns(); err != nil {
		logging.Error("[PostgreSQL] Warning: Could not seed attack patterns: %v", err)
	}

	return nil
}

// seedAttackPatterns inserts known attack patterns (PostgreSQL version)
func (pp *PostgresProvider) seedAttackPatterns() error {
	var count int
	err := pp.db.QueryRow("SELECT COUNT(*) FROM attack_patterns WHERE created_by = 'seed'").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		logging.Info("[PostgreSQL] Attack patterns already seeded (%d patterns)", count)
		return nil
	}

	logging.Info("[PostgreSQL] Seeding attack patterns...")

	// Simplified seeding - just add a few essential patterns
	patterns := []struct {
		appID          string
		signature      string
		attackType     string
		classification string
		method         string
		pathPattern    string
		responseCode   int
		confidence     float64
	}{
		{"default", "/.env", "reconnaissance", "env_probe", "GET", "/.env", 403, 0.95},
		{"default", "/.git", "reconnaissance", "source_enumeration", "GET", "/.git", 403, 0.92},
		{"default", "/admin", "reconnaissance", "directory_enumeration", "GET", "/admin", 403, 0.88},
	}

	stmt, err := pp.db.Prepare(`
		INSERT INTO attack_patterns 
		(app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, response_code, times_seen, created_by, claude_confidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 'seed', $8)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range patterns {
		_, err := stmt.Exec(p.appID, p.signature, p.attackType, p.classification, p.method, p.pathPattern, p.responseCode, p.confidence)
		if err != nil {
			logging.Error("[PostgreSQL] Warning: Could not seed pattern %s: %v", p.signature, err)
			continue
		}
	}

	logging.Info("[PostgreSQL] Successfully seeded %d attack patterns", len(patterns))
	return nil
}

// === ALL THE SAME METHODS AS SQLITE BUT WITH POSTGRESQL SYNTAX ===

// Note: PostgreSQL uses $1, $2 placeholders instead of ?
// Below are the implementations with PostgreSQL-compatible SQL

func (pp *PostgresProvider) StoreAttackPattern(appID, signature, attackType, classification, method, path, payloadTemplate string, responseCode int, createdBy string, confidence float64) error {
	query := `
		INSERT INTO attack_patterns 
		(app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, times_seen, created_by, claude_confidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10)
		ON CONFLICT(app_id, attack_signature) DO UPDATE SET 
			times_seen = attack_patterns.times_seen + 1,
			last_seen = CURRENT_TIMESTAMP
	`
	_, err := pp.db.Exec(query, appID, signature, attackType, classification, method, path, payloadTemplate, responseCode, createdBy, confidence)
	return err
}

func (pp *PostgresProvider) GetAllPatterns(appID string) ([]map[string]interface{}, error) {
	log.Printf("[DEBUG] GetAllPatterns called with appID='%s'", appID)
	query := ` 
		SELECT id, attack_signature, attack_type, attack_classification, http_method,
		       path_pattern, payload_template, response_code, times_seen, claude_confidence
		FROM attack_patterns
		WHERE app_id = $1
		ORDER BY times_seen DESC
	`       
		
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		log.Printf("[ERROR] GetAllPatterns query error: %v", err)
		return nil, err
	}       
	defer rows.Close()

	var patterns []map[string]interface{}
	rowCount := 0
	for rows.Next() {
		rowCount++
		var id int64
		var signature, attackType, classification, method, pathPattern string
		var payloadTemplate sql.NullString  // <-- CHANGED to sql.NullString
		var responseCode, timesSeen int
		var confidence float64

		err := rows.Scan(&id, &signature, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &timesSeen, &confidence)
		if err != nil {
			log.Printf("[ERROR] GetAllPatterns scan error on row %d: %v", rowCount, err)
			continue
		}

		// Convert sql.NullString to regular string
		payloadTemplateStr := ""
		if payloadTemplate.Valid {
			payloadTemplateStr = payloadTemplate.String
		}

		patterns = append(patterns, map[string]interface{}{
			"id":                    id,
			"attack_signature":      signature,
			"attack_type":           attackType,
			"attack_classification": classification,
			"http_method":           method,
			"path_pattern":          pathPattern,
			"payload_template":      payloadTemplateStr,  // <-- Use the converted string
			"response_code":         responseCode,
			"times_seen":            timesSeen,
			"confidence":            confidence,
		})
	}

	log.Printf("[DEBUG] GetAllPatterns returning %d patterns (iterated %d rows)", len(patterns), rowCount)
	return patterns, rows.Err()
}


func (pp *PostgresProvider) GetPatternBySignature(appID, signature string) (map[string]interface{}, error) {
	query := `
		SELECT id, attack_type, attack_classification, http_method, path_pattern, 
		       payload_template, response_code, claude_confidence
		FROM attack_patterns 
		WHERE app_id = $1 AND attack_signature = $2
	`
	
	var id int64
	var attackType, classification, method, pathPattern, payloadTemplate string
	var responseCode int
	var confidence float64

	err := pp.db.QueryRow(query, appID, signature).Scan(&id, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &confidence)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                    id,
		"attack_type":           attackType,
		"attack_classification": classification,
		"http_method":           method,
		"path_pattern":          pathPattern,
		"payload_template":      payloadTemplate,
		"response_code":         responseCode,
		"confidence":            confidence,
	}, nil
}

func (pp *PostgresProvider) UpdatePatternTimestamp(appID, signature string) error {
	query := `
		UPDATE attack_patterns 
		SET last_seen = CURRENT_TIMESTAMP, times_seen = times_seen + 1
		WHERE app_id = $1 AND attack_signature = $2
	`
	_, err := pp.db.Exec(query, appID, signature)
	return err
}

func (pp *PostgresProvider) LogAttackInstance(appID string, patternID *int64, sourceIP, userAgent, path, method string, returnedHoneypot, attackerAccepted bool) error {
	query := `
		INSERT INTO attack_instances 
		(app_id, pattern_id, source_ip, user_agent, requested_path, http_method, returned_honeypot, attacker_accepted, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
	`
	_, err := pp.db.Exec(query, appID, patternID, sourceIP, userAgent, path, method, returnedHoneypot, attackerAccepted)
	return err
}


func (pp *PostgresProvider) GetAttackInstances(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ai.id, ai.source_ip, ai.user_agent, ai.requested_path, ai.http_method,
		       ai.returned_honeypot, ai.attacker_accepted, ai.timestamp,
		       ap.attack_type, ap.attack_classification
		FROM attack_instances ai
		LEFT JOIN attack_patterns ap ON ai.pattern_id = ap.id
		WHERE ai.app_id = $1
		ORDER BY ai.timestamp DESC
		LIMIT $2
	`
	
	rows, err := pp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var instances []map[string]interface{}
	for rows.Next() {
		var id int64
		var sourceIP, userAgent, path, method string
		var timestamp time.Time
		var returnedHoneypot, attackerAccepted bool
		var attackType, classification sql.NullString

		err := rows.Scan(&id, &sourceIP, &userAgent, &path, &method, &returnedHoneypot, &attackerAccepted, &timestamp, &attackType, &classification)
		if err != nil {
			continue
		}

		instances = append(instances, map[string]interface{}{
			"id":                 id,
			"source_ip":          sourceIP,
			"user_agent":         userAgent,
			"path":               path,
			"method":             method,
			"returned_honeypot":  returnedHoneypot,
			"attacker_accepted":  attackerAccepted,
			"timestamp":          timestamp.Format(time.RFC3339),
			"attack_type":        attackType.String,
			"classification":     classification.String,
		})
	}

	return instances, rows.Err()
}

func (pp *PostgresProvider) UpdateAttackerProfile(appID, sourceIP string, attackTypes []string, successfulProbe bool) error {
	attackTypesJSON, _ := json.Marshal(attackTypes)
	
	successCount := 0
	if successfulProbe {
		successCount = 1
	}
	
	query := `
		INSERT INTO attacker_profiles 
		(app_id, source_ip, total_requests, successful_probes, attack_types)
		VALUES ($1, $2, 1, $3, $4)
		ON CONFLICT(app_id, source_ip) DO UPDATE SET
			total_requests = attacker_profiles.total_requests + 1,
			successful_probes = attacker_profiles.successful_probes + $5,
			attack_types = $6,
			last_seen = CURRENT_TIMESTAMP
	`
	
	_, err := pp.db.Exec(query, appID, sourceIP, successCount, string(attackTypesJSON), successCount, string(attackTypesJSON))
	return err
}

func (pp *PostgresProvider) GetAttackerProfile(appID, sourceIP string) (map[string]interface{}, error) {
	query := `
		SELECT total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles
		WHERE app_id = $1 AND source_ip = $2
	`
	
	var totalRequests, successfulProbes int
	var attackTypes string
	var firstSeen, lastSeen time.Time

	err := pp.db.QueryRow(query, appID, sourceIP).Scan(&totalRequests, &successfulProbes, &attackTypes, &firstSeen, &lastSeen)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_requests":    totalRequests,
		"successful_probes": successfulProbes,
		"attack_types":      attackTypes,
		"first_seen":        firstSeen.Format(time.RFC3339),
		"last_seen":         lastSeen.Format(time.RFC3339),
	}, nil
}

func (pp *PostgresProvider) GetTopAttackers(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT source_ip, total_requests, successful_probes, attack_types, last_seen
		FROM attacker_profiles
		WHERE app_id = $1
		ORDER BY total_requests DESC
		LIMIT $2
	`
	
	rows, err := pp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attackers []map[string]interface{}
	for rows.Next() {
		var sourceIP, attackTypes string
		var lastSeen time.Time
		var totalRequests, successfulProbes int

		err := rows.Scan(&sourceIP, &totalRequests, &successfulProbes, &attackTypes, &lastSeen)
		if err != nil {
			continue
		}

		attackers = append(attackers, map[string]interface{}{
			"source_ip":         sourceIP,
			"total_requests":    totalRequests,
			"successful_probes": successfulProbes,
			"attack_types":      attackTypes,
			"last_seen":         lastSeen.Format(time.RFC3339),
		})
	}

	return attackers, rows.Err()
}

// GetAttackerProfiles returns all attacker profiles for an app
func (pp *PostgresProvider) GetAttackerProfiles(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles
		WHERE app_id = $1
		ORDER BY total_requests DESC
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attackers []map[string]interface{}
	for rows.Next() {
		var sourceIP, attackTypes, firstSeen, lastSeen string
		var totalRequests, successfulProbes int

		err := rows.Scan(&sourceIP, &totalRequests, &successfulProbes, &attackTypes, &firstSeen, &lastSeen)
		if err != nil {
			continue
		}

		attackers = append(attackers, map[string]interface{}{
			"source_ip":         sourceIP,
			"total_requests":    totalRequests,
			"successful_probes": successfulProbes,
			"attack_types":      attackTypes,
			"first_seen":        firstSeen,
			"last_seen":         lastSeen,
		})
	}

	return attackers, rows.Err()
}

// GetExceptions returns all exceptions (alias for GetAllExceptions)
func (pp *PostgresProvider) GetExceptions(appID string) ([]map[string]interface{}, error) {
	return pp.GetAllExceptions(appID)
}

// === ATTACKER INTERACTIONS ===

// StoreAttackerInteraction stores attacker interaction data
func (pp *PostgresProvider) StoreAttackerInteraction(appID string, patternID int64, sourceIP, interactionType, interactionData string) error {
	query := `
		INSERT INTO attacker_interactions 
		(app_id, pattern_id, source_ip, interaction_type, interaction_data, timestamp)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
	`
	_, err := pp.db.Exec(query, appID, patternID, sourceIP, interactionType, interactionData)
	return err
}

// === INTELLIGENCE COLLECTION TEMPLATES ===

// GetIntelCollectionTemplates returns all intelligence collection templates
func (pp *PostgresProvider) GetIntelCollectionTemplates() ([]map[string]interface{}, error) {
	query := `
		SELECT id, name, description, payload_template, conditions, enabled, created_at
		FROM intel_collection_templates
		ORDER BY id
	`
	
	rows, err := pp.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id int64
		var name, description, payloadTemplate, conditions, createdAt string
		var enabled bool

		err := rows.Scan(&id, &name, &description, &payloadTemplate, &conditions, &enabled, &createdAt)
		if err != nil {
			continue
		}

		templates = append(templates, map[string]interface{}{
			"id":               id,
			"name":             name,
			"description":      description,
			"payload_template": payloadTemplate,
			"conditions":       conditions,
			"enabled":          enabled,
			"created_at":       createdAt,
		})
	}

	return templates, rows.Err()
}

// === API TOKENS ===

// CreateAPIToken creates a new API token
func (pp *PostgresProvider) CreateAPIToken(userID int64, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt string) (int64, error) {
	query := `
		INSERT INTO api_tokens 
		(user_id, token_name, token_hash, token_prefix, app_id, permissions, expires_at, created_at, last_used_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP, NULL, TRUE)
		RETURNING id
	`
	
	var tokenID int64
	err := pp.db.QueryRow(query, userID, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt).Scan(&tokenID)
	if err != nil {
		return 0, err
	}
	
	return tokenID, nil
}

// ValidateAPIToken validates an API token and returns user information
func (pp *PostgresProvider) ValidateAPIToken(tokenHash string) (map[string]interface{}, error) {
	query := `
		SELECT t.id, t.user_id, t.token_name, t.app_id, t.permissions, t.expires_at, 
		       u.username, u.email, u.role
		FROM api_tokens t
		JOIN api_users u ON t.user_id = u.id
		WHERE t.token_hash = $1 AND t.is_active = TRUE
		  AND (t.expires_at IS NULL OR t.expires_at > CURRENT_TIMESTAMP)
	`
	
	var tokenID, userID int64
	var tokenName, appID, permissions, username, email, role string
	var expiresAt sql.NullString
	
	err := pp.db.QueryRow(query, tokenHash).Scan(
		&tokenID, &userID, &tokenName, &appID, &permissions, &expiresAt,
		&username, &email, &role,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Update last_used_at
	updateQuery := `UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1`
	pp.db.Exec(updateQuery, tokenID)
	
	return map[string]interface{}{
		"token_id":    tokenID,
		"user_id":     userID,
		"username":    username,
		"email":       email,
		"role":        role,
		"app_id":      appID,
		"permissions": permissions,
		"expires_at":  expiresAt.String,
	}, nil
}

func (pp *PostgresProvider) AddException(appID, ipAddress, path, reason string) error {
	query := `
		INSERT INTO exceptions (app_id, ip_address, path, reason, enabled)
		VALUES ($1, $2, $3, $4, TRUE)
		ON CONFLICT(app_id, ip_address, path) DO UPDATE SET
			reason = $5,
			enabled = TRUE
	`
	_, err := pp.db.Exec(query, appID, ipAddress, path, reason, reason)
	return err
}

func (pp *PostgresProvider) RemoveException(appID, ipAddress, path string) error {
	query := `DELETE FROM exceptions WHERE app_id = $1 AND ip_address = $2 AND path = $3`
	_, err := pp.db.Exec(query, appID, ipAddress, path)
	return err
}

func (pp *PostgresProvider) GetAllExceptions(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, ip_address, path, reason, created_at, enabled
		FROM exceptions
		WHERE app_id = $1
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var ipAddress, path, reason string
		var createdAt time.Time
		var enabled bool

		err := rows.Scan(&id, &ipAddress, &path, &reason, &createdAt, &enabled)
		if err != nil {
			continue
		}

		exceptions = append(exceptions, map[string]interface{}{
			"id":         id,
			"ip_address": ipAddress,
			"path":       path,
			"reason":     reason,
			"created_at": createdAt.Format(time.RFC3339),
			"enabled":    enabled,
		})
	}

	return exceptions, rows.Err()
}

func (pp *PostgresProvider) StoreLegitimateRequest(appID, method, path, pathSig, bodySig, headersSig string) error {
	query := `
		INSERT INTO legitimate_requests 
		(app_id, http_method, path, path_signature, body_signature, headers_signature, hit_count, claude_validated)
		VALUES ($1, $2, $3, $4, $5, $6, 1, TRUE)
		ON CONFLICT(app_id, path_signature, body_signature, headers_signature) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			hit_count = legitimate_requests.hit_count + 1
	`
	_, err := pp.db.Exec(query, appID, method, path, pathSig, bodySig, headersSig)
	return err
}

func (pp *PostgresProvider) GetLegitimateRequest(appID, pathSig, bodySig, headersSig string) (bool, error) {
	query := `
		SELECT id FROM legitimate_requests
		WHERE app_id = $1 AND path_signature = $2 AND body_signature = $3 AND headers_signature = $4
	`
	
	var id int64
	err := pp.db.QueryRow(query, appID, pathSig, bodySig, headersSig).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	return true, nil
}

func (pp *PostgresProvider) AddKeywordException(appID, exceptionType, keyword, reason string) error {
	query := `
		INSERT INTO keyword_exceptions (app_id, exception_type, keyword, reason, enabled)
		VALUES ($1, $2, $3, $4, TRUE)
		ON CONFLICT(app_id, exception_type, keyword) DO UPDATE SET
			reason = $5,
			enabled = TRUE
	`
	_, err := pp.db.Exec(query, appID, exceptionType, keyword, reason, reason)
	return err
}

func (pp *PostgresProvider) RemoveKeywordException(appID, exceptionType, keyword string) error {
	query := `DELETE FROM keyword_exceptions WHERE app_id = $1 AND exception_type = $2 AND keyword = $3`
	_, err := pp.db.Exec(query, appID, exceptionType, keyword)
	return err
}

func (pp *PostgresProvider) GetKeywordExceptions(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, exception_type, keyword, reason, enabled, created_at
		FROM keyword_exceptions
		WHERE app_id = $1 AND enabled = TRUE
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var exceptionType, keyword, reason string
		var createdAt time.Time
		var enabled bool

		err := rows.Scan(&id, &exceptionType, &keyword, &reason, &enabled, &createdAt)
		if err != nil {
			continue
		}

		exceptions = append(exceptions, map[string]interface{}{
			"id":             id,
			"exception_type": exceptionType,
			"keyword":        keyword,
			"reason":         reason,
			"enabled":        enabled,
			"created_at":     createdAt.Format(time.RFC3339),
		})
	}

	return exceptions, rows.Err()
}

func (pp *PostgresProvider) LogLLMCall(appID, fingerprint, provider string, wasAttack bool, attackType string, confidence float64, tokensUsed int) error {
	query := `
		INSERT INTO llm_api_calls 
		(app_id, request_fingerprint, llm_provider, was_attack, attack_type, confidence, tokens_used)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := pp.db.Exec(query, appID, fingerprint, provider, wasAttack, attackType, confidence, tokensUsed)
	return err
}

func (pp *PostgresProvider) StoreThreatIntelligence(appID, sourceIP string, riskScore int, abuseScore *float64, abuseReports *int, vtMalicious, vtSuspicious bool, isVPN, isProxy bool, country, org, privacyType, threatLevel string) error {
	query := `
		INSERT INTO threat_intelligence 
		(app_id, source_ip, risk_score, threat_level, abuseipdb_score, abuseipdb_reports, 
		 virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy, 
		 ipinfo_country, ipinfo_org, ipinfo_privacy_type, enriched_at, cached_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '24 hours')
		ON CONFLICT(app_id, source_ip) DO UPDATE SET
			risk_score = $14,
			threat_level = $15,
			abuseipdb_score = $16,
			abuseipdb_reports = $17,
			virustotal_malicious = $18,
			virustotal_suspicious = $19,
			is_vpn = $20,
			is_proxy = $21,
			ipinfo_country = $22,
			ipinfo_org = $23,
			ipinfo_privacy_type = $24,
			enriched_at = CURRENT_TIMESTAMP,
			cached_until = CURRENT_TIMESTAMP + INTERVAL '24 hours',
			updated_at = CURRENT_TIMESTAMP
	`
	
	_, err := pp.db.Exec(query, 
		appID, sourceIP, riskScore, threatLevel, abuseScore, abuseReports, 
		vtMalicious, vtSuspicious, isVPN, isProxy, 
		country, org, privacyType,
		// For UPDATE clause
		riskScore, threatLevel, abuseScore, abuseReports,
		vtMalicious, vtSuspicious, isVPN, isProxy,
		country, org, privacyType,
	)
	return err
}

func (pp *PostgresProvider) GetThreatIntelligence(appID, sourceIP string) (map[string]interface{}, error) {
	query := `
		SELECT risk_score, threat_level, abuseipdb_score, abuseipdb_reports,
		       virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy,
		       ipinfo_country, ipinfo_org, ipinfo_privacy_type, enriched_at, cached_until
		FROM threat_intelligence
		WHERE app_id = $1 AND source_ip = $2
	`
	
	var riskScore int
	var threatLevel string
	var abuseScore sql.NullFloat64
	var abuseReports sql.NullInt64
	var vtMalicious, vtSuspicious, isVPN, isProxy bool
	var country, org, privacyType string
	var enrichedAt, cachedUntil time.Time

	err := pp.db.QueryRow(query, appID, sourceIP).Scan(
		&riskScore, &threatLevel, &abuseScore, &abuseReports,
		&vtMalicious, &vtSuspicious, &isVPN, &isProxy,
		&country, &org, &privacyType, &enrichedAt, &cachedUntil,
	)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"risk_score":            riskScore,
		"threat_level":          threatLevel,
		"is_vpn":                isVPN,
		"is_proxy":              isProxy,
		"ipinfo_country":        country,
		"ipinfo_org":            org,
		"ipinfo_privacy_type":   privacyType,
		"enriched_at":           enrichedAt.Format(time.RFC3339),
		"cached_until":          cachedUntil.Format(time.RFC3339),
		"virustotal_malicious":  vtMalicious,
		"virustotal_suspicious": vtSuspicious,
	}

	if abuseScore.Valid {
		result["abuseipdb_score"] = abuseScore.Float64
	}
	if abuseReports.Valid {
		result["abuseipdb_reports"] = abuseReports.Int64
	}

	return result, nil
}

func (pp *PostgresProvider) IsThreatIntelligenceCached(appID, sourceIP string) (bool, error) {
	query := `
		SELECT COUNT(*) FROM threat_intelligence
		WHERE app_id = $1 AND source_ip = $2 AND cached_until > CURRENT_TIMESTAMP
	`
	
	var count int
	err := pp.db.QueryRow(query, appID, sourceIP).Scan(&count)
	if err != nil {
		return false, err
	}
	
	return count > 0, nil
}

// GetThreatIntelList returns list of threat intelligence records
func (pp *PostgresProvider) GetThreatIntelList(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_score, abuseipdb_reports, 
		       virustotal_malicious, virustotal_suspicious, country, last_seen 
		FROM threat_intelligence 
		WHERE app_id = $1
		ORDER BY last_seen DESC 
		LIMIT $2
	`
	
	rows, err := pp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []map[string]interface{}
	for rows.Next() {
		var ipAddress, threatLevel, country, lastSeen string
		var riskScore, abuseScore, abuseReports, vtMalicious, vtSuspicious int
		
		if err := rows.Scan(&ipAddress, &riskScore, &threatLevel, &abuseScore, &abuseReports,
			&vtMalicious, &vtSuspicious, &country, &lastSeen); err != nil {
			continue
		}
		
		results = append(results, map[string]interface{}{
			"ip_address":            ipAddress,
			"risk_score":            riskScore,
			"threat_level":          threatLevel,
			"abuseipdb_score":       abuseScore,
			"abuseipdb_reports":     abuseReports,
			"virustotal_malicious":  vtMalicious,
			"virustotal_suspicious": vtSuspicious,
			"country":               country,
			"last_seen":             lastSeen,
		})
	}
	
	return results, rows.Err()
}

// GetTopThreatsByRiskScore returns top threats ordered by risk score
func (pp *PostgresProvider) GetTopThreatsByRiskScore(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_reports, 
		       virustotal_malicious, country, last_seen
		FROM threat_intelligence
		WHERE app_id = $1
		ORDER BY risk_score DESC
		LIMIT $2
	`
	
	rows, err := pp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []map[string]interface{}
	for rows.Next() {
		var ipAddress, threatLevel, country, lastSeen string
		var riskScore, abuseReports, vtMalicious int
		
		if err := rows.Scan(&ipAddress, &riskScore, &threatLevel, &abuseReports,
			&vtMalicious, &country, &lastSeen); err != nil {
			continue
		}
		
		results = append(results, map[string]interface{}{
			"ip_address":           ipAddress,
			"risk_score":           riskScore,
			"threat_level":         threatLevel,
			"abuseipdb_reports":    abuseReports,
			"virustotal_malicious": vtMalicious,
			"country":              country,
			"last_seen":            lastSeen,
		})
	}
	
	return results, rows.Err()
}

// GetThreatIntelStats returns threat intelligence statistics by level
func (pp *PostgresProvider) GetThreatIntelStats(appID string) (int64, int64, int64, int64, int64, error) {
	var totalIPs, critical, high, medium, low int64
	
	if err := pp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = $1", appID).Scan(&totalIPs); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	
	pp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = $1 AND threat_level = 'CRITICAL'", appID).Scan(&critical)
	pp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = $1 AND threat_level = 'HIGH'", appID).Scan(&high)
	pp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = $1 AND threat_level = 'MEDIUM'", appID).Scan(&medium)
	pp.db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE app_id = $1 AND threat_level = 'LOW'", appID).Scan(&low)
	
	return totalIPs, critical, high, medium, low, nil
}

// GetThreatIntelDetail returns detailed threat intelligence for a specific IP
func (pp *PostgresProvider) GetThreatIntelDetail(appID, ipAddress string) (map[string]interface{}, error) {
	query := `
		SELECT ip_address, risk_score, threat_level, abuseipdb_score, abuseipdb_reports,
		       virustotal_malicious, virustotal_suspicious, ipinfo_city, ipinfo_country, 
		       last_seen, created_at
		FROM threat_intelligence
		WHERE ip_address = $1 AND app_id = $2
	`
	
	var ip, threatLevel, city, country, lastSeen, createdAt string
	var riskScore, abuseScore, abuseReports, vtMalicious, vtSuspicious int
	
	err := pp.db.QueryRow(query, ipAddress, appID).Scan(
		&ip, &riskScore, &threatLevel, &abuseScore, &abuseReports,
		&vtMalicious, &vtSuspicious, &city, &country, &lastSeen, &createdAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"ip_address":            ip,
		"risk_score":            riskScore,
		"threat_level":          threatLevel,
		"abuseipdb_score":       abuseScore,
		"abuseipdb_reports":     abuseReports,
		"virustotal_malicious":  vtMalicious,
		"virustotal_suspicious": vtSuspicious,
		"ipinfo_city":           city,
		"ipinfo_country":        country,
		"last_seen":             lastSeen,
		"created_at":            createdAt,
	}, nil
}

// === NOTIFICATIONS ===

// GetNotificationHistory returns notification send history
func (pp *PostgresProvider) GetNotificationHistory(appID string, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT threat_level, source_ip, attack_type, notification_type, status, sent_at
		FROM notification_history
		WHERE app_id = $1
		ORDER BY sent_at DESC
		LIMIT $2
	`
	
	rows, err := pp.db.Query(query, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var history []map[string]interface{}
	for rows.Next() {
		var threatLevel, sourceIP, attackType, notificationType, status, sentAt string
		
		if err := rows.Scan(&threatLevel, &sourceIP, &attackType, &notificationType, &status, &sentAt); err != nil {
			continue
		}
		
		history = append(history, map[string]interface{}{
			"threat_level":      threatLevel,
			"source_ip":         sourceIP,
			"attack_type":       attackType,
			"notification_type": notificationType,
			"status":            status,
			"sent_at":           sentAt,
		})
	}
	
	return history, rows.Err()
}

// === ATTACKER INTERACTIONS ===

// GetAttackerInteractionsCount returns count of attacker interactions
func (pp *PostgresProvider) GetAttackerInteractionsCount(appID string) (int64, error) {
	var count int64
	err := pp.db.QueryRow("SELECT COUNT(*) FROM attacker_interactions WHERE app_id = $1", appID).Scan(&count)
	return count, err
}

// === EXCEPTIONS ===

// CheckException checks if a request matches an exception rule
func (pp *PostgresProvider) CheckException(appID, path, clientIP string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM exceptions 
			WHERE enabled = TRUE
			AND app_id = $1
			AND path = $2
			AND (ip_address = $3 OR ip_address = '*')
		)
	`
	err := pp.db.QueryRow(query, appID, path, clientIP).Scan(&exists)
	return exists, err
}


func (pp *PostgresProvider) GetActiveWebhooks(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, endpoint, auth_type, auth_value
		FROM webhooks_config
		WHERE app_id = $1 AND enabled = TRUE
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []map[string]interface{}
	for rows.Next() {
		var id int64
		var endpoint, authType string
		var authValue sql.NullString

		err := rows.Scan(&id, &endpoint, &authType, &authValue)
		if err != nil {
			continue
		}

		authVal := ""
		if authValue.Valid {
			authVal = authValue.String
		}

		webhooks = append(webhooks, map[string]interface{}{
			"id":         id,
			"endpoint":   endpoint,
			"auth_type":  authType,
			"auth_value": authVal,
		})
	}

	return webhooks, rows.Err()
}


// === PAYLOAD TEMPLATES ===

// GetPayloadTemplate retrieves active payload template for attack type
func (pp *PostgresProvider) GetPayloadTemplate(attackType string) (string, string, int, error) {
	var content, contentType string
	var statusCode int

	query := `
		SELECT content, content_type, http_status_code 
		FROM payload_templates 
		WHERE attack_type = $1 AND is_active = TRUE
		ORDER BY priority DESC 
		LIMIT 1
	`

	err := pp.db.QueryRow(query, attackType).Scan(&content, &contentType, &statusCode)
	if err != nil {
		return "", "", 0, err
	}

	return content, contentType, statusCode, nil
}

// CachePayloadTemplate stores a generated payload in the database cache
func (pp *PostgresProvider) CachePayloadTemplate(name, attackType, content string) error {
	query := `
		INSERT INTO payload_templates 
		(name, attack_type, payload_type, content, content_type, http_status_code, is_active, created_at, created_by)
		VALUES ($1, $2, 'dynamic', $3, 'application/json', 200, TRUE, CURRENT_TIMESTAMP, 'llm_cache')
		ON CONFLICT (name) DO UPDATE SET
			content = EXCLUDED.content,
			created_at = CURRENT_TIMESTAMP
	`
	_, err := pp.db.Exec(query, name, attackType, content)
	return err
}

// GetPayloadCacheStats returns statistics about cached payloads
func (pp *PostgresProvider) GetPayloadCacheStats() (int64, int64, error) {
	var totalActive, activeLLM int64
	
	err := pp.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = TRUE").Scan(&totalActive)
	if err != nil {
		return 0, 0, err
	}
	
	err = pp.db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = TRUE AND created_by = 'llm_cache'").Scan(&activeLLM)
	if err != nil {
		return 0, 0, err
	}
	
	return totalActive, activeLLM, nil
}

// AddPayloadCondition adds a condition to a payload template
func (pp *PostgresProvider) AddPayloadCondition(payloadID int64, conditionType, conditionValue, operator string) error {
	query := `
		INSERT INTO payload_conditions (payload_template_id, condition_type, condition_value, operator)
		VALUES ($1, $2, $3, $4)
	`
	_, err := pp.db.Exec(query, payloadID, conditionType, conditionValue, operator)
	return err
}

// RemovePayloadCondition removes a condition from a payload template
func (pp *PostgresProvider) RemovePayloadCondition(conditionID int64) error {
	query := `DELETE FROM payload_conditions WHERE id = $1`
	_, err := pp.db.Exec(query, conditionID)
	return err
}

// GetPayloadConditions retrieves all conditions for a payload template
func (pp *PostgresProvider) GetPayloadConditions(payloadID int64) ([]map[string]interface{}, error) {
	query := `
		SELECT id, condition_type, condition_value, operator
		FROM payload_conditions
		WHERE payload_template_id = $1
		ORDER BY id ASC
	`
	
	rows, err := pp.db.Query(query, payloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var conditions []map[string]interface{}
	for rows.Next() {
		var id int64
		var conditionType, conditionValue, operator string
		
		if err := rows.Scan(&id, &conditionType, &conditionValue, &operator); err != nil {
			continue
		}
		
		conditions = append(conditions, map[string]interface{}{
			"id":              id,
			"condition_type":  conditionType,
			"condition_value": conditionValue,
			"operator":        operator,
		})
	}
	
	return conditions, rows.Err()
}

// UpdatePayloadCondition updates an existing payload condition
func (pp *PostgresProvider) UpdatePayloadCondition(conditionID int64, conditionType, conditionValue, operator string) error {
	query := `
		UPDATE payload_conditions
		SET condition_type = $1, condition_value = $2, operator = $3
		WHERE id = $4
	`
	_, err := pp.db.Exec(query, conditionType, conditionValue, operator, conditionID)
	return err
}



// Configuration methods
func (pp *PostgresProvider) GetConfigValue(appID, category, key string) (string, error) {
	query := `SELECT value FROM config_settings WHERE app_id = $1 AND category = $2 AND key = $3`
	var value string
	err := pp.db.QueryRow(query, appID, category, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (pp *PostgresProvider) SetConfigValue(appID, category, key, value, dataType string, isSensitive bool, updatedBy string) error {
	query := `
		INSERT INTO config_settings (app_id, category, key, value, data_type, is_sensitive, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(app_id, category, key) DO UPDATE SET
			value = $8,
			data_type = $9,
			is_sensitive = $10,
			updated_at = CURRENT_TIMESTAMP,
			updated_by = $11
	`
	_, err := pp.db.Exec(query, appID, category, key, value, dataType, isSensitive, updatedBy, value, dataType, isSensitive, updatedBy)
	return err
}

func (pp *PostgresProvider) GetConfigByCategory(appID, category string) ([]map[string]interface{}, error) {
	query := `
		SELECT key, value, data_type, is_sensitive, updated_at
		FROM config_settings
		WHERE app_id = $1 AND category = $2
	`
	
	rows, err := pp.db.Query(query, appID, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []map[string]interface{}
	for rows.Next() {
		var key, value, dataType string
		var updatedAt time.Time
		var isSensitive bool

		err := rows.Scan(&key, &value, &dataType, &isSensitive, &updatedAt)
		if err != nil {
			continue
		}

		configs = append(configs, map[string]interface{}{
			"key":          key,
			"value":        value,
			"data_type":    dataType,
			"is_sensitive": isSensitive,
			"updated_at":   updatedAt.Format(time.RFC3339),
		})
	}

	return configs, rows.Err()
}

func (pp *PostgresProvider) GetAllConfig(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT category, key, value, data_type, is_sensitive, updated_at
		FROM config_settings
		WHERE app_id = $1
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []map[string]interface{}
	for rows.Next() {
		var category, key, value, dataType string
		var updatedAt time.Time
		var isSensitive bool

		err := rows.Scan(&category, &key, &value, &dataType, &isSensitive, &updatedAt)
		if err != nil {
			continue
		}

		configs = append(configs, map[string]interface{}{
			"category":     category,
			"key":          key,
			"value":        value,
			"data_type":    dataType,
			"is_sensitive": isSensitive,
			"updated_at":   updatedAt.Format(time.RFC3339),
		})
	}

	return configs, rows.Err()
}

func (pp *PostgresProvider) DeleteConfigValue(appID, category, key string) error {
	query := `DELETE FROM config_settings WHERE app_id = $1 AND category = $2 AND key = $3`
	_, err := pp.db.Exec(query, appID, category, key)
	return err
}

// Keycloak methods
func (pp *PostgresProvider) GetKeycloakConfig(appID string) (map[string]interface{}, error) {
	query := `
		SELECT realm, auth_server_url, client_id, client_secret, enabled
		FROM keycloak_config
		WHERE app_id = $1
	`
	
	var realm, authServerURL, clientID, clientSecret string
	var enabled bool

	err := pp.db.QueryRow(query, appID).Scan(&realm, &authServerURL, &clientID, &clientSecret, &enabled)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"realm":           realm,
		"auth_server_url": authServerURL,
		"client_id":       clientID,
		"client_secret":   clientSecret,
		"enabled":         enabled,
	}, nil
}

func (pp *PostgresProvider) SetKeycloakConfig(appID, realm, authServerURL, clientID, clientSecret string) error {
	query := `
		INSERT INTO keycloak_config (app_id, realm, auth_server_url, client_id, client_secret, enabled)
		VALUES ($1, $2, $3, $4, $5, TRUE)
		ON CONFLICT(app_id) DO UPDATE SET
			realm = $6,
			auth_server_url = $7,
			client_id = $8,
			client_secret = $9,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := pp.db.Exec(query, appID, realm, authServerURL, clientID, clientSecret, realm, authServerURL, clientID, clientSecret)
	return err
}

func (pp *PostgresProvider) GetRoleMapping(appID, keycloakRole string) ([]string, error) {
	query := `
		SELECT ifrit_permissions FROM keycloak_role_mappings
		WHERE app_id = $1 AND keycloak_role = $2
	`
	
	var permissionsJSON string
	err := pp.db.QueryRow(query, appID, keycloakRole).Scan(&permissionsJSON)
	if err != nil {
		return nil, err
	}

	var permissions []string
	if err := json.Unmarshal([]byte(permissionsJSON), &permissions); err != nil {
		return nil, err
	}

	return permissions, nil
}

func (pp *PostgresProvider) SetRoleMapping(appID, keycloakRole string, permissions []string) error {
	permissionsJSON, _ := json.Marshal(permissions)
	
	query := `
		INSERT INTO keycloak_role_mappings (app_id, keycloak_role, ifrit_permissions)
		VALUES ($1, $2, $3)
		ON CONFLICT(app_id, keycloak_role) DO UPDATE SET
			ifrit_permissions = $4
	`
	_, err := pp.db.Exec(query, appID, keycloakRole, string(permissionsJSON), string(permissionsJSON))
	return err
}

// Service Token methods
func (pp *PostgresProvider) CreateServiceToken(appID, tokenName, tokenHash, tokenPrefix, keycloakServiceAccountID string, permissions []string, expiresAt *string) (int64, error) {
	permissionsJSON, _ := json.Marshal(permissions)
	
	query := `
		INSERT INTO service_tokens 
		(app_id, token_name, token_hash, token_prefix, keycloak_service_account_id, permissions, is_active, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)
		RETURNING id
	`
	
	var id int64
	err := pp.db.QueryRow(query, appID, tokenName, tokenHash, tokenPrefix, keycloakServiceAccountID, string(permissionsJSON), expiresAt).Scan(&id)
	return id, err
}

func (pp *PostgresProvider) ValidateServiceToken(tokenHash string) (map[string]interface{}, error) {
	query := `
		SELECT id, app_id, token_name, permissions, is_active, expires_at, keycloak_service_account_id
		FROM service_tokens
		WHERE token_hash = $1 AND is_active = TRUE
	`
	
	var id int64
	var appID, tokenName, permissionsJSON string
	var isActive bool
	var expiresAt, keycloakServiceAccountID sql.NullString

	err := pp.db.QueryRow(query, tokenHash).Scan(&id, &appID, &tokenName, &permissionsJSON, &isActive, &expiresAt, &keycloakServiceAccountID)
	if err != nil {
		return nil, err
	}

	// Check expiry
	if expiresAt.Valid {
		expiry, _ := time.Parse(time.RFC3339, expiresAt.String)
		if time.Now().After(expiry) {
			return nil, fmt.Errorf("token expired")
		}
	}

	var permissions []string
	json.Unmarshal([]byte(permissionsJSON), &permissions)

	result := map[string]interface{}{
		"id":          id,
		"app_id":      appID,
		"token_name":  tokenName,
		"permissions": permissions,
		"is_active":   isActive,
	}

	if keycloakServiceAccountID.Valid {
		result["keycloak_service_account_id"] = keycloakServiceAccountID.String
	}

	return result, nil
}

func (pp *PostgresProvider) RevokeServiceToken(tokenID int64) error {
	query := `UPDATE service_tokens SET is_active = FALSE WHERE id = $1`
	_, err := pp.db.Exec(query, tokenID)
	return err
}

func (pp *PostgresProvider) GetServiceTokens(appID string) ([]map[string]interface{}, error) {
	query := `
		SELECT id, token_name, token_prefix, permissions, is_active, created_at, last_used_at, expires_at
		FROM service_tokens
		WHERE app_id = $1
		ORDER BY created_at DESC
	`
	
	rows, err := pp.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []map[string]interface{}
	for rows.Next() {
		var id int64
		var tokenName, tokenPrefix, permissionsJSON string
		var createdAt time.Time
		var isActive bool
		var lastUsedAt, expiresAt sql.NullTime

		err := rows.Scan(&id, &tokenName, &tokenPrefix, &permissionsJSON, &isActive, &createdAt, &lastUsedAt, &expiresAt)
		if err != nil {
			continue
		}

		var permissions []string
		json.Unmarshal([]byte(permissionsJSON), &permissions)

		token := map[string]interface{}{
			"id":           id,
			"token_name":   tokenName,
			"token_prefix": tokenPrefix,
			"permissions":  permissions,
			"is_active":    isActive,
			"created_at":   createdAt.Format(time.RFC3339),
		}

		if lastUsedAt.Valid {
			token["last_used_at"] = lastUsedAt.Time.Format(time.RFC3339)
		}
		if expiresAt.Valid {
			token["expires_at"] = expiresAt.Time.Format(time.RFC3339)
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (pp *PostgresProvider) UpdateServiceTokenLastUsed(tokenID int64) error {
	query := `UPDATE service_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := pp.db.Exec(query, tokenID)
	return err
}
