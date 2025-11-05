package database

import (
	"database/sql"
	"encoding/json"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
	mu sync.RWMutex
}

func NewSQLiteDB(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	s := &SQLiteDB{db: db}
	if err := s.createTables(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *SQLiteDB) createTables() error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS attack_patterns (
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
		`CREATE TABLE IF NOT EXISTS attack_instances (
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
		`CREATE TABLE IF NOT EXISTS attacker_profiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_ip TEXT UNIQUE,
			total_requests INTEGER DEFAULT 0,
			successful_probes INTEGER DEFAULT 0,
			attack_types TEXT,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS llm_api_calls (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_fingerprint TEXT,
			llm_provider TEXT,
			was_attack BOOLEAN,
			attack_type TEXT,
			confidence REAL,
			tokens_used INTEGER,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS anonymization_log (
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
		`CREATE TABLE IF NOT EXISTS exceptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			path TEXT NOT NULL,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			enabled BOOLEAN DEFAULT 1,
			UNIQUE(ip_address, path)
		)`,
	}

	for _, schema := range schemas {
		if _, err := s.db.Exec(schema); err != nil {
			return err
		}
	}

	return nil
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

func (s *SQLiteDB) StoreAttackPattern(signature, attackType, classification, method, path, payload string, responseCode int, createdBy string, confidence float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attack_patterns (attack_signature, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, created_by, claude_confidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(attack_signature) DO UPDATE SET times_seen = times_seen + 1, last_seen = CURRENT_TIMESTAMP`,
		signature, attackType, classification, method, path, payload, responseCode, createdBy, confidence,
	)
	return err
}

func (s *SQLiteDB) StoreAttackInstance(patternID int64, sourceIP, userAgent, requestedPath, method string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO attack_instances (pattern_id, source_ip, user_agent, requested_path, http_method)
		 VALUES (?, ?, ?, ?, ?)`,
		patternID, sourceIP, userAgent, requestedPath, method,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func (s *SQLiteDB) UpdateAttackerProfile(sourceIP, attackType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attacker_profiles (source_ip, total_requests, attack_types, first_seen, last_seen)
		 VALUES (?, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT(source_ip) DO UPDATE SET 
			total_requests = total_requests + 1,
			attack_types = CASE 
				WHEN attack_types LIKE '%' || ? || '%' THEN attack_types
				ELSE attack_types || ',' || ?
			END,
			last_seen = CURRENT_TIMESTAMP`,
		sourceIP, attackType, attackType, attackType,
	)
	return err
}

func (s *SQLiteDB) SeedPatternsFromFile(filePath string) error {
	data, _ := json.Marshal(map[string]interface{}{
		"patterns": []map[string]interface{}{
			{
				"attack_type":           "env_probe",
				"attack_classification": "reconnaissance",
				"http_method":           "GET",
				"path_pattern":          "/.env",
				"response_code":         200,
				"payload_template":      `{"API_KEY":"sk-prod-12345","DB_HOST":"prod-db.internal","DB_PASS":"SecureP@ss123","DB_USER":"admin"}`,
				"confidence":            0.95,
			},
			{
				"attack_type":           "git_probe",
				"attack_classification": "reconnaissance",
				"http_method":           "GET",
				"path_pattern":          "/.git",
				"response_code":         404,
				"payload_template":      `{"error":"Repository not found","status":404}`,
				"confidence":            0.95,
			},
			{
				"attack_type":           "path_traversal",
				"attack_classification": "exploitation",
				"http_method":           "GET",
				"path_pattern":          "/etc/passwd",
				"response_code":         404,
				"payload_template":      `{"error":"File not found","status":404}`,
				"confidence":            0.90,
			},
			{
				"attack_type":           "admin_probe",
				"attack_classification": "reconnaissance",
				"http_method":           "GET",
				"path_pattern":          "/admin",
				"response_code":         401,
				"payload_template":      `{"error":"Unauthorized","status":401}`,
				"confidence":            0.85,
			},
			{
				"attack_type":           "config_probe",
				"attack_classification": "reconnaissance",
				"http_method":           "GET",
				"path_pattern":          "/config",
				"response_code":         404,
				"payload_template":      `{"error":"Not found","status":404}`,
				"confidence":            0.80,
			},
		},
	})

	var patterns map[string]interface{}
	json.Unmarshal(data, &patterns)

	patternList := patterns["patterns"].([]interface{})
	for _, p := range patternList {
		pattern := p.(map[string]interface{})
		s.StoreAttackPattern(
			"",
			pattern["attack_type"].(string),
			pattern["attack_classification"].(string),
			pattern["http_method"].(string),
			pattern["path_pattern"].(string),
			pattern["payload_template"].(string),
			int(pattern["response_code"].(float64)),
			"seed",
			pattern["confidence"].(float64),
		)
	}

	return nil
}

func (s *SQLiteDB) GetAllPatterns() ([]map[string]interface{}, error) {
s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, attack_type, attack_classification, http_method, path_pattern, COALESCE(payload_template, ''), response_code, claude_confidence
		 FROM attack_patterns`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []map[string]interface{}
	for rows.Next() {
		var id, responseCode int64
		var attackType, classification, method, pathPattern, payloadTemplate string
		var confidence float64

		if err := rows.Scan(&id, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &confidence); err != nil {
			return nil, err
		}

		pattern := map[string]interface{}{
			"id":                    id,
			"attack_type":           attackType,
			"attack_classification": classification,
			"http_method":           method,
			"path_pattern":          pathPattern,
			"payload_template":      payloadTemplate,
			"response_code":         responseCode,
			"confidence":            confidence,
		}
		patterns = append(patterns, pattern)
	}

	return patterns, rows.Err()
	
}

func (s *SQLiteDB) GetAttackInstances(limit int) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, pattern_id, source_ip, user_agent, requested_path, http_method, timestamp 
		 FROM attack_instances 
		 ORDER BY timestamp DESC 
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var instances []map[string]interface{}
	for rows.Next() {
		var id, patternID int64
		var sourceIP, userAgent, requestedPath, httpMethod, timestamp string

		if err := rows.Scan(&id, &patternID, &sourceIP, &userAgent, &requestedPath, &httpMethod, &timestamp); err != nil {
			return nil, err
		}

		// Get attack type from pattern
		attackType := "unknown"
		if patternID > 0 {
			_ = s.db.QueryRow(
				`SELECT attack_type FROM attack_patterns WHERE id = ?`,
				patternID,
			).Scan(&attackType)
		}

		instance := map[string]interface{}{
			"id":              id,
			"pattern_id":      patternID,
			"source_ip":       sourceIP,
			"user_agent":      userAgent,
			"requested_path":  requestedPath,
			"http_method":     httpMethod,
			"attack_type":     attackType,
			"detection_stage": 3,
			"timestamp":       timestamp,
		}
		instances = append(instances, instance)
	}

	return instances, rows.Err()
}

func (s *SQLiteDB) GetAttackerProfiles() ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, source_ip, total_requests, attack_types, first_seen, last_seen 
		 FROM attacker_profiles 
		 ORDER BY total_requests DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []map[string]interface{}
	for rows.Next() {
		var id, totalRequests int64
		var sourceIP, attackTypes, firstSeen, lastSeen string

		if err := rows.Scan(&id, &sourceIP, &totalRequests, &attackTypes, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}

		profile := map[string]interface{}{
			"id":             id,
			"source_ip":      sourceIP,
			"total_requests": totalRequests,
			"attack_types":   attackTypes,
			"first_seen":     firstSeen,
			"last_seen":      lastSeen,
		}
		profiles = append(profiles, profile)
	}

	return profiles, rows.Err()
}
// AddException adds a path pattern to the exceptions whitelist
// Use "*" for ip_address to match any IP for that path
func (s *SQLiteDB) AddException(ipAddress, path, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO exceptions (ip_address, path, reason, enabled)
		 VALUES (?, ?, ?, 1)
		 ON CONFLICT(ip_address, path) DO NOTHING`,
		ipAddress,
		path,
		reason,
	)
	return err
}

// GetDB returns the underlying *sql.DB connection
func (s *SQLiteDB) GetDB() *sql.DB {
	return s.db
}


