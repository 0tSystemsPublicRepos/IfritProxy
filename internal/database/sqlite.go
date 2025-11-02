package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
	mu sync.RWMutex
}

type AttackPattern struct {
	AttackSignature     string  `json:"attack_signature"`
	AttackType          string  `json:"attack_type"`
	AttackClassification string `json:"attack_classification"`
	HTTPMethod          string  `json:"http_method"`
	PathPattern         string  `json:"path_pattern"`
	PayloadTemplate     string  `json:"payload_template"`
	ResponseCode        int64   `json:"response_code"`
	CreatedBy           string  `json:"created_by"`
}

type PatternsFile struct {
	Patterns []AttackPattern `json:"patterns"`
}

func NewSQLiteDB(path string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	sqliteDB := &SQLiteDB{db: db}
	if err := sqliteDB.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return sqliteDB, nil
}

func (s *SQLiteDB) initSchema() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS exceptions (
			id INTEGER PRIMARY KEY,
			ip_address TEXT,
			path TEXT,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			enabled BOOLEAN DEFAULT 1
		)`,

		`CREATE TABLE IF NOT EXISTS attack_patterns (
			id INTEGER PRIMARY KEY,
			attack_signature TEXT UNIQUE,
			attack_type TEXT,
			attack_classification TEXT,
			http_method TEXT,
			path_pattern TEXT,
			payload_template TEXT,
			response_code INTEGER,
			times_seen INTEGER DEFAULT 1,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP,
			created_by TEXT,
			claude_confidence FLOAT
		)`,

		`CREATE TABLE IF NOT EXISTS attack_instances (
			id INTEGER PRIMARY KEY,
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
			id INTEGER PRIMARY KEY,
			source_ip TEXT UNIQUE,
			total_requests INTEGER DEFAULT 0,
			successful_probes INTEGER DEFAULT 0,
			attack_types TEXT,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS llm_api_calls (
			id INTEGER PRIMARY KEY,
			request_fingerprint TEXT,
			llm_provider TEXT,
			was_attack BOOLEAN,
			attack_type TEXT,
			confidence FLOAT,
			tokens_used INTEGER,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS anonymization_log (
			id INTEGER PRIMARY KEY,
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
	}

	for _, table := range tables {
		if _, err := s.db.Exec(table); err != nil {
			return err
		}
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_attack_patterns_type ON attack_patterns(attack_type)`,
		`CREATE INDEX IF NOT EXISTS idx_attack_patterns_signature ON attack_patterns(attack_signature)`,
		`CREATE INDEX IF NOT EXISTS idx_attack_instances_ip ON attack_instances(source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_attack_instances_timestamp ON attack_instances(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_attacker_profiles_ip ON attacker_profiles(source_ip)`,
	}

	for _, index := range indexes {
		s.db.Exec(index)
	}

	return nil
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

func (s *SQLiteDB) GetDB() *sql.DB {
	return s.db
}

// Seed patterns from JSON file (call this on startup)
func (s *SQLiteDB) SeedPatternsFromFile(filePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read patterns file: %w", err)
	}

	var patternsFile PatternsFile
	if err := json.Unmarshal(data, &patternsFile); err != nil {
		return fmt.Errorf("failed to parse patterns file: %w", err)
	}

	seedCount := 0
	for _, p := range patternsFile.Patterns {
		// Check if pattern already exists
		_, err := s.getPatternBySignatureUnsafe(p.AttackSignature)
		if err == nil {
			// Pattern already exists
			continue
		}

		// Insert new pattern
		_, err = s.storeAttackPatternUnsafe(
			p.AttackSignature,
			p.AttackType,
			p.AttackClassification,
			p.HTTPMethod,
			p.PathPattern,
			p.PayloadTemplate,
			p.ResponseCode,
			p.CreatedBy,
			0.95, // confidence
		)
		if err != nil {
			fmt.Printf("Error seeding pattern %s: %v\n", p.AttackType, err)
			continue
		}
		seedCount++
	}

	fmt.Printf("✓ Seeded %d attack patterns from database\n", seedCount)
	return nil
}

func (s *SQLiteDB) StoreAttackInstance(patternID int64, sourceIP, userAgent, path, method string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO attack_instances (pattern_id, source_ip, user_agent, requested_path, http_method)
		 VALUES (?, ?, ?, ?, ?)`,
		patternID, sourceIP, userAgent, path, method,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func (s *SQLiteDB) GetAttacksByIP(ip string, limit int) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, pattern_id, source_ip, requested_path, http_method, timestamp
		 FROM attack_instances WHERE source_ip = ? ORDER BY timestamp DESC LIMIT ?`,
		ip, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attacks []map[string]interface{}
	for rows.Next() {
		var id, patternID int64
		var sourceIP, path, method, timestamp string

		if err := rows.Scan(&id, &patternID, &sourceIP, &path, &method, &timestamp); err != nil {
			return nil, err
		}

		attack := map[string]interface{}{
			"id":         id,
			"pattern_id": patternID,
			"source_ip":  sourceIP,
			"path":       path,
			"method":     method,
			"timestamp":  timestamp,
		}
		attacks = append(attacks, attack)
	}

	return attacks, rows.Err()
}

// Private method without lock (for use within locked sections)
func (s *SQLiteDB) storeAttackPatternUnsafe(signature, attackType, classification, method, pathPattern, payloadTemplate string, responseCode int64, createdBy string, confidence float64) (int64, error) {
	result, err := s.db.Exec(
		`INSERT INTO attack_patterns (attack_signature, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, created_by, claude_confidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		signature, attackType, classification, method, pathPattern, payloadTemplate, responseCode, createdBy, confidence,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// Public method with lock
func (s *SQLiteDB) StoreAttackPattern(signature, attackType, classification, method, pathPattern, payloadTemplate string, responseCode int64, createdBy string, confidence float64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storeAttackPatternUnsafe(signature, attackType, classification, method, pathPattern, payloadTemplate, responseCode, createdBy, confidence)
}

// Private method without lock
func (s *SQLiteDB) getPatternBySignatureUnsafe(signature string) (map[string]interface{}, error) {
	row := s.db.QueryRow(
		`SELECT id, attack_type, attack_classification, payload_template, response_code, times_seen, claude_confidence
		 FROM attack_patterns WHERE attack_signature = ?`,
		signature,
	)

	var id, timesSeen, responseCode int64
	var attackType, classification, payloadTemplate string
	var confidence float64

	err := row.Scan(&id, &attackType, &classification, &payloadTemplate, &responseCode, &timesSeen, &confidence)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                id,
		"attack_type":       attackType,
		"classification":    classification,
		"payload_template":  payloadTemplate,
		"response_code":     responseCode,
		"times_seen":        timesSeen,
		"confidence":        confidence,
	}, nil
}

// Public method with lock
func (s *SQLiteDB) GetPatternBySignature(signature string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getPatternBySignatureUnsafe(signature)
}

func (s *SQLiteDB) UpdateAttackerProfile(sourceIP string, attackType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attacker_profiles (source_ip, total_requests, attack_types, first_seen, last_seen)
		 VALUES (?, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT(source_ip) DO UPDATE SET
		   total_requests = total_requests + 1,
		   last_seen = CURRENT_TIMESTAMP,
		   attack_types = attack_types || ',' || ?`,
		sourceIP, attackType, attackType,
	)
	return err
}

func (s *SQLiteDB) GetAttackerProfile(sourceIP string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(
		`SELECT id, source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen
		 FROM attacker_profiles WHERE source_ip = ?`,
		sourceIP,
	)

	var id, totalRequests, successfulProbes int64
	var ip, attackTypes, firstSeen, lastSeen string

	err := row.Scan(&id, &ip, &totalRequests, &successfulProbes, &attackTypes, &firstSeen, &lastSeen)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                id,
		"source_ip":         ip,
		"total_requests":    totalRequests,
		"successful_probes": successfulProbes,
		"attack_types":      attackTypes,
		"first_seen":        firstSeen,
		"last_seen":         lastSeen,
	}, nil
}

func (s *SQLiteDB) GetAllPatterns() ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, claude_confidence
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
