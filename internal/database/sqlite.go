package database

import (
	"database/sql"
	"sync"
	"time"

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
	return nil // Tables created in init.go
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// StoreAttackPattern stores an attack pattern (with app_id support)
func (s *SQLiteDB) StoreAttackPattern(appID, signature, attackType, classification, method, path, payload string, responseCode int, createdBy string, confidence float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attack_patterns (app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, payload_template, response_code, created_by, claude_confidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(app_id, attack_signature) DO UPDATE SET times_seen = times_seen + 1, last_seen = CURRENT_TIMESTAMP`,
		appID, signature, attackType, classification, method, path, payload, responseCode, createdBy, confidence,
	)
	return err
}

// StoreAttackInstance stores a detected attack (with app_id support)
func (s *SQLiteDB) StoreAttackInstance(appID string, patternID int64, sourceIP, userAgent, requestedPath, method string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO attack_instances (app_id, pattern_id, source_ip, user_agent, requested_path, http_method)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		appID, patternID, sourceIP, userAgent, requestedPath, method,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// UpdateAttackerProfile updates attacker profile (with app_id support)
func (s *SQLiteDB) UpdateAttackerProfile(appID, sourceIP, attackType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attacker_profiles (app_id, source_ip, total_requests, attack_types, first_seen, last_seen)
		 VALUES (?, ?, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT(app_id, source_ip) DO UPDATE SET 
			total_requests = total_requests + 1,
			attack_types = CASE 
				WHEN attack_types LIKE '%' || ? || '%' THEN attack_types
				ELSE attack_types || ',' || ?
			END,
			last_seen = CURRENT_TIMESTAMP`,
		appID, sourceIP, attackType, attackType, attackType,
	)
	return err
}

// GetAllPatterns retrieves patterns for specific app
func (s *SQLiteDB) GetAllPatterns(appID string) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, app_id, attack_type, attack_classification, http_method, path_pattern, COALESCE(payload_template, ''), response_code, claude_confidence
		 FROM attack_patterns
		 WHERE app_id = ?
		 ORDER BY times_seen DESC`,
		appID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []map[string]interface{}
	for rows.Next() {
		var id, responseCode int64
		var appIDVal, attackType, classification, method, pathPattern, payloadTemplate string
		var confidence float64

		if err := rows.Scan(&id, &appIDVal, &attackType, &classification, &method, &pathPattern, &payloadTemplate, &responseCode, &confidence); err != nil {
			return nil, err
		}

		pattern := map[string]interface{}{
			"id":                    id,
			"app_id":                appIDVal,
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

// GetAttackInstances retrieves attack instances for specific app
func (s *SQLiteDB) GetAttackInstances(appID string, limit int) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, app_id, pattern_id, source_ip, user_agent, requested_path, http_method, timestamp 
		 FROM attack_instances 
		 WHERE app_id = ?
		 ORDER BY timestamp DESC 
		 LIMIT ?`,
		appID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var instances []map[string]interface{}
	for rows.Next() {
		var id, patternID int64
		var appIDVal, sourceIP, userAgent, requestedPath, httpMethod, timestamp string

		if err := rows.Scan(&id, &appIDVal, &patternID, &sourceIP, &userAgent, &requestedPath, &httpMethod, &timestamp); err != nil {
			return nil, err
		}

		// Get attack type from pattern
		attackType := "unknown"
		if patternID > 0 {
			_ = s.db.QueryRow(
				`SELECT attack_type FROM attack_patterns WHERE id = ? AND app_id = ?`,
				patternID, appIDVal,
			).Scan(&attackType)
		}

		instance := map[string]interface{}{
			"id":              id,
			"app_id":          appIDVal,
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

// GetAttackerProfiles retrieves attacker profiles for specific app
func (s *SQLiteDB) GetAttackerProfiles(appID string) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, app_id, source_ip, total_requests, attack_types, first_seen, last_seen 
		 FROM attacker_profiles 
		 WHERE app_id = ?
		 ORDER BY total_requests DESC`,
		appID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []map[string]interface{}
	for rows.Next() {
		var id, totalRequests int64
		var appIDVal, sourceIP, attackTypes, firstSeen, lastSeen string

		if err := rows.Scan(&id, &appIDVal, &sourceIP, &totalRequests, &attackTypes, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}

		profile := map[string]interface{}{
			"id":             id,
			"app_id":         appIDVal,
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

// AddException adds a path pattern to the exceptions whitelist (with app_id support)
func (s *SQLiteDB) AddException(appID, ipAddress, path, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO exceptions (app_id, ip_address, path, reason, enabled)
		 VALUES (?, ?, ?, ?, 1)
		 ON CONFLICT(app_id, ip_address, path) DO NOTHING`,
		appID, ipAddress, path, reason,
	)
	return err
}

// GetExceptions retrieves exceptions for specific app
func (s *SQLiteDB) GetExceptions(appID string) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, app_id, ip_address, path, reason, enabled, created_at
		 FROM exceptions
		 WHERE app_id = ?
		 ORDER BY created_at DESC`,
		appID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var appIDVal, ipAddress, path, reason, createdAt string
		var enabled bool

		if err := rows.Scan(&id, &appIDVal, &ipAddress, &path, &reason, &enabled, &createdAt); err != nil {
			return nil, err
		}

		exception := map[string]interface{}{
			"id":         id,
			"app_id":     appIDVal,
			"ip_address": ipAddress,
			"path":       path,
			"reason":     reason,
			"enabled":    enabled,
			"created_at": createdAt,
		}
		exceptions = append(exceptions, exception)
	}

	return exceptions, rows.Err()
}

// StoreLegitimateRequest stores a validated legitimate request
func (s *SQLiteDB) StoreLegitimateRequest(appID, method, path, pathSig, bodySig, headersSig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO legitimate_requests (app_id, http_method, path, path_signature, body_signature, headers_signature, claude_validated)
		 VALUES (?, ?, ?, ?, ?, ?, 1)
		 ON CONFLICT(app_id, path_signature, body_signature, headers_signature) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			hit_count = hit_count + 1`,
		appID, method, path, pathSig, bodySig, headersSig,
	)
	return err
}

// GetLegitimateRequest checks if request is in legitimate cache
func (s *SQLiteDB) GetLegitimateRequest(appID, pathSig, bodySig, headersSig string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(
			SELECT 1 FROM legitimate_requests
			WHERE app_id = ? AND path_signature = ? AND body_signature = ? AND headers_signature = ?
		)`,
		appID, pathSig, bodySig, headersSig,
	).Scan(&exists)

	return exists, err
}

// AddKeywordException adds a keyword to skip during detection
func (s *SQLiteDB) AddKeywordException(appID, exceptionType, keyword, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO keyword_exceptions (app_id, exception_type, keyword, reason, enabled)
		 VALUES (?, ?, ?, ?, 1)
		 ON CONFLICT(app_id, exception_type, keyword) DO NOTHING`,
		appID, exceptionType, keyword, reason,
	)
	return err
}

// GetKeywordExceptions retrieves keyword exceptions for specific app
func (s *SQLiteDB) GetKeywordExceptions(appID string) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, app_id, exception_type, keyword, reason, enabled
		 FROM keyword_exceptions
		 WHERE app_id = ? AND enabled = 1`,
		appID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []map[string]interface{}
	for rows.Next() {
		var id int64
		var appIDVal, exceptionType, keyword, reason string
		var enabled bool

		if err := rows.Scan(&id, &appIDVal, &exceptionType, &keyword, &reason, &enabled); err != nil {
			return nil, err
		}

		exception := map[string]interface{}{
			"id":               id,
			"app_id":           appIDVal,
			"exception_type":   exceptionType,
			"keyword":          keyword,
			"reason":           reason,
			"enabled":          enabled,
		}
		exceptions = append(exceptions, exception)
	}

	return exceptions, rows.Err()
}

// StoreAttackerInteraction records attacker behavior
func (s *SQLiteDB) StoreAttackerInteraction(appID string, attackInstanceID int64, sourceIP, interactionType, interactionData string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO attacker_interactions (app_id, attack_instance_id, source_ip, interaction_type, interaction_data)
		 VALUES (?, ?, ?, ?, ?)`,
		appID, attackInstanceID, sourceIP, interactionType, interactionData,
	)
	return err
}

// GetIntelCollectionTemplates retrieves active intel collection templates
func (s *SQLiteDB) GetIntelCollectionTemplates() ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, name, template_type, content, description, is_active
		 FROM intel_collection_templates
		 WHERE is_active = 1`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id int64
		var name, templateType, content, description string
		var isActive bool

		if err := rows.Scan(&id, &name, &templateType, &content, &description, &isActive); err != nil {
			return nil, err
		}

		template := map[string]interface{}{
			"id":              id,
			"name":            name,
			"template_type":   templateType,
			"content":         content,
			"description":     description,
			"is_active":       isActive,
		}
		templates = append(templates, template)
	}

	return templates, rows.Err()
}

// CreateAPIUser creates a new API user
func (s *SQLiteDB) CreateAPIUser(username, email, passwordHash, role string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO api_users (username, email, password_hash, role, is_active)
		 VALUES (?, ?, ?, ?, 1)`,
		username, email, passwordHash, role,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetAPIUser retrieves user by username
func (s *SQLiteDB) GetAPIUser(username string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var id int64
	var email, passwordHash, role string
	var isActive bool
	var lastLogin sql.NullString

	err := s.db.QueryRow(
		`SELECT id, email, password_hash, role, is_active, COALESCE(last_login, '')
		 FROM api_users
		 WHERE username = ?`,
		username,
	).Scan(&id, &email, &passwordHash, &role, &isActive, &lastLogin)

	if err != nil {
		return nil, err
	}

	user := map[string]interface{}{
		"id":           id,
		"username":     username,
		"email":        email,
		"password_hash": passwordHash,
		"role":         role,
		"is_active":    isActive,
		"last_login":   lastLogin.String,
	}

	return user, nil
}

// CreateAPIToken creates a new API token
func (s *SQLiteDB) CreateAPIToken(userID int64, tokenName, tokenHash, tokenPrefix, appID, permissions string, expiresAt string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		`INSERT INTO api_tokens (user_id, token_name, token_hash, token_prefix, app_id, permissions, is_active, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?)`,
		userID, tokenName, tokenHash, tokenPrefix, appID, permissions, expiresAt,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// ValidateAPIToken checks if token is valid
func (s *SQLiteDB) ValidateAPIToken(tokenHash string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var userID int64
	var username, role, appID string
	var isActive bool
	var expiresAt sql.NullString

	err := s.db.QueryRow(
		`SELECT t.user_id, u.username, u.role, t.app_id, t.is_active, COALESCE(t.expires_at, '')
		 FROM api_tokens t
		 JOIN api_users u ON t.user_id = u.id
		 WHERE t.token_hash = ? AND t.is_active = 1 AND u.is_active = 1`,
		tokenHash,
	).Scan(&userID, &username, &role, &appID, &isActive, &expiresAt)

	if err != nil {
		return nil, err
	}

	token := map[string]interface{}{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"app_id":   appID,
		"is_active": isActive,
		"expires_at": expiresAt.String,
	}

	return token, nil
}

// GetDB returns the underlying *sql.DB connection
func (s *SQLiteDB) GetDB() *sql.DB {
	return s.db
}

// StoreThreatIntelligence stores or updates threat intelligence for an IP
func (s *SQLiteDB) StoreThreatIntelligence(appID, sourceIP string, riskScore int, abuseIPDBScore *float64, abuseIPDBReports *int, virusTotalMalicious, virusTotalSuspicious, ipinfoVPN, ipinfoProxy bool, country, org, privacyType string, threatLevel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cachedUntil := time.Now().AddDate(0, 0, 1) // 24 hours from now
	var err error
	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO attacker_profiles (app_id, source_ip)
		VALUES (?, ?)
	`, appID, sourceIP)
	
	if err != nil {
		return err
	}



	_, err = s.db.Exec(`
		INSERT INTO threat_intelligence 
		(app_id, source_ip, risk_score, abuseipdb_score, abuseipdb_reports, virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy, ipinfo_country, ipinfo_org, ipinfo_privacy_type, threat_level, enriched_at, cached_until, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(app_id, source_ip) DO UPDATE SET
			risk_score = excluded.risk_score,
			abuseipdb_score = excluded.abuseipdb_score,
			abuseipdb_reports = excluded.abuseipdb_reports,
			virustotal_malicious = excluded.virustotal_malicious,
			virustotal_suspicious = excluded.virustotal_suspicious,
			is_vpn = excluded.is_vpn,
			is_proxy = excluded.is_proxy,
			ipinfo_country = excluded.ipinfo_country,
			ipinfo_org = excluded.ipinfo_org,
			ipinfo_privacy_type = excluded.ipinfo_privacy_type,
			threat_level = excluded.threat_level,
			enriched_at = CURRENT_TIMESTAMP,
			cached_until = ?,
			updated_at = CURRENT_TIMESTAMP
	`,
		appID, sourceIP, riskScore, abuseIPDBScore, abuseIPDBReports, virusTotalMalicious, virusTotalSuspicious, ipinfoVPN, ipinfoProxy, country, org, privacyType, threatLevel, cachedUntil, cachedUntil,
	)

	return err
}

// GetThreatIntelligence retrieves threat intelligence for an IP
func (s *SQLiteDB) GetThreatIntelligence(appID, sourceIP string) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		id, riskScore, abuseIPDBReports, virusTotalMalicious, virusTotalSuspicious int64
		abuseIPDBScore sql.NullFloat64
		isVPN, isProxy, isHosting, isTor bool
		country, org, privacyType, threatLevel, enrichedAt, cachedUntil, lastAttackAt string
		totalAttacks int64
	)

	err := s.db.QueryRow(`
		SELECT id, risk_score, abuseipdb_score, abuseipdb_reports, virustotal_malicious, virustotal_suspicious, is_vpn, is_proxy, is_hosting, is_tor, ipinfo_country, ipinfo_org, ipinfo_privacy_type, threat_level, enriched_at, cached_until, last_attack_at, total_attacks
		FROM threat_intelligence
		WHERE app_id = ? AND source_ip = ?
	`, appID, sourceIP).Scan(&id, &riskScore, &abuseIPDBScore, &abuseIPDBReports, &virusTotalMalicious, &virusTotalSuspicious, &isVPN, &isProxy, &isHosting, &isTor, &country, &org, &privacyType, &threatLevel, &enrichedAt, &cachedUntil, &lastAttackAt, &totalAttacks)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return map[string]interface{}{
		"id":                    id,
		"app_id":                appID,
		"source_ip":             sourceIP,
		"risk_score":            riskScore,
		"abuseipdb_score":       abuseIPDBScore.Float64,
		"abuseipdb_reports":     abuseIPDBReports,
		"virustotal_malicious":  virusTotalMalicious,
		"virustotal_suspicious": virusTotalSuspicious,
		"is_vpn":                isVPN,
		"is_proxy":              isProxy,
		"is_hosting":            isHosting,
		"is_tor":                isTor,
		"country":               country,
		"org":                   org,
		"privacy_type":          privacyType,
		"threat_level":          threatLevel,
		"enriched_at":           enrichedAt,
		"cached_until":          cachedUntil,
		"last_attack_at":        lastAttackAt,
		"total_attacks":         totalAttacks,
	}, nil
}

// GetTopThreatsByRiskScore retrieves top attackers by risk score for an app
func (s *SQLiteDB) GetTopThreatsByRiskScore(appID string, limit int) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, source_ip, risk_score, threat_level, total_attacks, ipinfo_country, updated_at
		FROM threat_intelligence
		WHERE app_id = ?
		ORDER BY risk_score DESC
		LIMIT ?
	`, appID, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []map[string]interface{}
	for rows.Next() {
		var id, riskScore, totalAttacks int64
		var sourceIP, threatLevel, country, updatedAt string

		if err := rows.Scan(&id, &sourceIP, &riskScore, &threatLevel, &totalAttacks, &country, &updatedAt); err != nil {
			continue
		}

		threats = append(threats, map[string]interface{}{
			"id":           id,
			"source_ip":    sourceIP,
			"risk_score":   riskScore,
			"threat_level": threatLevel,
			"total_attacks": totalAttacks,
			"country":      country,
			"updated_at":   updatedAt,
		})
	}

	return threats, rows.Err()
}

// IsThreatIntelligenceCached checks if threat intel data is still valid (within cache TTL)
func (s *SQLiteDB) IsThreatIntelligenceCached(appID, sourceIP string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cachedUntil string
	err := s.db.QueryRow(`
		SELECT cached_until FROM threat_intelligence
		WHERE app_id = ? AND source_ip = ?
	`, appID, sourceIP).Scan(&cachedUntil)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	parsedTime, err := time.Parse(time.RFC3339, cachedUntil)
	if err != nil {
		return false, err
	}

	return time.Now().Before(parsedTime), nil
}
