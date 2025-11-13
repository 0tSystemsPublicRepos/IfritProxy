package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
	"crypto/rand"
	"math/big"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
)

var db *sql.DB

func init() {
	cobra.OnInitialize(initDB)
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "data/ifrit.db")
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ifrit-cli",
		Short: "IFRIT CLI - Complete Database Management",
		Long: `IFRIT CLI manages all IFRIT Proxy database entities.
Manage attacks, patterns, attackers, exceptions, keyword exceptions, intel templates, and more.`,
	}

	// Attack commands
	attackCmd := &cobra.Command{
		Use:   "attack",
		Short: "Manage attack instances",
	}
	attackCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List recent attacks", Run: listAttacks},
		&cobra.Command{Use: "view [id]", Short: "View attack details", Args: cobra.ExactArgs(1), Run: viewAttack},
		&cobra.Command{Use: "stats", Short: "Show attack statistics", Run: attackStats},
		&cobra.Command{Use: "by-ip [ip]", Short: "Attacks from IP", Args: cobra.ExactArgs(1), Run: attacksByIP},
		&cobra.Command{Use: "by-path [path]", Short: "Attacks on path", Args: cobra.ExactArgs(1), Run: attacksByPath},
	)

	// Pattern commands
	patternCmd := &cobra.Command{
		Use:   "pattern",
		Short: "Manage attack patterns",
	}
	patternCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all patterns", Run: listPatterns},
		&cobra.Command{Use: "view [id]", Short: "View pattern details", Args: cobra.ExactArgs(1), Run: viewPattern},
		&cobra.Command{Use: "add [type] [signature]", Short: "Add new pattern", Args: cobra.MinimumNArgs(2), Run: addPattern},
		&cobra.Command{Use: "remove [id]", Short: "Remove pattern", Args: cobra.ExactArgs(1), Run: removePattern},
	)

	// Attacker commands
	attackerCmd := &cobra.Command{
		Use:   "attacker",
		Short: "Manage attacker profiles",
	}
	attackerCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all attackers", Run: listAttackers},
		&cobra.Command{Use: "view [id]", Short: "View attacker details", Args: cobra.ExactArgs(1), Run: viewAttacker},
		&cobra.Command{Use: "search [ip]", Short: "Search attacker by IP", Args: cobra.ExactArgs(1), Run: searchAttacker},
		&cobra.Command{Use: "remove [id]", Short: "Remove attacker profile", Args: cobra.ExactArgs(1), Run: removeAttacker},
	)

	// Exception commands
	exceptionCmd := &cobra.Command{
		Use:   "exception",
		Short: "Manage exceptions (whitelists)",
	}
	exceptionCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all exceptions", Run: listExceptions},
		&cobra.Command{Use: "view [id]", Short: "View exception details", Args: cobra.ExactArgs(1), Run: viewException},
		&cobra.Command{Use: "add [ip] [path]", Short: "Add exception (use - for any)", Args: cobra.ExactArgs(2), Run: addException},
		&cobra.Command{Use: "remove [id]", Short: "Remove exception", Args: cobra.ExactArgs(1), Run: removeException},
		&cobra.Command{Use: "enable [id]", Short: "Enable exception", Args: cobra.ExactArgs(1), Run: enableException},
		&cobra.Command{Use: "disable [id]", Short: "Disable exception", Args: cobra.ExactArgs(1), Run: disableException},
	)

	// Keyword Exception commands
	keywordCmd := &cobra.Command{
		Use:   "keyword",
		Short: "Manage keyword exceptions",
	}
	keywordCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all keyword exceptions", Run: listKeywordExceptions},
		&cobra.Command{Use: "view [id]", Short: "View keyword exception details", Args: cobra.ExactArgs(1), Run: viewKeywordException},
		&cobra.Command{Use: "add [type] [keyword]", Short: "Add keyword exception (path|body_field|header)", Args: cobra.ExactArgs(2), Run: addKeywordException},
		&cobra.Command{Use: "remove [id]", Short: "Remove keyword exception", Args: cobra.ExactArgs(1), Run: removeKeywordException},
	)

	// Intel Template commands
	intelCmd := &cobra.Command{
		Use:   "intel",
		Short: "Manage intel collection templates",
	}
	intelCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all intel templates", Run: listIntelTemplates},
		&cobra.Command{Use: "view [id]", Short: "View intel template details", Args: cobra.ExactArgs(1), Run: viewIntelTemplate},
		&cobra.Command{Use: "toggle [id]", Short: "Toggle intel template active status", Args: cobra.ExactArgs(1), Run: toggleIntelTemplate},
	)

	// Payload Template commands
	payloadCmd := &cobra.Command{
		Use:   "payload",
		Short: "Manage payload templates",
	}
	payloadCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all payload templates", Run: listPayloads},
		&cobra.Command{Use: "view [id]", Short: "View payload template details", Args: cobra.ExactArgs(1), Run: viewPayload},
		&cobra.Command{Use: "stats", Short: "Payload statistics", Run: payloadStats},
	)

	// Legitimate requests commands
	legitimateCmd := &cobra.Command{
		Use:   "legitimate",
		Short: "Query legitimate requests cache",
	}
	legitimateCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List cached legitimate requests", Run: listLegitimate},
		&cobra.Command{Use: "stats", Short: "Cache statistics", Run: legitimateStats},
	)

	// Attacker interactions commands
	interactionCmd := &cobra.Command{
		Use:   "interaction",
		Short: "Query attacker interactions",
	}
	interactionCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List recent interactions", Run: listInteractions},
		&cobra.Command{Use: "by-ip [ip]", Short: "Interactions from IP", Args: cobra.ExactArgs(1), Run: interactionsByIP},
	)

	// Threat Intelligence commands
	threatCmd := &cobra.Command{
		Use:   "threat",
		Short: "Query threat intelligence data",
	}
	threatCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all enriched threats", Run: listThreats},
		&cobra.Command{Use: "view [ip]", Short: "View threat details for IP", Args: cobra.ExactArgs(1), Run: viewThreat},
		&cobra.Command{Use: "top [limit]", Short: "Top threats by risk score", Args: cobra.MaximumNArgs(1), Run: topThreats},
		&cobra.Command{Use: "stats", Short: "Threat intelligence statistics", Run: threatStats},
	)

	// Database commands
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations",
	}
	dbCmd.AddCommand(
		&cobra.Command{Use: "stats", Short: "Database statistics", Run: dbStats},
		&cobra.Command{Use: "schema", Short: "Show database schema", Run: showSchema},
	)

	// API Token commands
	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage API tokens",
	}
	tokenCmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all API tokens", Run: listTokens},
		&cobra.Command{Use: "create [user_id] [token_name]", Short: "Create new API token", Args: cobra.ExactArgs(2), Run: createToken},
		&cobra.Command{Use: "revoke [id]", Short: "Revoke API token", Args: cobra.ExactArgs(1), Run: revokeToken},
		&cobra.Command{Use: "validate [token]", Short: "Validate API token", Args: cobra.ExactArgs(1), Run: validateToken},
	)

	rootCmd.AddCommand(attackCmd, patternCmd, attackerCmd, exceptionCmd, keywordCmd, intelCmd, payloadCmd, legitimateCmd, interactionCmd, threatCmd, dbCmd, tokenCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// ============== ATTACK COMMANDS ==============

func listAttacks(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, pattern_id, source_ip, requested_path, http_method, timestamp
		FROM attack_instances ORDER BY timestamp DESC LIMIT 50
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tPATTERN ID\tSOURCE IP\tMETHOD\tPATH\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id, patternID int
		var appID, sourceIP, path, method, timestamp string
		rows.Scan(&id, &appID, &patternID, &sourceIP, &path, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\n", id, appID, patternID, sourceIP, method, path, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d attacks\n", count)
}

func viewAttack(cmd *cobra.Command, args []string) {
	var id, patternID int
	var appID, sourceIP, userAgent, path, method, timestamp string

	err := db.QueryRow(`
		SELECT id, app_id, pattern_id, source_ip, user_agent, requested_path, http_method, timestamp
		FROM attack_instances WHERE id = ?
	`, args[0]).Scan(&id, &appID, &patternID, &sourceIP, &userAgent, &path, &method, &timestamp)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf(`
Attack #%d
=========
App ID:            %s
Pattern ID:        %d
Source IP:         %s
User Agent:        %s
Path:              %s
Method:            %s
Timestamp:         %s
`, id, appID, patternID, sourceIP, userAgent, path, method, timestamp)
}

func attackStats(cmd *cobra.Command, args []string) {
	var total, uniqueIPs int
	var latest string

	db.QueryRow(`
		SELECT COUNT(*), COUNT(DISTINCT source_ip), MAX(timestamp)
		FROM attack_instances
	`).Scan(&total, &uniqueIPs, &latest)

	fmt.Printf(`
Attack Statistics
==================
Total Attacks:       %d
Unique Attackers:    %d
Latest Attack:       %s
`, total, uniqueIPs, latest)
}

func attacksByIP(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, requested_path, http_method, timestamp
		FROM attack_instances WHERE source_ip = ? ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Attacks from %s\n", args[0])
	fmt.Fprintln(w, "ID\tMETHOD\tPATH\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id int
		var path, method, timestamp string
		rows.Scan(&id, &path, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, method, path, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", count)
}

func attacksByPath(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, http_method, timestamp
		FROM attack_instances WHERE requested_path = ? ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Attacks on %s\n", args[0])
	fmt.Fprintln(w, "ID\tSOURCE IP\tMETHOD\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id int
		var sourceIP, method, timestamp string
		rows.Scan(&id, &sourceIP, &method, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, sourceIP, method, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", count)
}

// ============== PATTERN COMMANDS ==============

func listPatterns(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, attack_type, http_method, path_pattern, times_seen, last_seen
		FROM attack_patterns ORDER BY times_seen DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tTYPE\tMETHOD\tPATTERN\tSEEN\tLAST SEEN")

	count := 0
	for rows.Next() {
		var id, timesSeen int
		var appID, attackType, method, pattern, lastSeen string
		rows.Scan(&id, &appID, &attackType, &method, &pattern, &timesSeen, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s\n", id, appID, attackType, method, pattern, timesSeen, lastSeen)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d patterns\n", count)
}

func viewPattern(cmd *cobra.Command, args []string) {
	var id, responseCode, timesSeen int
	var appID, signature, attackType, classification, method, pathPattern, payload, createdBy string
	var confidence sql.NullFloat64
	var firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern,
		       payload_template, response_code, times_seen, first_seen, last_seen, created_by, claude_confidence
		FROM attack_patterns WHERE id = ?
	`, args[0]).Scan(&id, &appID, &signature, &attackType, &classification, &method, &pathPattern,
		&payload, &responseCode, &timesSeen, &firstSeen, &lastSeen, &createdBy, &confidence)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	conf := "N/A"
	if confidence.Valid {
		conf = fmt.Sprintf("%.2f", confidence.Float64)
	}

	fmt.Printf(`
Pattern #%d
==========
App ID:            %s
Signature:         %s
Attack Type:       %s
Classification:    %s
Method:            %s
Path Pattern:      %s
Response Code:     %d
Times Seen:        %d
Confidence:        %s
Created By:        %s
First Seen:        %s
Last Seen:         %s
`, id, appID, signature, attackType, classification, method, pathPattern,
		responseCode, timesSeen, conf, createdBy, firstSeen, lastSeen)
}

func addPattern(cmd *cobra.Command, args []string) {
	attackType := args[0]
	signature := args[1]

	stmt, err := db.Prepare(`
		INSERT INTO attack_patterns (app_id, attack_signature, attack_type, attack_classification, http_method, path_pattern, created_by)
		VALUES ('default', ?, ?, 'custom', 'GET', ?, 'cli')
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(signature, attackType, signature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Printf("✓ Pattern added (ID: %d)\n", id)
}

func removePattern(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("DELETE FROM attack_patterns WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Printf("✓ Pattern removed\n")
	} else {
		fmt.Printf("✗ Pattern not found\n")
	}
}

// ============== ATTACKER COMMANDS ==============

func listAttackers(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, source_ip, total_requests, last_seen
		FROM attacker_profiles ORDER BY total_requests DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tIP ADDRESS\tREQUESTS\tLAST SEEN")

	count := 0
	for rows.Next() {
		var id, totalReqs int
		var appID, ip, lastSeen string
		rows.Scan(&id, &appID, &ip, &totalReqs, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n", id, appID, ip, totalReqs, lastSeen)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d attackers\n", count)
}

func viewAttacker(cmd *cobra.Command, args []string) {
	var id, totalReqs int
	var appID, ip, attackTypes, firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, app_id, source_ip, total_requests, attack_types, first_seen, last_seen
		FROM attacker_profiles WHERE id = ?
	`, args[0]).Scan(&id, &appID, &ip, &totalReqs, &attackTypes, &firstSeen, &lastSeen)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf(`
Attacker Profile #%d
===================
App ID:        %s
IP Address:    %s
Total Requests: %d
Attack Types:  %s
First Seen:    %s
Last Seen:     %s
`, id, appID, ip, totalReqs, attackTypes, firstSeen, lastSeen)
}

func searchAttacker(cmd *cobra.Command, args []string) {
	var id, totalReqs int
	var appID, attackTypes, firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, app_id, total_requests, attack_types, first_seen, last_seen
		FROM attacker_profiles WHERE source_ip = ?
	`, args[0]).Scan(&id, &appID, &totalReqs, &attackTypes, &firstSeen, &lastSeen)

	if err == sql.ErrNoRows {
		fmt.Printf("✗ No attacker profile for IP: %s\n", args[0])
		return
	}
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf(`
Attacker Profile for %s
======================
ID:             %d
App ID:         %s
Total Requests: %d
Attack Types:   %s
First Seen:     %s
Last Seen:      %s
`, args[0], id, appID, totalReqs, attackTypes, firstSeen, lastSeen)
}

func removeAttacker(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("DELETE FROM attacker_profiles WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Printf("✓ Attacker profile removed\n")
	} else {
		fmt.Printf("✗ Profile not found\n")
	}
}

// ============== EXCEPTION COMMANDS ==============

func listExceptions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, ip_address, path, reason, enabled, created_at
		FROM exceptions ORDER BY created_at DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tIP\tPATH\tREASON\tENABLED\tCREATED")

	count := 0
	for rows.Next() {
		var id int
		var appID, ip, path, reason, created string
		var enabled sql.NullBool
		rows.Scan(&id, &appID, &ip, &path, &reason, &enabled, &created)
		en := "✗"
		if enabled.Valid && enabled.Bool {
			en = "✓"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", id, appID, ip, path, reason, en, created)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d exceptions\n", count)
}

func viewException(cmd *cobra.Command, args []string) {
	var id int
	var appID, ip, path, reason, created string
	var enabled sql.NullBool

	err := db.QueryRow(`
		SELECT id, app_id, ip_address, path, reason, enabled, created_at
		FROM exceptions WHERE id = ?
	`, args[0]).Scan(&id, &appID, &ip, &path, &reason, &enabled, &created)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	en := "Disabled"
	if enabled.Valid && enabled.Bool {
		en = "Enabled"
	}

	fmt.Printf(`
Exception #%d
============
App ID:     %s
IP Address: %s
Path:       %s
Reason:     %s
Status:     %s
Created:    %s
`, id, appID, ip, path, reason, en, created)
}

func addException(cmd *cobra.Command, args []string) {
	ip := args[0]
	path := args[1]
	if ip == "-" {
		ip = "*"
	}

	stmt, err := db.Prepare(`
		INSERT INTO exceptions (app_id, ip_address, path, reason, enabled, created_at)
		VALUES ('default', ?, ?, ?, 1, ?)
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	result, err := stmt.Exec(ip, path, "CLI whitelist", now)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Printf("✓ Exception added (ID: %d)\n", id)
}

func removeException(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("DELETE FROM exceptions WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Printf("✓ Exception removed\n")
	} else {
		fmt.Printf("✗ Exception not found\n")
	}
}

func enableException(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("UPDATE exceptions SET enabled = 1 WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()
	stmt.Exec(args[0])
	fmt.Printf("✓ Exception enabled\n")
}

func disableException(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("UPDATE exceptions SET enabled = 0 WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()
	stmt.Exec(args[0])
	fmt.Printf("✓ Exception disabled\n")
}

// ============== KEYWORD EXCEPTION COMMANDS ==============

func listKeywordExceptions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, exception_type, keyword, reason, enabled
		FROM keyword_exceptions ORDER BY app_id, exception_type
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tTYPE\tKEYWORD\tREASON\tENABLED")

	count := 0
	for rows.Next() {
		var id int
		var appID, exceptionType, keyword, reason string
		var enabled sql.NullBool
		rows.Scan(&id, &appID, &exceptionType, &keyword, &reason, &enabled)
		en := "✗"
		if enabled.Valid && enabled.Bool {
			en = "✓"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", id, appID, exceptionType, keyword, reason, en)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d keyword exceptions\n", count)
}

func viewKeywordException(cmd *cobra.Command, args []string) {
	var id int
	var appID, exceptionType, keyword, reason string
	var enabled sql.NullBool

	err := db.QueryRow(`
		SELECT id, app_id, exception_type, keyword, reason, enabled
		FROM keyword_exceptions WHERE id = ?
	`, args[0]).Scan(&id, &appID, &exceptionType, &keyword, &reason, &enabled)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	en := "Disabled"
	if enabled.Valid && enabled.Bool {
		en = "Enabled"
	}

	fmt.Printf(`
Keyword Exception #%d
====================
App ID:          %s
Exception Type:  %s (path|body_field|header)
Keyword:         %s
Reason:          %s
Status:          %s
`, id, appID, exceptionType, keyword, reason, en)
}

func addKeywordException(cmd *cobra.Command, args []string) {
	exceptionType := args[0]
	keyword := args[1]

	if exceptionType != "path" && exceptionType != "body_field" && exceptionType != "header" {
		fmt.Printf("✗ Invalid exception type. Must be: path, body_field, or header\n")
		return
	}

	stmt, err := db.Prepare(`
		INSERT INTO keyword_exceptions (app_id, exception_type, keyword, reason, enabled)
		VALUES ('default', ?, ?, ?, 1)
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(exceptionType, keyword, "CLI exception")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Printf("✓ Keyword exception added (ID: %d)\n", id)
}

func removeKeywordException(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("DELETE FROM keyword_exceptions WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Printf("✓ Keyword exception removed\n")
	} else {
		fmt.Printf("✗ Keyword exception not found\n")
	}
}

// ============== INTEL TEMPLATE COMMANDS ==============

func listIntelTemplates(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, name, template_type, is_active, created_at
		FROM intel_collection_templates ORDER BY id ASC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tACTIVE\tCREATED")

	count := 0
	for rows.Next() {
		var id int
		var name, templateType, created string
		var active sql.NullBool
		rows.Scan(&id, &name, &templateType, &active, &created)
		act := "✗"
		if active.Valid && active.Bool {
			act = "✓"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, name, templateType, act, created)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d intel templates\n", count)
}

func viewIntelTemplate(cmd *cobra.Command, args []string) {
	var id int
	var name, templateType, content, description, created string
	var active sql.NullBool

	err := db.QueryRow(`
		SELECT id, name, template_type, content, description, is_active, created_at
		FROM intel_collection_templates WHERE id = ?
	`, args[0]).Scan(&id, &name, &templateType, &content, &description, &active, &created)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	act := "Disabled"
	if active.Valid && active.Bool {
		act = "Enabled"
	}

	if len(content) > 200 {
		content = content[:200] + "..."
	}

	fmt.Printf(`
Intel Template #%d
================
Name:        %s
Type:        %s
Status:      %s
Description: %s
Content:     %s
Created:     %s
`, id, name, templateType, act, description, content, created)
}

func toggleIntelTemplate(cmd *cobra.Command, args []string) {
	var active sql.NullBool
	err := db.QueryRow("SELECT is_active FROM intel_collection_templates WHERE id = ?", args[0]).Scan(&active)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	newStatus := 1
	if active.Valid && active.Bool {
		newStatus = 0
	}

	stmt, _ := db.Prepare("UPDATE intel_collection_templates SET is_active = ? WHERE id = ?")
	defer stmt.Close()
	stmt.Exec(newStatus, args[0])

	status := "enabled"
	if newStatus == 0 {
		status = "disabled"
	}
	fmt.Printf("✓ Intel template %s\n", status)
}

// ============== PAYLOAD TEMPLATE COMMANDS ==============

func listPayloads(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, name, attack_type, payload_type, http_status_code, is_active, priority
		FROM payload_templates ORDER BY priority DESC, id ASC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tATTACK TYPE\tTYPE\tSTATUS CODE\tACTIVE\tPRIORITY")

	count := 0
	for rows.Next() {
		var id, statusCode, priority int
		var name, attackType, payloadType string
		var active sql.NullBool
		rows.Scan(&id, &name, &attackType, &payloadType, &statusCode, &active, &priority)
		act := "✗"
		if active.Valid && active.Bool {
			act = "✓"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%d\n", id, name, attackType, payloadType, statusCode, act, priority)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d payload templates\n", count)
}

func viewPayload(cmd *cobra.Command, args []string) {
	var id, statusCode int
	var name, attackType, payloadType, content, contentType string

	err := db.QueryRow(`
		SELECT id, name, attack_type, payload_type, content, content_type, http_status_code
		FROM payload_templates WHERE id = ?
	`, args[0]).Scan(&id, &name, &attackType, &payloadType, &content, &contentType, &statusCode)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(content) > 300 {
		content = content[:300] + "..."
	}

	fmt.Printf(`
Payload Template #%d
===================
Name:        %s
Attack Type: %s
Payload Type: %s
Content Type: %s
Status Code: %d
Content:     %s
`, id, name, attackType, payloadType, contentType, statusCode, content)
}

func payloadStats(cmd *cobra.Command, args []string) {
	var total, active int

	db.QueryRow("SELECT COUNT(*) FROM payload_templates").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM payload_templates WHERE is_active = 1").Scan(&active)

	fmt.Printf(`
Payload Statistics
==================
Total Templates: %d
Active:          %d
Intelligence:    Enabled
`, total, active)
}

// ============== LEGITIMATE REQUESTS COMMANDS ==============

func listLegitimate(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, http_method, path, hit_count, first_seen, last_seen
		FROM legitimate_requests ORDER BY last_seen DESC LIMIT 50
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tMETHOD\tPATH\tHITS\tLAST SEEN")

	count := 0
	for rows.Next() {
		var id, hitCount int
		var appID, method, path, lastSeen string
		rows.Scan(&id, &appID, &method, &path, &hitCount, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n", id, appID, method, path, hitCount, lastSeen)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d cached legitimate requests\n", count)
}

func legitimateStats(cmd *cobra.Command, args []string) {
	var total, hitCount int

	db.QueryRow("SELECT COUNT(*) FROM legitimate_requests").Scan(&total)
	db.QueryRow("SELECT SUM(hit_count) FROM legitimate_requests").Scan(&hitCount)

	fmt.Printf(`
Legitimate Request Cache Statistics
====================================
Cached Patterns:     %d
Total Hits:          %d
Cache Status:        Active
`, total, hitCount)
}

// ============== ATTACKER INTERACTIONS COMMANDS ==============

func listInteractions(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, app_id, source_ip, interaction_type, timestamp
		FROM attacker_interactions ORDER BY timestamp DESC LIMIT 50
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAPP ID\tSOURCE IP\tTYPE\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id int
		var appID, sourceIP, interactionType, timestamp string
		rows.Scan(&id, &appID, &sourceIP, &interactionType, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", id, appID, sourceIP, interactionType, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d recent interactions\n", count)
}

func interactionsByIP(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, interaction_type, timestamp
		FROM attacker_interactions WHERE source_ip = ? ORDER BY timestamp DESC
	`, args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Interactions from %s\n", args[0])
	fmt.Fprintln(w, "ID\tTYPE\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id int
		var interactionType, timestamp string
		rows.Scan(&id, &interactionType, &timestamp)
		fmt.Fprintf(w, "%d\t%s\t%s\n", id, interactionType, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", count)
}

// ============== THREAT INTELLIGENCE COMMANDS ==============

func listThreats(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, source_ip, risk_score, threat_level, ipinfo_country, total_attacks, updated_at
		FROM threat_intelligence ORDER BY risk_score DESC LIMIT 50
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tIP ADDRESS\tRISK SCORE\tTHREAT LEVEL\tCOUNTRY\tATTACKS\tUPDATED")

	count := 0
	for rows.Next() {
		var id, riskScore, totalAttacks int
		var sourceIP, threatLevel, country, updatedAt string
		rows.Scan(&id, &sourceIP, &riskScore, &threatLevel, &country, &totalAttacks, &updatedAt)
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%d\t%s\n", id, sourceIP, riskScore, threatLevel, country, totalAttacks, updatedAt)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d enriched threats\n", count)
}

func viewThreat(cmd *cobra.Command, args []string) {
	sourceIP := args[0]
	var id, riskScore, abuseReports, vtMalicious, vtSuspicious, totalAttacks int
	var abuseScore sql.NullFloat64
	var isVPN, isProxy bool
	var threatLevel, country, org, privacyType string
	var enrichedAt, cachedUntil, lastAttackAt sql.NullString

	err := db.QueryRow(`
		SELECT id, risk_score, abuseipdb_score, abuseipdb_reports, virustotal_malicious, virustotal_suspicious,
		       is_vpn, is_proxy, ipinfo_country, ipinfo_org, ipinfo_privacy_type, threat_level,
		       enriched_at, cached_until, last_attack_at, total_attacks
		FROM threat_intelligence WHERE source_ip = ?
	`, sourceIP).Scan(&id, &riskScore, &abuseScore, &abuseReports, &vtMalicious, &vtSuspicious,
		&isVPN, &isProxy, &country, &org, &privacyType, &threatLevel,
		&enrichedAt, &cachedUntil, &lastAttackAt, &totalAttacks)

	if err == sql.ErrNoRows {
		fmt.Printf("✗ No threat intelligence for IP: %s\n", sourceIP)
		return
	}
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	abuseScoreStr := "N/A"
	if abuseScore.Valid {
		abuseScoreStr = fmt.Sprintf("%.1f", abuseScore.Float64)
	}

	lastAttackStr := "Never"
	if lastAttackAt.Valid {
		lastAttackStr = lastAttackAt.String
	}

	enrichedStr := "N/A"
	if enrichedAt.Valid {
		enrichedStr = enrichedAt.String
	}

	cachedStr := "N/A"
	if cachedUntil.Valid {
		cachedStr = cachedUntil.String
	}

	vpnStr := "No"
	if isVPN {
		vpnStr = "Yes"
	}

	proxyStr := "No"
	if isProxy {
		proxyStr = "Yes"
	}

	fmt.Printf(`
Threat Intelligence for %s
==========================
ID:                  %d
Risk Score:          %d/100 (%s)
Country:             %s
Organization:        %s

AbuseIPDB Data
  Confidence Score:  %s
  Reports:           %d

VirusTotal Data
  Malicious:         %d
  Suspicious:        %d

Privacy/Hosting
  VPN:               %s
  Proxy:             %s
  Type:              %s

Detection Stats
  Total Attacks:     %d
  Last Attack:       %s

Cache Info
  Enriched:          %s
  Cache Until:       %s
`, sourceIP, id, riskScore, threatLevel, country, org,
		abuseScoreStr, abuseReports,
		vtMalicious, vtSuspicious,
		vpnStr, proxyStr, privacyType,
		totalAttacks, lastAttackStr,
		enrichedStr, cachedStr)
}


func topThreats(cmd *cobra.Command, args []string) {
	limit := 10
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &limit)
	}

	rows, err := db.Query(`
		SELECT id, source_ip, risk_score, threat_level, ipinfo_country, total_attacks, updated_at
		FROM threat_intelligence ORDER BY risk_score DESC LIMIT ?
	`, limit)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Top %d Threats by Risk Score\n", limit)
	fmt.Fprintln(w, "RANK\tIP ADDRESS\tRISK SCORE\tTHREAT LEVEL\tCOUNTRY\tATTACKS")

	rank := 1
	for rows.Next() {
		var id, riskScore, totalAttacks int
		var sourceIP, threatLevel, country, updatedAt string
		rows.Scan(&id, &sourceIP, &riskScore, &threatLevel, &country, &totalAttacks, &updatedAt)
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%d\n", rank, sourceIP, riskScore, threatLevel, country, totalAttacks)
		rank++
	}
	w.Flush()
}

func threatStats(cmd *cobra.Command, args []string) {
	var total, critical, high, medium, low int
	var avgScore float64

	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence").Scan(&total)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'CRITICAL'").Scan(&critical)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'HIGH'").Scan(&high)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'MEDIUM'").Scan(&medium)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence WHERE threat_level = 'LOW'").Scan(&low)
	db.QueryRow("SELECT COALESCE(AVG(risk_score), 0) FROM threat_intelligence").Scan(&avgScore)

	fmt.Printf(`
Threat Intelligence Statistics
===============================
Total Enriched IPs:   %d
Average Risk Score:   %.1f

Threat Level Distribution
  🔴 CRITICAL:        %d
  🟠 HIGH:            %d
  🟡 MEDIUM:          %d
  🟢 LOW:             %d

Status: Active enrichment workers running
Cache TTL: 24 hours
`, total, avgScore, critical, high, medium, low)
}

// ============== DATABASE COMMANDS ==============

func dbStats(cmd *cobra.Command, args []string) {
	var attacks, patterns, attackers, exceptions, keywords, intel, payloads, legitimate, interactions, threats int

	db.QueryRow("SELECT COUNT(*) FROM attack_instances").Scan(&attacks)
	db.QueryRow("SELECT COUNT(*) FROM attack_patterns").Scan(&patterns)
	db.QueryRow("SELECT COUNT(*) FROM attacker_profiles").Scan(&attackers)
	db.QueryRow("SELECT COUNT(*) FROM exceptions").Scan(&exceptions)
	db.QueryRow("SELECT COUNT(*) FROM keyword_exceptions").Scan(&keywords)
	db.QueryRow("SELECT COUNT(*) FROM intel_collection_templates").Scan(&intel)
	db.QueryRow("SELECT COUNT(*) FROM payload_templates").Scan(&payloads)
	db.QueryRow("SELECT COUNT(*) FROM legitimate_requests").Scan(&legitimate)
	db.QueryRow("SELECT COUNT(*) FROM attacker_interactions").Scan(&interactions)
	db.QueryRow("SELECT COUNT(*) FROM threat_intelligence").Scan(&threats)

	fileInfo, err := os.Stat("data/ifrit.db")
	size := "unknown"
	if err == nil {
		size = fmt.Sprintf("%.2f MB", float64(fileInfo.Size())/(1024*1024))
	}

	fmt.Printf(`
Database Statistics
====================
Attack Instances:      %d
Attack Patterns:       %d
Attacker Profiles:     %d
Threat Intelligence:   %d
Exceptions:            %d
Keyword Exceptions:    %d
Intel Templates:       %d
Payload Templates:     %d
Legitimate Requests:   %d
Attacker Interactions: %d
Database Size:         %s
`, attacks, patterns, attackers, threats, exceptions, keywords, intel, payloads, legitimate, interactions, size)
}

func showSchema(cmd *cobra.Command, args []string) {
	fmt.Println(`
IFRIT Database Tables (Phase 1.2)
=================================

CORE DETECTION
- attack_instances      Recorded attacks & honeypots
- attack_patterns       Known attack signatures
- attacker_profiles     Attacker information & behavior

THREAT INTELLIGENCE
- threat_intelligence   Enriched IP data (AbuseIPDB, VirusTotal, IPinfo)

WHITELISTING
- exceptions            IP/path exceptions
- keyword_exceptions    Keyword-based exception rules

LEARNING & CACHE
- legitimate_requests   Cached legitimate traffic
- learning_mode_requests Requests in learning mode

INTELLIGENCE
- attacker_interactions Attacker behavioral data
- intel_collection_templates Tracking/intel templates

PAYLOADS
- payload_templates     Honeypot response templates
- payload_conditions    Conditions for payload selection

API & LOGGING
- llm_api_calls         LLM API usage logs
- anonymization_log     Data anonymization records
- api_users             API user accounts
- api_tokens            API authentication tokens
`)
}

// ============== API TOKEN COMMANDS ==============

func listTokens(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, user_id, token_name, token_prefix, expires_at, created_at
		FROM api_tokens ORDER BY created_at DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tUSER ID\tNAME\tPREFIX\tEXPIRES AT\tSTATUS")

	count := 0
	for rows.Next() {
		var id, userID int
		var name, prefix, expiresAt, created string
		rows.Scan(&id, &userID, &name, &prefix, &expiresAt, &created)

		expTime, _ := time.Parse(time.RFC3339, expiresAt)
		status := "Active"
		if time.Now().After(expTime) {
			status = "EXPIRED"
		}

		fmt.Fprintf(w, "%d\t%d\t%s\t%s...\t%s\t%s\n", id, userID, name, prefix, expiresAt, status)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d API tokens\n", count)
}

func createToken(cmd *cobra.Command, args []string) {
	userID := args[0]

	// Auto-create user if doesn't exist
	var exists bool
	db.QueryRow("SELECT EXISTS(SELECT 1 FROM api_users WHERE id = ?)", userID).Scan(&exists)
	if !exists {
		db.Exec("INSERT INTO api_users (id, username, role, is_active) VALUES (?, ?, 'admin', 1)", userID, "user_"+userID)
		fmt.Printf("✓ User auto-created (ID: %s)\n", userID)
	}

	tokenName := args[1]

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		// Use crypto/rand instead of sequential
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			fmt.Printf("Error generating token: %v\n", err)
			return
		}
		b[i] = charset[num.Int64()]
	}
	tokenString := "ifr_" + string(b)

	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])
	tokenPrefix := tokenString[:8]
	expiresAt := time.Now().AddDate(0, 0, 90).Format(time.RFC3339)

	stmt, err := db.Prepare(`
		INSERT INTO api_tokens (user_id, token_name, token_hash, token_prefix, app_id, permissions, expires_at, created_at)
		VALUES (?, ?, ?, ?, 'default', '["read","write"]', ?, ?)
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	result, err := stmt.Exec(userID, tokenName, tokenHash, tokenPrefix, expiresAt, now)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	id, _ := result.LastInsertId()
	fmt.Printf("✓ Token created successfully\n")
	fmt.Printf("  ID:       %d\n", id)
	fmt.Printf("  Token:    %s\n", tokenString)
	fmt.Printf("  Expires:  %s\n\n", expiresAt)
	fmt.Printf("Save this token - you won't see it again!\n")
}

func revokeToken(cmd *cobra.Command, args []string) {
	stmt, err := db.Prepare("DELETE FROM api_tokens WHERE id = ?")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	result, err := stmt.Exec(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	affected, _ := result.RowsAffected()
	if affected > 0 {
		fmt.Printf("✓ Token revoked\n")
	} else {
		fmt.Printf("✗ Token not found\n")
	}
}

func validateToken(cmd *cobra.Command, args []string) {
	tokenString := args[0]
	hash := sha256.Sum256([]byte(tokenString))
	tokenHash := hex.EncodeToString(hash[:])

	var id, userID int
	var tokenName, appID, permissions, expiresAt string

	err := db.QueryRow(`
		SELECT id, user_id, token_name, app_id, permissions, expires_at
		FROM api_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&id, &userID, &tokenName, &appID, &permissions, &expiresAt)

	if err == sql.ErrNoRows {
		fmt.Printf("✗ Invalid token\n")
		return
	}
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	expTime, _ := time.Parse(time.RFC3339, expiresAt)
	status := "Valid"
	if time.Now().After(expTime) {
		status = "EXPIRED"
	}

	fmt.Printf(`
Token Validation
================
Status:       %s
ID:           %d
User ID:      %d
Token Name:   %s
App ID:       %s
Permissions:  %s
Expires At:   %s
`, status, id, userID, tokenName, appID, permissions, expiresAt)
}
