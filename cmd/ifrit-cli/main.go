package main

import (
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

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
Manage attacks, patterns, attackers, exceptions, and more.`,
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

	// Database commands
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations",
	}
	dbCmd.AddCommand(
		&cobra.Command{Use: "stats", Short: "Database statistics", Run: dbStats},
		&cobra.Command{Use: "schema", Short: "Show database schema", Run: showSchema},
	)

	rootCmd.AddCommand(attackCmd, patternCmd, attackerCmd, exceptionCmd, dbCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// ============== ATTACK COMMANDS ==============

func listAttacks(cmd *cobra.Command, args []string) {
	rows, err := db.Query(`
		SELECT id, pattern_id, source_ip, requested_path, http_method, returned_honeypot, timestamp
		FROM attack_instances ORDER BY timestamp DESC LIMIT 50
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tPATTERN ID\tSOURCE IP\tMETHOD\tPATH\tHONEYPOT\tTIMESTAMP")

	count := 0
	for rows.Next() {
		var id, patternID int
		var sourceIP, path, method, timestamp string
		var honeypot sql.NullBool
		rows.Scan(&id, &patternID, &sourceIP, &path, &method, &honeypot, &timestamp)
		hp := "✗"
		if honeypot.Valid && honeypot.Bool {
			hp = "✓"
		}
		fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%s\t%s\n", id, patternID, sourceIP, method, path, hp, timestamp)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d attacks\n", count)
}

func viewAttack(cmd *cobra.Command, args []string) {
	var id, patternID int
	var sourceIP, userAgent, path, method, timestamp string
	var honeypot, accepted sql.NullBool

	err := db.QueryRow(`
		SELECT id, pattern_id, source_ip, user_agent, requested_path, http_method, returned_honeypot, attacker_accepted, timestamp
		FROM attack_instances WHERE id = ?
	`, args[0]).Scan(&id, &patternID, &sourceIP, &userAgent, &path, &method, &honeypot, &accepted, &timestamp)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	hp := "No"
	if honeypot.Valid && honeypot.Bool {
		hp = "Yes"
	}
	acc := "No"
	if accepted.Valid && accepted.Bool {
		acc = "Yes"
	}

	fmt.Printf(`
Attack #%d
=========
Pattern ID:        %d
Source IP:         %s
User Agent:        %s
Path:              %s
Method:            %s
Honeypot Returned: %s
Attacker Accepted: %s
Timestamp:         %s
`, id, patternID, sourceIP, userAgent, path, method, hp, acc, timestamp)
}

func attackStats(cmd *cobra.Command, args []string) {
	var total, honeypot, uniqueIPs int
	var latest string

	db.QueryRow(`
		SELECT COUNT(*), COUNT(CASE WHEN returned_honeypot = 1 THEN 1 END), 
		       COUNT(DISTINCT source_ip), MAX(timestamp)
		FROM attack_instances
	`).Scan(&total, &honeypot, &uniqueIPs, &latest)

	rate := 0.0
	if total > 0 {
		rate = (float64(honeypot) / float64(total)) * 100
	}

	fmt.Printf(`
Attack Statistics
==================
Total Attacks:       %d
Honeypot Served:     %d (%.1f%%)
Unique IPs:          %d
Latest Attack:       %s
`, total, honeypot, rate, uniqueIPs, latest)
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
		SELECT id, attack_type, http_method, path_pattern, times_seen, last_seen
		FROM attack_patterns ORDER BY times_seen DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tMETHOD\tPATTERN\tSEEN\tLAST SEEN")

	count := 0
	for rows.Next() {
		var id, timesSeen int
		var attackType, method, pattern, lastSeen string
		rows.Scan(&id, &attackType, &method, &pattern, &timesSeen, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\n", id, attackType, method, pattern, timesSeen, lastSeen)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d patterns\n", count)

}

func viewPattern(cmd *cobra.Command, args []string) {
	var id, responseCode, timesSeen int
	var signature, attackType, classification, method, pathPattern, payload, createdBy string
	var confidence sql.NullFloat64
	var firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, attack_signature, attack_type, attack_classification, http_method, path_pattern,
		       payload_template, response_code, times_seen, first_seen, last_seen, created_by, claude_confidence
		FROM attack_patterns WHERE id = ?
	`, args[0]).Scan(&id, &signature, &attackType, &classification, &method, &pathPattern,
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
Type:              %s
Classification:    %s
Signature:         %s
HTTP Method:       %s
Path Pattern:      %s
Response Code:     %d
Times Seen:        %d
Created By:        %s
Claude Confidence: %s
First Seen:        %s
Last Seen:         %s
Payload Template:  %s
`, id, attackType, classification, signature, method, pathPattern, responseCode, timesSeen, createdBy, conf, firstSeen, lastSeen, payload)
}

func addPattern(cmd *cobra.Command, args []string) {
	attackType := args[0]
	signature := args[1]

	stmt, err := db.Prepare(`
		INSERT INTO attack_patterns (attack_type, attack_signature, times_seen, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	result, err := stmt.Exec(attackType, signature, 1, now, now)
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
		SELECT id, source_ip, total_requests, successful_probes, last_seen
		FROM attacker_profiles ORDER BY total_requests DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tIP ADDRESS\tREQUESTS\tPROBES\tLAST SEEN")

	count := 0
	for rows.Next() {
		var id, totalReqs, probes int
		var ip, lastSeen string
		rows.Scan(&id, &ip, &totalReqs, &probes, &lastSeen)
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\t%s\n", id, ip, totalReqs, probes, lastSeen)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d attackers\n", count)
}

func viewAttacker(cmd *cobra.Command, args []string) {
	var id, totalReqs, probes int
	var ip, attackTypes, firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, source_ip, total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles WHERE id = ?
	`, args[0]).Scan(&id, &ip, &totalReqs, &probes, &attackTypes, &firstSeen, &lastSeen)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf(`
Attacker Profile #%d
===================
IP Address:        %s
Total Requests:    %d
Successful Probes: %d
Attack Types:      %s
First Seen:        %s
Last Seen:         %s
`, id, ip, totalReqs, probes, attackTypes, firstSeen, lastSeen)
}

func searchAttacker(cmd *cobra.Command, args []string) {
	var id, totalReqs, probes int
	var attackTypes, firstSeen, lastSeen string

	err := db.QueryRow(`
		SELECT id, total_requests, successful_probes, attack_types, first_seen, last_seen
		FROM attacker_profiles WHERE source_ip = ?
	`, args[0]).Scan(&id, &totalReqs, &probes, &attackTypes, &firstSeen, &lastSeen)

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
ID:                %d
Total Requests:    %d
Successful Probes: %d
Attack Types:      %s
First Seen:        %s
Last Seen:         %s
`, args[0], id, totalReqs, probes, attackTypes, firstSeen, lastSeen)
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
		SELECT id, ip_address, path, reason, enabled, created_at
		FROM exceptions ORDER BY created_at DESC
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tIP\tPATH\tREASON\tENABLED\tCREATED")

	count := 0
	for rows.Next() {
		var id int
		var ip, path, reason, created string
		var enabled sql.NullBool
		rows.Scan(&id, &ip, &path, &reason, &enabled, &created)
		en := "✗"
		if enabled.Valid && enabled.Bool {
			en = "✓"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", id, ip, path, reason, en, created)
		count++
	}
	w.Flush()
	fmt.Printf("\nTotal: %d exceptions\n", count)
}

func viewException(cmd *cobra.Command, args []string) {
	var id int
	var ip, path, reason, created string
	var enabled sql.NullBool

	err := db.QueryRow(`
		SELECT id, ip_address, path, reason, enabled, created_at
		FROM exceptions WHERE id = ?
	`, args[0]).Scan(&id, &ip, &path, &reason, &enabled, &created)

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
IP Address: %s
Path:       %s
Reason:     %s
Status:     %s
Created:    %s
`, id, ip, path, reason, en, created)
}

func addException(cmd *cobra.Command, args []string) {
	ip := args[0]
	path := args[1]
	if ip == "-" {
		ip = ""
	}
	if path == "-" {
		path = ""
	}

	stmt, err := db.Prepare(`
		INSERT INTO exceptions (ip_address, path, reason, enabled, created_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer stmt.Close()

	now := time.Now().Format(time.RFC3339)
	result, err := stmt.Exec(ip, path, "CLI whitelist", 1, now)
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

// ============== DATABASE COMMANDS ==============

func dbStats(cmd *cobra.Command, args []string) {
	var attacks, patterns, attackers, exceptions int

	db.QueryRow("SELECT COUNT(*) FROM attack_instances").Scan(&attacks)
	db.QueryRow("SELECT COUNT(*) FROM attack_patterns").Scan(&patterns)
	db.QueryRow("SELECT COUNT(*) FROM attacker_profiles").Scan(&attackers)
	db.QueryRow("SELECT COUNT(*) FROM exceptions").Scan(&exceptions)

	fileInfo, err := os.Stat("data/ifrit.db")
	size := "unknown"
	if err == nil {
		size = fmt.Sprintf("%.2f MB", float64(fileInfo.Size())/(1024*1024))
	}

	fmt.Printf(`
Database Statistics
====================
Attack Instances:  %d
Attack Patterns:   %d
Attacker Profiles: %d
Exceptions:        %d
Database Size:     %s
`, attacks, patterns, attackers, exceptions, size)
}

func showSchema(cmd *cobra.Command, args []string) {
	fmt.Println(`
IFRIT Database Tables
=====================

1. attack_instances   - Recorded attacks
2. attack_patterns    - Known attack signatures
3. attacker_profiles  - Attacker information
4. exceptions         - Whitelisted IPs/paths
5. llm_api_calls      - LLM API usage logs (read-only)
6. anonymization_log  - Anonymization records (read-only)
`)
}
