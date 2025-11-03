package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/0tSystemsPublicRepos/ifrit/internal/api"
	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/detection"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
	"github.com/0tSystemsPublicRepos/ifrit/internal/proxy"
)

var (
	detectionEngine *detection.DetectionEngine
	reverseProxy    *proxy.ReverseProxy
	db              *database.SQLiteDB
	llmManager      *llm.Manager
)

func printBanner() {
	banner := `
                                                                                                
         %                                                                                      
          ##        @@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@      @@@@@@   @@@@@@@@@@@@@@@@@@@@  
          *.#       @@               @@   @@               @@    @@  @@   @@                @@  
         #..#       @@  @@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@  @@    @@  @@   @@@@@@@@@  @@  @@@@@  
       #*==#  #     @@  @                                 @@@    @@  @@          @@  @@         
     #*..#   ##     @@  @@@@@@@@@@@@      @@@@@@@@@@@@@@@@@      @@  @@          @@  @@         
    #. .#   ##      @@                    @@                     @@  @@          @@  @@         
   #:  #  ###  #    @@  @@                @@  @@@@@@@@  @@       @@  @@          @@  @@         
    *.    #   ##    @@  @#                @@  @      @@  @@      @@              @@  @@         
     ###    ##      @@@@@@                @@@@@@      @@@@@@     @@@@@@          @@@@@@         
        #  :                                                                                    
                    Threats Deception Proxy
                                                                                                
`
	fmt.Println(banner)
}

func main() {
	printBanner()
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	fmt.Printf("✓ Configuration loaded from: %s\n", cfg.System.HomeDir)
	fmt.Printf("✓ Database: %s\n", cfg.Database.Path)
	fmt.Printf("✓ Proxy target: %s\n", cfg.Server.ProxyTarget)
	fmt.Printf("✓ LLM Provider: %s\n", cfg.LLM.Primary)
	fmt.Println()

	// Initialize logging
	fmt.Println("Initializing logging...")
	if err := logging.Init(cfg.System.LogDir); err != nil {
		log.Printf("Warning: Failed to initialize logging: %v\n", err)
	}
	defer logging.Close()
	fmt.Printf("✓ Logging initialized to: %s\n", cfg.System.LogDir)

	// Initialize database
	fmt.Println("Initializing database...")
	var dbErr error
	db, dbErr = database.NewSQLiteDB(cfg.Database.Path)
	if dbErr != nil {
		logging.Error("Failed to initialize database: %v", dbErr)
		log.Fatalf("Failed to initialize database: %v", dbErr)
	}
	defer db.Close()
	fmt.Println("✓ Database initialized")

	// Seed patterns from config file
	fmt.Println("Loading attack patterns...")
	if err := db.SeedPatternsFromFile("./config/attack_patterns.json"); err != nil {
		logging.Error("Failed to load patterns: %v", err)
		log.Printf("Warning: Failed to load patterns: %v\n", err)
	}

	// Initialize LLM Manager
	fmt.Println("Initializing LLM manager...")
	llmManager = llm.NewManager(
		cfg.LLM.Primary,
		cfg.LLM.Claude.APIKey,
		cfg.LLM.Claude.Model,
		"gpt",
		cfg.LLM.GPT.APIKey,
		cfg.LLM.GPT.Model,
	)
	fmt.Printf("✓ LLM Manager initialized (Primary: %s)\n", cfg.LLM.Primary)

	// Initialize detection engine
	fmt.Println("Initializing detection engine...")
	detectionEngine = detection.NewDetectionEngine(
		cfg.Detection.WhitelistIPs,
		cfg.Detection.WhitelistPaths,
		db,
		llmManager,
	)
	fmt.Println("✓ Detection engine initialized")

	// Initialize reverse proxy
	fmt.Println("Initializing reverse proxy...")
	var proxyErr error
	reverseProxy, proxyErr = proxy.NewReverseProxy(cfg.Server.ProxyTarget)
	if proxyErr != nil {
		logging.Error("Failed to initialize reverse proxy: %v", proxyErr)
		log.Fatalf("Failed to initialize reverse proxy: %v", proxyErr)
	}
	fmt.Println("✓ Reverse proxy initialized")

	// Create request handler
	http.HandleFunc("/", handleRequest)

	// Start API server
	fmt.Println("Initializing API server...")
	apiServer := api.NewAPIServer(cfg.Server.APIListenAddr, "changeme", db)
	fmt.Printf("✓ API server will start on %s\n", cfg.Server.APIListenAddr)

	// Start proxy server
	fmt.Printf("IFRIT Proxy listening on %s\n", cfg.Server.ListenAddr)
	fmt.Printf("Target backend: %s\n", cfg.Server.ProxyTarget)
	fmt.Printf("API Server: %s\n", cfg.Server.APIListenAddr)
	fmt.Printf("Log directory: %s\n", cfg.System.LogDir)

	logging.Info("IFRIT Proxy started on %s", cfg.Server.ListenAddr)
	logging.Info("Target backend: %s", cfg.Server.ProxyTarget)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nShutting down IFRIT...")
		logging.Info("IFRIT Proxy shutting down")
		db.Close()
		os.Exit(0)
	}()

	// Start servers
	go func() {
		if err := http.ListenAndServe(cfg.Server.ListenAddr, nil); err != nil {
			logging.Error("Proxy server error: %v", err)
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	if err := apiServer.Start(); err != nil {
		logging.Error("API server error: %v", err)
		log.Fatalf("API server error: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := proxy.GetClientIP(r)

	fmt.Printf("[%s] %s %s\n", clientIP, r.Method, r.URL.Path)
	logging.Debug("Request from %s: %s %s", clientIP, r.Method, r.URL.Path)

	// Stage 1: Check exceptions
	if detectionEngine.CheckExceptions(r, clientIP) {
		fmt.Printf("  → Stage 1: Whitelisted (pass-through)\n")
		logging.Info("Request whitelisted from %s: %s %s", clientIP, r.Method, r.URL.Path)
		resp, err := reverseProxy.ForwardRequest(r)
		if err != nil {
			logging.Error("Failed to forward request: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Error: %v", err)
			return
		}
		copyResponse(w, resp)
		return
	}

	// Stage 2: Check local rules
	if result := detectionEngine.CheckLocalRules(r); result != nil {
		fmt.Printf("  → Stage 2: Local rule matched (%s, confidence: %.2f)\n", result.AttackType, result.Confidence)
		logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 2: Local Rule")

		instanceID, _ := db.StoreAttackInstance(0, clientIP, r.Header.Get("User-Agent"), r.URL.Path, r.Method)
		db.UpdateAttackerProfile(clientIP, result.AttackType)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"error":"Internal Server Error"}`)
		fmt.Printf("  → Honeypot response sent (instance_id: %d)\n", instanceID)
		return
	}

	// Stage 3: Check database patterns
	if result := detectionEngine.CheckDatabasePatterns(r); result != nil {
		fmt.Printf("  → Stage 3: Database pattern matched (%s, confidence: %.2f)\n", result.AttackType, result.Confidence)
		logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 3: Database Pattern")

		// Get the pattern ID from the database
		patterns, _ := db.GetAllPatterns()
		var patternID int64 = 0
		for _, p := range patterns {
			if p["path_pattern"].(string) == r.URL.Path && p["http_method"].(string) == r.Method {
				patternID = p["id"].(int64)
				break
			}
		}

		instanceID, _ := db.StoreAttackInstance(patternID, clientIP, r.Header.Get("User-Agent"), r.URL.Path, r.Method)
		db.UpdateAttackerProfile(clientIP, result.AttackType)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(result.PayloadTemplate), &payload); err == nil {
			json.NewEncoder(w).Encode(payload)
		} else {
			fmt.Fprintf(w, result.PayloadTemplate)
		}

		fmt.Printf("  → Honeypot payload sent (instance_id: %d)\n", instanceID)
		return
	}

	// Stage 4: LLM Analysis
	if result := detectionEngine.CheckLLMAnalysis(r); result != nil {
		fmt.Printf("  → Stage 4: LLM detected attack (%s, confidence: %.2f)\n", result.AttackType, result.Confidence)
		logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 4: LLM Analysis")

		instanceID, _ := db.StoreAttackInstance(0, clientIP, r.Header.Get("User-Agent"), r.URL.Path, r.Method)
		db.UpdateAttackerProfile(clientIP, result.AttackType)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(result.PayloadTemplate), &payload); err == nil {
			json.NewEncoder(w).Encode(payload)
		} else {
			fmt.Fprintf(w, result.PayloadTemplate)
		}

		fmt.Printf("  → Honeypot payload sent (instance_id: %d)\n", instanceID)
		return
	}

	// No attack detected - pass through
	fmt.Printf("  → Legitimate request (pass-through)\n")
	logging.Debug("Legitimate request from %s: %s %s", clientIP, r.Method, r.URL.Path)
	resp, err := reverseProxy.ForwardRequest(r)
	if err != nil {
		logging.Error("Failed to forward request from %s: %v", clientIP, err)
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	copyResponse(w, resp)
}

func copyResponse(w http.ResponseWriter, src *http.Response) error {
	for name, values := range src.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(src.StatusCode)

	_, err := io.Copy(w, src.Body)
	return err
}

