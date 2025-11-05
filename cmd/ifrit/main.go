package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/0tSystemsPublicRepos/ifrit/internal/anonymization"
	"github.com/0tSystemsPublicRepos/ifrit/internal/api"
	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
	"github.com/0tSystemsPublicRepos/ifrit/internal/detection"
	"github.com/0tSystemsPublicRepos/ifrit/internal/execution"
	"github.com/0tSystemsPublicRepos/ifrit/internal/llm"
	"github.com/0tSystemsPublicRepos/ifrit/internal/logging"
	"github.com/0tSystemsPublicRepos/ifrit/internal/payload"
	"github.com/0tSystemsPublicRepos/ifrit/internal/proxy"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("IFRIT Proxy - Intelligent Threat Deception Platform")
	fmt.Println("Version: 0.1 (MVP)")
	fmt.Println("========================================\n")

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("Configuration loaded\n")
	fmt.Printf("Database: %s\n", cfg.Database.Path)
	fmt.Printf("Proxy target: %s\n", cfg.Server.ProxyTarget)
	fmt.Printf("LLM Provider: %s\n", cfg.LLM.Primary)
	fmt.Println()

	// Initialize logging
	fmt.Println("Initializing logging...")
	if err := logging.Init(cfg.System.LogDir); err != nil {
		log.Printf("Warning: Failed to initialize logging: %v\n", err)
	}
	defer logging.Close()

	// Initialize database
	fmt.Println("Initializing database...")
	db, err := database.InitializeDatabase(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	fmt.Println("✓ Database initialized")

	// Initialize LLM Manager
	fmt.Println("Initializing LLM providers...")
	llmManager := llm.NewManager(
		cfg.LLM.Primary,
		cfg.LLM.Claude.APIKey,
		cfg.LLM.Claude.Model,
		"claude", // fallback to claude
		cfg.LLM.Claude.APIKey,
		cfg.LLM.Claude.Model,
	)
	fmt.Printf("✓ LLM Manager initialized (primary: %s)\n", llmManager.GetPrimaryName())

	// Initialize anonymization engine (BEFORE detection engine)
	fmt.Println("Initializing anonymization engine...")
	anonEngine := anonymization.NewAnonymizationEngine(
		cfg.Anonymization.Enabled,
		cfg.Anonymization.Strategy,
		cfg.Anonymization.StoreOriginal,
		cfg.Anonymization.SensitiveHeaders,
	)
	fmt.Printf("✓ Anonymization engine initialized (strategy: %s)\n", cfg.Anonymization.Strategy)

	// Initialize detection engine (AFTER anonymization engine)
	fmt.Println("Initializing detection engine...")
	detectionEngine := detection.NewDetectionEngine(
		cfg.Detection.WhitelistIPs,
		cfg.Detection.WhitelistPaths,
		db,
		llmManager,
		anonEngine,
	)
	fmt.Println("✓ Detection engine initialized")

	// Initialize payload manager
	fmt.Println("Initializing payload manager...")
	payloadManager := payload.NewPayloadManager(db.GetDB())
	payloadManager.SetLLMManager(llmManager)
	fmt.Println("✓ Payload manager initialized")

	// Set anonymization engine on Claude provider
	if provider := llmManager.GetProvider("claude"); provider != nil {
		if claudeProvider, ok := provider.(*llm.ClaudeProvider); ok {
			claudeProvider.SetAnonymizationEngine(anonEngine)
			log.Printf("Claude provider configured with anonymization engine")
		}
	}

	// Initialize execution mode handler
	fmt.Println("Initializing execution mode handler...")
	modeHandler := execution.NewExecutionModeHandler(&cfg.ExecutionMode, db)
	fmt.Printf("✓ Execution mode: %s\n", cfg.ExecutionMode.Mode)
	if modeHandler.IsOnboardingMode() {
		fmt.Println("  ⚠️  ONBOARDING MODE - All traffic will be whitelisted automatically")
		fmt.Printf("   Traffic log: %s\n", cfg.ExecutionMode.OnboardingLogFile)
	}

	// Initialize reverse proxy
	fmt.Println("Initializing reverse proxy...")
	reverseProxy, err := proxy.NewReverseProxy(cfg.Server.ProxyTarget)
	if err != nil {
		log.Fatalf("Failed to initialize reverse proxy: %v", err)
	}
	fmt.Println("✓ Reverse proxy initialized")

	// Initialize API server
	fmt.Println("Initializing API server...")
	apiServer := api.NewAPIServer(cfg.Server.APIListenAddr, "", db, llmManager)
	fmt.Println("✓ API server initialized")

	// Start API server in goroutine
	fmt.Printf("\nStarting API server on %s\n", cfg.Server.APIListenAddr)
	go func() {
		if err := apiServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	// Start main proxy server
	fmt.Printf("Starting proxy server on %s\n", cfg.Server.ListenAddr)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// DEBUG: Log every incoming request
		clientIP := proxy.GetClientIP(r)
		log.Printf("[REQUEST] %s %s from %s", r.Method, r.URL.Path, clientIP)

		// Check exceptions first
		if detectionEngine.CheckExceptions(r, clientIP) {
			log.Printf("[EXCEPTION] Request whitelisted: %s %s", r.Method, r.URL.Path)
			logging.Debug("Request from whitelisted IP: %s", clientIP)
			resp, err := reverseProxy.ForwardRequest(r)
			if err != nil {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			reverseProxy.CopyResponse(w, resp)
			return
		}

		// Stage 1: Check local rules
		result := detectionEngine.CheckLocalRules(r)
		if result != nil && result.IsAttack {
			log.Printf("[STAGE1] Attack detected: %s", result.AttackType)
			// In onboarding mode, auto-whitelist this path instead of blocking
			if modeHandler.IsOnboardingMode() {
				log.Printf("[ONBOARDING] Auto-whitelisting path: %s %s", r.Method, r.URL.Path)
				modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path)
				resp, err := reverseProxy.ForwardRequest(r)
				if err != nil {
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				reverseProxy.CopyResponse(w, resp)
				return
			}

			// Normal/Learning mode: return honeypot
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 1: Local Rules")
			db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)

			// Get payload response
			payloadResp, err := payloadManager.GetPayloadForAttack(
				payload.AttackerContext{
					SourceIP:       clientIP,
					AttackType:     result.AttackType,
					Classification: result.Classification,
					Path:           r.URL.Path,
				},
				&cfg.PayloadManagement,
				llmManager,
			)
			if err != nil || payloadResp == nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Internal server error"}`))
				return
			}
			w.Header().Set("Content-Type", payloadResp.ContentType)
			w.WriteHeader(payloadResp.StatusCode)
			w.Write([]byte(payloadResp.Body))
			return
		}

		// Stage 2: Check database patterns
		result = detectionEngine.CheckDatabasePatterns(r)
		if result != nil && result.IsAttack {
			log.Printf("[STAGE2] Attack detected: %s", result.AttackType)
			// In onboarding mode, auto-whitelist this path instead of blocking
			if modeHandler.IsOnboardingMode() {
				log.Printf("[ONBOARDING] Auto-whitelisting path: %s %s", r.Method, r.URL.Path)
				modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path)
				resp, err := reverseProxy.ForwardRequest(r)
				if err != nil {
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				reverseProxy.CopyResponse(w, resp)
				return
			}

			// Normal/Learning mode: return honeypot
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 2: Database Patterns")
			db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)

			// Get payload response
			payloadResp, err := payloadManager.GetPayloadForAttack(
				payload.AttackerContext{
					SourceIP:       clientIP,
					AttackType:     result.AttackType,
					Classification: result.Classification,
					Path:           r.URL.Path,
				},
				&cfg.PayloadManagement,
				llmManager,
			)
			if err != nil || payloadResp == nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Internal server error"}`))
				return
			}
			w.Header().Set("Content-Type", payloadResp.ContentType)
			w.WriteHeader(payloadResp.StatusCode)
			w.Write([]byte(payloadResp.Body))
			return
		}

		// Stage 3: LLM Analysis for POST/PUT/DELETE
		if contains(cfg.Detection.LLMOnlyOn, r.Method) && cfg.Detection.EnableLLM {
			result = detectionEngine.CheckLLMAnalysis(r)
			if result != nil && result.IsAttack {
				log.Printf("[STAGE3] Attack detected: %s", result.AttackType)
				// In onboarding mode, auto-whitelist this path instead of blocking
				if modeHandler.IsOnboardingMode() {
					log.Printf("[ONBOARDING] Auto-whitelisting path: %s %s", r.Method, r.URL.Path)
					modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path)
					resp, err := reverseProxy.ForwardRequest(r)
					if err != nil {
						http.Error(w, "Bad Gateway", http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					reverseProxy.CopyResponse(w, resp)
					return
				}

				// Normal/Learning mode: return honeypot
				logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 3: LLM Analysis")
				db.StoreAttackInstance(0, clientIP, "", r.URL.Path, r.Method)

				// Get payload response
				payloadResp, err := payloadManager.GetPayloadForAttack(
					payload.AttackerContext{
						SourceIP:       clientIP,
						AttackType:     result.AttackType,
						Classification: result.Classification,
						Path:           r.URL.Path,
					},
					&cfg.PayloadManagement,
					llmManager,
				)
				if err != nil || payloadResp == nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "Internal server error"}`))
					return
				}
				w.Header().Set("Content-Type", payloadResp.ContentType)
				w.WriteHeader(payloadResp.StatusCode)
				w.Write([]byte(payloadResp.Body))
				return
			}
		}

		// Not an attack, forward to backend
		log.Printf("[LEGITIMATE] Forwarding to backend: %s %s", r.Method, r.URL.Path)
		resp, err := reverseProxy.ForwardRequest(r)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		reverseProxy.CopyResponse(w, resp)
	})

	// Start proxy
	if err := http.ListenAndServe(cfg.Server.ListenAddr, mux); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy server error: %v", err)
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
