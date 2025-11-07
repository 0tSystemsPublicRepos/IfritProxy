package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
)

func main() {
	fmt.Println("                                                                             \n        ø       æææææææææææææææ  <æææææææææææææ     æææææ  ¤æææææææææææææææ  \n        øø      æ             æ  <æ            ææ   æ  ææ  ¤æ            \"æ  \n       øøø      æ  ææææææææææææ  <ææææææææææææ ææ   æ  ææ  ¤ææææææh æø ææææ  \n     <øøø  ø    æ  æø                         ææ    æ  ææ        æh æø       \n   ¤øøøø  øø    æ  ¤¤¤¤¤¤¤¤¤<    <æ/</<<<<<<¤‚      æ  ææ        æh æø       \n  \"øøø‚ åøå C   æ  æø            <æ \"ææææææ  æ‚     æ  ææ        æy æø       \n   øøø  ø  Cø   æ  æø            <æ \"æ    ææ  æ     æ            æy æø       \n    hø< \"¤ø     ææææø            <ææææ     æææææÐ   æææææ        ææææø       \n                                                                             \n                Author : Mehdi T - ifrit@0t.systems\n\t\tVersion: 0.1 (MVP)                                                                   \n                                                                             ")

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	fmt.Printf("Configuration loaded\n")
	fmt.Printf("Database: %s (type: %s)\n", cfg.Database.SQLite.Path, cfg.Database.Type)
	fmt.Printf("Proxy target: %s\n", cfg.Server.ProxyTarget)
	fmt.Printf("LLM Provider: %s\n", cfg.LLM.Primary)
	if cfg.Server.MultiAppMode {
		fmt.Printf("Multi-app mode: ENABLED (header: %s)\n", cfg.Server.AppIDHeader)
	} else {
		fmt.Printf("Multi-app mode: DISABLED\n")
	}
	fmt.Println()

	// Initialize logging
	fmt.Println("Initializing logging...")
	if err := logging.Init(cfg.System.LogDir); err != nil {
		log.Printf("Warning: Failed to initialize logging: %v\n", err)
	}
	defer logging.Close()

	// Initialize database
	fmt.Println("Initializing database...")
	db, err := database.InitializeDatabase(cfg.Database.SQLite.Path)
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

	// Initialize anonymization engine
	fmt.Println("Initializing anonymization engine...")
	anonEngine := anonymization.NewAnonymizationEngine(
		cfg.Anonymization.Enabled,
		cfg.Anonymization.Strategy,
		cfg.Anonymization.StoreOriginal,
		cfg.Anonymization.SensitiveHeaders,
	)
	fmt.Printf("✓ Anonymization engine initialized (strategy: %s)\n", cfg.Anonymization.Strategy)

	// Initialize detection engine
	fmt.Println("Initializing detection engine...")
	detectionEngine := detection.NewDetectionEngine(
		cfg.Detection.Mode,
		cfg.Detection.WhitelistIPs,
		cfg.Detection.WhitelistPaths,
		db,
		llmManager,
		anonEngine,
	)
	fmt.Println("✓ Detection engine initialized")
	fmt.Printf("  Mode: %s\n", cfg.Detection.Mode)

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
		// Extract app_id from header or use fallback
		appID := extractAppID(r, cfg)

		// Extract client IP
		clientIP := getClientIP(r)

		// DEBUG: Log every incoming request
		if cfg.System.Debug {
			log.Printf("[REQUEST] app_id=%s | %s %s from %s", appID, r.Method, r.URL.Path, clientIP)
		}

		// Check exceptions first (with app_id)
		if detectionEngine.CheckExceptions(r, clientIP, appID) {
			log.Printf("[EXCEPTION] app_id=%s | Request whitelisted: %s %s", appID, r.Method, r.URL.Path)
			logging.Debug("Request from whitelisted IP: %s (app: %s)", clientIP, appID)
			resp, err := forwardRequest(r, cfg, appID)
			if err != nil {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			copyResponse(w, resp)
			return
		}

		// In allowlist mode, block non-whitelisted requests
		if cfg.Detection.Mode == "allowlist" {
			log.Printf("[ALLOWLIST] app_id=%s | Blocking non-whitelisted request from %s to %s %s", appID, clientIP, r.Method, r.URL.Path)
			logging.Attack(clientIP, r.Method, r.URL.Path, "blocked_by_allowlist", "Allowlist Mode")
			db.StoreAttackInstance(appID, 0, clientIP, "", r.URL.Path, r.Method)

			// Treat as attack and use payload management
			payloadResp, err := payloadManager.GetPayloadForAttack(
				payload.AttackerContext{
					SourceIP:       clientIP,
					AttackType:     "blocked_by_allowlist",
					Classification: "policy",
					Path:           r.URL.Path,
				},
				&cfg.PayloadManagement,
				llmManager,
			)
			if err != nil || payloadResp == nil {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "Forbidden"}`))
				return
			}
			w.Header().Set("Content-Type", payloadResp.ContentType)
			w.WriteHeader(payloadResp.StatusCode)
			w.Write([]byte(payloadResp.Body))
			return
		}

		// Stage 1: Check local rules (with app_id)
		result := detectionEngine.CheckLocalRules(r, appID, cfg.Detection.SkipBodyCheckOnWhitelist)
		if result != nil && result.IsAttack {
			log.Printf("[STAGE1] app_id=%s | Attack detected: %s", appID, result.AttackType)
			// In onboarding mode, auto-whitelist this path instead of blocking
			if modeHandler.IsOnboardingMode() {
				log.Printf("[ONBOARDING] app_id=%s | Auto-whitelisting path: %s %s", appID, r.Method, r.URL.Path)
				modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path, appID)
				resp, err := forwardRequest(r, cfg, appID)
				if err != nil {
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				copyResponse(w, resp)
				return
			}

			// Normal/Learning mode: return honeypot
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 1: Local Rules")
			db.StoreAttackInstance(appID, 0, clientIP, "", r.URL.Path, r.Method)

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

		// Stage 2: Check database patterns (with app_id)
		result = detectionEngine.CheckDatabasePatterns(r, appID, cfg.Detection.SkipBodyCheckOnWhitelist)
		if result != nil && result.IsAttack {
			log.Printf("[STAGE2] app_id=%s | Attack detected: %s", appID, result.AttackType)
			// In onboarding mode, auto-whitelist this path instead of blocking
			if modeHandler.IsOnboardingMode() {
				log.Printf("[ONBOARDING] app_id=%s | Auto-whitelisting path: %s %s", appID, r.Method, r.URL.Path)
				modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path, appID)
				resp, err := forwardRequest(r, cfg, appID)
				if err != nil {
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				copyResponse(w, resp)
				return
			}

			// Normal/Learning mode: return honeypot
			logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 2: Database Patterns")
			db.StoreAttackInstance(appID, 0, clientIP, "", r.URL.Path, r.Method)

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

		// Stage 3: Check legitimate request cache (BEFORE LLM)
		isCached, err := detectionEngine.CheckLegitimateCache(r, appID, cfg.Detection.SkipBodyCheckOnWhitelist)
		if err == nil && isCached {
			log.Printf("[STAGE3] app_id=%s | Request is legitimate (cached), forwarding to backend", appID)
			resp, err := forwardRequest(r, cfg, appID)
			if err != nil {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			copyResponse(w, resp)
			return
		}

		// Stage 4: LLM Analysis for POST/PUT/DELETE (with app_id)
		if contains(cfg.Detection.LLMOnlyOn, r.Method) && cfg.Detection.EnableLLM {
			result = detectionEngine.CheckLLMAnalysis(r, appID, cfg.Detection.SkipBodyCheckOnWhitelist)
			if result != nil && result.IsAttack {
				log.Printf("[STAGE4] app_id=%s | Attack detected: %s", appID, result.AttackType)
				// In onboarding mode, auto-whitelist this path instead of blocking
				if modeHandler.IsOnboardingMode() {
					log.Printf("[ONBOARDING] app_id=%s | Auto-whitelisting path: %s %s", appID, r.Method, r.URL.Path)
					modeHandler.HandleOnboardingRequest(r.Method, r.URL.Path, appID)
					resp, err := forwardRequest(r, cfg, appID)
					if err != nil {
						http.Error(w, "Bad Gateway", http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					copyResponse(w, resp)
					return
				}

				// Normal/Learning mode: return honeypot
				logging.Attack(clientIP, r.Method, r.URL.Path, result.AttackType, "Stage 4: LLM Analysis")
				db.StoreAttackInstance(appID, 0, clientIP, "", r.URL.Path, r.Method)

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
		log.Printf("[LEGITIMATE] app_id=%s | Forwarding to backend: %s %s", appID, r.Method, r.URL.Path)
		resp, err := forwardRequest(r, cfg, appID)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyResponse(w, resp)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: mux,
	}

	// Start proxy in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n⏹️  Shutting down gracefully...")
	if err := server.Shutdown(context.Background()); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	fmt.Println("✓ Server stopped")
}

// extractAppID extracts app_id from request header or uses fallback
func extractAppID(r *http.Request, cfg *config.Config) string {
	if !cfg.Server.MultiAppMode {
		return cfg.Server.AppIDFallback
	}

	// Try to get from header
	appID := r.Header.Get(cfg.Server.AppIDHeader)
	if appID == "" {
		appID = cfg.Server.AppIDFallback
	}

	// TODO: Validate app exists in config.Apps
	return appID
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// forwardRequest forwards request to backend with app_id routing
func forwardRequest(r *http.Request, cfg *config.Config, appID string) (*http.Response, error) {
	// Determine target based on app_id
	target := cfg.Server.ProxyTarget
	if cfg.Server.MultiAppMode {
		if app, exists := cfg.Apps[appID]; exists && app.Enabled {
			target = app.ProxyTarget
		}
	}

	// Create new request to target
	req := r.Clone(r.Context())
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(target, "http://")
	req.URL.Host = strings.TrimPrefix(req.URL.Host, "https://")
	req.RequestURI = ""

	client := &http.Client{}
	return client.Do(req)
}

// copyResponse copies response from backend to client
func copyResponse(w http.ResponseWriter, src *http.Response) error {
	// Copy headers
	for name, values := range src.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Copy status code
	w.WriteHeader(src.StatusCode)

	// Copy body
	_, err := io.Copy(w, src.Body)
	return err
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
