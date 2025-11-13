package threat_intelligence

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type Enricher struct {
	config *config.ThreatIntelligenceConfig
	db     *database.SQLiteDB
	client *http.Client
	mu     sync.RWMutex
}

type EnrichmentResult struct {
	SourceIP      string
	RiskScore     int
	ThreatLevel   string
	AbuseIPDB     *AbuseIPDBData
	VirusTotal    *VirusTotalData
	IPInfo        *IPInfoData
	EnrichedAt    time.Time
}

type AbuseIPDBData struct {
	AbuseConfidenceScore float64
	TotalReports         int
	LastReportedAt       string
	UsageType            string
	ISP                  string
	Domain               string
	CountryCode          string
	IsWhitelisted        bool
	Score                float64
}

type VirusTotalData struct {
	Malicious   int
	Suspicious  int
	Harmless    int
	Undetected  int
	LastAnalysis string
}

type IPInfoData struct {
	Country    string
	City       string
	Region     string
	Org        string
	ISP        string
	Privacy    PrivacyData
}

type PrivacyData struct {
	VPN     bool
	Proxy   bool
	Hosting bool
	Tor     bool
	Type    string
}

func NewEnricher(cfg *config.ThreatIntelligenceConfig, db *database.SQLiteDB) *Enricher {
	return &Enricher{
		config: cfg,
		db:     db,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// EnrichIP enriches threat intelligence for an IP address
func (e *Enricher) EnrichIP(appID, sourceIP string) (*EnrichmentResult, error) {
	// Check if already cached
	cached, err := e.db.IsThreatIntelligenceCached(appID, sourceIP)
	if err == nil && cached {
		log.Printf("[THREAT_INTEL] Cache hit for IP: %s (app_id: %s)", sourceIP, appID)
		return nil, nil // Return from cache, don't re-enrich
	}

	result := &EnrichmentResult{
		SourceIP:   sourceIP,
		EnrichedAt: time.Now(),
		RiskScore:  0,
	}

	// Parallel enrichment from all sources
	var wg sync.WaitGroup
	errors := make([]error, 0)
	mu := sync.Mutex{}

	// AbuseIPDB enrichment
	if e.config.APIs.AbuseIPDB.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := e.enrichFromAbuseIPDB(sourceIP)
			if err != nil {
				log.Printf("[THREAT_INTEL] AbuseIPDB error for %s: %v", sourceIP, err)
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
				return
			}
			result.AbuseIPDB = data
			log.Printf("[THREAT_INTEL] AbuseIPDB enriched %s: score=%.1f", sourceIP, data.Score)
		}()
	}

	// VirusTotal enrichment
	if e.config.APIs.VirusTotal.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := e.enrichFromVirusTotal(sourceIP)
			if err != nil {
				log.Printf("[THREAT_INTEL] VirusTotal error for %s: %v", sourceIP, err)
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
				return
			}
			result.VirusTotal = data
			log.Printf("[THREAT_INTEL] VirusTotal enriched %s: malicious=%d suspicious=%d", sourceIP, data.Malicious, data.Suspicious)
		}()
	}

	// IPInfo enrichment
	if e.config.APIs.IPInfo.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := e.enrichFromIPInfo(sourceIP)
			if err != nil {
				log.Printf("[THREAT_INTEL] IPInfo error for %s: %v", sourceIP, err)
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
				return
			}
			result.IPInfo = data
			log.Printf("[THREAT_INTEL] IPInfo enriched %s: country=%s city=%s", sourceIP, data.Country, data.City)
		}()
	}

	wg.Wait()

	// Calculate risk score
	e.calculateRiskScore(result)

	// Store in database
	err = e.storeEnrichment(appID, result)
	if err != nil {
		log.Printf("[THREAT_INTEL] Error storing enrichment for %s: %v", sourceIP, err)
	}

	return result, nil
}

// enrichFromAbuseIPDB queries AbuseIPDB API
func (e *Enricher) enrichFromAbuseIPDB(sourceIP string) (*AbuseIPDBData, error) {
	if e.config.APIs.AbuseIPDB.APIKey == "" || e.config.APIs.AbuseIPDB.APIKey == "${ABUSEIPDB_API_KEY}" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", sourceIP)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", e.config.APIs.AbuseIPDB.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AbuseIPDB returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, _ := io.ReadAll(resp.Body)

	var abuseResp struct {
		Data struct {
			AbuseConfidenceScore float64 `json:"abuseConfidenceScore"`
			CountryCode          string  `json:"countryCode"`
			TotalReports         int     `json:"totalReports"`
			LastReportedAt       string  `json:"lastReportedAt"`
			UsageType            string  `json:"usageType"`
			ISP                  string  `json:"isp"`
			Domain               string  `json:"domain"`
			IsWhitelisted        bool    `json:"isWhitelisted"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return nil, fmt.Errorf("failed to parse AbuseIPDB response: %w", err)
	}

	return &AbuseIPDBData{
		AbuseConfidenceScore: abuseResp.Data.AbuseConfidenceScore,
		TotalReports:         abuseResp.Data.TotalReports,
		LastReportedAt:       abuseResp.Data.LastReportedAt,
		UsageType:            abuseResp.Data.UsageType,
		ISP:                  abuseResp.Data.ISP,
		Domain:               abuseResp.Data.Domain,
		CountryCode:          abuseResp.Data.CountryCode,
		IsWhitelisted:        abuseResp.Data.IsWhitelisted,
		Score:                abuseResp.Data.AbuseConfidenceScore,
	}, nil
}

// enrichFromVirusTotal queries VirusTotal API
func (e *Enricher) enrichFromVirusTotal(sourceIP string) (*VirusTotalData, error) {
	if e.config.APIs.VirusTotal.APIKey == "" || e.config.APIs.VirusTotal.APIKey == "${VIRUSTOTAL_API_KEY}" {
		return nil, fmt.Errorf("VirusTotal API key not configured")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", sourceIP)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-apikey", e.config.APIs.VirusTotal.APIKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("VirusTotal returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, _ := io.ReadAll(resp.Body)

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious   int `json:"malicious"`
					Suspicious  int `json:"suspicious"`
					Harmless    int `json:"harmless"`
					Undetected  int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate int `json:"last_analysis_date"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return nil, fmt.Errorf("failed to parse VirusTotal response: %w", err)
	}

	lastAnalysisDate := ""
	if vtResp.Data.Attributes.LastAnalysisDate > 0 {
		lastAnalysisDate = time.Unix(int64(vtResp.Data.Attributes.LastAnalysisDate), 0).Format(time.RFC3339)
	}

	return &VirusTotalData{
		Malicious:   vtResp.Data.Attributes.LastAnalysisStats.Malicious,
		Suspicious:  vtResp.Data.Attributes.LastAnalysisStats.Suspicious,
		Harmless:    vtResp.Data.Attributes.LastAnalysisStats.Harmless,
		Undetected:  vtResp.Data.Attributes.LastAnalysisStats.Undetected,
		LastAnalysis: lastAnalysisDate,
	}, nil
}

// enrichFromIPInfo queries IPInfo API
func (e *Enricher) enrichFromIPInfo(sourceIP string) (*IPInfoData, error) {
	if e.config.APIs.IPInfo.APIKey == "" || e.config.APIs.IPInfo.APIKey == "${IPINFO_API_KEY}" {
		return nil, fmt.Errorf("IPInfo API key not configured")
	}

	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", sourceIP, e.config.APIs.IPInfo.APIKey)
	resp, err := e.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("IPInfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IPInfo returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, _ := io.ReadAll(resp.Body)

	var ipinfoResp struct {
		Country string `json:"country"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Org     string `json:"org"`
		Privacy struct {
			VPN     bool   `json:"vpn"`
			Proxy   bool   `json:"proxy"`
			Hosting bool   `json:"hosting"`
			Tor     bool   `json:"tor"`
			Type    string `json:"type"`
		} `json:"privacy"`
	}

	if err := json.Unmarshal(body, &ipinfoResp); err != nil {
		return nil, fmt.Errorf("failed to parse IPInfo response: %w", err)
	}

	return &IPInfoData{
		Country: ipinfoResp.Country,
		City:    ipinfoResp.City,
		Region:  ipinfoResp.Region,
		Org:     ipinfoResp.Org,
		Privacy: PrivacyData{
			VPN:     ipinfoResp.Privacy.VPN,
			Proxy:   ipinfoResp.Privacy.Proxy,
			Hosting: ipinfoResp.Privacy.Hosting,
			Tor:     ipinfoResp.Privacy.Tor,
			Type:    ipinfoResp.Privacy.Type,
		},
	}, nil
}

// calculateRiskScore computes weighted risk score (0-100)
func (e *Enricher) calculateRiskScore(result *EnrichmentResult) {
	score := 0.0

	// AbuseIPDB score (40% weight)
	if result.AbuseIPDB != nil {
		abuseScore := result.AbuseIPDB.AbuseConfidenceScore * e.config.RiskScoreWeights.AbuseIPDBScore
		score += abuseScore
		log.Printf("[THREAT_INTEL] AbuseIPDB contribution: %.1f (%.1f * 0.4)", abuseScore, result.AbuseIPDB.AbuseConfidenceScore)
	}

	// VirusTotal detections (35% weight)
	if result.VirusTotal != nil {
		totalDetections := result.VirusTotal.Malicious + result.VirusTotal.Suspicious
		vtScore := float64(totalDetections) * 5.0 // Scale to 0-100
		if vtScore > 100 {
			vtScore = 100
		}
		vtScore = vtScore * e.config.RiskScoreWeights.VirusTotalDetections
		score += vtScore
		log.Printf("[THREAT_INTEL] VirusTotal contribution: %.1f (detections=%d)", vtScore, totalDetections)
	}

	// IPInfo risk (25% weight) - based on privacy type
	if result.IPInfo != nil {
		ipinfoScore := 0.0
		if result.IPInfo.Privacy.Tor {
			ipinfoScore = 100.0
		} else if result.IPInfo.Privacy.VPN || result.IPInfo.Privacy.Proxy {
			ipinfoScore = 60.0
		} else if result.IPInfo.Privacy.Hosting {
			ipinfoScore = 40.0
		}
		ipinfoScore = ipinfoScore * e.config.RiskScoreWeights.IPInfoRisk
		score += ipinfoScore
		log.Printf("[THREAT_INTEL] IPInfo contribution: %.1f (privacy=%s)", ipinfoScore, result.IPInfo.Privacy.Type)
	}

	result.RiskScore = int(score)

	// Determine threat level
	if result.RiskScore >= e.config.ThreatLevelThresholds.Critical {
		result.ThreatLevel = "CRITICAL"
	} else if result.RiskScore >= e.config.ThreatLevelThresholds.High {
		result.ThreatLevel = "HIGH"
	} else if result.RiskScore >= e.config.ThreatLevelThresholds.Medium {
		result.ThreatLevel = "MEDIUM"
	} else {
		result.ThreatLevel = "LOW"
	}

	log.Printf("[THREAT_INTEL] Final risk score for %s: %d (%s)", result.SourceIP, result.RiskScore, result.ThreatLevel)
}

// storeEnrichment saves enrichment result to database
func (e *Enricher) storeEnrichment(appID string, result *EnrichmentResult) error {
	var abuseScore *float64
	var abuseReports *int
	var vtMalicious, vtSuspicious bool
	var isVPN, isProxy bool
	var country, org, privacyType string

	if result.AbuseIPDB != nil {
		abuseScore = &result.AbuseIPDB.Score
		abuseReports = &result.AbuseIPDB.TotalReports
		country = result.AbuseIPDB.CountryCode
		org = result.AbuseIPDB.ISP
	}

	if result.VirusTotal != nil {
		vtMalicious = result.VirusTotal.Malicious > 0
		vtSuspicious = result.VirusTotal.Suspicious > 0
	}

	if result.IPInfo != nil {
		isVPN = result.IPInfo.Privacy.VPN
		isProxy = result.IPInfo.Privacy.Proxy
		privacyType = result.IPInfo.Privacy.Type
		if country == "" {
			country = result.IPInfo.Country
		}
		if org == "" {
			org = result.IPInfo.Org
		}
	}

	err := e.db.StoreThreatIntelligence(
		appID,
		result.SourceIP,
		result.RiskScore,
		abuseScore,
		abuseReports,
		vtMalicious,
		vtSuspicious,
		isVPN,
		isProxy,
		country,
		org,
		privacyType,
		result.ThreatLevel,
	)

	if err != nil {
		log.Printf("[THREAT_INTEL] Error storing enrichment: %v", err)
		return err
	}

	log.Printf("[THREAT_INTEL] Enrichment stored for %s: risk_score=%d threat_level=%s", result.SourceIP, result.RiskScore, result.ThreatLevel)
	return nil
}
