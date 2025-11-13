package threat_intelligence

import (
	"log"
	"sync"
	"time"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type Manager struct {
	config    *config.ThreatIntelligenceConfig
	enricher  *Enricher
	db        *database.SQLiteDB
	queue     chan EnrichmentJob
	workers   int
	stopChan  chan bool
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

type EnrichmentJob struct {
	AppID    string
	SourceIP string
	Retry    int
	MaxRetry int
}

func NewManager(cfg *config.ThreatIntelligenceConfig, db *database.SQLiteDB) *Manager {
	workers := cfg.EnrichmentWorkers
	if workers <= 0 {
		workers = 3
	}

	return &Manager{
		config:   cfg,
		enricher: NewEnricher(cfg, db),
		db:       db,
		queue:    make(chan EnrichmentJob, 1000), // Buffer for 1000 jobs
		workers:  workers,
		stopChan: make(chan bool),
	}
}

// Start starts the enrichment worker goroutines
func (m *Manager) Start() {
	if !m.config.Enabled {
		log.Println("[THREAT_INTEL] Threat Intelligence disabled in config")
		return
	}

	log.Printf("[THREAT_INTEL] Starting %d enrichment workers", m.workers)

	for i := 0; i < m.workers; i++ {
		m.wg.Add(1)
		go m.worker(i)
	}
}

// Stop gracefully shuts down enrichment workers
func (m *Manager) Stop() {
	log.Println("[THREAT_INTEL] Stopping enrichment workers")
	close(m.stopChan)
	m.wg.Wait()
	close(m.queue)
	log.Println("[THREAT_INTEL] Enrichment workers stopped")
}

// EnqueueEnrichment adds an IP to the enrichment queue
func (m *Manager) EnqueueEnrichment(appID, sourceIP string) {
	if !m.config.Enabled {
		return
	}

	// Check if already cached to avoid queue buildup
	cached, err := m.db.IsThreatIntelligenceCached(appID, sourceIP)
	if err == nil && cached {
		return // Already cached, no need to enqueue
	}

	job := EnrichmentJob{
		AppID:    appID,
		SourceIP: sourceIP,
		Retry:    0,
		MaxRetry: 3,
	}

	// Non-blocking send (queue might be full, but that's okay - we'll skip)
	select {
	case m.queue <- job:
		log.Printf("[THREAT_INTEL] Enqueued enrichment job for IP: %s (app_id: %s)", sourceIP, appID)
	default:
		log.Printf("[THREAT_INTEL] Queue full, skipping enrichment for IP: %s", sourceIP)
	}
}

// worker processes enrichment jobs from the queue
func (m *Manager) worker(id int) {
	defer m.wg.Done()
	log.Printf("[THREAT_INTEL] Worker %d started", id)

	for {
		select {
		case <-m.stopChan:
			log.Printf("[THREAT_INTEL] Worker %d stopping", id)
			return

		case job, ok := <-m.queue:
			if !ok {
				log.Printf("[THREAT_INTEL] Worker %d queue closed", id)
				return
			}

			m.processJob(job, id)
		}
	}
}

// processJob enriches a single IP
func (m *Manager) processJob(job EnrichmentJob, workerID int) {
	log.Printf("[THREAT_INTEL] Worker %d processing: %s (app_id: %s)", workerID, job.SourceIP, job.AppID)

	result, err := m.enricher.EnrichIP(job.AppID, job.SourceIP)
	if err != nil {
		log.Printf("[THREAT_INTEL] Worker %d enrichment failed for %s: %v (retry %d/%d)", workerID, job.SourceIP, err, job.Retry, job.MaxRetry)

		// Retry on failure
		if job.Retry < job.MaxRetry {
			job.Retry++
			time.Sleep(time.Second * time.Duration(job.Retry)) // Exponential backoff

			select {
			case m.queue <- job:
				log.Printf("[THREAT_INTEL] Requeued job for %s (retry %d)", job.SourceIP, job.Retry)
			default:
				log.Printf("[THREAT_INTEL] Failed to requeue job for %s", job.SourceIP)
			}
		}
		return
	}

	if result != nil {
		log.Printf("[THREAT_INTEL] Worker %d completed enrichment for %s: risk_score=%d threat_level=%s", workerID, job.SourceIP, result.RiskScore, result.ThreatLevel)
	}
}

// GetStats returns enrichment queue statistics
func (m *Manager) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":   m.config.Enabled,
		"workers":   m.workers,
		"queue_len": len(m.queue),
		"cache_ttl": m.config.CacheTTLHours,
	}
}
