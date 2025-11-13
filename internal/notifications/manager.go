package notifications

import (
	"log"
	"sync"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
	"github.com/0tSystemsPublicRepos/ifrit/internal/database"
)

type Manager struct {
	providers []NotificationProvider
	config    config.NotificationsConfig
	mu        sync.RWMutex
}

func NewManager(cfg *config.Config, db *database.SQLiteDB) *Manager {
	manager := &Manager{
		providers: []NotificationProvider{},
		config:    cfg.Notifications,  // Store config
	}

	// Initialize webhook provider
	if cfg.Webhooks.Enabled {
		manager.providers = append(manager.providers, NewWebhookProvider(&cfg.Webhooks, db))
		log.Printf("[NOTIFICATIONS] ✓ Webhook provider initialized")
	}

	// Initialize email provider
	if cfg.Notifications.Providers.Email.Enabled {
		manager.providers = append(manager.providers, NewEmailProvider(&cfg.Notifications.Providers.Email))
		log.Printf("[NOTIFICATIONS] ✓ Email provider initialized")
	}

	// Initialize Twilio provider
	if cfg.Notifications.Providers.Twilio.Enabled {
		manager.providers = append(manager.providers, NewTwilioProvider(&cfg.Notifications.Providers.Twilio))
		log.Printf("[NOTIFICATIONS] ✓ Twilio provider initialized")
	}

	// Initialize Slack provider
	if cfg.Notifications.Providers.Slack.Enabled {
		manager.providers = append(manager.providers, NewSlackProvider(&cfg.Notifications.Providers.Slack))
		log.Printf("[NOTIFICATIONS] ✓ Slack provider initialized")
	}

	if len(manager.providers) == 0 {
		log.Printf("[NOTIFICATIONS] No notification providers enabled")
	}

	return manager
}

// Send sends notification to all enabled providers based on configured rules
func (m *Manager) Send(notification *Notification) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.providers) == 0 {
		return nil
	}

	// CHECK NOTIFICATION RULES - Only send if threat level matches configured rules
	shouldSend := m.shouldSendNotification(notification.ThreatLevel)
	if !shouldSend {
		log.Printf("[NOTIFICATIONS] Skipped notification for %s threat (rule-based filtering)", notification.ThreatLevel)
		return nil
	}

	log.Printf("[NOTIFICATIONS] Sending notification for threat: %s/%d from %s", notification.ThreatLevel, notification.RiskScore, notification.SourceIP)

	// Send to all providers in parallel
	var wg sync.WaitGroup
	errors := make([]error, 0)
	mu := sync.Mutex{}

	for _, provider := range m.providers {
		if !provider.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(p NotificationProvider) {
			defer wg.Done()
			err := p.Send(notification)
			if err != nil {
				log.Printf("[NOTIFICATIONS] Error from %s provider: %v", p.Name(), err)
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}(provider)
	}

	wg.Wait()

	if len(errors) > 0 {
		log.Printf("[NOTIFICATIONS] %d provider(s) failed", len(errors))
	}

	return nil
}

// shouldSendNotification checks if notification should be sent based on threat level rules from config
func (m *Manager) shouldSendNotification(threatLevel string) bool {
	switch threatLevel {
	case "CRITICAL":
		return m.config.Rules.AlertOnCritical
	case "HIGH":
		return m.config.Rules.AlertOnHigh
	case "MEDIUM":
		return m.config.Rules.AlertOnMedium
	case "LOW":
		return m.config.Rules.AlertOnLow
	default:
		return false
	}
}

// GetProviderStatus returns status of all providers
func (m *Manager) GetProviderStatus() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]bool)
	for _, provider := range m.providers {
		status[provider.Name()] = provider.IsEnabled()
	}
	return status
}

// GetNotificationRules returns current notification rules from config
func (m *Manager) GetNotificationRules() map[string]bool {
	return map[string]bool{
		"CRITICAL": m.config.Rules.AlertOnCritical,
		"HIGH":     m.config.Rules.AlertOnHigh,
		"MEDIUM":   m.config.Rules.AlertOnMedium,
		"LOW":      m.config.Rules.AlertOnLow,
	}
}
