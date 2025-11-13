package notifications

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"github.com/0tSystemsPublicRepos/ifrit/internal/config"
)

type EmailProvider struct {
	config *config.EmailProviderConfig
}

func NewEmailProvider(cfg *config.EmailProviderConfig) *EmailProvider {
	return &EmailProvider{
		config: cfg,
	}
}

func (ep *EmailProvider) Name() string {
	return "email"
}

func (ep *EmailProvider) IsEnabled() bool {
	return ep.config.Enabled && ep.config.SMTPHost != "" && ep.config.SMTPUsername != ""
}

// Send sends email notification
func (ep *EmailProvider) Send(notification *Notification) error {
	if !ep.IsEnabled() {
		return nil
	}

	// Build email
	subject := fmt.Sprintf("[IFRIT] %s Threat Detected - %s from %s", notification.ThreatLevel, notification.AttackType, notification.SourceIP)
	body := ep.buildEmailBody(notification)

	// Parse recipients (comma-separated)
	recipients := []string{}
	if ep.config.SMTPUsername != "" {
		recipients = append(recipients, ep.config.SMTPUsername)
	}

	if len(recipients) == 0 {
		log.Printf("[EMAIL] No recipients configured")
		return fmt.Errorf("no email recipients configured")
	}

	// Send email
	err := ep.sendEmail(recipients, subject, body)
	if err != nil {
		log.Printf("[EMAIL] ✗ Failed to send email: %v", err)
		return err
	}

	log.Printf("[EMAIL] ✓ Email sent successfully to %d recipient(s) (threat: %s/%d)", len(recipients), notification.ThreatLevel, notification.RiskScore)
	return nil
}

// sendEmail sends SMTP email
func (ep *EmailProvider) sendEmail(recipients []string, subject, body string) error {
	// Build message
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		ep.config.FromAddress,
		strings.Join(recipients, ","),
		subject,
		body,
	)

	// SMTP authentication
	auth := smtp.PlainAuth(
		"",
		ep.config.SMTPUsername,
		ep.config.SMTPPassword,
		ep.config.SMTPHost,
	)

	// Send email
	addr := fmt.Sprintf("%s:%d", ep.config.SMTPHost, ep.config.SMTPPort)
	err := smtp.SendMail(
		addr,
		auth,
		ep.config.FromAddress,
		recipients,
		[]byte(message),
	)

	return err
}

// buildEmailBody constructs HTML email body
func (ep *EmailProvider) buildEmailBody(notification *Notification) string {
	threatColor := "#FFA500" // Orange
	if notification.ThreatLevel == "CRITICAL" {
		threatColor = "#FF0000" // Red
	} else if notification.ThreatLevel == "HIGH" {
		threatColor = "#FF6600" // Dark Orange
	} else if notification.ThreatLevel == "MEDIUM" {
		threatColor = "#FFA500" // Orange
	} else {
		threatColor = "#00AA00" // Green
	}

	abuseIPDBSection := ""
	if notification.AbuseIPDBReports > 0 {
		abuseIPDBSection = fmt.Sprintf(`
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ddd;">
					<strong>AbuseIPDB Confidence Score:</strong>
				</td>
				<td style="padding: 10px; border-bottom: 1px solid #ddd;">
					%.1f%% (%d reports)
				</td>
			</tr>
		`, notification.AbuseIPDBScore, notification.AbuseIPDBReports)
	}

	virusTotalSection := ""
	if notification.VirusTotalMalicious > 0 || notification.VirusTotalSuspicious > 0 {
		virusTotalSection = fmt.Sprintf(`
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ddd;">
					<strong>VirusTotal Detections:</strong>
				</td>
				<td style="padding: 10px; border-bottom: 1px solid #ddd;">
					Malicious: %d, Suspicious: %d
				</td>
			</tr>
		`, notification.VirusTotalMalicious, notification.VirusTotalSuspicious)
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<style>
		body { font-family: Arial, sans-serif; }
		.container { max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 5px; }
		.header { background-color: %s; color: white; padding: 20px; text-align: center; }
		.header h1 { margin: 0; font-size: 24px; }
		.content { padding: 20px; }
		.details { width: 100%%; border-collapse: collapse; margin-top: 20px; }
		.details td { padding: 10px; border-bottom: 1px solid #ddd; }
		.details tr:last-child td { border-bottom: none; }
		.footer { background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666; }
		.risk-score { font-size: 36px; font-weight: bold; color: %s; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>⚠️ IFRIT Threat Alert</h1>
			<p style="margin: 10px 0 0 0;">%s Threat Level Detected</p>
		</div>
		<div class="content">
			<p>A <strong>%s</strong> threat has been detected on your application.</p>
			
			<div style="text-align: center; margin: 20px 0;">
				<div>Risk Score</div>
				<div class="risk-score">%d/100</div>
			</div>

			<table class="details">
				<tr>
					<td><strong>Threat Level:</strong></td>
					<td style="color: %s; font-weight: bold;">%s</td>
				</tr>
				<tr>
					<td><strong>Attack Type:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>Source IP:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>Country:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>HTTP Method:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>Target Path:</strong></td>
					<td>%s</td>
				</tr>
				<tr>
					<td><strong>Timestamp:</strong></td>
					<td>%s</td>
				</tr>
				%s
				%s
			</table>

			<p style="margin-top: 20px; padding: 15px; background-color: #f9f9f9; border-left: 4px solid %s;">
				<strong>Recommended Action:</strong><br>
				Review the attack details and take appropriate action. IFRIT has blocked this request with a deceptive response.
			</p>
		</div>
		<div class="footer">
			<p>IFRIT Threat Intelligence System</p>
			<p>This is an automated alert. Do not reply to this email.</p>
		</div>
	</div>
</body>
</html>
	`, threatColor, threatColor,
		notification.ThreatLevel,
		notification.ThreatLevel,
		notification.RiskScore,
		threatColor, notification.ThreatLevel,
		notification.AttackType,
		notification.SourceIP,
		notification.Country,
		notification.Method,
		notification.Path,
		notification.Timestamp.Format("2006-01-02 15:04:05 MST"),
		abuseIPDBSection,
		virusTotalSection,
		threatColor,
	)

	return body
}
