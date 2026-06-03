package service

import (
	"blocklist/internal/config"
	"fmt"
	"net/smtp"
	"strings"

	zlog "github.com/rs/zerolog/log"
)

// headerSanitizer strips CR and LF characters, which are the delimiters used for
// email header (CRLF) injection. Any value interpolated into a message header
// must pass through this first so untrusted input cannot inject extra headers.
var headerSanitizer = strings.NewReplacer("\r", "", "\n", "")

// sanitizeHeader removes CR/LF from a value destined for an email header.
func sanitizeHeader(v string) string {
	return headerSanitizer.Replace(v)
}

type MailService struct {
	cfg *config.Config
}

func NewMailService(cfg *config.Config) *MailService {
	return &MailService{cfg: cfg}
}

func (s *MailService) SendAlert(subject string, body string) error {
	if s.cfg.SMTPHost == "" {
		return nil // Not configured
	}

	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)

	// Sanitize every value that lands in a header line so untrusted content (e.g.
	// an attacker-supplied block reason that reaches the subject) cannot inject
	// additional headers. The body is the last segment, after the blank-line
	// separator, so it cannot introduce headers.
	recipient := sanitizeHeader(s.cfg.SMTPTo)
	safeSubject := sanitizeHeader(subject)
	to := []string{recipient}
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", recipient, safeSubject, body))

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, sanitizeHeader(s.cfg.SMTPFrom), to, msg)
	if err != nil {
		zlog.Error().Err(err).Str("to", s.cfg.SMTPTo).Msg("Failed to send alert email")
		return err
	}

	zlog.Info().Str("to", s.cfg.SMTPTo).Msg("Alert email sent")
	return nil
}
