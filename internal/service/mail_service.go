package service

import (
	"blocklist/internal/config"
	"fmt"
	"net/smtp"
	"strings"

	zlog "github.com/rs/zerolog/log"
)

type MailService struct {
	cfg *config.Config
}

func NewMailService(cfg *config.Config) *MailService {
	return &MailService{cfg: cfg}
}

func sanitizeEmailContent(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

func (s *MailService) SendAlert(subject string, body string) error {
	if s.cfg.SMTPHost == "" {
		return nil // Not configured
	}

	safeToHeader := sanitizeEmailContent(s.cfg.SMTPTo)
	safeSubject := sanitizeEmailContent(subject)
	safeBody := sanitizeEmailContent(body)

	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	to := []string{s.cfg.SMTPTo}
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", safeToHeader, safeSubject, safeBody))

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, s.cfg.SMTPFrom, to, msg)
	if err != nil {
		zlog.Error().Err(err).Str("to", s.cfg.SMTPTo).Msg("Failed to send alert email")
		return err
	}

	zlog.Info().Str("to", s.cfg.SMTPTo).Msg("Alert email sent")
	return nil
}
