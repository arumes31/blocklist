package service

import (
	"blocklist/internal/models"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// PostgresRepo defines the interface for Postgres operations needed by AuthService
type PostgresRepo interface {
	GetAdmin(username string) (*models.AdminAccount, error)
	CreateAdmin(admin models.AdminAccount) error
	GetAPITokenByHash(hash string) (*models.APIToken, error)
}

// RedisRepo defines the interface for Redis operations needed by AuthService
type RedisRepo interface {
}

type AuthService struct {
	pg    PostgresRepo
	redis RedisRepo
}

func NewAuthService(pg PostgresRepo, r RedisRepo) *AuthService {
	return &AuthService{
		pg:    pg,
		redis: r,
	}
}

func (s *AuthService) CheckAuth(username, password, token string) bool {
	if s.pg == nil {
		return false
	}

	// API Token Auth
	if token != "" {
		hash := sha256.Sum256([]byte(token))
		hashStr := hex.EncodeToString(hash[:])
		t, err := s.pg.GetAPITokenByHash(hashStr)
		if err == nil && t != nil {
			// Check expiration. Fail closed: if a token carries an expiry we
			// cannot parse, reject it rather than treating it as non-expiring.
			if t.ExpiresAt != nil {
				expiresAt, perr := time.Parse(time.RFC3339, *t.ExpiresAt)
				if perr != nil || time.Now().After(expiresAt) {
					return false
				}
			}
			return true
		}
	}

	// User Auth
	if username == "" {
		return false
	}

	admin, err := s.pg.GetAdmin(username)
	if err != nil {
		return false
	}

	// Verify Password
	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		return false
	}

	// Verify TOTP. An empty stored secret means the account has not completed
	// 2FA enrollment; it must go through the enrollment flow, not authenticate.
	// totp.Validate against an empty secret accepts the attacker-computable
	// empty-key code, so we must reject it explicitly (2FA bypass otherwise).
	if admin.Token == "" {
		return false
	}
	return totp.Validate(token, admin.Token)
}

func (s *AuthService) VerifyTOTP(username, token string) bool {
	if s.pg == nil {
		return false
	}
	admin, err := s.pg.GetAdmin(username)
	if err != nil {
		return false
	}
	// Reject accounts with no enrolled TOTP secret: validating against an empty
	// secret would accept the attacker-computable empty-key code (2FA bypass).
	if admin.Token == "" {
		return false
	}
	return totp.Validate(token, admin.Token)
}

func (s *AuthService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (s *AuthService) CreateAdmin(username, password, role, permissions string) (*models.AdminAccount, error) {
	if s.pg == nil {
		return nil, nil
	}
	hash, err := s.HashPassword(password)
	if err != nil {
		return nil, err
	}

	if role == "" {
		role = "operator"
	}
	if permissions == "" {
		permissions = "gui_read"
	}

	admin := models.AdminAccount{
		Username:     username,
		PasswordHash: hash,
		Token:        "", // Leave empty to trigger 2FA setup on first login
		Role:         role,
		Permissions:  permissions,
	}

	err = s.pg.CreateAdmin(admin)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}
