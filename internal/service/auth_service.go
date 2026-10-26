package service

import (
	"blocklist/internal/models"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/pquerna/otp"
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

	// Token-only callers may validate an API credential, but a token must never
	// substitute for TOTP in a named user's password login.
	if token != "" && username == "" && password == "" {
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
			owner, err := s.pg.GetAdmin(t.Username)
			return err == nil && owner != nil && !owner.Disabled
		}
	}

	// User Auth
	if username == "" {
		return false
	}

	admin, err := s.pg.GetAdmin(username)
	if err != nil || admin == nil || admin.Disabled || admin.AuthSource == "entra" {
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
	return s.validateTOTP(username, token, admin.Token)
}

func (s *AuthService) VerifyTOTP(username, token string) bool {
	if s.pg == nil {
		return false
	}
	admin, err := s.pg.GetAdmin(username)
	if err != nil || admin == nil || admin.Disabled || admin.AuthSource == "entra" {
		return false
	}
	// Reject accounts with no enrolled TOTP secret: validating against an empty
	// secret would accept the attacker-computable empty-key code (2FA bypass).
	if admin.Token == "" {
		return false
	}
	return s.validateTOTP(username, token, admin.Token)
}

// TOTPStepClaimer records the last TOTP time step accepted for an account.
type TOTPStepClaimer interface {
	ClaimTOTPStep(username string, step int64) (bool, error)
}

func (s *AuthService) validateTOTP(username, code, secret string) bool {
	claimer, _ := s.redis.(TOTPStepClaimer)
	return ValidateTOTPOnce(claimer, username, code, secret)
}

// ValidateTOTPOnce validates code against secret (one 30-second step of skew,
// like totp.Validate) and, when a claimer is available, rejects any code whose
// time step is not newer than the last one accepted for username. Errors from
// the claimer fail closed.
func ValidateTOTPOnce(claimer TOTPStepClaimer, username, code, secret string) bool {
	if secret == "" {
		return false
	}
	now := time.Now().UTC()
	opts := totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, offset := range []int64{0, -1, 1} {
		at := now.Add(time.Duration(offset) * 30 * time.Second)
		ok, err := totp.ValidateCustom(code, secret, at, opts)
		if err != nil || !ok {
			continue
		}
		if claimer == nil {
			return true
		}
		claimed, err := claimer.ClaimTOTPStep(username, at.Unix()/30)
		return err == nil && claimed
	}
	return false
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
