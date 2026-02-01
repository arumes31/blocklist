package service

import (
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	pgRepo    *repository.PostgresRepository
	redisRepo *repository.RedisRepository
}

func NewAuthService(pg *repository.PostgresRepository, r *repository.RedisRepository) *AuthService {
	return &AuthService{
		pgRepo:    pg,
		redisRepo: r,
	}
}

func (s *AuthService) CheckAuth(username, password, token string) bool {
	if s.pgRepo == nil { return false }
	admin, err := s.pgRepo.GetAdmin(username)
	if err != nil {
		return false
	}

	// Verify Password
	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		return false
	}

	// Verify TOTP
	return totp.Validate(token, admin.Token)
}

func (s *AuthService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (s *AuthService) CreateAdmin(username, password, role, permissions string) (*models.AdminAccount, error) {
	if s.pgRepo == nil { return nil, nil }
	hash, err := s.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Generate TOTP Secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Blocklist App",
		AccountName: username,
	})
	if err != nil {
		return nil, err
	}

	if role == "" { role = "operator" }
	if permissions == "" { permissions = "gui_read" }

	admin := models.AdminAccount{
		Username:     username,
		PasswordHash: hash,
		Token:        key.Secret(),
		Role:         role,
		Permissions:  permissions,
	}

	err = s.pgRepo.CreateAdmin(admin)
	if err != nil {
		return nil, err
	}

	return &admin, nil
}
