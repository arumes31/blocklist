package service

import (
	"errors"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestDisabledAccountAuthentication(t *testing.T) {
	const password = "synthetic-password"
	const secret = "JBSWY3DPEHPK3PXP"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	for _, disabled := range []bool{true, false} {
		account := &models.AdminAccount{Username: "member", PasswordHash: string(hash), Token: secret, Disabled: disabled}
		pg := new(MockPostgresRepo)
		pg.On("GetAdmin", "member").Return(account, nil)
		svc := NewAuthService(pg, nil)
		require.Equal(t, !disabled, svc.CheckAuth("member", password, code))
		require.Equal(t, !disabled, svc.VerifyTOTP("member", code))
	}
}

func TestTokenAuthenticationRequiresEnabledOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account *models.AdminAccount
		err     error
		allowed bool
	}{
		{name: "enabled owner", account: &models.AdminAccount{}, allowed: true},
		{name: "disabled owner", account: &models.AdminAccount{Disabled: true}},
		{name: "missing owner"},
		{name: "unavailable owner", err: errors.New("database unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pg := new(MockPostgresRepo)
			pg.On("GetAPITokenByHash", mock.Anything).Return(&models.APIToken{Username: "member"}, nil).Once()
			pg.On("GetAdmin", "member").Return(tc.account, tc.err).Once()
			svc := NewAuthService(pg, nil)
			require.Equal(t, tc.allowed, svc.CheckAuth("", "", "synthetic-token"))
			pg.AssertExpectations(t)
		})
	}
}
