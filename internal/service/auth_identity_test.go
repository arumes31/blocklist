package service

import (
	"testing"

	"blocklist/internal/models"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAPITokenCannotReplaceAccountTOTP(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("synthetic-password"), bcrypt.MinCost)
	require.NoError(t, err)
	for _, source := range []string{"local", "entra"} {
		t.Run(source, func(t *testing.T) {
			pg := new(MockPostgresRepo)
			pg.On("GetAdmin", "victim").Return(&models.AdminAccount{Username: "victim", PasswordHash: string(hash), AuthSource: source, Token: "JBSWY3DPEHPK3PXP"}, nil)
			pg.On("GetAPITokenByHash", mock.Anything).Return(&models.APIToken{Username: "attacker"}, nil).Maybe()
			svc := NewAuthService(pg, nil)
			require.False(t, svc.CheckAuth("victim", "synthetic-password", "valid-api-token"))
			pg.AssertNotCalled(t, "GetAPITokenByHash", mock.Anything)
		})
	}
}
