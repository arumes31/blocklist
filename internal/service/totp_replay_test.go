package service

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

type memoryStepClaimer struct {
	last map[string]int64
	err  error
}

func (m *memoryStepClaimer) ClaimTOTPStep(username string, step int64) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if last, ok := m.last[username]; ok && step <= last {
		return false, nil
	}
	m.last[username] = step
	return true, nil
}

func TestValidateTOTPOnceRejectsReplay(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // Well-known test vector secret.
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	claimer := &memoryStepClaimer{last: map[string]int64{}}

	require.True(t, ValidateTOTPOnce(claimer, "alice", code, secret))
	require.False(t, ValidateTOTPOnce(claimer, "alice", code, secret), "same code must not be accepted twice")
	require.True(t, ValidateTOTPOnce(claimer, "bob", code, secret), "steps are tracked per account")

	previous, err := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	require.NoError(t, err)
	if previous != code {
		require.False(t, ValidateTOTPOnce(claimer, "alice", previous, secret), "older steps are rejected")
	}

	require.False(t, ValidateTOTPOnce(claimer, "carol", "000000x", secret))
	require.False(t, ValidateTOTPOnce(claimer, "carol", code, ""))
	require.False(t, ValidateTOTPOnce(&memoryStepClaimer{err: errors.New("redis down")}, "dave", code, secret), "fails closed")
	require.True(t, ValidateTOTPOnce(nil, "erin", code, secret))
}
