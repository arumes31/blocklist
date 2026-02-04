package service

import (
	"testing"
)

func TestAuthService_HashPassword(t *testing.T) {
	svc := NewAuthService(nil, nil)
	pass := "secret123"
	hash, err := svc.HashPassword(pass)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == pass {
		t.Error("hash should not be equal to password")
	}
}
