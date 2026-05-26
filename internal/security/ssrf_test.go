package security

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://google.com", false},
		{"https://google.com", false},
		{"http://127.0.0.1", true},
		{"http://localhost", true},
		{"http://169.254.169.254", true},
		{"ftp://google.com", true},
		{"http://invalid-host-that-does-not-resolve.test", false}, // Should be allowed here, caught by socket control
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
