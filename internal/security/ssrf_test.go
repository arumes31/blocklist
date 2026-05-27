package security

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsSafeURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"http://google.com", false, ""},
		{"https://google.com", false, ""},
		{"http://127.0.0.1", true, "URL resolves to internal IP: 127.0.0.1"}, // net.LookupIP("127.0.0.1") usually returns [127.0.0.1]
		{"http://localhost", true, "URL resolves to internal IP"},
		{"http://192.168.1.1", true, "URL resolves to internal IP: 192.168.1.1"},
		{"http://[::1]", true, "URL resolves to internal IP"},
		{"ftp://google.com", true, "unsupported scheme"},
		{"http://", true, "invalid URL host"},
		{"http://nonexistent-domain-that-should-fail-resolution.test", false, ""}, // Should be allowed according to memory
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := IsSafeURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsInternalIP(t *testing.T) {
	assert.True(t, IsInternalIP([]byte{127, 0, 0, 1}))
	assert.True(t, IsInternalIP([]byte{10, 0, 0, 1}))
	assert.True(t, IsInternalIP([]byte{172, 16, 0, 1}))
	assert.True(t, IsInternalIP([]byte{192, 168, 0, 1}))
	assert.False(t, IsInternalIP([]byte{8, 8, 8, 8}))
}
