package main

import (
	"bytes"
	"regexp"
	"testing"
)

func TestCensorWriter_Write(t *testing.T) {
	censorRE := regexp.MustCompile(`(?i)(password|secret|token)(["':\s]+)([^"'\s,{}]+)`)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "JSON password",
			input:    `"password":"secret123"`,
			expected: `"password":"[CENSORED]"`,
		},
		{
			name:     "Plain text secret",
			input:    "secret: my-secret-value",
			expected: "secret: [CENSORED]",
		},
		{
			name:     "Token with quotes",
			input:    "token 'hidden-token'",
			expected: "token '[CENSORED]'",
		},
		{
			name:     "Mixed case",
			input:    "PASSWORD: P4SS",
			expected: "PASSWORD: [CENSORED]",
		},
		{
			name:     "Multiple keys in JSON",
			input:    `{"user":"jules", "password":"123", "token":"abc"}`,
			expected: `{"user":"jules", "password":"[CENSORED]", "token":"[CENSORED]"}`,
		},
		{
			name:     "Not sensitive",
			input:    `{"message":"hello world"}`,
			expected: `{"message":"hello world"}`,
		},
		{
			name:     "Token with spaces",
			input:    "token   abc",
			expected: "token   [CENSORED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &CensorWriter{
				Writer: &buf,
				re:     censorRE,
			}

			_, err := w.Write([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if buf.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, buf.String())
			}
		})
	}
}
