package main

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
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
			input:    `{"password":"mysecretpassword"}`,
			expected: `{"password":"[CENSORED]"}`,
		},
		{
			name:     "JSON secret with spaces",
			input:    `{"secret" : "super-secret-value"}`,
			expected: `{"secret" : "[CENSORED]"}`,
		},
		{
			name:     "Plain text token",
			input:    "API token: abcdef123456",
			expected: "API token: [CENSORED]",
		},
		{
			name:     "Case insensitive PASSWORD",
			input:    "PASSWORD: secret123",
			expected: "PASSWORD: [CENSORED]",
		},
		{
			name:     "Multiple keys",
			input:    `{"password":"p1", "token":"t1", "other":"val"}`,
			expected: `{"password":"[CENSORED]", "token":"[CENSORED]", "other":"val"}`,
		},
		{
			name:     "No sensitive keys",
			input:    `{"username":"jules", "action":"login"}`,
			expected: `{"username":"jules", "action":"login"}`,
		},
		{
			name:     "Empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "Keys without values (partial match)",
			input:    "password:",
			expected: "password:",
		},
		{
			name:     "Mixed types",
			input:    "Log: secret: 'abc', token \"xyz\"",
			expected: "Log: secret: '[CENSORED]', token \"[CENSORED]\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &CensorWriter{
				Writer: &buf,
				re:     censorRE,
			}

			n, err := w.Write([]byte(tt.input))
			assert.NoError(t, err)
			assert.Equal(t, len(tt.expected), n)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}
