package main

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCensorWriter_Write(t *testing.T) {
	// Grounded from cmd/server/main.go (as updated by me to include =)
	censorRE := regexp.MustCompile(`(?i)(password|secret|token)(["':=\s]+)([^"'\s,{}\t]+)`)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No sensitive data",
			input:    `{"level":"info","msg":"hello world"}`,
			expected: `{"level":"info","msg":"hello world"}`,
		},
		{
			name:     "Censor password in JSON",
			input:    `{"level":"info","password":"mysecretpassword","msg":"login attempt"}`,
			expected: `{"level":"info","password":"[CENSORED]","msg":"login attempt"}`,
		},
		{
			name:     "Censor secret in JSON",
			input:    `{"secret": "hidden-key", "val": 123}`,
			expected: `{"secret": "[CENSORED]", "val": 123}`,
		},
		{
			name:     "Censor token in text",
			input:    "Authorized with token: ABC-123-XYZ",
			expected: "Authorized with token: [CENSORED]",
		},
		{
			name:     "Multiple sensitive fields",
			input:    `{"user":"admin","password":"p1","token":"t1","secret":"s1"}`,
			expected: `{"user":"admin","password":"[CENSORED]","token":"[CENSORED]","secret":"[CENSORED]"}`,
		},
		{
			name:     "Case insensitive matching",
			input:    `{"PASSWORD":"shhh"}`,
			expected: `{"PASSWORD":"[CENSORED]"}`,
		},
		{
			name:     "Different delimiters",
			input:    "password=topsecret secret: mine token abc",
			expected: "password=[CENSORED] secret: [CENSORED] token [CENSORED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			cw := &CensorWriter{
				Writer: &buf,
				re:     censorRE,
			}

			_, err := cw.Write([]byte(tt.input))
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}
