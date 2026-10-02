package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestEmbeddedAssetCache(t *testing.T) {
	assets := fstest.MapFS{"app.js": {Data: []byte("console.log('test')")}}
	r := gin.New()
	r.Group("/js", embeddedAssetCache(assets)).StaticFS("", http.FS(assets))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/js/app.js", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	etag := w.Header().Get("ETag")
	assert.NotEmpty(t, etag)
	request := httptest.NewRequest("GET", "/js/app.js", nil)
	request.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	assert.Equal(t, http.StatusNotModified, w.Code)
	assert.Empty(t, w.Body.String())

	updated := fstest.MapFS{"app.js": {Data: []byte("console.log('updated')")}}
	r = gin.New()
	r.Group("/js", embeddedAssetCache(updated)).StaticFS("", http.FS(updated))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEqual(t, etag, w.Header().Get("ETag"))
}

func TestCensorWriter_Write(t *testing.T) {
	censorRE := regexp.MustCompile(`(?i)(password|secret|token)(["':\s=]*[:=][\s"':=]*|\s*["']\s*)([^"'\s,{}]+)`)

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
			// io.Writer contract: n reports bytes consumed from the caller.
			assert.Equal(t, len(tt.input), n)
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}
