package api

import (
	"html/template"
	"strings"
)

// GetFuncMap returns the common template functions used across the application.
func GetFuncMap() template.FuncMap {
	return template.FuncMap{
		"lower":    strings.ToLower,
		"replace":  strings.ReplaceAll,
		"split":    strings.Split,
		"contains": strings.Contains,
		// safeHTML/safeURL bypass html/template's contextual auto-escaping and
		// MUST only be fed trusted, server-generated values. Audited callers:
		// safeURL is used solely for the server-generated TOTP QR data: URI
		// (login_totp_setup*.html); safeHTML currently has no callers. Never pipe
		// user-derived input through these — sanitize first or rely on the
		// template's default escaping instead.
		"safeHTML": func(s string) template.HTML { return template.HTML(s) }, // #nosec G203
		"safeURL":  func(s string) template.URL { return template.URL(s) },   // #nosec G203
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
	}
}
