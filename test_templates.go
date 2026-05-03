package main

import (
	"fmt"
	"html/template"
	"strings"
)

func main() {
	funcMap := template.FuncMap{
		"lower":    strings.ToLower,
		"replace":  strings.ReplaceAll,
		"split":    strings.Split,
		"contains": strings.Contains,
		"safeURL": func(s string) template.URL {
			if strings.HasPrefix(s, "data:image/png;base64,") {
				return template.URL(s) // #nosec G203
			}
			return template.URL("#")
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
	}

	_, err := template.New("").Funcs(funcMap).ParseGlob("cmd/server/templates/*.html")
	if err != nil {
		fmt.Printf("TEMPLATE ERROR: %v\n", err)
	} else {
		fmt.Println("TEMPLATES OK")
	}
}
