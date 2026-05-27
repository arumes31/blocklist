package main

import (
	"html/template"
	"blocklist/internal/api"
	"fmt"
)

func main() {
	funcMap := api.GetFuncMap()

	_, err := template.New("").Funcs(funcMap).ParseGlob("cmd/server/templates/*.html")
	if err != nil {
		fmt.Printf("TEMPLATE ERROR: %v\n", err)
	} else {
		fmt.Println("TEMPLATES OK")
	}
}
