package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurity_ForbiddenPatterns scans the source code for dangerous Go patterns
func TestSecurity_ForbiddenPatterns(t *testing.T) {
	forbidden := []string{
		"os.StartProcess", // Prefer safer alternatives
		"syscall.Exec",    // Low-level exec
		"unsafe.Pointer",  // Memory safety
		"http.ListenAndServeTLS", // Ensure we use modern config
	}

	// Also check for potential hardcoded secrets
	keywords := []string{
		"password :=",
		"secret :=",
		"key :=",
	}

	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil { return err }
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil { return err }

		body := string(content)
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Errorf("Security Risk: Forbidden pattern %q found in %s", f, path)
			}
		}

		// Heuristic check for hardcoded secrets (skipping config.go which has defaults)
		if !strings.Contains(path, "config.go") && !strings.Contains(path, "main.go") {
			for _, k := range keywords {
				if strings.Contains(body, k) {
					// This is a warning, not necessarily a failure as it might be a variable name
					t.Logf("Security Note: Potential hardcoded secret pattern %q found in %s", k, path)
				}
			}
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}
