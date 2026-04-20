package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phobologic/permcop/internal/config"
)

func TestStarterConfig_PathScopeExample(t *testing.T) {
	t.Parallel()

	const wantLine = `# path_scope = ["${PROJECT_DIR}"]`
	const wantComment = "# path_scope: match only when all path-args resolve within this directory subtree (see README)"

	if !strings.Contains(starterConfig, wantLine) {
		t.Errorf("starterConfig missing path_scope example line %q", wantLine)
	}
	if !strings.Contains(starterConfig, wantComment) {
		t.Errorf("starterConfig missing path_scope comment %q", wantComment)
	}
}

func TestStarterConfig_PathScopeUncommented_PassesValidate(t *testing.T) {
	// Build a minimal config that matches the uncommented form of the
	// "Read project source" example rule with path_scope enabled.
	const minimalRule = `
[defaults]
log_file = "~/.local/share/permcop/audit.log"

[[rules]]
name = "Read project source"
allow_read = ["./src/**", "./tests/**"]
deny_read  = ["./.env"]
path_scope = ["${PROJECT_DIR}"]
`
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := writeFile(cfgPath, minimalRule); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	// PROJECT_DIR must be set before validatePatterns so compileScopeEntries
	// can resolve the ${PROJECT_DIR} variable in path_scope.
	t.Setenv("PROJECT_DIR", dir)

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile rejected uncommented path_scope example: %v", err)
	}
	if err := validatePatterns(cfg); err != nil {
		t.Errorf("validatePatterns rejected uncommented path_scope example: %v", err)
	}
}

// writeFile writes content to path.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
