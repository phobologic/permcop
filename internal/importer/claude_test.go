package importer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikecafarella/permcop/internal/config"
)

func TestParseEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		wantTool    string
		wantPattern string
		wantOK      bool
	}{
		{"Bash(git log *)", "Bash", "git log *", true},
		{"Bash(npm run test)", "Bash", "npm run test", true},
		{"Bash", "Bash", "*", true},
		{"Read(./.env)", "Read", "./.env", true},
		{"Edit(./src/**)", "Edit", "./src/**", true},
		{"WebFetch(domain:example.com)", "WebFetch", "domain:example.com", true},
		{"", "", "", false},
		{"Bash(malformed", "", "", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			tool, pattern, ok := parseEntry(tc.input)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if ok {
				if tool != tc.wantTool {
					t.Errorf("tool: got %q, want %q", tool, tc.wantTool)
				}
				if pattern != tc.wantPattern {
					t.Errorf("pattern: got %q, want %q", pattern, tc.wantPattern)
				}
			}
		})
	}
}

func TestConvert_BashRules(t *testing.T) {
	t.Parallel()

	perms := ClaudePermissions{
		Allow: []string{"Bash(git log *)", "Bash(git status)"},
		Deny:  []string{"Bash(git push *)", "Bash(rm **)"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rules) != 1 {
		t.Fatalf("expected 1 bash rule, got %d", len(result.Rules))
	}

	r := result.Rules[0]
	if len(r.Allow) != 2 {
		t.Errorf("allow: got %d patterns, want 2", len(r.Allow))
	}
	if len(r.Deny) != 2 {
		t.Errorf("deny: got %d patterns, want 2", len(r.Deny))
	}

	// All patterns should be glob type
	for _, p := range append(r.Allow, r.Deny...) {
		if p.Type != config.PatternGlob {
			t.Errorf("pattern type: got %q, want glob", p.Type)
		}
	}
}

func TestConvert_FileRules(t *testing.T) {
	t.Parallel()

	perms := ClaudePermissions{
		Allow: []string{"Read(./src/**)", "Edit(./src/**)"},
		Deny:  []string{"Read(./.env)", "Edit(./.env)"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rules) != 1 {
		t.Fatalf("expected 1 file rule, got %d", len(result.Rules))
	}

	r := result.Rules[0]
	if len(r.AllowRead) != 1 || r.AllowRead[0] != "./src/**" {
		t.Errorf("allow_read: got %v", r.AllowRead)
	}
	if len(r.AllowWrite) != 1 || r.AllowWrite[0] != "./src/**" {
		t.Errorf("allow_write: got %v", r.AllowWrite)
	}
	if len(r.DenyRead) != 1 || r.DenyRead[0] != "./.env" {
		t.Errorf("deny_read: got %v", r.DenyRead)
	}
	if len(r.DenyWrite) != 1 || r.DenyWrite[0] != "./.env" {
		t.Errorf("deny_write: got %v", r.DenyWrite)
	}
}

func TestConvert_MixedRules(t *testing.T) {
	t.Parallel()

	perms := ClaudePermissions{
		Allow: []string{"Bash(git status)", "Read(./src/**)"},
		Deny:  []string{"Bash(git push *)", "WebFetch"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	// 2 rules: one bash, one file
	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d: %+v", len(result.Rules), result.Rules)
	}

	// WebFetch should be skipped
	if len(result.Skipped) != 1 || result.Skipped[0] != "WebFetch" {
		t.Errorf("skipped: got %v, want [WebFetch]", result.Skipped)
	}
}

func TestConvert_AskRulesWarn(t *testing.T) {
	t.Parallel()

	perms := ClaudePermissions{
		Ask: []string{"Bash(git push *)"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Warnings) == 0 {
		t.Error("expected warning for ask rule, got none")
	}
}

func TestConvert_BareToolName(t *testing.T) {
	t.Parallel()

	perms := ClaudePermissions{
		Allow: []string{"Bash"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result.Rules))
	}
	if len(result.Rules[0].Allow) != 1 || result.Rules[0].Allow[0].Pattern != "*" {
		t.Errorf("bare 'Bash' should produce allow pattern '*', got %+v", result.Rules[0].Allow)
	}
}

func TestConvert_Empty(t *testing.T) {
	t.Parallel()

	result, err := Convert(ClaudePermissions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rules) != 0 {
		t.Errorf("expected no rules for empty permissions, got %d", len(result.Rules))
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for empty permissions")
	}
}

func TestFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	settingsJSON := `{
		"permissions": {
			"allow": ["Bash(git log *)", "Read(./src/**)"],
			"deny": ["Bash(git push *)"]
		}
	}`
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(settingsJSON), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile: %v", err)
	}

	if len(result.Rules) != 2 {
		t.Errorf("expected 2 rules (bash + file), got %d", len(result.Rules))
	}
}

func TestFromFile_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := FromFile("/nonexistent/settings.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRulesToTOML(t *testing.T) {
	t.Parallel()

	rules := []config.Rule{
		{
			Name:        "test rule",
			Description: "a test",
			Allow:       []config.Pattern{{Type: config.PatternGlob, Pattern: "git *"}},
			Deny:        []config.Pattern{{Type: config.PatternGlob, Pattern: "git push *"}},
			AllowRead:   []string{"./src/**"},
			DenyRead:    []string{"./.env"},
		},
	}

	toml := RulesToTOML(rules)

	// Check key elements are present
	for _, want := range []string{
		`[[rules]]`,
		`name = "test rule"`,
		`description = "a test"`,
		`type = "glob"`,
		`pattern = "git *"`,
		`pattern = "git push *"`,
		`"./src/**"`,
		`"./.env"`,
	} {
		if !containsString(toml, want) {
			t.Errorf("TOML output missing %q\nGot:\n%s", want, toml)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsRuneSlice([]rune(s), []rune(substr)))
}

func containsRuneSlice(s, substr []rune) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := range substr {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
