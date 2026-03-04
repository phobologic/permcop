package importer

import (
	"os"
	"path/filepath"
	"strings"
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

	// Two groups: "git" (2 allow, 1 deny) and "rm" (0 allow, 1 deny)
	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 bash rules (one per prefix), got %d", len(result.Rules))
	}

	git := result.Rules[0]
	if git.Name != "Imported: git" {
		t.Errorf("rule[0] name: got %q, want %q", git.Name, "Imported: git")
	}
	if len(git.Allow) != 2 {
		t.Errorf("git allow: got %d patterns, want 2", len(git.Allow))
	}
	if len(git.Deny) != 1 {
		t.Errorf("git deny: got %d patterns, want 1", len(git.Deny))
	}

	rm := result.Rules[1]
	if rm.Name != "Imported: rm" {
		t.Errorf("rule[1] name: got %q, want %q", rm.Name, "Imported: rm")
	}
	if len(rm.Allow) != 0 {
		t.Errorf("rm allow: got %d patterns, want 0", len(rm.Allow))
	}
	if len(rm.Deny) != 1 {
		t.Errorf("rm deny: got %d patterns, want 1", len(rm.Deny))
	}

	// All patterns should be glob type
	for _, r := range result.Rules {
		for _, p := range append(r.Allow, r.Deny...) {
			if p.Type != config.PatternGlob {
				t.Errorf("pattern type: got %q, want glob", p.Type)
			}
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

func TestGroupPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		want    string
	}{
		{"git log *", "git"},
		{"make test", "make"},
		{"./permcop validate *", "permcop"}, // leading ./ stripped
		{"go build", "go"},
		{"*", "(other)"},
		{"", "(other)"},
		{"singleword", "singleword"},
		{"tk:*", "tk"},        // bare wildcard with colon separator
		{"permcop:*", "permcop"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.pattern, func(t *testing.T) {
			t.Parallel()
			got := groupPrefix(tc.pattern)
			if got != tc.want {
				t.Errorf("groupPrefix(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

func TestConvert_OtherGroupLast(t *testing.T) {
	t.Parallel()

	// Bare "Bash" produces pattern "*" which goes in (other); it should be last
	// even though it was encountered before the "git" entry.
	perms := ClaudePermissions{
		Allow: []string{"Bash", "Bash(git status)"},
	}

	result, err := Convert(perms)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(result.Rules))
	}
	if result.Rules[0].Name != "Imported: git" {
		t.Errorf("rule[0]: got %q, want \"Imported: git\"", result.Rules[0].Name)
	}
	if result.Rules[1].Name != "Imported: (other)" {
		t.Errorf("rule[1]: got %q, want \"Imported: (other)\"", result.Rules[1].Name)
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

func TestFromFiles_MergesTwoFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	settingsJSON := `{"permissions": {"allow": ["Bash(git log *)"], "deny": []}}`
	localJSON := `{"permissions": {"allow": ["Bash(npm run test)"], "deny": ["Bash(rm -rf *)"]}}`

	pathA := filepath.Join(dir, "settings.json")
	pathB := filepath.Join(dir, "settings.local.json")
	if err := os.WriteFile(pathA, []byte(settingsJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(localJSON), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := FromFiles([]string{pathA, pathB})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	// Both "git" and "npm" groups should be present.
	names := make(map[string]bool)
	for _, r := range result.Rules {
		names[r.Name] = true
	}
	if !names["Imported: git"] {
		t.Error("expected rule 'Imported: git' from settings.json")
	}
	if !names["Imported: npm"] {
		t.Error("expected rule 'Imported: npm' from settings.local.json")
	}
	// The deny from settings.local.json should appear in the rm rule.
	if !names["Imported: rm"] {
		t.Error("expected rule 'Imported: rm' (deny) from settings.local.json")
	}
}

func TestFromFiles_SingleFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	settingsJSON := `{"permissions": {"allow": ["Bash(make build)"], "deny": []}}`
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(settingsJSON), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := FromFiles([]string{path})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(result.Rules))
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
		if !strings.Contains(toml, want) {
			t.Errorf("TOML output missing %q\nGot:\n%s", want, toml)
		}
	}
}

