package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFile_Valid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
log_format = "json"
unknown_variable_action = "warn"
allow_sudo = true
subshell_depth_limit = 5

[[rules]]
name = "allow git"
allow = [{type="exact", pattern="git status"}]
deny  = [{type="prefix", pattern="git push"}]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.Defaults.LogFormat != "json" {
		t.Errorf("LogFormat: got %q, want %q", cfg.Defaults.LogFormat, "json")
	}
	if cfg.Defaults.UnknownVariableAction != VariableActionWarn {
		t.Errorf("VariableAction: got %q, want %q", cfg.Defaults.UnknownVariableAction, VariableActionWarn)
	}
	if !cfg.Defaults.AllowSudo {
		t.Error("AllowSudo: want true")
	}
	if cfg.Defaults.SubshellDepthLimit != 5 {
		t.Errorf("SubshellDepthLimit: got %d, want 5", cfg.Defaults.SubshellDepthLimit)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("Rules: got %d, want 1", len(cfg.Rules))
	}
	if cfg.Rules[0].Name != "allow git" {
		t.Errorf("Rule name: got %q", cfg.Rules[0].Name)
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := LoadFile("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadFile_InvalidTOML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "bad.toml", `this is not valid toml = = =`)

	_, err := LoadFile(filepath.Join(dir, "bad.toml"))
	if err == nil {
		t.Error("expected error for invalid TOML, got nil")
	}
}

func TestLoadFile_AppliesDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "empty.toml", ``)

	cfg, err := LoadFile(filepath.Join(dir, "empty.toml"))
	if err != nil {
		t.Fatal(err)
	}

	// Defaults should be applied
	if cfg.Defaults.LogFormat != "text" {
		t.Errorf("default LogFormat: got %q, want %q", cfg.Defaults.LogFormat, "text")
	}
	if cfg.Defaults.UnknownVariableAction != VariableActionDeny {
		t.Errorf("default VariableAction: got %q, want %q", cfg.Defaults.UnknownVariableAction, VariableActionDeny)
	}
	if cfg.Defaults.SubshellDepthLimit != 3 {
		t.Errorf("default SubshellDepthLimit: got %d, want 3", cfg.Defaults.SubshellDepthLimit)
	}
}

func TestMerge_ProjectRulesPrepended(t *testing.T) {
	t.Parallel()

	global := &Config{
		Rules: []Rule{{Name: "global rule A"}, {Name: "global rule B"}},
	}
	project := &Config{
		Rules: []Rule{{Name: "project rule X"}},
	}

	merged := merge(global, project)

	if len(merged.Rules) != 3 {
		t.Fatalf("merged rules: got %d, want 3", len(merged.Rules))
	}
	if merged.Rules[0].Name != "project rule X" {
		t.Errorf("first rule should be project rule, got %q", merged.Rules[0].Name)
	}
	if merged.Rules[1].Name != "global rule A" {
		t.Errorf("second rule should be global rule A, got %q", merged.Rules[1].Name)
	}
}

func TestMerge_ProjectDefaultsOverrideGlobal(t *testing.T) {
	t.Parallel()

	global := &Config{
		Defaults: Defaults{
			LogFormat:             "text",
			UnknownVariableAction: VariableActionDeny,
			SubshellDepthLimit:    3,
		},
	}
	project := &Config{
		Defaults: Defaults{
			LogFormat: "json", // project overrides log format
		},
	}

	merged := merge(global, project)

	if merged.Defaults.LogFormat != "json" {
		t.Errorf("LogFormat: got %q, want %q", merged.Defaults.LogFormat, "json")
	}
	// Variable action not overridden by project — global value preserved
	if merged.Defaults.UnknownVariableAction != VariableActionDeny {
		t.Errorf("VariableAction: got %q, want global value %q", merged.Defaults.UnknownVariableAction, VariableActionDeny)
	}
}

func TestMerge_NilProject(t *testing.T) {
	t.Parallel()

	global := &Config{
		Rules: []Rule{{Name: "global only"}},
	}

	merged := merge(global, nil)

	if merged != global {
		t.Error("merge with nil project should return global unchanged")
	}
}

func TestPatternUnmarshal_BareString(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "shorthand"
allow = ["git status", "git log"]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Rules[0].Allow) != 2 {
		t.Fatalf("allow: got %d patterns, want 2", len(cfg.Rules[0].Allow))
	}
	for _, p := range cfg.Rules[0].Allow {
		if p.Type != PatternGlob {
			t.Errorf("bare string pattern should default to glob, got %q", p.Type)
		}
	}
}

func TestLoadFile_ExpandVariables(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "expand rule"
expand_variables = true
allow = ["mv * /tmp/*"]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if !cfg.Rules[0].ExpandVariables {
		t.Error("expected ExpandVariables=true, got false")
	}
}

func TestLoadFile_ExpandVariables_DefaultFalse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "no expand"
allow = ["git status"]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Rules[0].ExpandVariables {
		t.Error("expected ExpandVariables=false by default, got true")
	}
}

func TestFindAndLoadProject_StopsAtGitRoot(t *testing.T) {
	t.Parallel()

	// Layout:
	//   root/                    ← .permcop.toml here (above git root)
	//   root/repo/.git/          ← git root boundary
	//   root/repo/subdir/        ← CWD for the search
	root := t.TempDir()
	gitRoot := filepath.Join(root, "repo")
	subdir := filepath.Join(gitRoot, "subdir")
	for _, d := range []string{filepath.Join(gitRoot, ".git"), subdir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// .permcop.toml in root (above the git boundary) — must NOT be loaded.
	writeConfig(t, root, projectFileName, `[[rules]]`+"\n"+"name = \"above git root\"")

	cfg, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config (traversal should stop at git root), got rules: %v", cfg.Rules)
	}
}

func TestFindAndLoadProject_LoadsConfigAtGitRoot(t *testing.T) {
	t.Parallel()

	// Layout:
	//   repo/.git/
	//   repo/.permcop.toml       ← should be found
	//   repo/subdir/             ← CWD
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	subdir := filepath.Join(root, "subdir")
	for _, d := range []string{gitDir, subdir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, root, projectFileName, "[[rules]]\nname = \"at git root\"")

	cfg, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Rules) == 0 || cfg.Rules[0].Name != "at git root" {
		t.Errorf("expected config at git root to be loaded, got: %v", cfg)
	}
}

func TestFindAndLoadProject_LoadsConfigBelowGitRoot(t *testing.T) {
	t.Parallel()

	// Layout:
	//   repo/.git/
	//   repo/subdir/.permcop.toml  ← should be found (within the repo)
	//   repo/subdir/deep/          ← CWD
	root := t.TempDir()
	subdir := filepath.Join(root, "subdir")
	deep := filepath.Join(subdir, "deep")
	for _, d := range []string{filepath.Join(root, ".git"), deep} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, subdir, projectFileName, "[[rules]]\nname = \"within repo\"")

	cfg, err := findAndLoadProject(deep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Rules) == 0 || cfg.Rules[0].Name != "within repo" {
		t.Errorf("expected config within repo to be loaded, got: %v", cfg)
	}
}

// captureStderr temporarily replaces os.Stderr with a pipe and returns the
// captured output after fn returns.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = orig
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestWarnBroadAllowRules_FiresForBroadAllowPattern(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "allow"

[[rules]]
name = "dangerous"
allow = ["*"]
`)

	var cfg *Config
	var loadErr error
	got := captureStderr(t, func() {
		cfg, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	_ = cfg

	if !strings.Contains(got, `rule "dangerous"`) {
		t.Errorf("expected warning mentioning rule name, got: %q", got)
	}
	if !strings.Contains(got, "unknown_variable_action=allow") {
		t.Errorf("expected warning mentioning unknown_variable_action=allow, got: %q", got)
	}
	if !strings.Contains(got, `"*"`) {
		t.Errorf("expected warning mentioning broad pattern, got: %q", got)
	}
}

func TestWarnBroadAllowRules_FiresForDoubleStar(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "allow"

[[rules]]
name = "also dangerous"
allow = ["**"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if !strings.Contains(got, "high risk") {
		t.Errorf("expected high-risk warning, got: %q", got)
	}
}

func TestWarnBroadAllowRules_SilentForNarrowPattern(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "allow"

[[rules]]
name = "narrow"
allow = ["git log *"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if got != "" {
		t.Errorf("expected no warning for narrow pattern, got: %q", got)
	}
}

func TestWarnBroadAllowRules_SilentForDenyAction(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "deny"

[[rules]]
name = "broad but deny"
allow = ["*"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if got != "" {
		t.Errorf("expected no warning when variable_action=deny, got: %q", got)
	}
}

func TestWarnBroadAllowRules_SilentForWarnAction(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "warn"

[[rules]]
name = "broad but warn"
allow = ["*"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if got != "" {
		t.Errorf("expected no warning when variable_action=warn, got: %q", got)
	}
}

func TestWarnBroadAllowRules_RuleLevelOverride(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "deny"

[[rules]]
name = "rule override allow"
unknown_variable_action = "allow"
allow = ["*"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if !strings.Contains(got, "high risk") {
		t.Errorf("expected warning when rule overrides variable_action=allow, got: %q", got)
	}
}

func TestApplyDefaults_HomeDirError(t *testing.T) {
	// Simulate os.UserHomeDir() failure by unsetting HOME (and related vars).
	// This test cannot be parallel because it mutates environment variables.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "") // Windows fallback

	cfg := &Config{}
	err := applyDefaults(cfg)
	if err == nil {
		// UserHomeDir may succeed via other means on some platforms;
		// if it does, the default log path should still be populated.
		if cfg.Defaults.LogFile == "" {
			t.Error("LogFile should be set when UserHomeDir succeeds")
		}
		return
	}
	if cfg.Defaults.LogFile != "" {
		t.Errorf("LogFile should remain empty on UserHomeDir error, got %q", cfg.Defaults.LogFile)
	}
}

func TestPatternUnmarshal_UnknownType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "bad pattern type"
allow = [{type="prefx", pattern="git status"}]
`)

	_, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err == nil {
		t.Error("expected error for unknown pattern type, got nil")
	}
}
