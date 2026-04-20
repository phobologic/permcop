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

	// nil project: result should have the same rules as global
	if len(merged.Rules) != 1 || merged.Rules[0].Name != "global only" {
		t.Errorf("merge with nil project: got %v, want global rules unchanged", merged.Rules)
	}
}

func TestMergeAll_FourLayerPriority(t *testing.T) {
	t.Parallel()

	projectLocal := &Config{Rules: []Rule{{Name: "pl"}}, Defaults: Defaults{LogFormat: "json"}}
	projectShared := &Config{Rules: []Rule{{Name: "ps"}}, Defaults: Defaults{LogFormat: "text", SubshellDepthLimit: 5}}
	globalLocal := &Config{Rules: []Rule{{Name: "gl"}}}
	globalShared := &Config{Rules: []Rule{{Name: "gs"}}}

	merged := mergeAll(projectLocal, projectShared, globalLocal, globalShared)

	// Rules in layer order: pl, ps, gl, gs
	wantOrder := []string{"pl", "ps", "gl", "gs"}
	if len(merged.Rules) != len(wantOrder) {
		t.Fatalf("rule count: got %d, want %d", len(merged.Rules), len(wantOrder))
	}
	for i, name := range wantOrder {
		if merged.Rules[i].Name != name {
			t.Errorf("rule[%d]: got %q, want %q", i, merged.Rules[i].Name, name)
		}
	}

	// LogFormat: projectLocal wins (json)
	if merged.Defaults.LogFormat != "json" {
		t.Errorf("LogFormat: got %q, want %q", merged.Defaults.LogFormat, "json")
	}
	// SubshellDepthLimit: projectLocal has zero, projectShared has 5 → 5 wins
	if merged.Defaults.SubshellDepthLimit != 5 {
		t.Errorf("SubshellDepthLimit: got %d, want 5", merged.Defaults.SubshellDepthLimit)
	}
}

func TestMergeAll_NilLayersSkipped(t *testing.T) {
	t.Parallel()

	a := &Config{Rules: []Rule{{Name: "a"}}}
	merged := mergeAll(nil, a, nil)
	if len(merged.Rules) != 1 || merged.Rules[0].Name != "a" {
		t.Errorf("expected single rule 'a', got %v", merged.Rules)
	}
}

func TestFindAndLoadProject_LoadsBothVariants(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	subdir := filepath.Join(root, "subdir")
	for _, d := range []string{gitDir, subdir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, root, projectFileName, "[[rules]]\nname = \"shared\"")
	writeConfig(t, root, projectLocalFileName, "[[rules]]\nname = \"local\"")

	shared, local, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared == nil || len(shared.Rules) == 0 || shared.Rules[0].Name != "shared" {
		t.Errorf("shared config not loaded correctly: %v", shared)
	}
	if local == nil || len(local.Rules) == 0 || local.Rules[0].Name != "local" {
		t.Errorf("local config not loaded correctly: %v", local)
	}
}

func TestFindAndLoadProject_OnlyLocalExists(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, root, projectLocalFileName, "[[rules]]\nname = \"local only\"")

	shared, local, err := findAndLoadProject(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared != nil {
		t.Errorf("expected nil shared config, got rules: %v", shared.Rules)
	}
	if local == nil || len(local.Rules) == 0 || local.Rules[0].Name != "local only" {
		t.Errorf("local config not loaded correctly: %v", local)
	}
}

func TestFindAndLoadProject_StopsAtGitRootBothFiles(t *testing.T) {
	t.Parallel()

	// Both .permcop.toml and .permcop.local.toml above the git boundary
	// must not be loaded.
	root := t.TempDir()
	gitRoot := filepath.Join(root, "repo")
	subdir := filepath.Join(gitRoot, "subdir")
	for _, d := range []string{filepath.Join(gitRoot, ".git"), subdir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, root, projectFileName, "[[rules]]\nname = \"above git\"")
	writeConfig(t, root, projectLocalFileName, "[[rules]]\nname = \"above git local\"")

	shared, local, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared != nil || local != nil {
		t.Errorf("expected nil configs (traversal stops at git root), got shared=%v local=%v", shared, local)
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

	shared, local, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared != nil || local != nil {
		t.Errorf("expected nil configs (traversal should stop at git root), got shared=%v local=%v", shared, local)
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

	shared, local, err := findAndLoadProject(subdir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared == nil || len(shared.Rules) == 0 || shared.Rules[0].Name != "at git root" {
		t.Errorf("expected shared config at git root to be loaded, got: %v", shared)
	}
	if local != nil {
		t.Errorf("expected nil local config, got: %v", local)
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

	shared, local, err := findAndLoadProject(deep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shared == nil || len(shared.Rules) == 0 || shared.Rules[0].Name != "within repo" {
		t.Errorf("expected shared config within repo to be loaded, got: %v", shared)
	}
	if local != nil {
		t.Errorf("expected nil local config, got: %v", local)
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
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = orig
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
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

func TestWarnBroadAllowRules_FiresForBroadAllowRead(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "allow"

[[rules]]
name = "broad read"
allow_read = ["**"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if !strings.Contains(got, `rule "broad read"`) {
		t.Errorf("expected warning mentioning rule name, got: %q", got)
	}
	if !strings.Contains(got, "allow_read") {
		t.Errorf("expected warning mentioning allow_read, got: %q", got)
	}
	if !strings.Contains(got, "high risk") {
		t.Errorf("expected high-risk warning, got: %q", got)
	}
}

func TestWarnBroadAllowRules_FiresForBroadAllowWrite(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[defaults]
unknown_variable_action = "allow"

[[rules]]
name = "broad write"
allow_write = ["*"]
`)

	var loadErr error
	got := captureStderr(t, func() {
		_, loadErr = LoadFile(filepath.Join(dir, "config.toml"))
	})
	if loadErr != nil {
		t.Fatalf("LoadFile: %v", loadErr)
	}
	if !strings.Contains(got, `rule "broad write"`) {
		t.Errorf("expected warning mentioning rule name, got: %q", got)
	}
	if !strings.Contains(got, "allow_write") {
		t.Errorf("expected warning mentioning allow_write, got: %q", got)
	}
	if !strings.Contains(got, "high risk") {
		t.Errorf("expected high-risk warning, got: %q", got)
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

func TestApplyDefaults_LogFileOutsideHome(t *testing.T) {
	cfg := &Config{Defaults: Defaults{LogFile: "/etc/cron.d/permcop"}}
	err := applyDefaults(cfg)
	if err == nil {
		t.Fatal("expected error for log_file outside home directory, got nil")
	}
	if !strings.Contains(err.Error(), "log_file") {
		t.Errorf("error should mention log_file, got: %v", err)
	}
}

func TestApplyDefaults_LogFileInsideHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}
	logPath := filepath.Join(home, "custom", "audit.log")
	cfg := &Config{Defaults: Defaults{LogFile: logPath}}
	if err := applyDefaults(cfg); err != nil {
		t.Errorf("expected no error for log_file inside home, got: %v", err)
	}
}

func TestLoadFile_PathScope_Present(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "scoped rule"
path_scope = ["/a", "~/b"]
allow = ["git status"]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	got := cfg.Rules[0].PathScope
	want := []string{"/a", "~/b"}
	if len(got) != len(want) {
		t.Fatalf("PathScope: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PathScope[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadFile_PathScope_Absent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "unscoped rule"
allow = ["git status"]
`)

	cfg, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].PathScope != nil {
		t.Errorf("PathScope: got %v, want nil", cfg.Rules[0].PathScope)
	}
}

func TestLoadFile_PathScope_EmptyList(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "bad scope"
path_scope = []
allow = ["git status"]
`)

	_, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err == nil {
		t.Fatal("expected error for empty path_scope, got nil")
	}
	if !strings.Contains(err.Error(), "bad scope") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
}

func TestLoadFile_PathScope_EmptyStringEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "whitespace scope"
path_scope = ["   "]
allow = ["git status"]
`)

	_, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err == nil {
		t.Fatal("expected error for whitespace-only path_scope entry, got nil")
	}
	if !strings.Contains(err.Error(), "whitespace scope") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
}

func TestLoadFile_PathScope_BlankEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
name = "blank scope"
path_scope = [""]
allow = ["git status"]
`)

	_, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err == nil {
		t.Fatal("expected error for empty-string path_scope entry, got nil")
	}
	if !strings.Contains(err.Error(), "blank scope") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
}

func TestLoadFile_PathScope_UnnamedRuleError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeConfig(t, dir, "config.toml", `
[[rules]]
path_scope = []
allow = ["git status"]
`)

	_, err := LoadFile(filepath.Join(dir, "config.toml"))
	if err == nil {
		t.Fatal("expected error for empty path_scope on unnamed rule, got nil")
	}
	if !strings.Contains(err.Error(), "rule[0]") {
		t.Errorf("error should use positional name for unnamed rule, got: %v", err)
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
