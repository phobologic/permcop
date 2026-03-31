package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
)

func newTestEngineWithEnv(t *testing.T, rules []config.Rule, defaults *config.Defaults, env map[string]string) *Engine {
	t.Helper()
	cfg := &config.Config{Rules: rules}
	if defaults != nil {
		cfg.Defaults = *defaults
	}
	if cfg.Defaults.SubshellDepthLimit == 0 {
		cfg.Defaults.SubshellDepthLimit = 3
	}
	if cfg.Defaults.UnknownVariableAction == "" {
		cfg.Defaults.UnknownVariableAction = config.VariableActionDeny
	}
	logPath := cfg.Defaults.LogFile
	if logPath == "" {
		logPath = os.DevNull
	}
	logger := audit.New(logPath, cfg.Defaults.LogFormat, 0, 0)
	var (
		e   *Engine
		err error
	)
	if env == nil {
		e, err = New(cfg, logger)
	} else {
		e, err = NewWithEnv(cfg, logger, env)
	}
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func newTestEngine(t *testing.T, rules []config.Rule, defaults *config.Defaults) *Engine {
	t.Helper()
	return newTestEngineWithEnv(t, rules, defaults, nil)
}

func TestEngine_BasicAllow(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "git reads",
			Allow: []config.Pattern{{Type: config.PatternExact, Pattern: "git status"}},
		},
	}, nil)

	r, err := e.Check("git status", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW, got DENY: %s", r.Reason)
	}
	if r.DecidingRule != "git reads" {
		t.Errorf("wrong rule: %q", r.DecidingRule)
	}
}

func TestEngine_DefaultDeny(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, nil, nil)

	r, err := e.Check("curl https://example.com", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Error("expected DENY, got ALLOW")
	}
}

func TestEngine_DenyBeatsAllow_SameRule(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "git",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "git"}},
			Deny:  []config.Pattern{{Type: config.PatternPrefix, Pattern: "git push"}},
		},
	}, nil)

	r, _ := e.Check("git push origin main", "/tmp")
	if r.Allowed {
		t.Error("expected DENY (deny pattern in same rule), got ALLOW")
	}
}

func TestEngine_DenyBeatsAllow_DifferentRules(t *testing.T) {
	t.Parallel()

	// Rule 1 allows everything with "git"
	// Rule 2 denies "git push"
	// The two-pass model means the deny in rule 2 wins over the allow in rule 1.
	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow all git",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "git"}},
		},
		{
			Name: "block git push",
			Deny: []config.Pattern{{Type: config.PatternPrefix, Pattern: "git push"}},
		},
	}, nil)

	r, _ := e.Check("git push origin main", "/tmp")
	if r.Allowed {
		t.Error("expected DENY (deny in different rule must beat allow), got ALLOW")
	}
	if r.DecidingRule != "block git push" {
		t.Errorf("wrong deciding rule: %q", r.DecidingRule)
	}
}

func TestEngine_ChainAllUnitsRequired(t *testing.T) {
	t.Parallel()

	// Rule only allows git status. git push is not allowed.
	// A chain with both should be denied because not all units are covered.
	e := newTestEngine(t, []config.Rule{
		{
			Name:  "git reads",
			Allow: []config.Pattern{{Type: config.PatternExact, Pattern: "git status"}},
		},
	}, nil)

	r, _ := e.Check("git status && git push origin main", "/tmp")
	if r.Allowed {
		t.Error("expected DENY (not all units covered by allow rule), got ALLOW")
	}
}

func TestEngine_PatternTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern config.Pattern
		command string
		want    bool
	}{
		{"exact match", config.Pattern{Type: config.PatternExact, Pattern: "git status"}, "git status", true},
		{"exact no partial", config.Pattern{Type: config.PatternExact, Pattern: "git status"}, "git status -s", false},
		{"prefix match", config.Pattern{Type: config.PatternPrefix, Pattern: "git log"}, "git log --oneline", true},
		{"prefix exact", config.Pattern{Type: config.PatternPrefix, Pattern: "git log"}, "git log", true},
		{"prefix no partial word", config.Pattern{Type: config.PatternPrefix, Pattern: "git log"}, "git logger", false},
		{"glob star", config.Pattern{Type: config.PatternGlob, Pattern: "go test *"}, "go test ./...", true},
		{"regex match", config.Pattern{Type: config.PatternRegex, Pattern: `^rm\s+-rf`}, "rm -rf /tmp/foo", true},
		{"regex no match", config.Pattern{Type: config.PatternRegex, Pattern: `^rm\s+-rf`}, "ls -la", false},
		// word_glob
		{"wg: command + any args", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep **"}, "grep -rn foo.txt", true},
		{"wg: ** matches zero tokens", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep **"}, "grep", true},
		{"wg: exact token count", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep"}, "grep", true},
		{"wg: no extra tokens allowed", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep"}, "grep -r", false},
		{"wg: flag char class match", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep -[rniElv]* **"}, "grep -rn foo.txt", true},
		{"wg: flag char class no match", config.Pattern{Type: config.PatternWordGlob, Pattern: "grep -[rniElv]* **"}, "grep --include=*.go foo", false},
		{"wg: star one token", config.Pattern{Type: config.PatternWordGlob, Pattern: "make *"}, "make build", true},
		{"wg: star not multi-token", config.Pattern{Type: config.PatternWordGlob, Pattern: "make *"}, "make build test", false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newTestEngine(t, []config.Rule{
				{Name: "test", Allow: []config.Pattern{tc.pattern}},
			}, nil)

			r, _ := e.Check(tc.command, "/tmp")
			if r.Allowed != tc.want {
				t.Errorf("Check(%q) allowed=%v, want %v", tc.command, r.Allowed, tc.want)
			}
		})
	}
}

func TestEngine_SudoBlocked(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow all",
			Allow: []config.Pattern{{Type: config.PatternGlob, Pattern: "*"}},
		},
	}, &config.Defaults{AllowSudo: false})

	tests := []struct {
		name    string
		command string
	}{
		{"direct sudo", "sudo rm -rf /"},
		{"sudo in chain", "echo hello && sudo rm -rf /"},
		{"sudo after pipe", "cat /etc/passwd | sudo tee /etc/shadow"},
		{"sudo after semicolon", "ls; sudo reboot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := e.Check(tt.command, "/tmp")
			if r.Allowed {
				t.Errorf("expected DENY for %q, got ALLOW", tt.command)
			}
		})
	}
}

func TestEngine_SudoAllowedWhenConfigured(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow sudo git",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "sudo git"}},
		},
	}, &config.Defaults{AllowSudo: true})

	r, _ := e.Check("sudo git status", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW for sudo with allow_sudo=true, got DENY: %s", r.Reason)
	}
}

func TestEngine_VariableDeny(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow echo",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
	}, &config.Defaults{UnknownVariableAction: config.VariableActionDeny})

	r, _ := e.Check("echo $SECRET", "/tmp")
	if r.Allowed {
		t.Error("expected DENY for variable with variable_action=deny, got ALLOW")
	}
}

func TestEngine_VariableWarn(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow echo with warn",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
	}, &config.Defaults{UnknownVariableAction: config.VariableActionWarn})

	r, _ := e.Check("echo $SECRET", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW (warn) for variable with variable_action=warn, got DENY: %s", r.Reason)
	}
	if r.Decision != audit.DecisionWarn {
		t.Errorf("expected WARN decision, got %q", r.Decision)
	}
}

func TestEngine_VariableAllow(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow echo",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
	}, &config.Defaults{UnknownVariableAction: config.VariableActionAllow})

	r, _ := e.Check("echo $SECRET", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW for variable with variable_action=allow, got DENY: %s", r.Reason)
	}
}

func TestEngine_PerRuleVariableOverride(t *testing.T) {
	t.Parallel()

	// Global deny, but this rule overrides to warn
	allowAction := config.VariableActionWarn
	e := newTestEngine(t, []config.Rule{
		{
			Name:           "echo with warn override",
			Allow:          []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			VariableAction: allowAction,
		},
	}, &config.Defaults{UnknownVariableAction: config.VariableActionDeny})

	r, _ := e.Check("echo $HOME", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW (per-rule warn), got DENY: %s", r.Reason)
	}
}

func TestEngine_DenySubshells(t *testing.T) {
	t.Parallel()

	denySubshells := true
	e := newTestEngine(t, []config.Rule{
		{
			Name:          "allow echo no subshells",
			Allow:         []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			DenySubshells: &denySubshells,
		},
	}, nil)

	r, _ := e.Check("echo $(whoami)", "/tmp")
	if r.Allowed {
		t.Error("expected DENY for subshell with deny_subshells=true, got ALLOW")
	}
}

func TestEngine_RedirectAllowRead(t *testing.T) {
	t.Parallel()

	// Both command and read units must be covered (each by any rule).
	// This rule covers both: allow covers "cat", allow_read covers the file.
	e := newTestEngine(t, []config.Rule{
		{
			Name:      "cat project files",
			Allow:     []config.Pattern{{Type: config.PatternExact, Pattern: "cat"}},
			AllowRead: []string{"/project/**"},
		},
	}, nil)

	r, _ := e.Check("cat < /project/src/main.go", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW for read within allowed path, got DENY: %s", r.Reason)
	}

	// No rule covers the "cat" command unit → deny.
	e2 := newTestEngine(t, []config.Rule{
		{Name: "read only rule", AllowRead: []string{"/project/**"}},
	}, nil)
	r2, _ := e2.Check("cat < /project/src/main.go", "/tmp")
	if r2.Allowed {
		t.Error("expected DENY: no rule covers the 'cat' command unit")
	}
}

func TestEngine_RedirectDenyWrite(t *testing.T) {
	t.Parallel()

	// A complete rule must cover both the command and the file write unit.
	e := newTestEngine(t, []config.Rule{
		{
			Name:       "echo to tmp but not secrets",
			Allow:      []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			AllowWrite: []string{"/tmp/**"},
			DenyWrite:  []string{"/tmp/secrets/**"},
		},
	}, nil)

	// Allowed write (echo + write to /tmp, not in secrets)
	r, _ := e.Check("echo hi > /tmp/out.txt", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW write to /tmp/out.txt, got DENY: %s", r.Reason)
	}

	// Denied write (deny_write pattern in same rule wins over allow_write)
	r2, _ := e.Check("echo hi > /tmp/secrets/key.pem", "/tmp")
	if r2.Allowed {
		t.Error("expected DENY write to /tmp/secrets/, got ALLOW")
	}
}

func TestEngine_ParseError(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:  "allow all",
			Allow: []config.Pattern{{Type: config.PatternGlob, Pattern: "*"}},
		},
	}, nil)

	r, _ := e.Check("echo $((", "/tmp") // unclosed arithmetic
	if r.Allowed {
		t.Error("expected DENY for parse error, got ALLOW")
	}
}

func TestEngine_RedirectDenyWriteInsideAllowedDir(t *testing.T) {
	t.Parallel()

	// A single rule covers both the command and the write unit.
	e := newTestEngine(t, []config.Rule{
		{
			Name:       "echo to tmp",
			Allow:      []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			AllowWrite: []string{"/tmp/**"},
		},
	}, nil)

	r, _ := e.Check("echo hi > /tmp/out.txt", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW (echo + write to /tmp), got DENY: %s", r.Reason)
	}
}

func TestEngine_MultiRuleCoverage(t *testing.T) {
	t.Parallel()

	// Rule A covers "echo" commands, Rule B covers writes to /tmp.
	// With per-unit evaluation, each unit independently finds any covering rule.
	// The command unit is covered by Rule A, the write unit by Rule B → ALLOW.
	e := newTestEngine(t, []config.Rule{
		{
			Name:  "echo only",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
		{
			Name:       "write tmp only",
			AllowWrite: []string{"/tmp/**"},
		},
	}, nil)

	r, _ := e.Check("echo hi > /tmp/out.txt", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW: each unit covered by a different rule, got DENY: %s", r.Reason)
	}
}

func TestEngine_MultiRuleCoverage_MissingWriteRule(t *testing.T) {
	t.Parallel()

	// Rule covers the command but there is no rule covering the write unit → DENY.
	e := newTestEngine(t, []config.Rule{
		{
			Name:  "echo only",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
	}, nil)

	r, _ := e.Check("echo hi > /tmp/out.txt", "/tmp")
	if r.Allowed {
		t.Error("expected DENY: write unit has no covering rule")
	}
}

func TestEngine_WriteZoneAndCommandRule(t *testing.T) {
	t.Parallel()

	// Global write-zone rule + separate command rule.
	// "git log > /tmp/out.txt" has two units: "git log" command and "/tmp/out.txt" write.
	// Command covered by git rule, write covered by write-zone rule → ALLOW.
	e := newTestEngine(t, []config.Rule{
		{
			Name:  "git reads",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "git log"}},
		},
		{
			Name:       "write zone",
			AllowWrite: []string{"/tmp/**"},
		},
	}, nil)

	r, _ := e.Check("git log > /tmp/out.txt", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW (git command + write zone), got DENY: %s", r.Reason)
	}

	// Without the write-zone rule, the write unit is uncovered → DENY.
	e2 := newTestEngine(t, []config.Rule{
		{
			Name:  "git reads",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "git log"}},
		},
	}, nil)
	r2, _ := e2.Check("git log > /tmp/out.txt", "/tmp")
	if r2.Allowed {
		t.Error("expected DENY: no rule covers the write unit")
	}
}

func TestEngine_VariableWarnCoveredByRule(t *testing.T) {
	t.Parallel()

	// Unit with variable is covered by a rule with unknown_variable_action=warn → WARN-allow.
	warnAction := config.VariableActionWarn
	e := newTestEngine(t, []config.Rule{
		{
			Name:           "echo with warn",
			Allow:          []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			VariableAction: warnAction,
		},
	}, &config.Defaults{UnknownVariableAction: config.VariableActionDeny})

	r, _ := e.Check("echo $SECRET", "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW (warn), got DENY: %s", r.Reason)
	}
	if r.Decision != audit.DecisionWarn {
		t.Errorf("expected WARN decision, got %q", r.Decision)
	}
}

func TestEngine_ReadFileRuleWithConfigFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testFile := filepath.Join(dir, "code.go")
	if err := os.WriteFile(testFile, []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}

	// Rule must cover both the "cat" command AND the read file unit.
	e := newTestEngine(t, []config.Rule{
		{
			Name:      "cat src files",
			Allow:     []config.Pattern{{Type: config.PatternExact, Pattern: "cat"}},
			AllowRead: []string{dir + "/**"},
		},
	}, nil)

	r, _ := e.Check("cat < "+testFile, "/tmp")
	if !r.Allowed {
		t.Errorf("expected ALLOW for read within tmpdir, got DENY: %s", r.Reason)
	}

	// Reading outside the allowed dir should be denied.
	r2, _ := e.Check("cat < /etc/passwd", "/tmp")
	if r2.Allowed {
		t.Error("expected DENY for read outside allowed dir, got ALLOW")
	}
}

// --- expand_variables tests ---

func TestEngine_ExpandVariables_Allow(t *testing.T) {
	t.Parallel()

	// $TARGET expands to /tmp/safe.txt; rule allows "mv * /tmp/*".
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "mv to tmp",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "mv * /tmp/*"}},
		},
	}, nil, map[string]string{"TARGET": "/tmp/safe.txt"})

	r, err := e.Check("mv $TARGET /tmp/out.txt", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW after expansion, got DENY: %s", r.Reason)
	}
}

func TestEngine_ExpandVariables_DenyViaDenyPattern(t *testing.T) {
	t.Parallel()

	// $DIR expands to /home/user; deny pattern should catch it after expansion.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "rm in tmp only",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "rm *"}},
			Deny:            []config.Pattern{{Type: config.PatternGlob, Pattern: "rm -rf /home/**"}},
		},
	}, nil, map[string]string{"DIR": "/home/user"})

	r, err := e.Check("rm -rf $DIR", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY (expanded deny pattern matched), got ALLOW")
	}
}

func TestEngine_ExpandVariables_MissingVar_FailClosed(t *testing.T) {
	t.Parallel()

	// Variable not in env → rule can't cover → deny.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "mv anywhere",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "mv *"}},
		},
	}, nil, map[string]string{} /* empty env */)

	r, err := e.Check("mv $TARGET /tmp/out", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY (missing var fail-closed), got ALLOW")
	}
}

func TestEngine_ExpandVariables_NoExpansionWithoutFlag(t *testing.T) {
	t.Parallel()

	// Rule does NOT have expand_variables; variable command is denied by default
	// (unknown_variable_action = deny).
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:  "mv anywhere",
			Allow: []config.Pattern{{Type: config.PatternGlob, Pattern: "mv *"}},
		},
	}, nil, map[string]string{"TARGET": "/tmp/safe.txt"})

	r, err := e.Check("mv $TARGET /tmp/out", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY (no expand_variables, variable triggers deny), got ALLOW")
	}
}

func TestEngine_ExpandVariables_BracedVar(t *testing.T) {
	t.Parallel()

	// ${SRC} form should expand the same as $SRC.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "cp to tmp",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "cp /data/* /tmp/*"}},
		},
	}, nil, map[string]string{"SRC": "/data/file.txt"})

	r, err := e.Check("cp ${SRC} /tmp/file.txt", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW for braced var expansion, got DENY: %s", r.Reason)
	}
}

func TestEngine_ExpandVariables_MultipleVars_AllResolved(t *testing.T) {
	t.Parallel()

	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "cp files",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "cp /src/* /dst/*"}},
		},
	}, nil, map[string]string{"SRC": "/src/a.txt", "DST": "/dst/b.txt"})

	r, err := e.Check("cp $SRC $DST", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW for both vars resolved, got DENY: %s", r.Reason)
	}
}

func TestEngine_ExpandVariables_MultipleVars_OneUnresolved(t *testing.T) {
	t.Parallel()

	// SRC is set but DST is not — fail-closed.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "cp files",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "cp *"}},
		},
	}, nil, map[string]string{"SRC": "/src/a.txt"} /* DST missing */)

	r, err := e.Check("cp $SRC $DST", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY (DST unresolved, fail-closed), got ALLOW")
	}
}

func TestEngine_ExpandVariables_FallbackToOtherRule(t *testing.T) {
	t.Parallel()

	// Rule 1: expand_variables=true, var not in env → can't cover.
	// Rule 2: no expand, unknown_variable_action=allow → covers.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "strict mv",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "mv /tmp/*"}},
		},
		{
			Name:           "permissive mv",
			Allow:          []config.Pattern{{Type: config.PatternGlob, Pattern: "mv *"}},
			VariableAction: config.VariableActionAllow,
		},
	}, nil, map[string]string{} /* empty env */)

	r, err := e.Check("mv $TARGET /tmp/out", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW via fallback rule, got DENY: %s", r.Reason)
	}
	if r.DecidingRule != "permissive mv" {
		t.Errorf("expected deciding rule 'permissive mv', got %q", r.DecidingRule)
	}
}
