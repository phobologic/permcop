package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
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

func TestEngine_ExpandVariables_MissingVar_SkippedRulesPopulated(t *testing.T) {
	t.Parallel()

	// When expand_variables=true and $FINDING is not in env, the rule is skipped.
	// The pass-through RuleMatch should carry a SkippedRule entry identifying
	// the rule and the missing variable, so the audit log can surface a near-miss hint.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:            "echo commands",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
		},
	}, nil, map[string]string{} /* empty env — $FINDING not present */)

	r, err := e.Check("echo $FINDING", "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Fatal("expected PASS/deny, got ALLOW")
	}
	if !r.FallThrough {
		t.Fatal("expected FallThrough=true (pass-through), got deny")
	}

	// Find the pass-through RuleMatch for the uncovered unit.
	var passMatch *audit.RuleMatch
	for i := range r.RuleMatches {
		m := &r.RuleMatches[i]
		if m.Action == "deny" && m.Rule == "" {
			passMatch = m
			break
		}
	}
	if passMatch == nil {
		t.Fatal("no pass-through RuleMatch found")
	}
	if len(passMatch.SkippedRules) == 0 {
		t.Fatal("expected SkippedRules to be populated, got none")
	}
	sk := passMatch.SkippedRules[0]
	if sk.Rule != "echo commands" {
		t.Errorf("expected skipped rule %q, got %q", "echo commands", sk.Rule)
	}
	if !strings.Contains(sk.Reason, "$FINDING") {
		t.Errorf("expected reason to mention $FINDING, got %q", sk.Reason)
	}
	if !strings.Contains(sk.Reason, "not in env") {
		t.Errorf("expected reason to mention 'not in env', got %q", sk.Reason)
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

// TestEngine_AssignmentCommandSubstitution verifies that commands embedded in
// variable assignment values (e.g., T7=$(tk create ...)) are extracted and
// evaluated against rules. Previously they were silently dropped, bypassing
// all rule evaluation.
func TestEngine_AssignmentCommandSubstitution(t *testing.T) {
	t.Parallel()

	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:  "tk commands",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "tk create"}},
		},
		{
			Name:           "echo",
			Allow:          []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			VariableAction: config.VariableActionAllow,
		},
	}, nil, map[string]string{})

	// The tk create inside $(...) must be covered by the "tk commands" rule.
	r, err := e.Check(`T7=$(tk create "foo" -t task -p 2) ; echo $T7`, "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW, got DENY: %s", r.Reason)
	}
}

func TestEngine_AssignmentCommandSubstitution_Deny(t *testing.T) {
	t.Parallel()

	// No rule covers tk create — it should be denied even though it's inside an assignment.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:           "echo only",
			Allow:          []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			VariableAction: config.VariableActionAllow,
		},
	}, nil, map[string]string{})

	r, err := e.Check(`T7=$(tk create "foo") ; echo $T7`, "/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY (tk create has no rule), got ALLOW: %s", r.Reason)
	}
}

// --- escalate_flags tests ---

func TestEngine_EscalateFlags_FallsThrough(t *testing.T) {
	t.Parallel()

	// escalate_flags causes the unit to fall through (PASS), not be denied.
	e := newTestEngine(t, []config.Rule{
		{
			Name: "safe-sed",
			Allow: []config.Pattern{
				{
					Type:          config.PatternPrefix,
					Pattern:       "sed",
					EscalateFlags: []string{"-i", "--in-place"},
				},
			},
		},
	}, nil)

	tests := []struct {
		cmd         string
		allowed     bool
		fallThrough bool
	}{
		{"sed 's/foo/bar/' file.txt", true, false},
		{"sed -n 's/foo/bar/p' file.txt", true, false},
		{"sed -i 's/foo/bar/' file.txt", false, true},
		{"sed --in-place 's/foo/bar/' file.txt", false, true},
		{"sed --in-place=.bak 's/foo/bar/' file.txt", false, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			r, err := e.Check(tc.cmd, "/tmp")
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allowed {
				t.Errorf("Check(%q): allowed=%v, want %v", tc.cmd, r.Allowed, tc.allowed)
			}
			if r.FallThrough != tc.fallThrough {
				t.Errorf("Check(%q): fallThrough=%v, want %v", tc.cmd, r.FallThrough, tc.fallThrough)
			}
		})
	}
}

func TestEngine_EscalateFlags_BundledShortFlag(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name: "safe-sed",
			Allow: []config.Pattern{
				{
					Type:          config.PatternPrefix,
					Pattern:       "sed",
					EscalateFlags: []string{"-i"},
				},
			},
		},
	}, nil)

	tests := []struct {
		cmd         string
		allowed     bool
		fallThrough bool
	}{
		{"sed -n 's/foo/bar/p' file.txt", true, false},  // -n is fine
		{"sed -ni 's/foo/bar/p' file.txt", false, true}, // -ni bundles -i
		{"sed -in 's/foo/bar/p' file.txt", false, true}, // -in bundles -i
		{"sed -i 's/foo/bar/' file.txt", false, true},   // exact -i
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			r, err := e.Check(tc.cmd, "/tmp")
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allowed {
				t.Errorf("Check(%q): allowed=%v, want %v", tc.cmd, r.Allowed, tc.allowed)
			}
			if r.FallThrough != tc.fallThrough {
				t.Errorf("Check(%q): fallThrough=%v, want %v", tc.cmd, r.FallThrough, tc.fallThrough)
			}
		})
	}
}

func TestEngine_EscalateFlags_ScopedToPattern(t *testing.T) {
	t.Parallel()

	// escalate_flags on the sed pattern should not affect the grep pattern.
	e := newTestEngine(t, []config.Rule{
		{
			Name: "text-tools",
			Allow: []config.Pattern{
				{
					Type:          config.PatternPrefix,
					Pattern:       "sed",
					EscalateFlags: []string{"-i"},
				},
				{Type: config.PatternPrefix, Pattern: "grep"},
			},
		},
	}, nil)

	r, err := e.Check("grep -i pattern file.txt", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("grep -i should be allowed (escalate_flags only on sed pattern): %s", r.Reason)
	}
}

// --- strip_command_path tests ---

func TestEngine_StripCommandPath_FullPath(t *testing.T) {
	t.Parallel()

	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:  "sed-reads",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "sed"}},
		},
	}, &config.Defaults{
		SubshellDepthLimit:    3,
		UnknownVariableAction: config.VariableActionDeny,
		StripCommandPath:      true,
	}, nil)

	tests := []struct {
		cmd     string
		allowed bool
	}{
		{"sed 's/foo/bar/' file.txt", true},
		{"/usr/bin/sed 's/foo/bar/' file.txt", true},
		{"/usr/local/bin/sed 's/foo/bar/' file.txt", true},
		{"/usr/bin/awk '{print}' file.txt", false}, // awk has no rule
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			r, err := e.Check(tc.cmd, "/tmp")
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allowed {
				t.Errorf("Check(%q): allowed=%v, want %v (reason: %s)", tc.cmd, r.Allowed, tc.allowed, r.Reason)
			}
		})
	}
}

func TestEngine_StripCommandPath_PerRuleOverride(t *testing.T) {
	t.Parallel()

	// Global: strip off. Rule: strip on.
	strip := true
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:             "sed-reads",
			Allow:            []config.Pattern{{Type: config.PatternPrefix, Pattern: "sed"}},
			StripCommandPath: &strip,
		},
	}, &config.Defaults{
		SubshellDepthLimit:    3,
		UnknownVariableAction: config.VariableActionDeny,
		StripCommandPath:      false, // global off
	}, nil)

	r, err := e.Check("/usr/bin/sed 's/foo/bar/' file.txt", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW with per-rule strip_command_path=true: %s", r.Reason)
	}
}

func TestEngine_StripCommandPath_OffByDefault(t *testing.T) {
	t.Parallel()

	// No strip_command_path set anywhere — full path should NOT match bare "sed" pattern.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name:  "sed-reads",
			Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "sed"}},
		},
	}, &config.Defaults{
		SubshellDepthLimit:    3,
		UnknownVariableAction: config.VariableActionDeny,
	}, nil)

	r, err := e.Check("/usr/bin/sed 's/foo/bar/' file.txt", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Errorf("expected DENY: full path should not match bare 'sed' pattern without strip_command_path")
	}
}

func TestEngine_StripCommandPath_WithEscalateFlags(t *testing.T) {
	t.Parallel()

	// strip_command_path + escalate_flags: /usr/bin/sed -i should fall through.
	e := newTestEngineWithEnv(t, []config.Rule{
		{
			Name: "safe-sed",
			Allow: []config.Pattern{
				{
					Type:          config.PatternPrefix,
					Pattern:       "sed",
					EscalateFlags: []string{"-i"},
				},
			},
		},
	}, &config.Defaults{
		SubshellDepthLimit:    3,
		UnknownVariableAction: config.VariableActionDeny,
		StripCommandPath:      true,
	}, nil)

	tests := []struct {
		cmd         string
		allowed     bool
		fallThrough bool
	}{
		{"/usr/bin/sed 's/foo/bar/' file.txt", true, false},
		{"/usr/bin/sed -i 's/foo/bar/' file.txt", false, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			r, err := e.Check(tc.cmd, "/tmp")
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tc.allowed {
				t.Errorf("Check(%q): allowed=%v, want %v", tc.cmd, r.Allowed, tc.allowed)
			}
			if r.FallThrough != tc.fallThrough {
				t.Errorf("Check(%q): fallThrough=%v, want %v", tc.cmd, r.FallThrough, tc.fallThrough)
			}
		})
	}
}

func TestCompileScopeEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		pathScope      []string // nil means field omitted
		homeDir        string
		env            map[string]string
		wantConfigured bool
		wantScope      []string
	}{
		{
			name:           "nil path_scope: scopeConfigured false, scope nil",
			pathScope:      nil,
			wantConfigured: false,
			wantScope:      nil,
		},
		{
			name:           "tilde expansion with homeDir",
			pathScope:      []string{"~/proj"},
			homeDir:        "/home/x",
			wantConfigured: true,
			wantScope:      []string{"/home/x/proj"},
		},
		{
			name:           "variable expansion DIR=/foo",
			pathScope:      []string{"${DIR}"},
			env:            map[string]string{"DIR": "/foo"},
			wantConfigured: true,
			wantScope:      []string{"/foo"},
		},
		{
			name:           "variable unset: entry dropped, scopeConfigured true",
			pathScope:      []string{"${DIR}"},
			env:            map[string]string{},
			wantConfigured: true,
			wantScope:      nil,
		},
		{
			name:           "variable set to empty: entry dropped, scopeConfigured true",
			pathScope:      []string{"${DIR}"},
			env:            map[string]string{"DIR": ""},
			wantConfigured: true,
			wantScope:      nil,
		},
		{
			name:           "relative path dropped",
			pathScope:      []string{"relative/path"},
			wantConfigured: true,
			wantScope:      nil,
		},
		{
			name:           "dotdot and trailing slash cleaned",
			pathScope:      []string{"/foo/bar/../baz/"},
			wantConfigured: true,
			wantScope:      []string{"/foo/baz"},
		},
		{
			name:           "empty pathScope slice: scopeConfigured true, scope nil",
			pathScope:      []string{},
			wantConfigured: true,
			wantScope:      nil,
		},
		{
			name:           "tilde with empty homeDir: entry dropped",
			pathScope:      []string{"~/proj"},
			homeDir:        "",
			wantConfigured: true,
			wantScope:      nil,
		},
		{
			name:           "compound path with empty-valued variable: entry dropped",
			pathScope:      []string{"/prefix/${DIR}/suffix"},
			env:            map[string]string{"DIR": ""},
			wantConfigured: true,
			wantScope:      nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := tc.env
			if env == nil {
				env = map[string]string{}
			}
			configured, scope := compileScopeEntries(tc.pathScope, tc.homeDir, env)

			if configured != tc.wantConfigured {
				t.Errorf("scopeConfigured: got %v, want %v", configured, tc.wantConfigured)
			}
			if len(scope) != len(tc.wantScope) {
				t.Fatalf("scope: got %v, want %v", scope, tc.wantScope)
			}
			for i, want := range tc.wantScope {
				if scope[i] != want {
					t.Errorf("scope[%d]: got %q, want %q", i, scope[i], want)
				}
			}
		})
	}
}

func TestPathsInScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		args            []string
		scope           []string
		scopeConfigured bool
		cwd             string
		homeDir         string
		want            bool
	}{
		{
			name:            "scopeConfigured false: always true",
			args:            []string{"rm", "/etc/passwd"},
			scope:           nil,
			scopeConfigured: false,
			want:            true,
		},
		{
			name:            "nil args: vacuous true",
			args:            nil,
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "empty args: vacuous true",
			args:            []string{},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "no candidates: vacuous true",
			args:            []string{"git", "status"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "scope empty, no candidates: true",
			args:            []string{"git", "status"},
			scope:           nil,
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "scope empty, candidate present: false",
			args:            []string{"cp", "/src/file", "/dst/file"},
			scope:           nil,
			scopeConfigured: true,
			want:            false,
		},
		{
			name:            "all candidates in-scope: true",
			args:            []string{"cp", "/proj/a", "/proj/b"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			cwd:             "/proj",
			want:            true,
		},
		{
			name:            "one candidate out-of-scope: false",
			args:            []string{"cp", "/proj/a", "/etc/passwd"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            false,
		},
		{
			name:            "relative path resolved via cwd: in-scope",
			args:            []string{"cat", "./file"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			cwd:             "/proj/src",
			want:            true,
		},
		{
			name:            "exact scope match",
			args:            []string{"ls", "/proj"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "prefix collision: /project-other not matched by /proj scope",
			args:            []string{"cat", "/project-other/file"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            false,
		},
		{
			name:            "scope entry /: any absolute candidate in-scope",
			args:            []string{"cat", "/anything/at/all"},
			scope:           []string{"/"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "flag --out=/etc/passwd: RHS extracted, out-of-scope",
			args:            []string{"tool", "--out=/etc/passwd"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            false,
		},
		{
			name:            "flag -o=/proj/file: RHS in-scope",
			args:            []string{"tool", "-o=/proj/file"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "bare flag -i: not a candidate",
			args:            []string{"sed", "-i"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true, // -i is a bare flag with no "=", not a candidate; no candidates → vacuous true
		},
		{
			name:            "bare flag --recursive: not a candidate",
			args:            []string{"rsync", "--recursive"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true,
		},
		{
			name:            "token with unexpanded variable: treated as literal",
			args:            []string{"cat", "$HOME/foo"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			cwd:             "/other", // resolves to /other/$HOME/foo — not under /proj
			want:            false,
		},
		{
			name:            "args[0] never a candidate even if it contains /",
			args:            []string{"/usr/bin/cat", "/proj/file"},
			scope:           []string{"/proj"},
			scopeConfigured: true,
			want:            true, // only /proj/file is evaluated
		},
		{
			name:            "tilde in arg expanded via homeDir",
			args:            []string{"cat", "~/proj/file"},
			scope:           []string{"/home/x/proj"},
			scopeConfigured: true,
			homeDir:         "/home/x",
			want:            true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := pathsInScope(tc.args, tc.scope, tc.scopeConfigured, tc.cwd, tc.homeDir)
			if got != tc.want {
				t.Errorf("pathsInScope(%v, scope=%v, configured=%v, cwd=%q, home=%q) = %v, want %v",
					tc.args, tc.scope, tc.scopeConfigured, tc.cwd, tc.homeDir, got, tc.want)
			}
		})
	}
}

func TestEngine_PathScope_ExpandVariables(t *testing.T) {
	t.Parallel()

	rule := config.Rule{
		Name:            "proj writes",
		Allow:           []config.Pattern{{Type: config.PatternPrefix, Pattern: "cp"}},
		ExpandVariables: true,
		PathScope:       []string{"/proj"},
	}

	t.Run("DIR=/proj: expanded arg in-scope, allow", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{"DIR": "/proj"})
		r, err := e.Check("cp $DIR/file /proj/out", "/proj")
		if err != nil {
			t.Fatal(err)
		}
		if !r.Allowed {
			t.Errorf("expected ALLOW, got DENY: %s", r.Reason)
		}
	})

	t.Run("DIR=/other: expanded arg out-of-scope, deny", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{"DIR": "/other"})
		r, err := e.Check("cp $DIR/file /proj/out", "/proj")
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed {
			t.Errorf("expected DENY (out-of-scope arg), got ALLOW")
		}
	})
}

// TestEngine_PathScope covers all 20 path_scope integration scenarios.
func TestEngine_PathScope(t *testing.T) {
	t.Parallel()

	// allowRule builds a simple prefix-allow rule with the given path_scope.
	allowRule := func(name, prefix string, scope []string) config.Rule {
		return config.Rule{
			Name:      name,
			Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: prefix}},
			PathScope: scope,
		}
	}

	// assertAllowed checks that the result is an allow decision.
	assertAllowed := func(t *testing.T, r *Result, label string) {
		t.Helper()
		if !r.Allowed {
			t.Errorf("%s: expected Allowed=true, got Allowed=false FallThrough=%v Reason=%q", label, r.FallThrough, r.Reason)
		}
	}

	// assertFallThrough checks that the result is a pass-through (no rule covered).
	assertFallThrough := func(t *testing.T, r *Result, label string) {
		t.Helper()
		if !r.FallThrough {
			t.Errorf("%s: expected FallThrough=true, got Allowed=%v FallThrough=false", label, r.Allowed)
		}
	}

	// lastDenyMatch returns the last RuleMatch with action "deny" (the fall-through record).
	lastDenyMatch := func(matches []audit.RuleMatch) *audit.RuleMatch {
		for i := len(matches) - 1; i >= 0; i-- {
			if matches[i].Action == "deny" {
				return &matches[i]
			}
		}
		return nil
	}

	// hasAllowMatch returns true if any RuleMatch has action "allow" for the given rule.
	hasAllowMatch := func(matches []audit.RuleMatch, ruleName string) bool {
		for _, m := range matches {
			if m.Action == "allow" && m.Rule == ruleName {
				return true
			}
		}
		return false
	}

	// --- Scenario 1: in-scope absolute path ---
	t.Run("1_in_scope_absolute", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("cp /proj/a /proj/b", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "in-scope absolute")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r', got %v", r.RuleMatches)
		}
	})

	// --- Scenario 2: out-of-scope absolute path ---
	t.Run("2_out_of_scope_absolute", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("cp /etc/passwd /proj/b", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r, "out-of-scope absolute")
		if dm := lastDenyMatch(r.RuleMatches); dm == nil {
			t.Errorf("expected a deny RuleMatch for fall-through; got %v", r.RuleMatches)
		}
	})

	// --- Scenario 3: relative path resolved via cwd ---
	t.Run("3_relative_path_resolved_via_cwd", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("cp ./file /proj/out", "/proj")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "relative resolved via cwd")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 4: ~/ expansion in scope entry ---
	t.Run("4_tilde_expansion_in_scope_entry", func(t *testing.T) {
		t.Parallel()
		homeDir, err := os.UserHomeDir()
		if err != nil || homeDir == "" {
			t.Skip("no home dir available")
		}
		// Scope entry "~/testpermcop" compiles to homeDir+"/testpermcop".
		// Command arg "~/testpermcop/file" expands to homeDir+"/testpermcop/file" in pathsInScope.
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"~/testpermcop"})}, nil, map[string]string{})
		r, err := e.Check("ls ~/testpermcop/file", homeDir)
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "tilde expansion in scope entry")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 5: ${VAR} expansion in scope entry ---
	t.Run("5_var_expansion_in_scope_entry", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"${DIR}"})}, nil, map[string]string{"DIR": "/proj"})
		r, err := e.Check("ls /proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "var expansion in scope entry")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 6: ${VAR} unset — entry dropped, other entries still usable ---
	t.Run("6_var_unset_other_entry_still_usable", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"${UNSET_XYZ}", "/proj"})}, nil, map[string]string{})
		r, err := e.Check("ls /proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		// ${UNSET_XYZ} is dropped but /proj survives; /proj/file is in-scope.
		assertAllowed(t, r, "unset var entry dropped, other survives")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 7: ${VAR}="" — entry dropped ---
	t.Run("7_var_empty_entry_dropped", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"${DIR}"})}, nil, map[string]string{"DIR": ""})
		r, err := e.Check("ls /proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		// Scope is empty after dropping the entry; candidate present → abstain.
		assertFallThrough(t, r, "empty var entry dropped, scope empty")
		if dm := lastDenyMatch(r.RuleMatches); dm == nil {
			t.Errorf("expected a deny RuleMatch for fall-through; got %v", r.RuleMatches)
		}
	})

	// --- Scenario 8: all scope entries dropped — abstains with candidates, covers without ---
	t.Run("8_all_entries_dropped", func(t *testing.T) {
		t.Parallel()
		rule := allowRule("r", "cp", []string{"${GONE_XYZ}"})
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})

		// With path candidate: scope empty + candidate → abstain.
		r1, err := e.Check("cp /etc/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r1, "all-dropped scope with candidate")
		if dm := lastDenyMatch(r1.RuleMatches); dm == nil {
			t.Errorf("expected a deny RuleMatch for fall-through; got %v", r1.RuleMatches)
		}

		// Without path candidates: vacuous pass → allow.
		r2, err := e.Check("cp -r", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r2, "all-dropped scope without candidates")
		if !hasAllowMatch(r2.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r' (vacuous pass)")
		}
	})

	// --- Scenario 9: nonexistent resolved path works lexically ---
	t.Run("9_nonexistent_path_lexical", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("ls /proj/does_not_exist_xyz_abc", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "nonexistent path lexically in-scope")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 10: multiple path args, all in-scope ---
	t.Run("10_multiple_args_all_in_scope", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("cp /proj/a /proj/b", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "all path args in-scope")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 11: multiple path args, one out-of-scope ---
	t.Run("11_multiple_args_one_out_of_scope", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("cp /proj/a /etc/passwd", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r, "one path arg out-of-scope")
		if dm := lastDenyMatch(r.RuleMatches); dm == nil {
			t.Errorf("expected a deny RuleMatch for fall-through; got %v", r.RuleMatches)
		}
	})

	// --- Scenario 12: no path candidates — vacuous pass ---
	t.Run("12_no_path_candidates_vacuous_pass", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "git", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("git status", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "no path candidates: vacuous pass")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 13: root scope "/" — any absolute path in-scope ---
	t.Run("13_root_scope", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "ls", []string{"/"})}, nil, map[string]string{})
		r, err := e.Check("ls /anything/at/all", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "root scope covers any absolute path")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 14: escalate_flags checked before path_scope ---
	t.Run("14_escalate_flags_before_path_scope", func(t *testing.T) {
		t.Parallel()
		rule := config.Rule{
			Name: "r",
			Allow: []config.Pattern{{
				Type:          config.PatternPrefix,
				Pattern:       "cp",
				EscalateFlags: []string{"--force"},
			}},
			PathScope: []string{"/proj"},
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})

		// --force present AND /proj/file in-scope: escalate fires first → falls through.
		r1, err := e.Check("cp --force /proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r1, "escalate fires before path_scope check")
		if dm := lastDenyMatch(r1.RuleMatches); dm == nil {
			t.Errorf("r1: expected a deny RuleMatch for fall-through; got %v", r1.RuleMatches)
		}

		// No --force, in-scope: escalate doesn't fire, path_scope passes → allow.
		r2, err := e.Check("cp /proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r2, "no escalate flag, in-scope: allowed")
		if !hasAllowMatch(r2.RuleMatches, "r") {
			t.Errorf("r2: expected allow RuleMatch from rule 'r'")
		}

		// No --force, out-of-scope: escalate doesn't fire, path_scope abstains → fall-through.
		r3, err := e.Check("cp /etc/passwd", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r3, "no escalate flag, out-of-scope: fall-through")
		if dm := lastDenyMatch(r3.RuleMatches); dm == nil {
			t.Errorf("r3: expected a deny RuleMatch for fall-through; got %v", r3.RuleMatches)
		}
	})

	// --- Scenario 15: deny in Pass 1 beats allow with path_scope in Pass 2 ---
	t.Run("15_deny_pass1_beats_path_scope_allow", func(t *testing.T) {
		t.Parallel()
		rules := []config.Rule{
			{
				Name: "blocker",
				Deny: []config.Pattern{{Type: config.PatternPrefix, Pattern: "rm"}},
			},
			allowRule("permitter", "rm", []string{"/proj"}),
		}
		e := newTestEngineWithEnv(t, rules, nil, map[string]string{})
		r, err := e.Check("rm /proj/file", "/proj")
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed || r.FallThrough {
			t.Errorf("expected explicit deny, got Allowed=%v FallThrough=%v", r.Allowed, r.FallThrough)
		}
		if r.DecidingRule != "blocker" {
			t.Errorf("deciding rule: got %q, want %q", r.DecidingRule, "blocker")
		}
		// Verify deny RuleMatch present.
		hasDeny := false
		for _, m := range r.RuleMatches {
			if m.Action == "deny" && m.Rule == "blocker" {
				hasDeny = true
			}
		}
		if !hasDeny {
			t.Errorf("expected deny RuleMatch from rule 'blocker'; got %v", r.RuleMatches)
		}
	})

	// --- Scenario 16: unexpanded $VAR in argv — rule abstains via path_scope ---
	t.Run("16_unexpanded_var_argv_abstains", func(t *testing.T) {
		t.Parallel()
		// VariableActionAllow so the variable check does not block before path_scope runs.
		rule := config.Rule{
			Name:           "cat-proj",
			Allow:          []config.Pattern{{Type: config.PatternPrefix, Pattern: "cat"}},
			PathScope:      []string{"/proj"},
			VariableAction: config.VariableActionAllow,
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})
		// $HOME/foo is treated as a literal token; it contains "/" so it is a path
		// candidate. With cwd=/home/user it resolves to /home/user/$HOME/foo — not
		// under /proj — so pathsInScope returns false and the rule abstains.
		r, err := e.Check("cat $HOME/foo", "/home/user")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r, "unexpanded var in argv: rule abstains")
		dm := lastDenyMatch(r.RuleMatches)
		if dm == nil {
			t.Fatalf("expected a deny RuleMatch for fall-through; got %v", r.RuleMatches)
		}
		if len(dm.SkippedRules) == 0 {
			t.Fatal("expected SkippedRules to be populated for path_scope abstention, got none")
		}
		sk := dm.SkippedRules[0]
		if sk.Rule != "cat-proj" {
			t.Errorf("skipped rule: got %q, want %q", sk.Rule, "cat-proj")
		}
		const wantReason = "path_scope: /home/user/$HOME/foo not under any scope entry"
		if sk.Reason != wantReason {
			t.Errorf("skipped reason: got %q, want %q", sk.Reason, wantReason)
		}
	})

	// --- Scenario 17: command at position 0 with "/" is not a candidate ---
	t.Run("17_command_at_pos0_not_candidate", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "./scripts/deploy.sh", []string{"/proj"})}, nil, map[string]string{})
		// args[0]="./scripts/deploy.sh" is skipped; args[1]="/proj/arg" is the only candidate.
		r, err := e.Check("./scripts/deploy.sh /proj/arg", "/proj")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "pos-0 token not a candidate")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 18: quoted arg with spaces — only the path arg is a candidate ---
	t.Run("18_quoted_arg_with_spaces", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "cp", []string{"/proj"})}, nil, map[string]string{})
		// Parser produces Args=["cp", "my file.txt", "/proj/dest"].
		// "my file.txt" has no "/" → not a candidate.
		// "/proj/dest" → candidate → in-scope.
		r, err := e.Check(`cp "my file.txt" /proj/dest`, "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "quoted arg with spaces: only path arg is candidate")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})

	// --- Scenario 19: --out=/etc/passwd with scope /proj — RHS extracted, out-of-scope ---
	t.Run("19_flag_eq_rhs_out_of_scope", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "tool", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("tool --out=/etc/passwd", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertFallThrough(t, r, "--out=/etc/passwd RHS out-of-scope")
		if dm := lastDenyMatch(r.RuleMatches); dm == nil {
			t.Errorf("expected a deny RuleMatch for fall-through; got %v", r.RuleMatches)
		}
	})

	// --- Scenario 20: -o=/proj/file with scope /proj — RHS in-scope ---
	t.Run("20_flag_eq_rhs_in_scope", func(t *testing.T) {
		t.Parallel()
		e := newTestEngineWithEnv(t, []config.Rule{allowRule("r", "tool", []string{"/proj"})}, nil, map[string]string{})
		r, err := e.Check("tool -o=/proj/file", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		assertAllowed(t, r, "-o=/proj/file RHS in-scope")
		if !hasAllowMatch(r.RuleMatches, "r") {
			t.Errorf("expected allow RuleMatch from rule 'r'")
		}
	})
}

func TestEngine_PathScope_SkippedRules(t *testing.T) {
	t.Parallel()

	lastDenyMatch := func(matches []audit.RuleMatch) *audit.RuleMatch {
		for i := len(matches) - 1; i >= 0; i-- {
			if matches[i].Action == "deny" {
				return &matches[i]
			}
		}
		return nil
	}

	// Out-of-scope: SkippedRule recorded with correct reason and resolved path.
	t.Run("out_of_scope_records_skipped_rule", func(t *testing.T) {
		t.Parallel()
		rule := config.Rule{
			Name:      "cp-proj",
			Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "cp"}},
			PathScope: []string{"/proj"},
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})
		r, err := e.Check("cp /etc/passwd /proj/dest", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		if !r.FallThrough {
			t.Fatalf("expected FallThrough, got Allowed=%v", r.Allowed)
		}
		dm := lastDenyMatch(r.RuleMatches)
		if dm == nil {
			t.Fatalf("no deny RuleMatch found; got %v", r.RuleMatches)
		}
		if len(dm.SkippedRules) == 0 {
			t.Fatal("expected SkippedRules for path_scope abstention, got none")
		}
		sk := dm.SkippedRules[0]
		if sk.Rule != "cp-proj" {
			t.Errorf("skipped rule: got %q, want %q", sk.Rule, "cp-proj")
		}
		const wantReason = "path_scope: /etc/passwd not under any scope entry"
		if sk.Reason != wantReason {
			t.Errorf("skipped reason: got %q, want %q", sk.Reason, wantReason)
		}
	})

	// In-scope: no path_scope SkippedRule emitted.
	t.Run("in_scope_no_skipped_rule", func(t *testing.T) {
		t.Parallel()
		rule := config.Rule{
			Name:      "cp-proj",
			Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "cp"}},
			PathScope: []string{"/proj"},
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})
		r, err := e.Check("cp /proj/src /proj/dest", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		if !r.Allowed {
			t.Fatalf("expected Allowed, got FallThrough=%v", r.FallThrough)
		}
		for _, m := range r.RuleMatches {
			for _, sk := range m.SkippedRules {
				if strings.HasPrefix(sk.Reason, "path_scope:") {
					t.Errorf("unexpected path_scope SkippedRule on allow: %+v", sk)
				}
			}
		}
	})

	// escalate_flags fires before path_scope: no path_scope SkippedRule emitted.
	t.Run("escalate_before_path_scope_no_path_scope_skipped_rule", func(t *testing.T) {
		t.Parallel()
		rule := config.Rule{
			Name: "cp-proj",
			Allow: []config.Pattern{{
				Type:          config.PatternPrefix,
				Pattern:       "cp",
				EscalateFlags: []string{"--force"},
			}},
			PathScope: []string{"/proj"},
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})
		// --force fires escalate; /etc/passwd would also fail path_scope.
		r, err := e.Check("cp --force /etc/passwd /proj/dest", "/tmp")
		if err != nil {
			t.Fatal(err)
		}
		if !r.FallThrough {
			t.Fatalf("expected FallThrough from escalate, got Allowed=%v", r.Allowed)
		}
		dm := lastDenyMatch(r.RuleMatches)
		if dm == nil {
			t.Fatalf("no deny RuleMatch; got %v", r.RuleMatches)
		}
		for _, sk := range dm.SkippedRules {
			if strings.HasPrefix(sk.Reason, "path_scope:") {
				t.Errorf("path_scope SkippedRule emitted when escalate fired first: %+v", sk)
			}
		}
	})

	// Relative path resolved against cwd appears in reason string.
	t.Run("relative_path_resolved_in_reason", func(t *testing.T) {
		t.Parallel()
		rule := config.Rule{
			Name:      "ls-proj",
			Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "ls"}},
			PathScope: []string{"/proj"},
		}
		e := newTestEngineWithEnv(t, []config.Rule{rule}, nil, map[string]string{})
		// "other/dir" is relative; with cwd=/home/user it resolves to /home/user/other/dir.
		r, err := e.Check("ls other/dir", "/home/user")
		if err != nil {
			t.Fatal(err)
		}
		if !r.FallThrough {
			t.Fatalf("expected FallThrough, got Allowed=%v", r.Allowed)
		}
		dm := lastDenyMatch(r.RuleMatches)
		if dm == nil {
			t.Fatalf("no deny RuleMatch; got %v", r.RuleMatches)
		}
		if len(dm.SkippedRules) == 0 {
			t.Fatal("expected SkippedRules for path_scope abstention, got none")
		}
		const wantReason = "path_scope: /home/user/other/dir not under any scope entry"
		if dm.SkippedRules[0].Reason != wantReason {
			t.Errorf("reason: got %q, want %q", dm.SkippedRules[0].Reason, wantReason)
		}
	})
}
