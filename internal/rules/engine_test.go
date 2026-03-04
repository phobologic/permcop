package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func newTestEngine(t *testing.T, rules []config.Rule, defaults *config.Defaults) *Engine {
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
	logger := audit.New(logPath, cfg.Defaults.LogFormat)
	return New(cfg, logger)
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

	r, _ := e.Check("sudo rm -rf /", "/tmp")
	if r.Allowed {
		t.Error("expected DENY for sudo, got ALLOW")
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

	// A rule must cover ALL units (command + file redirect) to allow the command.
	// allow_read alone doesn't cover the "cat" command unit.
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

	// Rule with only allow_read cannot cover the command unit — deny.
	e2 := newTestEngine(t, []config.Rule{
		{Name: "read only rule", AllowRead: []string{"/project/**"}},
	}, nil)
	r2, _ := e2.Check("cat < /project/src/main.go", "/tmp")
	if r2.Allowed {
		t.Error("expected DENY: rule has allow_read but no allow command pattern for 'cat'")
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

	// Two separate rules: one for the command, one for the write.
	// Both units must be covered by a single rule — or each by separate rules?
	// Actually in the two-pass model, all units must be covered by ONE rule's allows.
	// This is a limitation: you need a single rule that covers both the command and its redirects.
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

func TestEngine_AllUnitsMustMatchSingleRule(t *testing.T) {
	t.Parallel()

	// Rule A covers "echo" commands, Rule B covers writes to /tmp.
	// A chain "echo hi > /tmp/out.txt" has two units: the command and the write.
	// Neither rule alone covers both units — should deny.
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
	if r.Allowed {
		t.Error("expected DENY: no single rule covers both the command and the redirect")
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
