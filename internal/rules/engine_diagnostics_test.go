package rules

import (
	"os"
	"strings"
	"testing"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
	"github.com/phobologic/permcop/internal/parser"
)

// diagRule returns a rule that references $PERMCOP_PROJECT_ROOT in the given field.
func diagRuleWithField(name, field string) config.Rule {
	r := config.Rule{Name: name}
	ref := "${PERMCOP_PROJECT_ROOT}/src/**"
	switch field {
	case "path_scope":
		r.PathScope = []string{ref}
		r.Allow = []config.Pattern{{Type: config.PatternPrefix, Pattern: "ls"}}
	case "allow_read":
		r.AllowRead = []string{ref}
	case "allow_write":
		r.AllowWrite = []string{ref}
	case "deny_read":
		r.DenyRead = []string{ref}
	case "deny_write":
		r.DenyWrite = []string{ref}
	}
	return r
}

func TestDiagnosticPresentWhenUnresolved(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{diagRuleWithField("scope-rule", "path_scope")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)

	// No CWD that resolves .git → PERMCOP_PROJECT_ROOT absent from pathEnv.
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) == 0 {
		t.Fatal("expected at least one engine-level diagnostic when PERMCOP_PROJECT_ROOT is unresolved")
	}
	if !strings.Contains(e.diagnostics[0], "scope-rule") {
		t.Errorf("diagnostic should name the rule; got: %q", e.diagnostics[0])
	}
	if !strings.Contains(e.diagnostics[0], "PERMCOP_PROJECT_ROOT") {
		t.Errorf("diagnostic should mention PERMCOP_PROJECT_ROOT; got: %q", e.diagnostics[0])
	}
}

func TestDiagnosticAbsentWhenResolved(t *testing.T) {
	t.Parallel()

	projectRoot := makeProjectRoot(t)
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{diagRuleWithField("scope-rule", "path_scope")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)

	e, err := NewWithEnv(cfg, logger, map[string]string{}, projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 0 {
		t.Errorf("expected no diagnostics when PERMCOP_PROJECT_ROOT resolves; got: %v", e.diagnostics)
	}
}

func TestDiagnosticFiresForEachField(t *testing.T) {
	t.Parallel()

	fields := []string{"path_scope", "allow_read", "allow_write", "deny_read", "deny_write"}
	for _, field := range fields {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				Defaults: defaultsForTest(),
				Rules:    []config.Rule{diagRuleWithField("rule-"+field, field)},
			}
			logger := audit.New(os.DevNull, "", 0, 0)
			e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
			if err != nil {
				t.Fatal(err)
			}
			if len(e.diagnostics) == 0 {
				t.Errorf("field %q: expected diagnostic when PERMCOP_PROJECT_ROOT is unresolved", field)
			}
		})
	}
}

func TestDiagnosticOnlyOnePerRuleAcrossMultipleFields(t *testing.T) {
	t.Parallel()

	// Rule references PERMCOP_PROJECT_ROOT in multiple fields.
	r := config.Rule{
		Name:       "multi-field-rule",
		PathScope:  []string{"${PERMCOP_PROJECT_ROOT}/a"},
		AllowRead:  []string{"${PERMCOP_PROJECT_ROOT}/b"},
		AllowWrite: []string{"${PERMCOP_PROJECT_ROOT}/c"},
		DenyRead:   []string{"${PERMCOP_PROJECT_ROOT}/d"},
		DenyWrite:  []string{"${PERMCOP_PROJECT_ROOT}/e"},
	}
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{r},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 1 {
		t.Errorf("expected exactly 1 diagnostic for rule with multiple fields; got %d: %v", len(e.diagnostics), e.diagnostics)
	}
}

func TestDiagnosticDedupAcrossMultipleRulesWithIdenticalMessages(t *testing.T) {
	t.Parallel()

	// Two rules with the same name produce identical diagnostic messages.
	r1 := config.Rule{
		Name:      "dup-rule",
		PathScope: []string{"${PERMCOP_PROJECT_ROOT}/x"},
		Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "ls"}},
	}
	r2 := config.Rule{
		Name:      "dup-rule",
		PathScope: []string{"${PERMCOP_PROJECT_ROOT}/y"},
		Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "cat"}},
	}
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{r1, r2},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 1 {
		t.Errorf("expected 1 deduplicated diagnostic for two rules with identical messages; got %d: %v", len(e.diagnostics), e.diagnostics)
	}
}

func TestDiagnosticAttachedToEveryAuditEntry(t *testing.T) {
	t.Parallel()

	// We need to capture the logged entries. Write to a temp log file and read it back.
	dir := t.TempDir()
	logPath := dir + "/audit.log"

	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules: []config.Rule{
			diagRuleWithField("scope-rule", "path_scope"),
			// Allow rule so Check can produce ALLOW entries.
			{
				Name:  "allow-echo",
				Allow: []config.Pattern{{Type: config.PatternPrefix, Pattern: "echo"}},
			},
			// Deny rule so Check can produce an explicit DENY entry.
			{
				Name: "deny-rm",
				Deny: []config.Pattern{{Type: config.PatternPrefix, Pattern: "rm"}},
			},
		},
	}
	logger := audit.New(logPath, "text", 0, 0)
	defer logger.Close() //nolint:errcheck

	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}

	// ALLOW entry.
	_, _ = e.Check("echo hello", "/tmp")
	// DENY entry (matched by deny-rm rule).
	_, _ = e.Check("rm -rf /secret", "/tmp")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	diagCount := strings.Count(content, "  diag: ")
	if diagCount < 2 {
		t.Errorf("expected diagnostic in every emitted audit entry (at least 2); found %d occurrences in:\n%s", diagCount, content)
	}
}

func TestNoDiagnosticForOtherUnresolvedVariables(t *testing.T) {
	t.Parallel()

	// A rule with a different variable that is also unresolved should not produce
	// the PERMCOP_PROJECT_ROOT diagnostic.
	r := config.Rule{
		Name:      "other-var-rule",
		AllowRead: []string{"$SOME_OTHER_VAR/src/**"},
	}
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{r},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 0 {
		t.Errorf("expected no diagnostic for unrelated unresolved variable; got: %v", e.diagnostics)
	}
}

func TestFallThroughCheckCarriesDiagnostics(t *testing.T) {
	t.Parallel()

	// Rule references PERMCOP_PROJECT_ROOT but no command allow pattern → any
	// command falls through (no covering rule). With an unresolved project root
	// the engine must still propagate diagnostics onto Result.Entry.Diagnostics.
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{diagRuleWithField("write-rule", "allow_write")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}

	result, err := e.Check("touch /tmp/foo", "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.FallThrough {
		t.Fatalf("expected fall-through; got Allowed=%v Reason=%q", result.Allowed, result.Reason)
	}
	if len(result.Diagnostics) == 0 {
		t.Error("fall-through result.Diagnostics must be non-empty when engine has active diagnostics")
	}
}

func TestFallThroughCheckFileCarriesDiagnostics(t *testing.T) {
	t.Parallel()

	// Rule has allow_write referencing PERMCOP_PROJECT_ROOT. With an unresolved
	// project root the glob compiles to nil and never matches, so any CheckFile
	// call falls through. The engine must propagate diagnostics onto the result.
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{diagRuleWithField("write-rule", "allow_write")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}

	result, err := e.CheckFile("/tmp/testfile.txt", parser.UnitWriteFile, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.FallThrough {
		t.Fatalf("expected fall-through; got Allowed=%v Reason=%q", result.Allowed, result.Reason)
	}
	if len(result.Diagnostics) == 0 {
		t.Error("fall-through result.Diagnostics must be non-empty when engine has active diagnostics")
	}
}

func TestDiagnosticMessagePathScopeOnlySaysEffectivelyDropped(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{diagRuleWithField("scope-only", "path_scope")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) == 0 {
		t.Fatal("expected diagnostic")
	}
	if !strings.Contains(e.diagnostics[0], "effectively dropped") {
		t.Errorf("path_scope-only unresolved should say 'effectively dropped'; got: %q", e.diagnostics[0])
	}
}

func TestDiagnosticMessageGlobFieldsOnlySaysPathGlobIneffective(t *testing.T) {
	t.Parallel()

	for _, field := range []string{"allow_read", "allow_write", "deny_read", "deny_write"} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				Defaults: defaultsForTest(),
				Rules:    []config.Rule{diagRuleWithField("glob-only-"+field, field)},
			}
			logger := audit.New(os.DevNull, "", 0, 0)
			e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
			if err != nil {
				t.Fatal(err)
			}
			if len(e.diagnostics) == 0 {
				t.Fatalf("field %q: expected diagnostic", field)
			}
			if strings.Contains(e.diagnostics[0], "effectively dropped") {
				t.Errorf("field %q: glob-only unresolved must not say 'effectively dropped'; got: %q", field, e.diagnostics[0])
			}
			if !strings.Contains(e.diagnostics[0], "path-glob constraints") {
				t.Errorf("field %q: glob-only unresolved should mention 'path-glob constraints'; got: %q", field, e.diagnostics[0])
			}
		})
	}
}

func TestDiagnosticMessageBothFieldsSaysEffectivelyDropped(t *testing.T) {
	t.Parallel()

	// When path_scope AND glob fields both reference the var, "effectively dropped"
	// takes precedence because the scope constraint is the more severe impact.
	r := config.Rule{
		Name:       "both-fields",
		PathScope:  []string{"${PERMCOP_PROJECT_ROOT}/a"},
		AllowWrite: []string{"${PERMCOP_PROJECT_ROOT}/b/**"},
		Allow:      []config.Pattern{{Type: config.PatternPrefix, Pattern: "ls"}},
	}
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{r},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, "/nonexistent/cwd/xyz-permcop-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic; got %d: %v", len(e.diagnostics), e.diagnostics)
	}
	if !strings.Contains(e.diagnostics[0], "effectively dropped") {
		t.Errorf("path_scope+glob-fields unresolved should say 'effectively dropped'; got: %q", e.diagnostics[0])
	}
}

func TestDiagnosticNotEmittedWhenProjectRootResolved(t *testing.T) {
	t.Parallel()

	// A rule referencing $PERMCOP_PROJECT_ROOT (without braces) — resolves fine.
	projectRoot := makeProjectRoot(t)
	r := config.Rule{
		Name:      "dollar-style",
		AllowRead: []string{"$PERMCOP_PROJECT_ROOT/src/**"},
	}
	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{r},
	}
	logger := audit.New(os.DevNull, "", 0, 0)
	e, err := NewWithEnv(cfg, logger, map[string]string{}, projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.diagnostics) != 0 {
		t.Errorf("expected no diagnostic when $PERMCOP_PROJECT_ROOT resolves; got: %v", e.diagnostics)
	}
}
