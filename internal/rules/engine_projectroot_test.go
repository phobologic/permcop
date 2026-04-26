package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
)

// makeProjectRoot creates a temp dir containing a .git directory and returns its path.
func makeProjectRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// scopeRuleFor returns a rule whose path_scope is ${PERMCOP_PROJECT_ROOT} and
// that allows any command matching the given prefix.
func scopeRuleFor(prefix string) config.Rule {
	return config.Rule{
		Name:      "scope-rule",
		PathScope: []string{"${PERMCOP_PROJECT_ROOT}"},
		Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: prefix}},
	}
}

func defaultsForTest() config.Defaults {
	return config.Defaults{
		SubshellDepthLimit:    3,
		UnknownVariableAction: config.VariableActionDeny,
	}
}

func TestProjectRootEnvInjection(t *testing.T) {
	t.Parallel()

	projectRoot := makeProjectRoot(t)
	// Resolve symlinks so paths match what resolveProjectRoot returns on macOS (/private/var/...).
	realProjectRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatal(err)
	}

	// A subdirectory inside the project — resolveProjectRoot should still find projectRoot.
	subdirCWD := filepath.Join(projectRoot, "subdir")
	if err := os.MkdirAll(subdirCWD, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules:    []config.Rule{scopeRuleFor("ls")},
	}
	logger := audit.New(os.DevNull, "", 0, 0)

	// Use realProjectRoot so pathsInScope sees the same resolved path that pathEnv holds.
	pathInside := filepath.Join(realProjectRoot, "src", "main.go")
	pathOutside := "/tmp/outside-permcop-test"
	checkInside := "ls " + pathInside
	checkOutside := "ls " + pathOutside

	t.Run("ResolvesSucceeds_EnvEmpty", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{}
		e, err := NewWithEnv(cfg, logger, env, subdirCWD)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := e.Check(checkInside, projectRoot)
		if !r.Allowed {
			t.Errorf("path inside project root should be allowed; FallThrough=%v Reason=%q", r.FallThrough, r.Reason)
		}
		r, _ = e.Check(checkOutside, projectRoot)
		if r.Allowed {
			t.Error("path outside project root should not be allowed")
		}
	})

	t.Run("ResolvesSucceeds_EnvPrePopulatedDifferentValue", func(t *testing.T) {
		t.Parallel()
		// Env has PERMCOP_PROJECT_ROOT pointing elsewhere; synthetic value must overwrite it.
		env := map[string]string{"PERMCOP_PROJECT_ROOT": "/some/other/path"}
		e, err := NewWithEnv(cfg, logger, env, subdirCWD)
		if err != nil {
			t.Fatal(err)
		}
		// After overwrite, scope is projectRoot; pathInside should be allowed.
		r, _ := e.Check(checkInside, projectRoot)
		if !r.Allowed {
			t.Errorf("path inside actual project root should be allowed after env overwrite; FallThrough=%v Reason=%q", r.FallThrough, r.Reason)
		}
		// /some/other/path is gone from scope, so pathOutside is still out.
		r, _ = e.Check(checkOutside, projectRoot)
		if r.Allowed {
			t.Error("path outside real project root should still be denied after overwrite")
		}
	})

	t.Run("ResolveFails_EnvPrePopulated", func(t *testing.T) {
		t.Parallel()
		// CWD resolves to nothing; PERMCOP_PROJECT_ROOT must be absent from pathEnv even though env has it.
		env := map[string]string{"PERMCOP_PROJECT_ROOT": projectRoot}
		e, err := NewWithEnv(cfg, logger, env, "/nonexistent/cwd/xyz-permcop-test")
		if err != nil {
			t.Fatal(err)
		}
		// pathEnv lacks PERMCOP_PROJECT_ROOT → compileScopeEntries drops the entry →
		// scopeConfigured=true, scope=nil → pathsInScope returns false for all paths.
		r, _ := e.Check(checkInside, projectRoot)
		if r.Allowed {
			t.Error("resolution failed; PERMCOP_PROJECT_ROOT should be absent from pathEnv; scope should block all paths")
		}
	})

	t.Run("ResolveFails_EnvEmpty", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{}
		e, err := NewWithEnv(cfg, logger, env, "/nonexistent/cwd/xyz-permcop-test")
		if err != nil {
			t.Fatal(err)
		}
		r, _ := e.Check(checkInside, projectRoot)
		if r.Allowed {
			t.Error("resolution failed with empty env; scope should block all paths")
		}
	})

	t.Run("CallerEnvNotMutated", func(t *testing.T) {
		t.Parallel()
		original := map[string]string{"FOO": "bar", "PERMCOP_PROJECT_ROOT": "original-value"}
		before := map[string]string{"FOO": "bar", "PERMCOP_PROJECT_ROOT": "original-value"}
		_, err := NewWithEnv(cfg, logger, original, subdirCWD)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, original) {
			t.Errorf("caller env was mutated: got %v, want %v", original, before)
		}
	})
}

// TestProjectRootExpandVariablesIsolation verifies that the synthetic
// PERMCOP_PROJECT_ROOT injected into pathEnv does NOT leak into e.env, so a
// rule with expand_variables=true cannot expand $PERMCOP_PROJECT_ROOT unless
// the caller's env explicitly contained the variable.
func TestProjectRootExpandVariablesIsolation(t *testing.T) {
	t.Parallel()

	projectRoot := makeProjectRoot(t)

	cfg := &config.Config{
		Defaults: defaultsForTest(),
		Rules: []config.Rule{{
			Name:            "expand-test",
			ExpandVariables: true,
			Allow:           []config.Pattern{{Type: config.PatternGlob, Pattern: "ls *"}},
		}},
	}
	logger := audit.New(os.DevNull, "", 0, 0)

	t.Run("SyntheticValueNotInExpandEnv", func(t *testing.T) {
		t.Parallel()
		// Env does NOT contain PERMCOP_PROJECT_ROOT. Engine is built with a valid
		// CWD so pathEnv WILL have PERMCOP_PROJECT_ROOT set — but e.env must not.
		env := map[string]string{"OTHER": "value"}
		e, err := NewWithEnv(cfg, logger, env, projectRoot)
		if err != nil {
			t.Fatal(err)
		}
		// expand_variables cannot resolve $PERMCOP_PROJECT_ROOT → rule skipped → FallThrough.
		r, err := e.Check("ls $PERMCOP_PROJECT_ROOT", projectRoot)
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed {
			t.Error("expand_variables must not see synthetic PERMCOP_PROJECT_ROOT; expected FallThrough")
		}
		if !r.FallThrough {
			t.Errorf("expected FallThrough, got Allowed=%v Reason=%q", r.Allowed, r.Reason)
		}
	})

	t.Run("ExplicitValueInExpandEnv", func(t *testing.T) {
		t.Parallel()
		// Resolve symlinks so the expanded path matches what the filesystem sees.
		realRoot, err := filepath.EvalSymlinks(projectRoot)
		if err != nil {
			t.Fatal(err)
		}
		// Env explicitly contains PERMCOP_PROJECT_ROOT; expand_variables should resolve it.
		env := map[string]string{"PERMCOP_PROJECT_ROOT": realRoot}
		e, err := NewWithEnv(cfg, logger, env, projectRoot)
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.Check("ls $PERMCOP_PROJECT_ROOT", projectRoot)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Allowed {
			t.Errorf("expand_variables with explicit PERMCOP_PROJECT_ROOT should resolve; FallThrough=%v Reason=%q", r.FallThrough, r.Reason)
		}
	})
}
