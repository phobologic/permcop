package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
	"github.com/phobologic/permcop/internal/rules"
)

// TestEngineUsesHookCwd asserts that rules.New, when given the hook payload's cwd
// as startCWD, resolves PERMCOP_PROJECT_ROOT to that directory — enabling
// path_scope = ["${PERMCOP_PROJECT_ROOT}"] to match writes under the hook root
// but not under a different process CWD.
func TestEngineUsesHookCwd(t *testing.T) {
	t.Parallel()

	// hookRoot: a directory with .git — resolveProjectRoot will find it.
	hookRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(hookRoot, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	realHookRoot, err := filepath.EvalSymlinks(hookRoot)
	if err != nil {
		t.Fatal(err)
	}

	// processCwd: a separate directory with no .git — resolveProjectRoot finds nothing.
	processCwd := t.TempDir()

	cfg := &config.Config{
		Defaults: config.Defaults{
			SubshellDepthLimit:    3,
			UnknownVariableAction: config.VariableActionDeny,
		},
		Rules: []config.Rule{{
			Name:      "project-write",
			PathScope: []string{"${PERMCOP_PROJECT_ROOT}"},
			Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "touch"}},
		}},
	}
	logger := audit.New(os.DevNull, "", 0, 0)

	targetFile := filepath.Join(realHookRoot, "newfile.txt")
	cmd := "touch " + targetFile

	t.Run("HookCwdUsed_AllowsWriteUnderHookRoot", func(t *testing.T) {
		t.Parallel()
		// startCWD = hookRoot (as if hook payload's cwd was used).
		engine, err := rules.New(cfg, logger, hookRoot)
		if err != nil {
			t.Fatal(err)
		}
		r, err := engine.Check(cmd, hookRoot)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Allowed {
			t.Errorf("write under hook root should be allowed; FallThrough=%v Reason=%q", r.FallThrough, r.Reason)
		}
	})

	t.Run("ProcessCwdUsed_DoesNotAllowWriteUnderHookRoot", func(t *testing.T) {
		t.Parallel()
		// startCWD = processCwd (no .git → PERMCOP_PROJECT_ROOT unresolved → scope blocks all).
		engine, err := rules.New(cfg, logger, processCwd)
		if err != nil {
			t.Fatal(err)
		}
		r, err := engine.Check(cmd, processCwd)
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed {
			t.Error("write under hook root should not be allowed when process CWD has no project root")
		}
	})
}
