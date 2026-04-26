package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// testBinary holds the path to the permcop binary built once for all e2e tests.
var (
	testBinaryPath string
	testBinaryOnce sync.Once
	testBinaryErr  error
)

// TestMain builds the permcop binary once before running all tests in this package.
func TestMain(m *testing.M) {
	testBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "permcop-e2e-*")
		if err != nil {
			testBinaryErr = fmt.Errorf("create temp dir for binary: %w", err)
			return
		}
		binPath := filepath.Join(dir, "permcop")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			_ = os.RemoveAll(dir)
			testBinaryErr = fmt.Errorf("build permcop binary: %w", err)
			return
		}
		testBinaryPath = binPath
	})
	if testBinaryErr != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot build test binary: %v\n", testBinaryErr)
		os.Exit(1)
	}
	code := m.Run()
	// Clean up binary dir on exit.
	if testBinaryPath != "" {
		_ = os.RemoveAll(filepath.Dir(testBinaryPath))
	}
	os.Exit(code)
}

// writePayload returns a PreToolUse JSON payload for a Write tool invocation.
func writePayload(cwd, filePath string) string {
	toolInput, _ := json.Marshal(map[string]string{"file_path": filePath})
	envelope, _ := json.Marshal(map[string]interface{}{
		"session_id": "e2e-test",
		"tool_name":  "Write",
		"tool_input": json.RawMessage(toolInput),
		"cwd":        cwd,
	})
	return string(envelope)
}

// hookDecision extracts the permissionDecision field from the binary's JSON stdout.
func hookDecision(output []byte) string {
	var out struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(output, &out); err != nil {
		return ""
	}
	return out.HookSpecificOutput.PermissionDecision
}

// runPermcop executes the permcop binary in check mode with the given stdin payload.
// projectDir is used as the subprocess working directory (for config lookup).
// fakeHome overrides HOME to prevent loading the user's real global config.
func runPermcop(t *testing.T, projectDir, fakeHome, payload string) []byte {
	t.Helper()
	cmd := exec.Command(testBinaryPath, "check")
	cmd.Stdin = strings.NewReader(payload)
	cmd.Dir = projectDir
	// Inherit the parent environment but override HOME so global config is isolated.
	env := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "HOME=") {
			env = append(env, e)
		}
	}
	env = append(env, "HOME="+fakeHome)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		// exit code is always 0; a non-zero exit is a real error
		t.Fatalf("permcop check exited with error: %v\noutput: %s", err, out)
	}
	return out
}

// projectConfig returns TOML config content with path_scope and allow_write using
// ${PERMCOP_PROJECT_ROOT} and audit log directed to auditLogPath.
func projectConfig(auditLogPath string) string {
	return fmt.Sprintf(`[defaults]
log_file = %q
log_format = "json"

[[rules]]
name = "project-write"
path_scope = ["${PERMCOP_PROJECT_ROOT}"]
allow_write = ["${PERMCOP_PROJECT_ROOT}/**"]
`, auditLogPath)
}

// TestPermcopProjectRootE2E exercises the full PERMCOP_PROJECT_ROOT flow via
// subprocess invocation of the real permcop binary.
func TestPermcopProjectRootE2E(t *testing.T) {
	t.Run("write_inside_project_allowed", func(t *testing.T) {
		t.Parallel()

		projRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(projRoot, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(projRoot, "child")
		if err := os.Mkdir(child, 0755); err != nil {
			t.Fatal(err)
		}
		realProjRoot, err := filepath.EvalSymlinks(projRoot)
		if err != nil {
			t.Fatal(err)
		}
		fakeHome := t.TempDir()
		// Audit log must be inside HOME (enforced by config validator).
		auditLog := filepath.Join(fakeHome, "audit.log")

		if err := os.WriteFile(
			filepath.Join(projRoot, ".permcop.toml"),
			[]byte(projectConfig(auditLog)),
			0644,
		); err != nil {
			t.Fatal(err)
		}

		// Write to a path inside the project tree.
		targetFile := filepath.Join(realProjRoot, "newfile.txt")
		out := runPermcop(t, projRoot, fakeHome, writePayload(child, targetFile))

		if got := hookDecision(out); got != "allow" {
			t.Errorf("expected decision=allow, got %q\noutput: %s", got, out)
		}
	})

	t.Run("write_outside_project_denied", func(t *testing.T) {
		t.Parallel()

		projRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(projRoot, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(projRoot, "child")
		if err := os.Mkdir(child, 0755); err != nil {
			t.Fatal(err)
		}
		outsideDir := t.TempDir()
		fakeHome := t.TempDir()
		// Audit log must be inside HOME (enforced by config validator).
		auditLog := filepath.Join(fakeHome, "audit.log")

		if err := os.WriteFile(
			filepath.Join(projRoot, ".permcop.toml"),
			[]byte(projectConfig(auditLog)),
			0644,
		); err != nil {
			t.Fatal(err)
		}

		// Write to a path outside the project tree.
		targetFile := filepath.Join(outsideDir, "outsidefile.txt")
		out := runPermcop(t, projRoot, fakeHome, writePayload(child, targetFile))

		// allow_write = ["${PERMCOP_PROJECT_ROOT}/**"] doesn't cover the outside path;
		// no rule covers the unit → fall-through (empty output, not an explicit allow).
		if got := hookDecision(out); got == "allow" {
			t.Errorf("write outside project root must not be allowed; got decision=%q\noutput: %s", got, out)
		}
	})

	t.Run("no_git_ancestor_denied_with_diagnostic", func(t *testing.T) {
		t.Parallel()

		// projRoot has .git and the config file (binary process CWD).
		projRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(projRoot, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		// noGitDir has no .git ancestor — PERMCOP_PROJECT_ROOT cannot resolve from it.
		noGitDir := t.TempDir()
		fakeHome := t.TempDir()
		// Audit log must be inside HOME (enforced by config validator).
		auditLog := filepath.Join(fakeHome, "audit.log")

		if err := os.WriteFile(
			filepath.Join(projRoot, ".permcop.toml"),
			[]byte(projectConfig(auditLog)),
			0644,
		); err != nil {
			t.Fatal(err)
		}

		targetFile := filepath.Join(noGitDir, "file.txt")
		out := runPermcop(t, projRoot, fakeHome, writePayload(noGitDir, targetFile))

		// PERMCOP_PROJECT_ROOT unresolved → allow_write pattern compiles to nil (never matches)
		// → no rule covers the unit → fall-through (empty output, not an explicit allow).
		if got := hookDecision(out); got == "allow" {
			t.Errorf("write with unresolved PERMCOP_PROJECT_ROOT must not be allowed; got decision=%q\noutput: %s", got, out)
		}

		// Verify the audit log contains the PERMCOP_PROJECT_ROOT unresolved diagnostic.
		logData, err := os.ReadFile(auditLog)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		const wantDiag = "PERMCOP_PROJECT_ROOT"
		if !strings.Contains(string(logData), wantDiag) {
			t.Errorf("audit log does not contain %q\nlog contents:\n%s", wantDiag, logData)
		}
		const wantRule = "project-write"
		if !strings.Contains(string(logData), wantRule) {
			t.Errorf("audit log does not name rule %q in diagnostic\nlog contents:\n%s", wantRule, logData)
		}
	})
}
