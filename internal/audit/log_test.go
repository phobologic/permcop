package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phobologic/permcop/internal/parser"
)

func TestLoggerMultipleWrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger := New(path, "text", 0, 0)
	t.Cleanup(func() { _ = logger.Close() })

	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := logger.Log(Entry{
		Timestamp:       ts,
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	}); err != nil {
		t.Fatalf("first Log: %v", err)
	}

	if err := logger.Log(Entry{
		Timestamp:       ts,
		Decision:        DecisionDeny,
		Reason:          "no matching rule",
		OriginalCommand: "rm -rf /",
	}); err != nil {
		t.Fatalf("second Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "ALLOW") {
		t.Error("expected ALLOW entry in log")
	}
	if !strings.Contains(content, "DENY") {
		t.Error("expected DENY entry in log")
	}
	if !strings.Contains(content, "git status") {
		t.Error("expected first command in log")
	}
	if !strings.Contains(content, "rm -rf /") {
		t.Error("expected second command in log")
	}
}

func TestTimestampIsRFC3339(t *testing.T) {
	t.Parallel()

	line := textLine(Entry{
		Timestamp:       time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	})

	parts := strings.SplitN(line, " ", 2)
	ts := parts[0]
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", ts, err)
	}
}

func TestPassEntryShowsPerUnitDetail(t *testing.T) {
	t.Parallel()

	units := []parser.CheckableUnit{
		{Value: "git add ."},
		{Value: "cat foo"},
	}
	matches := []RuleMatch{
		{Rule: "git", Pattern: "git add *", Unit: "git add .", Action: "allow"},
		{Rule: "", Pattern: "", Unit: "cat foo", Action: ""},
	}

	line := textLine(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionPassThrough,
		Reason:          "no matching rule; deferred to Claude Code",
		OriginalCommand: "git add . && cat foo",
		Units:           units,
		RuleMatches:     matches,
	})

	if !strings.Contains(line, "pass   [cat foo]  (no rule") {
		t.Errorf("PASS entry missing pass label for uncovered unit; got:\n%s", line)
	}
	if strings.Contains(line, "(default deny)") {
		t.Errorf("PASS entry should not contain '(default deny)'; got:\n%s", line)
	}
}

func TestDenyEntryDefaultDenyLabel(t *testing.T) {
	t.Parallel()

	matches := []RuleMatch{
		{Rule: "", Pattern: "", Unit: "rm -rf /", Action: ""},
	}

	line := textLine(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionDeny,
		Reason:          "no matching rule",
		OriginalCommand: "rm -rf /",
		RuleMatches:     matches,
	})

	if !strings.Contains(line, "(default deny)") {
		t.Errorf("DENY entry missing '(default deny)'; got:\n%s", line)
	}
	if strings.Contains(line, "(no rule") {
		t.Errorf("DENY entry should not contain '(no rule'; got:\n%s", line)
	}
}

func TestLoggerRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// maxSizeMB=0 triggers rotation after 0 bytes — effectively on every write
	// after the first — but that's awkward to test. Instead write a tiny file,
	// then create a logger with maxBytes set low via the internal field directly.
	// We test via the exported New() by writing enough to cross the threshold.
	//
	// Use maxSizeMB=1, maxFiles=2 and pre-fill the file to just under 1 MB so
	// a single additional write pushes it over.
	logger := New(path, "text", 1, 2)
	t.Cleanup(func() { _ = logger.Close() })

	// Pre-fill with ~1 MB of data by writing directly to the file.
	fill := strings.Repeat("x", 1024*1024)
	if err := os.WriteFile(path, []byte(fill), 0600); err != nil {
		t.Fatalf("pre-fill: %v", err)
	}
	// Open the logger to the existing file (lazy open happens on first Log).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	logger.file = f

	// This write should trigger rotation because size >= 1 MB threshold.
	if err := logger.Log(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	}); err != nil {
		t.Fatalf("Log after pre-fill: %v", err)
	}

	// audit.log.1 should now exist (the rotated copy).
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected %s.1 after rotation: %v", path, err)
	}

	// audit.log should be a fresh (small) file.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("current log missing after rotation: %v", err)
	}
	if info.Size() >= 1024*1024 {
		t.Errorf("current log is %d bytes; expected fresh small file", info.Size())
	}
}

func TestLoggerRotationPrunesOldest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Pre-create rotated files .1 and .2 (maxFiles=2 means .3 must not exist).
	for i := 1; i <= 2; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte("old"), 0600); err != nil {
			t.Fatalf("create rotated file: %v", err)
		}
	}

	logger := New(path, "text", 1, 2)
	t.Cleanup(func() { _ = logger.Close() })

	fill := strings.Repeat("x", 1024*1024)
	if err := os.WriteFile(path, []byte(fill), 0600); err != nil {
		t.Fatalf("pre-fill: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	logger.file = f

	if err := logger.Log(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// .3 must not exist (pruned).
	if _, err := os.Stat(fmt.Sprintf("%s.3", path)); err == nil {
		t.Errorf("expected %s.3 to be pruned but it exists", path)
	}
	// .1 and .2 must exist.
	for i := 1; i <= 2; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err != nil {
			t.Errorf("expected %s.%d to exist: %v", path, i, err)
		}
	}
}

func TestTextLineCWD(t *testing.T) {
	t.Parallel()

	line := textLine(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionPassThrough,
		Reason:          "no matching rule; deferred to Claude Code",
		OriginalCommand: "git cherry-pick abc1234",
		CWD:             "/Users/mike/git/pbp/.worktrees/implementer-1",
	})

	if !strings.Contains(line, "cwd:") {
		t.Errorf("expected cwd: line in output; got:\n%s", line)
	}
	if !strings.Contains(line, "/Users/mike/git/pbp/.worktrees/implementer-1") {
		t.Errorf("expected cwd path in output; got:\n%s", line)
	}
}

func TestTextLineNoCWDWhenEmpty(t *testing.T) {
	t.Parallel()

	line := textLine(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	})

	if strings.Contains(line, "cwd:") {
		t.Errorf("expected no cwd: line when CWD is empty; got:\n%s", line)
	}
}

func TestLoggerCloseIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logger := New(filepath.Join(dir, "audit.log"), "text", 0, 0)

	// Close on a logger that never wrote — should be a no-op.
	if err := logger.Close(); err != nil {
		t.Fatalf("Close on unused logger: %v", err)
	}
}

func TestDiagnosticsTextRendering(t *testing.T) {
	t.Parallel()

	t.Run("SingleDiagRendered", func(t *testing.T) {
		t.Parallel()
		line := textLine(Entry{
			Timestamp:       time.Now(),
			Decision:        DecisionDeny,
			OriginalCommand: "ls /repo",
			Diagnostics:     []string{`rule "my-rule": ${PERMCOP_PROJECT_ROOT} unresolved (no .git ancestor found above request CWD); rule effectively dropped.`},
		})
		if !strings.Contains(line, "  diag: ") {
			t.Errorf("expected diag: line in text output; got:\n%s", line)
		}
		if !strings.Contains(line, "PERMCOP_PROJECT_ROOT") {
			t.Errorf("expected PERMCOP_PROJECT_ROOT in diag line; got:\n%s", line)
		}
	})

	t.Run("MultipleDiagsEachOnOwnLine", func(t *testing.T) {
		t.Parallel()
		line := textLine(Entry{
			Timestamp:       time.Now(),
			Decision:        DecisionDeny,
			OriginalCommand: "ls /repo",
			Diagnostics:     []string{"diag one", "diag two"},
		})
		if !strings.Contains(line, "  diag: diag one") {
			t.Errorf("expected first diag line; got:\n%s", line)
		}
		if !strings.Contains(line, "  diag: diag two") {
			t.Errorf("expected second diag line; got:\n%s", line)
		}
	})

	t.Run("NoDiagsNoLine", func(t *testing.T) {
		t.Parallel()
		line := textLine(Entry{
			Timestamp:       time.Now(),
			Decision:        DecisionAllow,
			OriginalCommand: "git status",
		})
		if strings.Contains(line, "diag:") {
			t.Errorf("expected no diag: line when Diagnostics is empty; got:\n%s", line)
		}
	})
}

func TestDiagnosticsJSONRendering(t *testing.T) {
	t.Parallel()

	t.Run("DiagsPresentInJSON", func(t *testing.T) {
		t.Parallel()
		line, err := jsonLine(Entry{
			Timestamp:       time.Now(),
			Decision:        DecisionDeny,
			OriginalCommand: "ls /repo",
			Diagnostics:     []string{"diag message"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(line, `"diagnostics"`) {
			t.Errorf("expected diagnostics key in JSON; got: %s", line)
		}
		if !strings.Contains(line, "diag message") {
			t.Errorf("expected diag message value in JSON; got: %s", line)
		}
	})

	t.Run("DiagOmittedWhenEmpty", func(t *testing.T) {
		t.Parallel()
		line, err := jsonLine(Entry{
			Timestamp:       time.Now(),
			Decision:        DecisionAllow,
			OriginalCommand: "git status",
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, `"diagnostics"`) {
			t.Errorf("expected diagnostics key absent from JSON when empty; got: %s", line)
		}
	})
}

func TestDiagnosticsLoggedViaLogger(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	logger := New(path, "text", 0, 0)
	t.Cleanup(func() { _ = logger.Close() })

	if err := logger.Log(Entry{
		Timestamp:       time.Now(),
		Decision:        DecisionDeny,
		OriginalCommand: "ls /repo",
		Diagnostics:     []string{"rule unresolved warning"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "rule unresolved warning") {
		t.Errorf("expected diagnostic in log file; got:\n%s", string(data))
	}
}
