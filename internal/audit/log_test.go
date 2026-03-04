package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikecafarella/permcop/internal/parser"
)

func TestLoggerMultipleWrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger := New(path, "text")
	defer logger.Close()

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

func TestTimestampUsesLocalOffset(t *testing.T) {
	t.Parallel()

	line := textLine(Entry{
		Timestamp:       time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Decision:        DecisionAllow,
		OriginalCommand: "git status",
	})

	// The formatted timestamp must not end with bare "Z" — it should carry an offset.
	// In UTC the offset is "+00:00", not "Z", when using .Local() on a UTC-zone time.
	// We just check that the ISO-8601 offset separator appears and "Z" is absent as suffix.
	parts := strings.SplitN(line, " ", 2)
	ts := parts[0]
	if strings.HasSuffix(ts, "Z") {
		t.Errorf("timestamp %q ends with Z; want local offset (e.g. +00:00 or -05:00)", ts)
	}
	if !strings.ContainsAny(ts[len("2006-01-02T15:04:05"):], "+-") {
		t.Errorf("timestamp %q missing UTC offset in local format", ts)
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

func TestLoggerCloseIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logger := New(filepath.Join(dir, "audit.log"), "text")

	// Close on a logger that never wrote — should be a no-op.
	if err := logger.Close(); err != nil {
		t.Fatalf("Close on unused logger: %v", err)
	}
}
