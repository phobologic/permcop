package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLoggerCloseIdempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logger := New(filepath.Join(dir, "audit.log"), "text")

	// Close on a logger that never wrote — should be a no-op.
	if err := logger.Close(); err != nil {
		t.Fatalf("Close on unused logger: %v", err)
	}
}
