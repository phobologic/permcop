package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikecafarella/permcop/internal/parser"
)

// writeEntries logs entries to a new logger at path, then closes it.
func writeEntries(t *testing.T, path, format string, entries []Entry) {
	t.Helper()
	logger := New(path, format, 0, 0)
	for _, e := range entries {
		if err := logger.Log(e); err != nil {
			t.Fatalf("log entry: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}
}

func makePassEntry(cmd string, ts time.Time) Entry {
	return Entry{
		Timestamp:       ts,
		Decision:        DecisionPassThrough,
		Reason:          "no matching rule; deferred to Claude Code",
		OriginalCommand: cmd,
		Units:           []parser.CheckableUnit{{Value: cmd}},
		RuleMatches: []RuleMatch{
			{Rule: "", Pattern: "", Unit: cmd, Action: ""},
		},
	}
}

func TestReadPASSEntries_JSONFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	now := time.Now().Truncate(time.Second)
	entries := []Entry{
		makePassEntry("git push origin main", now.Add(-2*time.Hour)),
		{Timestamp: now.Add(-1 * time.Hour), Decision: DecisionAllow, OriginalCommand: "git status"},
		makePassEntry("brew update", now.Add(-30*time.Minute)),
		makePassEntry("git push origin main", now), // duplicate command
	}
	writeEntries(t, path, "json", entries)

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("ReadPASSEntries: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 PASS entries, got %d", len(got))
	}

	// Most recent first.
	if got[0].OriginalCommand != "git push origin main" {
		t.Errorf("entry[0]: want 'git push origin main', got %q", got[0].OriginalCommand)
	}
	if got[1].OriginalCommand != "brew update" {
		t.Errorf("entry[1]: want 'brew update', got %q", got[1].OriginalCommand)
	}
	if got[2].OriginalCommand != "git push origin main" {
		t.Errorf("entry[2]: want 'git push origin main', got %q", got[2].OriginalCommand)
	}
}

func TestReadPASSEntries_TextFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	now := time.Now().Truncate(time.Second)
	entries := []Entry{
		makePassEntry("git push origin main", now.Add(-2*time.Hour)),
		{Timestamp: now.Add(-1 * time.Hour), Decision: DecisionDeny, Reason: "blocked", OriginalCommand: "rm -rf /"},
		makePassEntry("brew update", now),
	}
	writeEntries(t, path, "text", entries)

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("ReadPASSEntries: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 PASS entries, got %d", len(got))
	}
	if got[0].OriginalCommand != "brew update" {
		t.Errorf("entry[0]: want 'brew update', got %q", got[0].OriginalCommand)
	}
	if got[1].OriginalCommand != "git push origin main" {
		t.Errorf("entry[1]: want 'git push origin main', got %q", got[1].OriginalCommand)
	}
}

func TestReadPASSEntries_Limit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	now := time.Now().Truncate(time.Second)
	entries := []Entry{
		makePassEntry("cmd1", now.Add(-3*time.Hour)),
		makePassEntry("cmd2", now.Add(-2*time.Hour)),
		makePassEntry("cmd3", now.Add(-1*time.Hour)),
		makePassEntry("cmd4", now),
	}
	writeEntries(t, path, "json", entries)

	got, err := ReadPASSEntries(path, 2)
	if err != nil {
		t.Fatalf("ReadPASSEntries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].OriginalCommand != "cmd4" {
		t.Errorf("entry[0]: want 'cmd4', got %q", got[0].OriginalCommand)
	}
	if got[1].OriginalCommand != "cmd3" {
		t.Errorf("entry[1]: want 'cmd3', got %q", got[1].OriginalCommand)
	}
}

func TestReadPASSEntries_RotatedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	now := time.Now().Truncate(time.Second)

	// Write old entry to rotated file .1
	old := []Entry{makePassEntry("old-cmd", now.Add(-24*time.Hour))}
	writeEntries(t, path+".1", "json", old)

	// Write new entry to primary file
	new := []Entry{makePassEntry("new-cmd", now)}
	writeEntries(t, path, "json", new)

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("ReadPASSEntries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (primary + rotated), got %d", len(got))
	}
	// Most recent first.
	if got[0].OriginalCommand != "new-cmd" {
		t.Errorf("entry[0]: want 'new-cmd', got %q", got[0].OriginalCommand)
	}
	if got[1].OriginalCommand != "old-cmd" {
		t.Errorf("entry[1]: want 'old-cmd', got %q", got[1].OriginalCommand)
	}
}

func TestReadPASSEntries_MissingFile(t *testing.T) {
	t.Parallel()

	got, err := ReadPASSEntries("/nonexistent/path/audit.log", 10)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 entries for missing file, got %d", len(got))
	}
}

func TestReadPASSEntries_EmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 entries, got %d", len(got))
	}
}

func TestExtractBracket(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		wantVal  string
		wantRest string
	}{
		{"[hello] rest", "hello", " rest"},
		{"[git push] extra", "git push", " extra"},
		{"no bracket", "", "no bracket"},
		{"[unclosed", "", "[unclosed"},
		{"  [padded]", "padded", ""},
	}
	for _, tc := range tests {
		v, rest := extractBracket(tc.input)
		if v != tc.wantVal || rest != tc.wantRest {
			t.Errorf("extractBracket(%q) = (%q, %q), want (%q, %q)",
				tc.input, v, rest, tc.wantVal, tc.wantRest)
		}
	}
}

func TestIsTextHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		want bool
	}{
		{"2026-03-04T12:00:00-08:00 PASS", true},
		{"2026-03-04T12:00:00+00:00 ALLOW", true},
		{"  original: git status", false},
		{"    pass   [git status]", false},
		{"", false},
		{"not-a-timestamp PASS", false},
	}
	for _, tc := range tests {
		got := isTextHeader(tc.line)
		if got != tc.want {
			t.Errorf("isTextHeader(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestReadPASSEntries_TextOriginalCommand(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	ts := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	entries := []Entry{makePassEntry("git push origin main", ts)}
	writeEntries(t, path, "text", entries)

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("ReadPASSEntries: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].OriginalCommand != "git push origin main" {
		t.Errorf("OriginalCommand: got %q, want %q", got[0].OriginalCommand, "git push origin main")
	}
}

func TestReadPASSEntries_RotatedFilesMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Only primary file exists; .1, .2, etc. do not.
	now := time.Now().Truncate(time.Second)
	writeEntries(t, path, "json", []Entry{makePassEntry("cmd1", now)})

	got, err := ReadPASSEntries(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
}
