package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/mikecafarella/permcop/internal/config"
)

func TestParseSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		n     int
		want  []int
	}{
		{"", 5, nil},
		{"none", 5, nil},
		{"NONE", 5, nil},
		{"all", 3, []int{1, 2, 3}},
		{"ALL", 3, []int{1, 2, 3}},
		{"1", 5, []int{1}},
		{"2,3", 5, []int{2, 3}},
		{"1-3", 5, []int{1, 2, 3}},
		{"1-3, 5", 5, []int{1, 2, 3, 5}},
		{"3, 1", 5, []int{1, 3}},           // sorted
		{"1, 1, 2", 5, []int{1, 2}},        // dedup
		{"0", 5, nil},                       // out of range
		{"6", 5, nil},                       // out of range
		{"1-10", 3, []int{1, 2, 3}},        // clamped to n
	}
	for _, tc := range tests {
		got := parseSelection(tc.input, tc.n)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseSelection(%q, %d) = %v, want %v", tc.input, tc.n, got, tc.want)
		}
	}
}

func TestSuggestRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		command     string
		wantName    string
		wantType    config.PatternType
		wantPattern string
	}{
		{
			command:     "git status",
			wantName:    "Allow git status",
			wantType:    config.PatternExact,
			wantPattern: "git status",
		},
		{
			command:     "git push origin main",
			wantName:    "Allow git push",
			wantType:    config.PatternGlob,
			wantPattern: "git push *",
		},
		{
			command:     "make",
			wantName:    "Allow make",
			wantType:    config.PatternExact,
			wantPattern: "make",
		},
		{
			command:     "brew update && brew upgrade",
			wantName:    "Allow brew update",
			wantType:    config.PatternGlob,
			wantPattern: "brew update *",
		},
	}
	for _, tc := range tests {
		r := suggestRule(tc.command)
		if r.Name != tc.wantName {
			t.Errorf("suggestRule(%q).Name = %q, want %q", tc.command, r.Name, tc.wantName)
		}
		if len(r.Allow) != 1 {
			t.Fatalf("suggestRule(%q): expected 1 allow pattern, got %d", tc.command, len(r.Allow))
		}
		if r.Allow[0].Type != tc.wantType {
			t.Errorf("suggestRule(%q).Allow[0].Type = %q, want %q", tc.command, r.Allow[0].Type, tc.wantType)
		}
		if r.Allow[0].Pattern != tc.wantPattern {
			t.Errorf("suggestRule(%q).Allow[0].Pattern = %q, want %q", tc.command, r.Allow[0].Pattern, tc.wantPattern)
		}
	}
}

func TestStripSuggestHeader(t *testing.T) {
	t.Parallel()

	input := "# Suggested rule for: git push\n# Edit as needed.\n\n[[rules]]\nname = \"foo\"\n"
	got := stripSuggestHeader(input)
	if got != "[[rules]]\nname = \"foo\"\n" {
		t.Errorf("stripSuggestHeader returned %q", got)
	}

	// Content with no header is returned as-is (minus leading blank lines).
	noHeader := "[[rules]]\nname = \"bar\"\n"
	if got2 := stripSuggestHeader(noHeader); got2 != noHeader {
		t.Errorf("stripSuggestHeader(no header) = %q, want %q", got2, noHeader)
	}

	// All comments → empty string.
	if got3 := stripSuggestHeader("# only comments\n"); got3 != "" {
		t.Errorf("stripSuggestHeader(only comments) = %q, want empty", got3)
	}
}

func TestTimeAgo(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		t    time.Time
		want string
	}{
		{now.Add(-30 * time.Second), "just now"},
		{now.Add(-1 * time.Minute), "1 minute ago"},
		{now.Add(-5 * time.Minute), "5 minutes ago"},
		{now.Add(-1 * time.Hour), "1 hour ago"},
		{now.Add(-3 * time.Hour), "3 hours ago"},
		{now.Add(-30 * time.Hour), "yesterday"},
		{now.Add(-72 * time.Hour), "3 days ago"},
	}
	for _, tc := range tests {
		got := timeAgo(tc.t)
		if got != tc.want {
			t.Errorf("timeAgo(-%v) = %q, want %q", time.Since(tc.t).Round(time.Second), got, tc.want)
		}
	}
}
