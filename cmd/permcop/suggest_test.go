package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/mikecafarella/permcop/internal/audit"
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
		{"3, 1", 5, []int{1, 3}},    // sorted
		{"1, 1, 2", 5, []int{1, 2}}, // dedup
		{"0", 5, nil},               // out of range
		{"6", 5, nil},               // out of range
		{"1-10", 3, []int{1, 2, 3}}, // clamped to n
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

func TestPassUnitsFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		matches []audit.RuleMatch
		want    []string
	}{
		{
			name:    "empty matches",
			matches: nil,
			want:    nil,
		},
		{
			name: "single allow — no pass units",
			matches: []audit.RuleMatch{
				{Unit: "git status", Action: "allow", Rule: "git", Pattern: "git status"},
			},
			want: nil,
		},
		{
			name: "single pass unit (text format)",
			matches: []audit.RuleMatch{
				{Unit: "brew upgrade", Action: "pass"},
			},
			want: []string{"brew upgrade"},
		},
		{
			name: "single pass unit (JSON/engine format)",
			matches: []audit.RuleMatch{
				{Unit: "brew upgrade", Action: "deny", Rule: ""},
			},
			want: []string{"brew upgrade"},
		},
		{
			name: "single pass unit (legacy empty action)",
			matches: []audit.RuleMatch{
				{Unit: "brew upgrade", Action: "", Rule: ""},
			},
			want: []string{"brew upgrade"},
		},
		{
			name: "chain: one allow, one pass",
			matches: []audit.RuleMatch{
				{Unit: "brew update", Action: "allow", Rule: "brew", Pattern: "brew update"},
				{Unit: "brew upgrade", Action: "deny", Rule: ""},
			},
			want: []string{"brew upgrade"},
		},
		{
			name: "chain: both pass",
			matches: []audit.RuleMatch{
				{Unit: "brew update", Action: "deny", Rule: ""},
				{Unit: "brew upgrade", Action: "deny", Rule: ""},
			},
			want: []string{"brew update", "brew upgrade"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Entry{RuleMatches: tc.matches}
			got := passUnitsFrom(e)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("passUnitsFrom: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLabelForEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cmd       string
		passUnits []string
		want      string
	}{
		{
			name:      "no pass units — no annotation",
			cmd:       "git status",
			passUnits: nil,
			want:      "git status",
		},
		{
			name:      "single unit equals command — no annotation",
			cmd:       "git push origin main",
			passUnits: []string{"git push origin main"},
			want:      "git push origin main",
		},
		{
			name:      "single unit differs from command — annotate",
			cmd:       "brew update && brew upgrade",
			passUnits: []string{"brew upgrade"},
			want:      "brew update && brew upgrade  [→ brew upgrade]",
		},
		{
			name:      "two pass units — annotate both",
			cmd:       "brew update && brew upgrade",
			passUnits: []string{"brew update", "brew upgrade"},
			want:      "brew update && brew upgrade  [→ brew update, brew upgrade]",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := labelForEntry(tc.cmd, tc.passUnits)
			if got != tc.want {
				t.Errorf("labelForEntry(%q, %v) = %q, want %q", tc.cmd, tc.passUnits, got, tc.want)
			}
		})
	}
}

func TestSuggestRulesForUnits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		passUnits []string
		fallback  string
		wantNames []string
	}{
		{
			name:      "empty pass units — falls back to full command",
			passUnits: nil,
			fallback:  "brew update && brew upgrade",
			wantNames: []string{"Allow brew update"},
		},
		{
			name:      "single pass unit",
			passUnits: []string{"brew upgrade"},
			fallback:  "brew update && brew upgrade",
			wantNames: []string{"Allow brew upgrade"},
		},
		{
			name:      "two pass units — two rules",
			passUnits: []string{"brew update", "brew upgrade"},
			fallback:  "brew update && brew upgrade",
			wantNames: []string{"Allow brew update", "Allow brew upgrade"},
		},
		{
			name:      "single unit simple command",
			passUnits: []string{"git status"},
			fallback:  "git status",
			wantNames: []string{"Allow git status"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := suggestRulesForUnits(tc.passUnits, tc.fallback)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("suggestRulesForUnits: got %d rules, want %d", len(got), len(tc.wantNames))
			}
			for i, r := range got {
				if r.Name != tc.wantNames[i] {
					t.Errorf("rule[%d].Name = %q, want %q", i, r.Name, tc.wantNames[i])
				}
			}
		})
	}
}
