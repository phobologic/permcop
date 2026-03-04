package parser

import (
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		command   string
		wantUnits []CheckableUnit
		wantErr   bool
	}{
		{
			name:    "simple command",
			command: "git status",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git status"},
			},
		},
		{
			name:    "AND chain",
			command: "git status && git log",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git status"},
				{Kind: UnitCommand, Value: "git log"},
			},
		},
		{
			name:    "OR chain",
			command: "git fetch || echo failed",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git fetch"},
				{Kind: UnitCommand, Value: "echo failed"},
			},
		},
		{
			name:    "semicolon chain",
			command: "echo a; echo b",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo a"},
				{Kind: UnitCommand, Value: "echo b"},
			},
		},
		{
			name:    "pipe",
			command: "git log --oneline | head -5",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git log --oneline"},
				{Kind: UnitCommand, Value: "head -5"},
			},
		},
		{
			name:    "output redirect",
			command: "echo hello > /tmp/out.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello"},
				{Kind: UnitWriteFile, Value: "/tmp/out.txt"},
			},
		},
		{
			name:    "append redirect",
			command: "echo hello >> /tmp/out.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello"},
				{Kind: UnitWriteFile, Value: "/tmp/out.txt"},
			},
		},
		{
			name:    "input redirect",
			command: "cat < /tmp/input.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "cat"},
				{Kind: UnitReadFile, Value: "/tmp/input.txt"},
			},
		},
		{
			name:    "variable in argument",
			command: "echo $HOME",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo $HOME", HasVariable: true},
			},
		},
		{
			name:    "subshell command substitution",
			command: "echo $(whoami)",
			// The outer command has a subshell marker, AND the subshell's command is
			// extracted as its own unit so it can be independently permission-checked.
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo $(...)", HasSubshell: true},
				{Kind: UnitCommand, Value: "whoami"},
			},
		},
		{
			name:    "quoted argument preserved",
			command: `git commit -m "fix bug"`,
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git commit -m fix bug"},
			},
		},
		{
			name:    "single quoted argument",
			command: "echo 'hello world'",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello world"},
			},
		},
		{
			name:    "relative redirect resolved to cwd",
			command: "echo hi > output.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hi"},
				{Kind: UnitWriteFile, Value: "/tmp/testcwd/output.txt"},
			},
		},
		{
			name:    "parse error",
			command: "echo $((",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cwd := "/tmp/testcwd"
			if tc.name == "relative redirect resolved to cwd" {
				// Special cwd for this test
			}

			result := Parse(tc.command, cwd, 3)

			if tc.wantErr {
				if result.ParseError == nil {
					t.Errorf("expected parse error, got none; units: %v", result.Units)
				}
				return
			}

			if result.ParseError != nil {
				t.Fatalf("unexpected parse error: %v", result.ParseError)
			}

			if len(result.Units) != len(tc.wantUnits) {
				t.Fatalf("got %d units, want %d\ngot:  %+v\nwant: %+v",
					len(result.Units), len(tc.wantUnits), result.Units, tc.wantUnits)
			}

			for i, got := range result.Units {
				want := tc.wantUnits[i]
				if got.Kind != want.Kind {
					t.Errorf("unit[%d] kind: got %q, want %q", i, got.Kind, want.Kind)
				}
				if got.Value != want.Value {
					t.Errorf("unit[%d] value: got %q, want %q", i, got.Value, want.Value)
				}
				if got.HasVariable != want.HasVariable {
					t.Errorf("unit[%d] HasVariable: got %v, want %v", i, got.HasVariable, want.HasVariable)
				}
				if got.HasSubshell != want.HasSubshell {
					t.Errorf("unit[%d] HasSubshell: got %v, want %v", i, got.HasSubshell, want.HasSubshell)
				}
			}
		})
	}
}

func TestParse_VariableNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		command   string
		wantVars  []string // expected Variables on the first unit
		wantCount int      // expected number of units
	}{
		{
			name:      "single variable",
			command:   "mv $TARGET /tmp/out",
			wantVars:  []string{"TARGET"},
			wantCount: 1,
		},
		{
			name:      "braced variable",
			command:   "cp ${SRC} /dst",
			wantVars:  []string{"SRC"},
			wantCount: 1,
		},
		{
			name:      "multiple variables",
			command:   "cp $SRC $DST",
			wantVars:  []string{"SRC", "DST"},
			wantCount: 1,
		},
		{
			name:      "variable in double-quoted string",
			command:   `echo "hello $USER"`,
			wantVars:  []string{"USER"},
			wantCount: 1,
		},
		{
			name:      "no variables",
			command:   "git status",
			wantVars:  nil,
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := Parse(tc.command, "/tmp", 3)
			if result.ParseError != nil {
				t.Fatalf("unexpected parse error: %v", result.ParseError)
			}
			if len(result.Units) != tc.wantCount {
				t.Fatalf("got %d units, want %d", len(result.Units), tc.wantCount)
			}
			got := result.Units[0].Variables
			if len(got) != len(tc.wantVars) {
				t.Fatalf("Variables: got %v, want %v", got, tc.wantVars)
			}
			for i, name := range tc.wantVars {
				if got[i] != name {
					t.Errorf("Variables[%d]: got %q, want %q", i, got[i], name)
				}
			}
		})
	}
}
