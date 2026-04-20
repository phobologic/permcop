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
				{Kind: UnitCommand, Value: "git status", Args: []string{"git", "status"}},
			},
		},
		{
			name:    "AND chain",
			command: "git status && git log",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git status", Args: []string{"git", "status"}},
				{Kind: UnitCommand, Value: "git log", Args: []string{"git", "log"}},
			},
		},
		{
			name:    "OR chain",
			command: "git fetch || echo failed",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git fetch", Args: []string{"git", "fetch"}},
				{Kind: UnitCommand, Value: "echo failed", Args: []string{"echo", "failed"}},
			},
		},
		{
			name:    "semicolon chain",
			command: "echo a; echo b",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo a", Args: []string{"echo", "a"}},
				{Kind: UnitCommand, Value: "echo b", Args: []string{"echo", "b"}},
			},
		},
		{
			name:    "pipe",
			command: "git log --oneline | head -5",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git log --oneline", Args: []string{"git", "log", "--oneline"}},
				{Kind: UnitCommand, Value: "head -5", Args: []string{"head", "-5"}},
			},
		},
		{
			name:    "output redirect",
			command: "echo hello > /tmp/out.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello", Args: []string{"echo", "hello"}},
				{Kind: UnitWriteFile, Value: "/tmp/out.txt"},
			},
		},
		{
			name:    "append redirect",
			command: "echo hello >> /tmp/out.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello", Args: []string{"echo", "hello"}},
				{Kind: UnitWriteFile, Value: "/tmp/out.txt"},
			},
		},
		{
			name:    "input redirect",
			command: "cat < /tmp/input.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "cat", Args: []string{"cat"}},
				{Kind: UnitReadFile, Value: "/tmp/input.txt"},
			},
		},
		{
			name:    "variable in argument",
			command: "echo $HOME",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo $HOME", Args: []string{"echo", "$HOME"}, HasVariable: true},
			},
		},
		{
			name:    "subshell command substitution",
			command: "echo $(whoami)",
			// The outer command has a subshell marker, AND the subshell's command is
			// extracted as its own unit so it can be independently permission-checked.
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo $(...)", Args: []string{"echo", "$(...)"}, HasSubshell: true},
				{Kind: UnitCommand, Value: "whoami", Args: []string{"whoami"}},
			},
		},
		{
			name:    "quoted argument preserved",
			command: `git commit -m "fix bug"`,
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git commit -m fix bug", Args: []string{"git", "commit", "-m", "fix bug"}},
			},
		},
		{
			name:    "single quoted argument",
			command: "echo 'hello world'",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hello world", Args: []string{"echo", "hello world"}},
			},
		},
		{
			name:    "relative redirect resolved to cwd",
			command: "echo hi > output.txt",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hi", Args: []string{"echo", "hi"}},
				{Kind: UnitWriteFile, Value: "/tmp/testcwd/output.txt"},
			},
		},
		{
			name:    "subshell inside double-quoted argument",
			command: `git commit -m "$(cat file)"`,
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git commit -m $(...)", Args: []string{"git", "commit", "-m", "$(...)"}, HasSubshell: true},
				{Kind: UnitCommand, Value: "cat file", Args: []string{"cat", "file"}},
			},
		},
		{
			name:    "subshell with heredoc inside double-quoted argument",
			command: "git commit -m \"$(cat <<'EOF'\nsome message\nEOF\n)\"",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "git commit -m $(...)", Args: []string{"git", "commit", "-m", "$(...)"}, HasSubshell: true},
				{Kind: UnitCommand, Value: "cat", Args: []string{"cat"}},
			},
		},
		{
			name:    "fd redirect 2>&1 no extra unit",
			command: "make install 2>&1",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "make install", Args: []string{"make", "install"}},
			},
		},
		{
			name:    "fd redirect 1>&2 no extra unit",
			command: "echo hi 1>&2",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hi", Args: []string{"echo", "hi"}},
			},
		},
		{
			name:    "fd redirect <&0 no extra unit",
			command: "cat <&0",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "cat", Args: []string{"cat"}},
			},
		},
		{
			name:    "real file redirect with fd redirect",
			command: "cmd >out.txt 2>&1",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "cmd", Args: []string{"cmd"}},
				{Kind: UnitWriteFile, Value: "/tmp/testcwd/out.txt"},
			},
		},
		{
			name:    "parse error",
			command: "echo $((",
			wantErr: true,
		},
		{
			name:    "bare variable assignment with command substitution",
			command: "FOO=$(whoami)",
			// The outer assignment emits no command unit (no args), but the
			// command substitution value is extracted and checked independently.
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "whoami", Args: []string{"whoami"}},
			},
		},
		{
			name:    "variable assignment followed by command",
			command: `T7=$(tk create "foo" -t task) ; echo $T7`,
			// The tk create inside $(...) must be extracted as a unit; echo $T7 is
			// the second statement.
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "tk create foo -t task", Args: []string{"tk", "create", "foo", "-t", "task"}},
				{Kind: UnitCommand, Value: "echo $T7", Args: []string{"echo", "$T7"}, HasVariable: true},
			},
		},
		{
			name:    "assignment with literal value and command",
			command: "FOO=bar echo hi",
			// No subshell in the assignment value, so only the command unit is emitted.
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "echo hi", Args: []string{"echo", "hi"}},
			},
		},
		{
			name:    "args populated for sed with flag and path",
			command: "sed -i /proj/file",
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "sed -i /proj/file", Args: []string{"sed", "-i", "/proj/file"}},
			},
		},
		{
			name:    "args with double-quoted space-containing argument",
			command: `cp "my file.txt" /tmp/`,
			wantUnits: []CheckableUnit{
				{Kind: UnitCommand, Value: "cp my file.txt /tmp/", Args: []string{"cp", "my file.txt", "/tmp/"}},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cwd := "/tmp/testcwd"

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
				if len(got.Args) != len(want.Args) {
					t.Errorf("unit[%d] Args: got %v, want %v", i, got.Args, want.Args)
				} else {
					for j, arg := range want.Args {
						if got.Args[j] != arg {
							t.Errorf("unit[%d] Args[%d]: got %q, want %q", i, j, got.Args[j], arg)
						}
					}
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

func TestParse_DepthExceededFallback(t *testing.T) {
	t.Parallel()

	// With maxDepth=2, the innermost subshell of echo $(echo $(echo $(echo x)))
	// exceeds the depth limit and must emit a fallback UnitCommand with non-nil Args.
	result := Parse("echo $(echo $(echo $(echo x)))", "/tmp", 2)
	if result.ParseError != nil {
		t.Fatalf("unexpected parse error: %v", result.ParseError)
	}

	var fallback *CheckableUnit
	for i := range result.Units {
		u := &result.Units[i]
		if u.Kind == UnitCommand && u.Value == "$(...)" && u.HasVariable {
			fallback = u
			break
		}
	}
	if fallback == nil {
		t.Fatalf("no depth-exceeded fallback unit found; units: %+v", result.Units)
	}
	if len(fallback.Args) != 1 || fallback.Args[0] != "$(...)" {
		t.Errorf("fallback Args: got %v, want [\"$(...)\"]", fallback.Args)
	}
}
