package parser

import (
	"fmt"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// UnitKind distinguishes the type of a checkable unit.
type UnitKind string

const (
	UnitCommand   UnitKind = "command"
	UnitReadFile  UnitKind = "read"
	UnitWriteFile UnitKind = "write"
)

// CheckableUnit represents one atomic piece of a command chain that must be
// individually evaluated against the rule engine.
type CheckableUnit struct {
	Kind UnitKind
	// For UnitCommand: the full command string (e.g., "git push origin main")
	// For UnitReadFile/UnitWriteFile: the file path
	Value       string
	Args        []string // For UnitCommand: per-argument strings with quoting removed; nil for file units
	HasVariable bool     // true if any $VAR or ${VAR} was found in the value
	Variables   []string // names of variables found (without $), e.g. ["TARGET", "HOME"]
	HasSubshell bool     // true if any $(...) or backtick subshell was found
}

// ParseResult is the output of parsing a full command string.
type ParseResult struct {
	Units      []CheckableUnit
	ParseError error
}

// Parse parses a shell command string and returns all CheckableUnits.
// maxDepth limits recursive subshell expansion (prevents infinite loops on
// deeply nested $() constructs).
func Parse(command string, cwd string, maxDepth int) *ParseResult {
	r := strings.NewReader(command)
	f, err := syntax.NewParser().Parse(r, "")
	if err != nil {
		return &ParseResult{ParseError: fmt.Errorf("shell parse error: %w", err)}
	}

	v := &visitor{cwd: cwd, maxDepth: maxDepth}
	syntax.Walk(f, v.walk)

	return &ParseResult{Units: v.units}
}

type visitor struct {
	cwd      string
	maxDepth int
	units    []CheckableUnit
}

func (v *visitor) walk(node syntax.Node) bool {
	if node == nil {
		return false
	}

	switch n := node.(type) {
	case *syntax.CallExpr:
		v.handleCallExpr(n)
		return false // we handled children manually in handleCallExpr

	case *syntax.Redirect:
		v.handleRedirect(n)
		return false
	}

	return true
}

func (v *visitor) handleCallExpr(n *syntax.CallExpr) {
	if len(n.Args) > 0 {
		var parts []string
		var combined wordFlags

		for _, word := range n.Args {
			part, flags := wordToString(word, v.cwd, v.maxDepth-1)
			combined.hasVariable = combined.hasVariable || flags.hasVariable
			combined.variables = append(combined.variables, flags.variables...)
			combined.hasSubshell = combined.hasSubshell || flags.hasSubshell
			parts = append(parts, part)
		}

		unit := CheckableUnit{
			Kind:        UnitCommand,
			Value:       strings.Join(parts, " "),
			Args:        parts,
			HasVariable: combined.hasVariable,
			Variables:   combined.variables,
			HasSubshell: combined.hasSubshell,
		}
		v.units = append(v.units, unit)

		// Walk into any subshells in the arguments that we haven't flattened
		for _, word := range n.Args {
			v.walkSubshellsInWord(word, 1)
		}
	}

	// Walk into subshells in assignment values (e.g., T7=$(cmd) or bare T7=$(cmd)).
	// These must be checked independently — the command inside $(...) is not visible
	// from the outer unit value and would otherwise bypass rule evaluation entirely.
	for _, assign := range n.Assigns {
		if assign.Value != nil {
			v.walkSubshellsInWord(assign.Value, 1)
		}
	}
}

func (v *visitor) handleRedirect(n *syntax.Redirect) {
	if n.Word == nil {
		return
	}

	path, flags := wordToString(n.Word, v.cwd, v.maxDepth-1)

	// Heredocs (<<, <<-, <<<) provide inline stdin to a command — they don't
	// read or write files, so there's no file unit to emit.
	// FD duplicates (2>&1, 1<&0) redirect between file descriptors — no file involved.
	switch n.Op {
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc,
		syntax.DplOut, syntax.DplIn: // fd-to-fd: 2>&1, 1<&0 — no file involved
		return
	}

	var kind UnitKind
	switch n.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll,
		syntax.ClbOut:
		kind = UnitWriteFile
	default: // RdrIn, DplIn, RdrInOut, etc.
		kind = UnitReadFile
	}

	// Resolve relative paths against cwd
	if !filepath.IsAbs(path) && !flags.hasVariable && !flags.hasSubshell {
		path = filepath.Join(v.cwd, path)
	}

	v.units = append(v.units, CheckableUnit{
		Kind:        kind,
		Value:       path,
		HasVariable: flags.hasVariable,
		Variables:   flags.variables,
		HasSubshell: flags.hasSubshell,
	})
}

// walkSubshellsInWord finds CmdSubst ($(...)) in a word and recursively
// parses them as additional units, up to maxDepth.
func (v *visitor) walkSubshellsInWord(word *syntax.Word, depth int) {
	if depth > v.maxDepth {
		// Too deep — treat as a variable (unknown)
		v.units = append(v.units, CheckableUnit{
			Kind:        UnitCommand,
			Value:       "$(...)",
			HasVariable: true,
		})
		return
	}

	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.CmdSubst:
			inner := &visitor{cwd: v.cwd, maxDepth: v.maxDepth - depth}
			syntax.Walk(p, inner.walk)
			v.units = append(v.units, inner.units...)
		case *syntax.DblQuoted:
			for _, dqPart := range p.Parts {
				if cs, ok := dqPart.(*syntax.CmdSubst); ok {
					inner := &visitor{cwd: v.cwd, maxDepth: v.maxDepth - depth}
					syntax.Walk(cs, inner.walk)
					v.units = append(v.units, inner.units...)
				}
			}
		}
	}
}

// wordFlags carries what was found during word-to-string conversion.
type wordFlags struct {
	hasVariable bool
	variables   []string // variable names collected (without $)
	hasSubshell bool
}

// wordToString converts a syntax.Word to a string, tracking variables and subshells.
func wordToString(word *syntax.Word, cwd string, remainingDepth int) (string, wordFlags) {
	var sb strings.Builder
	var flags wordFlags

	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			inner, innerFlags := dblQuotedToString(p, cwd, remainingDepth)
			flags.hasVariable = flags.hasVariable || innerFlags.hasVariable
			flags.variables = append(flags.variables, innerFlags.variables...)
			flags.hasSubshell = flags.hasSubshell || innerFlags.hasSubshell
			sb.WriteString(inner)
		case *syntax.ParamExp: // $VAR or ${VAR}
			flags.hasVariable = true
			flags.variables = append(flags.variables, p.Param.Value)
			sb.WriteString("$" + p.Param.Value)
		case *syntax.CmdSubst: // $(...)
			flags.hasSubshell = true
			sb.WriteString("$(...)")
		case *syntax.ArithmExp: // $((...))
			flags.hasVariable = true
			sb.WriteString("$((...))")
		default:
			flags.hasVariable = true
			sb.WriteString("?")
		}
	}

	return sb.String(), flags
}

// dblQuotedToString is intentionally separate from wordToString rather than a
// recursive call. Inside double quotes, SglQuoted and ArithmExp are not valid
// constructs, so this function only handles the subset of part types that can
// legally appear within a double-quoted word. Merging the two would require
// either dead branches here or conditional logic that obscures that constraint.
func dblQuotedToString(dq *syntax.DblQuoted, cwd string, remainingDepth int) (string, wordFlags) {
	var sb strings.Builder
	var flags wordFlags

	for _, part := range dq.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.ParamExp:
			flags.hasVariable = true
			flags.variables = append(flags.variables, p.Param.Value)
			sb.WriteString("$" + p.Param.Value)
		case *syntax.CmdSubst:
			flags.hasSubshell = true
			sb.WriteString("$(...)")
		default:
			flags.hasVariable = true
			sb.WriteString("?")
		}
	}

	return sb.String(), flags
}
