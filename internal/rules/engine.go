package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
	"github.com/mikecafarella/permcop/internal/parser"
)

// expandVarsRe matches ${VAR} and $VAR shell variable references.
var expandVarsRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// compiledPattern holds a pre-compiled pattern for fast repeated matching.
// Glob and regex patterns are compiled once at engine construction.
type compiledPattern struct {
	p  config.Pattern
	re *regexp.Regexp // non-nil for PatternRegex
	g  glob.Glob      // non-nil for PatternGlob
}

func newCompiledPattern(p config.Pattern) compiledPattern {
	cp := compiledPattern{p: p}
	switch p.Type {
	case config.PatternGlob, "":
		cp.g, _ = glob.Compile(p.Pattern)
	case config.PatternRegex:
		cp.re, _ = regexp.Compile(p.Pattern)
	}
	return cp
}

func (cp compiledPattern) match(value string) bool {
	switch cp.p.Type {
	case config.PatternExact:
		return value == cp.p.Pattern
	case config.PatternPrefix:
		return value == cp.p.Pattern || strings.HasPrefix(value, cp.p.Pattern+" ")
	case config.PatternGlob, "":
		if cp.g == nil {
			return false
		}
		return cp.g.Match(value)
	case config.PatternRegex:
		if cp.re == nil {
			return false
		}
		return cp.re.MatchString(value)
	}
	return false
}

// compiledGlobPath holds a pre-compiled path glob with ~/ expanded.
type compiledGlobPath struct {
	raw string    // original pattern string, used for audit output
	g   glob.Glob // nil if compilation failed (treated as non-matching)
}

func newCompiledGlobPath(pattern, homeDir string) compiledGlobPath {
	raw := pattern
	if strings.HasPrefix(pattern, "~/") {
		if homeDir == "" {
			return compiledGlobPath{raw: raw}
		}
		pattern = homeDir + pattern[1:]
	}
	g, _ := glob.Compile(pattern, filepath.Separator)
	return compiledGlobPath{raw: raw, g: g}
}

func (c compiledGlobPath) match(path string) bool {
	return c.g != nil && c.g.Match(path)
}

// compiledRule mirrors config.Rule with all patterns pre-compiled.
type compiledRule struct {
	rule       *config.Rule
	allow      []compiledPattern
	deny       []compiledPattern
	allowRead  []compiledGlobPath
	denyRead   []compiledGlobPath
	allowWrite []compiledGlobPath
	denyWrite  []compiledGlobPath
}

func compileRules(rules []config.Rule, homeDir string) []compiledRule {
	cr := make([]compiledRule, len(rules))
	for i := range rules {
		r := &rules[i]
		cr[i].rule = r
		cr[i].allow = compilePatterns(r.Allow)
		cr[i].deny = compilePatterns(r.Deny)
		cr[i].allowRead = compileGlobPaths(r.AllowRead, homeDir)
		cr[i].denyRead = compileGlobPaths(r.DenyRead, homeDir)
		cr[i].allowWrite = compileGlobPaths(r.AllowWrite, homeDir)
		cr[i].denyWrite = compileGlobPaths(r.DenyWrite, homeDir)
	}
	return cr
}

func compilePatterns(ps []config.Pattern) []compiledPattern {
	out := make([]compiledPattern, len(ps))
	for i, p := range ps {
		out[i] = newCompiledPattern(p)
	}
	return out
}

func compileGlobPaths(patterns []string, homeDir string) []compiledGlobPath {
	out := make([]compiledGlobPath, len(patterns))
	for i, p := range patterns {
		out[i] = newCompiledGlobPath(p, homeDir)
	}
	return out
}

// Result is the outcome of evaluating a command against the rule set.
type Result struct {
	audit.Entry
	Allowed bool
}

// Engine evaluates commands against a config.
type Engine struct {
	cfg           *config.Config
	logger        *audit.Logger
	env           map[string]string // variable environment for expand_variables; nil = use os.Environ()
	homeDir       string            // resolved once at construction for ~/ expansion in file patterns
	compiledRules []compiledRule    // pre-compiled patterns for all rules
}

// New creates an Engine using the process environment for variable expansion.
func New(cfg *config.Config, logger *audit.Logger) *Engine {
	homeDir, _ := os.UserHomeDir()
	return &Engine{
		cfg:           cfg,
		logger:        logger,
		env:           osEnvMap(),
		homeDir:       homeDir,
		compiledRules: compileRules(cfg.Rules, homeDir),
	}
}

// NewWithEnv creates an Engine with an explicit environment map, primarily for testing.
func NewWithEnv(cfg *config.Config, logger *audit.Logger, env map[string]string) *Engine {
	homeDir, _ := os.UserHomeDir()
	return &Engine{
		cfg:           cfg,
		logger:        logger,
		env:           env,
		homeDir:       homeDir,
		compiledRules: compileRules(cfg.Rules, homeDir),
	}
}

// osEnvMap converts os.Environ() into a map for fast lookup.
func osEnvMap() map[string]string {
	raw := os.Environ()
	m := make(map[string]string, len(raw))
	for _, kv := range raw {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// logAudit writes an audit entry and surfaces any write error to stderr so
// operators know when auditing is broken. For a security enforcement tool,
// silently dropping audit records is unacceptable.
func (e *Engine) logAudit(entry audit.Entry) {
	if err := e.logger.Log(entry); err != nil {
		fmt.Fprintf(os.Stderr, "permcop: audit log error: %v\n", err)
	}
}

// Check evaluates command (the raw string from Claude Code) against the rule set.
// cwd is the working directory for resolving relative file paths.
func (e *Engine) Check(command, cwd string) (*Result, error) {
	entry := audit.Entry{
		Timestamp:       time.Now(),
		OriginalCommand: command,
	}

	deny := func(reason, rule, pattern string, unit *parser.CheckableUnit) (*Result, error) {
		entry.Decision = audit.DecisionDeny
		entry.Reason = reason
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = unit
		e.logAudit(entry)
		return &Result{Entry: entry, Allowed: false}, nil
	}

	allow := func(rule, pattern string, unit *parser.CheckableUnit) (*Result, error) {
		entry.Decision = audit.DecisionAllow
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = unit
		e.logAudit(entry)
		return &Result{Entry: entry, Allowed: true}, nil
	}

	warnAllow := func(rule, pattern string, unit *parser.CheckableUnit, reason string) (*Result, error) {
		entry.Decision = audit.DecisionWarn
		entry.Reason = reason
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = unit
		e.logAudit(entry)
		return &Result{Entry: entry, Allowed: true}, nil
	}

	// --- Pre-checks (fail-closed) ---

	// Config availability is checked by the caller; if we got here, config is valid.

	// Parse the command
	parsed := parser.Parse(command, cwd, e.cfg.Defaults.SubshellDepthLimit)
	if parsed.ParseError != nil {
		return deny(fmt.Sprintf("command parse error: %v", parsed.ParseError), "", "", nil)
	}
	entry.Units = parsed.Units

	if len(parsed.Units) == 0 {
		return deny("empty command", "", "", nil)
	}

	// sudo check — runs after parsing so chained commands (e.g. "echo hi && sudo rm -rf /")
	// are correctly detected via their individual AST units rather than a raw prefix check.
	if !e.cfg.Defaults.AllowSudo {
		for i := range parsed.Units {
			if u := &parsed.Units[i]; u.Kind == parser.UnitCommand && unitHasSudo(u.Value) {
				return deny("sudo not permitted", "", "", u)
			}
		}
	}

	// --- Pass 1: Deny scan (all rules × all units) ---
	// Only explicit deny patterns are evaluated here.
	for i := range e.compiledRules {
		cr := e.compiledRules[i]
		for j := range parsed.Units {
			u := parsed.Units[j] // copy; may be modified by expansion
			if cr.rule.ExpandVariables && u.HasVariable {
				expanded, ok := expandVars(u.Value, e.env)
				if !ok {
					// Variable not in env — skip this rule for this unit (not a deny).
					continue
				}
				u.Value = expanded
				u.HasVariable = false
			}
			if matched, patStr := matchesDenyPattern(cr, &u); matched {
				return deny("matched deny pattern", cr.rule.Name, patStr, &u)
			}
		}
	}

	// --- Pass 2: Allow scan (per-unit; each unit independently finds any covering rule) ---
	// All units must be covered for the command to be allowed.
	var lastUnit *parser.CheckableUnit
	var lastPat, lastRule string
	var warnReason string

	for i := range parsed.Units {
		orig := &parsed.Units[i]
		covered := false

		for j := range e.compiledRules {
			cr := e.compiledRules[j]

			u := *orig // copy; may be modified by expansion

			// expand_variables: resolve env vars before matching this rule.
			if cr.rule.ExpandVariables && u.HasVariable {
				expanded, ok := expandVars(u.Value, e.env)
				if !ok {
					// Variable not in env — this rule cannot cover the unit.
					continue
				}
				u.Value = expanded
				u.HasVariable = false
			}

			// Subshell: this rule's effective setting determines if it can cover the unit.
			if e.cfg.EffectiveDenySubshells(cr.rule) && u.HasSubshell {
				continue
			}

			// Variable: this rule's effective setting determines if it can cover the unit.
			varAction := e.cfg.EffectiveVariableAction(cr.rule)
			if u.HasVariable && varAction == config.VariableActionDeny {
				continue
			}

			if ok, pat := unitCoveredByRule(cr, u); ok {
				lastUnit = orig
				lastPat = pat
				lastRule = cr.rule.Name
				covered = true
				if u.HasVariable && varAction == config.VariableActionWarn {
					warnReason = "variable in command (unknown_variable_action=warn)"
				}
				break
			}
		}

		if !covered {
			return deny("no matching allow rule", "", "", orig)
		}
	}

	if warnReason != "" {
		return warnAllow(lastRule, lastPat, lastUnit, warnReason)
	}
	return allow(lastRule, lastPat, lastUnit)
}

// CheckFile evaluates a direct file-access tool call (Read, Write, Edit, MultiEdit)
// against the rule set. kind must be parser.UnitReadFile or parser.UnitWriteFile.
// path should be an absolute path.
func (e *Engine) CheckFile(path string, kind parser.UnitKind) (*Result, error) {
	unit := parser.CheckableUnit{Kind: kind, Value: path}
	entry := audit.Entry{
		Timestamp:       time.Now(),
		OriginalCommand: fmt.Sprintf("<%s %s>", kind, path),
		Units:           []parser.CheckableUnit{unit},
	}

	deny := func(reason, rule, pattern string) (*Result, error) {
		entry.Decision = audit.DecisionDeny
		entry.Reason = reason
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = &unit
		e.logAudit(entry)
		return &Result{Entry: entry, Allowed: false}, nil
	}

	allow := func(rule, pattern string) (*Result, error) {
		entry.Decision = audit.DecisionAllow
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = &unit
		e.logAudit(entry)
		return &Result{Entry: entry, Allowed: true}, nil
	}

	if path == "" {
		return deny("empty file path", "", "")
	}

	// Pass 1: Deny scan
	for i := range e.compiledRules {
		cr := e.compiledRules[i]
		if matched, patStr := matchesDenyPattern(cr, &unit); matched {
			return deny("matched deny pattern", cr.rule.Name, patStr)
		}
	}

	// Pass 2: Allow scan (file-only rules can cover a single file unit)
	for i := range e.compiledRules {
		cr := e.compiledRules[i]
		if covered, pat := unitCoveredByRule(cr, unit); covered {
			return allow(cr.rule.Name, pat)
		}
	}

	return deny("no matching allow rule", "", "")
}

// --- Matching helpers ---

func matchesDenyPattern(cr compiledRule, u *parser.CheckableUnit) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, cp := range cr.deny {
			if cp.match(u.Value) {
				return true, patternString(cp.p)

			}
		}
	case parser.UnitReadFile:
		for _, gp := range cr.denyRead {
			if gp.match(u.Value) {
				return true, "deny_read:" + gp.raw
			}
		}
	case parser.UnitWriteFile:
		for _, gp := range cr.denyWrite {
			if gp.match(u.Value) {
				return true, "deny_write:" + gp.raw
			}
		}
	}
	return false, ""
}

func unitCoveredByRule(cr compiledRule, u parser.CheckableUnit) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, cp := range cr.allow {
			if cp.match(u.Value) {
				return true, patternString(cp.p)

			}
		}
	case parser.UnitReadFile:
		for _, gp := range cr.allowRead {
			if gp.match(u.Value) {
				return true, "allow_read:" + gp.raw
			}
		}
	case parser.UnitWriteFile:
		for _, gp := range cr.allowWrite {
			if gp.match(u.Value) {
				return true, "allow_write:" + gp.raw
			}
		}
	}
	return false, ""
}

func patternString(p config.Pattern) string {
	return fmt.Sprintf("%s:%s", p.Type, p.Pattern)
}

// expandVars replaces $VAR and ${VAR} occurrences in s using env.
// Returns (expanded, true) if all variables were resolved, or ("", false) if
// any variable was missing from env.
func expandVars(s string, env map[string]string) (string, bool) {
	allResolved := true
	result := expandVarsRe.ReplaceAllStringFunc(s, func(match string) string {
		// Extract variable name from either ${VAR} or $VAR form.
		sub := expandVarsRe.FindStringSubmatch(match)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		val, ok := env[name]
		if !ok {
			allResolved = false
			return match // leave unexpanded; caller checks allResolved
		}
		return val
	})
	if !allResolved {
		return "", false
	}
	return result, true
}

// unitHasSudo reports whether a single parsed command unit invokes sudo.
// The value is the AST-reconstructed command string for one unit (e.g. "sudo git status"),
// so a simple prefix check here is correct — the AST has already handled quoting, chaining,
// and other shell syntax.
func unitHasSudo(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "sudo" ||
		strings.HasPrefix(trimmed, "sudo ") ||
		strings.HasPrefix(trimmed, "sudo\t")
}
