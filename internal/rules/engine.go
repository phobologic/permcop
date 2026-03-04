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

// Result is the outcome of evaluating a command against the rule set.
type Result struct {
	audit.Entry
	Allowed bool
}

// Engine evaluates commands against a config.
type Engine struct {
	cfg     *config.Config
	logger  *audit.Logger
	env     map[string]string // variable environment for expand_variables; nil = use os.Environ()
	homeDir string            // resolved once at construction for ~/ expansion in file patterns
}

// New creates an Engine using the process environment for variable expansion.
func New(cfg *config.Config, logger *audit.Logger) *Engine {
	homeDir, _ := os.UserHomeDir()
	return &Engine{cfg: cfg, logger: logger, env: osEnvMap(), homeDir: homeDir}
}

// NewWithEnv creates an Engine with an explicit environment map, primarily for testing.
func NewWithEnv(cfg *config.Config, logger *audit.Logger, env map[string]string) *Engine {
	homeDir, _ := os.UserHomeDir()
	return &Engine{cfg: cfg, logger: logger, env: env, homeDir: homeDir}
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
		_ = e.logger.Log(entry)
		return &Result{Entry: entry, Allowed: false}, nil
	}

	allow := func(rule, pattern string, unit *parser.CheckableUnit) (*Result, error) {
		entry.Decision = audit.DecisionAllow
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = unit
		_ = e.logger.Log(entry)
		return &Result{Entry: entry, Allowed: true}, nil
	}

	warnAllow := func(rule, pattern string, unit *parser.CheckableUnit, reason string) (*Result, error) {
		entry.Decision = audit.DecisionWarn
		entry.Reason = reason
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = unit
		_ = e.logger.Log(entry)
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
	for i := range e.cfg.Rules {
		r := &e.cfg.Rules[i]
		for j := range parsed.Units {
			u := parsed.Units[j] // copy; may be modified by expansion
			if r.ExpandVariables && u.HasVariable {
				expanded, ok := expandVars(u.Value, e.env)
				if !ok {
					// Variable not in env — skip this rule for this unit (not a deny).
					continue
				}
				u.Value = expanded
				u.HasVariable = false
			}
			if matched, patStr := matchesDenyPattern(r, &u, e.homeDir); matched {
				return deny("matched deny pattern", r.Name, patStr, &u)
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

		for j := range e.cfg.Rules {
			r := &e.cfg.Rules[j]

			u := *orig // copy; may be modified by expansion

			// expand_variables: resolve env vars before matching this rule.
			if r.ExpandVariables && u.HasVariable {
				expanded, ok := expandVars(u.Value, e.env)
				if !ok {
					// Variable not in env — this rule cannot cover the unit.
					continue
				}
				u.Value = expanded
				u.HasVariable = false
			}

			// Subshell: this rule's effective setting determines if it can cover the unit.
			if e.cfg.EffectiveDenySubshells(r) && u.HasSubshell {
				continue
			}

			// Variable: this rule's effective setting determines if it can cover the unit.
			varAction := e.cfg.EffectiveVariableAction(r)
			if u.HasVariable && varAction == config.VariableActionDeny {
				continue
			}

			if ok, pat := unitCoveredByRule(e.cfg, r, u, e.homeDir); ok {
				lastUnit = orig
				lastPat = pat
				lastRule = r.Name
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
		_ = e.logger.Log(entry)
		return &Result{Entry: entry, Allowed: false}, nil
	}

	allow := func(rule, pattern string) (*Result, error) {
		entry.Decision = audit.DecisionAllow
		entry.DecidingRule = rule
		entry.DecidingPattern = pattern
		entry.DecidingUnit = &unit
		_ = e.logger.Log(entry)
		return &Result{Entry: entry, Allowed: true}, nil
	}

	if path == "" {
		return deny("empty file path", "", "")
	}

	// Pass 1: Deny scan
	for i := range e.cfg.Rules {
		r := &e.cfg.Rules[i]
		if matched, patStr := matchesDenyPattern(r, &unit, e.homeDir); matched {
			return deny("matched deny pattern", r.Name, patStr)
		}
	}

	// Pass 2: Allow scan (file-only rules can cover a single file unit)
	for i := range e.cfg.Rules {
		r := &e.cfg.Rules[i]
		if covered, pat := unitCoveredByRule(e.cfg, r, unit, e.homeDir); covered {
			return allow(r.Name, pat)
		}
	}

	return deny("no matching allow rule", "", "")
}

// --- Matching helpers ---

func matchesDenyPattern(r *config.Rule, u *parser.CheckableUnit, homeDir string) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, p := range r.Deny {
			if matchPattern(p, u.Value) {
				return true, patternString(p)
			}
		}
	case parser.UnitReadFile:
		for _, pat := range r.DenyRead {
			if matchGlobPath(pat, u.Value, homeDir) {
				return true, "deny_read:" + pat
			}
		}
	case parser.UnitWriteFile:
		for _, pat := range r.DenyWrite {
			if matchGlobPath(pat, u.Value, homeDir) {
				return true, "deny_write:" + pat
			}
		}
	}
	return false, ""
}

func unitCoveredByRule(_ *config.Config, r *config.Rule, u parser.CheckableUnit, homeDir string) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, p := range r.Allow {
			if matchPattern(p, u.Value) {
				return true, patternString(p)
			}
		}
	case parser.UnitReadFile:
		for _, pat := range r.AllowRead {
			if matchGlobPath(pat, u.Value, homeDir) {
				return true, "allow_read:" + pat
			}
		}
	case parser.UnitWriteFile:
		for _, pat := range r.AllowWrite {
			if matchGlobPath(pat, u.Value, homeDir) {
				return true, "allow_write:" + pat
			}
		}
	}
	return false, ""
}

func matchPattern(p config.Pattern, value string) bool {
	switch p.Type {
	case config.PatternExact:
		return value == p.Pattern
	case config.PatternPrefix:
		return value == p.Pattern || strings.HasPrefix(value, p.Pattern+" ")
	case config.PatternGlob, "":
		g, err := glob.Compile(p.Pattern)
		if err != nil {
			return false
		}
		return g.Match(value)
	case config.PatternRegex:
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	return false
}

func matchGlobPath(pattern, path, homeDir string) bool {
	if strings.HasPrefix(pattern, "~/") {
		if homeDir == "" {
			return false
		}
		// Replace ~ with homeDir; pattern[1:] starts with /, so homeDir + pattern[1:] is correct.
		pattern = homeDir + pattern[1:]
	}
	g, err := glob.Compile(pattern, filepath.Separator)
	if err != nil {
		return false
	}
	return g.Match(path)
}

func patternString(p config.Pattern) string {
	return fmt.Sprintf("%s:%s", p.Type, p.Pattern)
}

// expandVars replaces $VAR and ${VAR} occurrences in s using env.
// Returns (expanded, true) if all variables were resolved, or ("", false) if
// any variable was missing from env.
func expandVars(s string, env map[string]string) (string, bool) {
	// Match ${VAR} and $VAR (identifiers: [A-Za-z_][A-Za-z0-9_]*)
	re := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	allResolved := true
	result := re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract variable name from either ${VAR} or $VAR form.
		sub := re.FindStringSubmatch(match)
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
