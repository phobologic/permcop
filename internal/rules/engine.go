package rules

import (
	"fmt"
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
	cfg    *config.Config
	logger *audit.Logger
}

// New creates an Engine.
func New(cfg *config.Config, logger *audit.Logger) *Engine {
	return &Engine{cfg: cfg, logger: logger}
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

	// sudo check
	if !e.cfg.Defaults.AllowSudo && hasSudo(command) {
		return deny("sudo not permitted", "", "", nil)
	}

	// Parse the command
	parsed := parser.Parse(command, cwd, e.cfg.Defaults.SubshellDepthLimit)
	if parsed.ParseError != nil {
		return deny(fmt.Sprintf("command parse error: %v", parsed.ParseError), "", "", nil)
	}
	entry.Units = parsed.Units

	if len(parsed.Units) == 0 {
		return deny("empty command", "", "", nil)
	}

	// --- Pass 1: Deny scan (all rules × all units) ---
	// Only explicit deny patterns are evaluated here.
	for i := range e.cfg.Rules {
		r := &e.cfg.Rules[i]
		for j := range parsed.Units {
			u := &parsed.Units[j]
			if matched, patStr := matchesDenyPattern(r, u); matched {
				return deny("matched deny pattern", r.Name, patStr, u)
			}
		}
	}

	// --- Pass 2: Allow scan (per-unit; each unit independently finds any covering rule) ---
	// All units must be covered for the command to be allowed.
	var lastUnit *parser.CheckableUnit
	var lastPat, lastRule string
	var warnReason string

	for i := range parsed.Units {
		u := &parsed.Units[i]
		covered := false

		for j := range e.cfg.Rules {
			r := &e.cfg.Rules[j]

			// Subshell: this rule's effective setting determines if it can cover the unit.
			if e.cfg.EffectiveDenySubshells(r) && u.HasSubshell {
				continue
			}

			// Variable: this rule's effective setting determines if it can cover the unit.
			varAction := e.cfg.EffectiveVariableAction(r)
			if u.HasVariable && varAction == config.VariableActionDeny {
				continue
			}

			if ok, pat := unitCoveredByRule(e.cfg, r, *u); ok {
				lastUnit = u
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
			return deny("no matching allow rule", "", "", u)
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
		if matched, patStr := matchesDenyPattern(r, &unit); matched {
			return deny("matched deny pattern", r.Name, patStr)
		}
	}

	// Pass 2: Allow scan (file-only rules can cover a single file unit)
	for i := range e.cfg.Rules {
		r := &e.cfg.Rules[i]
		if covered, pat := unitCoveredByRule(e.cfg, r, unit); covered {
			return allow(r.Name, pat)
		}
	}

	return deny("no matching allow rule", "", "")
}

// --- Matching helpers ---

func matchesDenyPattern(r *config.Rule, u *parser.CheckableUnit) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, p := range r.Deny {
			if matchPattern(p, u.Value) {
				return true, patternString(p)
			}
		}
	case parser.UnitReadFile:
		for _, pat := range r.DenyRead {
			if matchGlobPath(pat, u.Value) {
				return true, "deny_read:" + pat
			}
		}
	case parser.UnitWriteFile:
		for _, pat := range r.DenyWrite {
			if matchGlobPath(pat, u.Value) {
				return true, "deny_write:" + pat
			}
		}
	}
	return false, ""
}


func unitCoveredByRule(_ *config.Config, r *config.Rule, u parser.CheckableUnit) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, p := range r.Allow {
			if matchPattern(p, u.Value) {
				return true, patternString(p)
			}
		}
	case parser.UnitReadFile:
		for _, pat := range r.AllowRead {
			if matchGlobPath(pat, u.Value) {
				return true, "allow_read:" + pat
			}
		}
	case parser.UnitWriteFile:
		for _, pat := range r.AllowWrite {
			if matchGlobPath(pat, u.Value) {
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

func matchGlobPath(pattern, path string) bool {
	// Resolve glob relative to home if it starts with ~/
	if strings.HasPrefix(pattern, "~/") {
		// Leave as-is; gobwas/glob handles literal ~
	}
	// Use ** for recursive matching
	g, err := glob.Compile(pattern, filepath.Separator)
	if err != nil {
		return false
	}
	return g.Match(path)
}

func patternString(p config.Pattern) string {
	return fmt.Sprintf("%s:%s", p.Type, p.Pattern)
}

func hasSudo(command string) bool {
	// Quick prefix check — the parser will catch more complex cases,
	// but this handles the common "sudo <cmd>" case before parsing.
	trimmed := strings.TrimSpace(command)
	return trimmed == "sudo" ||
		strings.HasPrefix(trimmed, "sudo ") ||
		strings.HasPrefix(trimmed, "sudo\t")
}
