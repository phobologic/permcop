package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gobwas/glob"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
	"github.com/phobologic/permcop/internal/parser"
)

// compiledPattern holds a pre-compiled pattern for fast repeated matching.
// Glob and regex patterns are compiled once at engine construction.
type compiledPattern struct {
	p        config.Pattern
	re       *regexp.Regexp // non-nil for PatternRegex
	g        glob.Glob      // non-nil for PatternGlob
	wgTokens []glob.Glob    // for PatternWordGlob; nil entry marks a "**" wildcard token
}

func newCompiledPattern(p config.Pattern) (compiledPattern, error) {
	cp := compiledPattern{p: p}
	var err error
	switch p.Type {
	case config.PatternGlob, "":
		cp.g, err = glob.Compile(p.Pattern)
		if err != nil {
			return compiledPattern{}, fmt.Errorf("invalid glob pattern %q: %w", p.Pattern, err)
		}
	case config.PatternWordGlob:
		parts := strings.Fields(p.Pattern)
		cp.wgTokens = make([]glob.Glob, len(parts))
		for i, part := range parts {
			if part == "**" {
				cp.wgTokens[i] = nil // sentinel: matches zero or more tokens
			} else {
				cp.wgTokens[i], err = glob.Compile(part)
				if err != nil {
					return compiledPattern{}, fmt.Errorf("invalid word_glob token %q: %w", part, err)
				}
			}
		}
	case config.PatternRegex:
		cp.re, err = regexp.Compile(p.Pattern)
		if err != nil {
			return compiledPattern{}, fmt.Errorf("invalid regex pattern %q: %w", p.Pattern, err)
		}
	}
	return cp, nil
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
	case config.PatternWordGlob:
		return matchWordGlob(cp.wgTokens, strings.Fields(value))
	case config.PatternRegex:
		if cp.re == nil {
			return false
		}
		return cp.re.MatchString(value)
	}
	return false
}

// matchWordGlob matches command tokens against word_glob pattern tokens.
// A nil entry in patTokens represents a "**" wildcard (zero or more tokens).
func matchWordGlob(patTokens []glob.Glob, cmdTokens []string) bool {
	if len(patTokens) == 0 {
		return len(cmdTokens) == 0
	}
	if patTokens[0] == nil { // "**": try consuming 0..N remaining command tokens
		for i := 0; i <= len(cmdTokens); i++ {
			if matchWordGlob(patTokens[1:], cmdTokens[i:]) {
				return true
			}
		}
		return false
	}
	if len(cmdTokens) == 0 {
		return false
	}
	if !patTokens[0].Match(cmdTokens[0]) {
		return false
	}
	return matchWordGlob(patTokens[1:], cmdTokens[1:])
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

func compileRules(rules []config.Rule, homeDir string) ([]compiledRule, error) {
	cr := make([]compiledRule, len(rules))
	for i := range rules {
		r := &rules[i]
		cr[i].rule = r
		var err error
		if cr[i].allow, err = compilePatterns(r.Allow); err != nil {
			return nil, fmt.Errorf("rule %q allow: %w", r.Name, err)
		}
		if cr[i].deny, err = compilePatterns(r.Deny); err != nil {
			return nil, fmt.Errorf("rule %q deny: %w", r.Name, err)
		}
		cr[i].allowRead = compileGlobPaths(r.AllowRead, homeDir)
		cr[i].denyRead = compileGlobPaths(r.DenyRead, homeDir)
		cr[i].allowWrite = compileGlobPaths(r.AllowWrite, homeDir)
		cr[i].denyWrite = compileGlobPaths(r.DenyWrite, homeDir)
	}
	return cr, nil
}

func compilePatterns(ps []config.Pattern) ([]compiledPattern, error) {
	out := make([]compiledPattern, len(ps))
	for i, p := range ps {
		cp, err := newCompiledPattern(p)
		if err != nil {
			return nil, err
		}
		out[i] = cp
	}
	return out, nil
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
	Allowed     bool
	FallThrough bool // true when no allow rule matched; defer to Claude Code
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
// Returns an error if any rule contains an invalid glob or regex pattern.
func New(cfg *config.Config, logger *audit.Logger) (*Engine, error) {
	homeDir, _ := os.UserHomeDir()
	cr, err := compileRules(cfg.Rules, homeDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:           cfg,
		logger:        logger,
		env:           osEnvMap(),
		homeDir:       homeDir,
		compiledRules: cr,
	}, nil
}

// NewWithEnv creates an Engine with an explicit environment map, primarily for testing.
// Returns an error if any rule contains an invalid glob or regex pattern.
func NewWithEnv(cfg *config.Config, logger *audit.Logger, env map[string]string) (*Engine, error) {
	homeDir, _ := os.UserHomeDir()
	cr, err := compileRules(cfg.Rules, homeDir)
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg:           cfg,
		logger:        logger,
		env:           env,
		homeDir:       homeDir,
		compiledRules: cr,
	}, nil
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
	// Collect all deny hits before returning so RuleMatches is complete.
	var denyMatches []audit.RuleMatch
	var firstDenyOrig *parser.CheckableUnit
	var firstDenyRule, firstDenyPat string

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
			if u.Kind == parser.UnitCommand && e.cfg.EffectiveStripCommandPath(cr.rule) {
				u.Value = stripCmdPath(u.Value)
			}
			if matched, patStr := matchesDenyPattern(cr, &u); matched {
				denyMatches = append(denyMatches, audit.RuleMatch{
					Rule:    cr.rule.Name,
					Pattern: patStr,
					Unit:    u.Value,
					Action:  "deny",
				})
				if firstDenyOrig == nil {
					firstDenyOrig = &parsed.Units[j]
					firstDenyRule = cr.rule.Name
					firstDenyPat = patStr
				}
			}
		}
	}
	if len(denyMatches) > 0 {
		entry.RuleMatches = denyMatches
		return deny("matched deny pattern", firstDenyRule, firstDenyPat, firstDenyOrig)
	}

	// --- Pass 2: Allow scan (per-unit; each unit independently finds any covering rule) ---
	// All units must be covered for the command to be allowed.
	var lastUnit *parser.CheckableUnit
	var lastPat, lastRule string
	var warnReason string
	var allowMatches []audit.RuleMatch

	for i := range parsed.Units {
		orig := &parsed.Units[i]
		covered := false
		var skippedRules []audit.SkippedRule

		for j := range e.compiledRules {
			cr := e.compiledRules[j]

			u := *orig // copy; may be modified by expansion

			// expand_variables: resolve env vars before matching this rule.
			if cr.rule.ExpandVariables && u.HasVariable {
				expanded, ok := expandVars(u.Value, e.env)
				if !ok {
					// Variable not in env — this rule cannot cover the unit.
					// Record which variables are missing so the audit log can
					// surface a near-miss hint instead of a silent skip.
					seen := make(map[string]bool)
					var missing []string
					for _, v := range orig.Variables {
						if seen[v] {
							continue
						}
						seen[v] = true
						if _, exists := e.env[v]; !exists {
							missing = append(missing, "$"+v)
						}
					}
					skippedRules = append(skippedRules, audit.SkippedRule{
						Rule:   cr.rule.Name,
						Reason: "expand_variables: " + strings.Join(missing, ", ") + " not in env",
					})
					continue
				}
				u.Value = expanded
				u.HasVariable = false
			}

			// Strip command path for pattern matching.
			if u.Kind == parser.UnitCommand && e.cfg.EffectiveStripCommandPath(cr.rule) {
				u.Value = stripCmdPath(u.Value)
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
				allowMatches = append(allowMatches, audit.RuleMatch{
					Rule:    cr.rule.Name,
					Pattern: pat,
					Unit:    u.Value,
					Action:  "allow",
				})
				if u.HasVariable && varAction == config.VariableActionWarn {
					warnReason = "variable in command (unknown_variable_action=warn)"
				}
				break
			}
		}

		if !covered {
			allowMatches = append(allowMatches, audit.RuleMatch{
				Rule:         "",
				Unit:         orig.Value,
				Action:       "deny",
				SkippedRules: skippedRules,
			})
			entry.RuleMatches = allowMatches
			return &Result{Entry: entry, FallThrough: true}, nil
		}
	}

	entry.RuleMatches = allowMatches
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

	// Pass 1: Deny scan — collect all hits before returning.
	var denyMatchesFile []audit.RuleMatch
	var firstDenyRuleFile, firstDenyPatFile string

	for i := range e.compiledRules {
		cr := e.compiledRules[i]
		if matched, patStr := matchesDenyPattern(cr, &unit); matched {
			denyMatchesFile = append(denyMatchesFile, audit.RuleMatch{
				Rule:    cr.rule.Name,
				Pattern: patStr,
				Unit:    unit.Value,
				Action:  "deny",
			})
			if firstDenyRuleFile == "" {
				firstDenyRuleFile = cr.rule.Name
				firstDenyPatFile = patStr
			}
		}
	}
	if len(denyMatchesFile) > 0 {
		entry.RuleMatches = denyMatchesFile
		return deny("matched deny pattern", firstDenyRuleFile, firstDenyPatFile)
	}

	// Pass 2: Allow scan (file-only rules can cover a single file unit)
	for i := range e.compiledRules {
		cr := e.compiledRules[i]
		if covered, pat := unitCoveredByRule(cr, unit); covered {
			entry.RuleMatches = []audit.RuleMatch{{
				Rule:    cr.rule.Name,
				Pattern: pat,
				Unit:    unit.Value,
				Action:  "allow",
			}}
			return allow(cr.rule.Name, pat)
		}
	}

	entry.RuleMatches = []audit.RuleMatch{{
		Unit:   unit.Value,
		Action: "deny",
	}}
	return &Result{Entry: entry, FallThrough: true}, nil
}

// --- Command path stripping ---

// stripCmdPath strips the directory prefix from the first token of a command
// unit value. For example, "/usr/bin/sed -i file" becomes "sed -i file".
// This allows patterns written with bare command names to match full-path invocations.
func stripCmdPath(value string) string {
	if i := strings.IndexByte(value, ' '); i >= 0 {
		return filepath.Base(value[:i]) + value[i:]
	}
	return filepath.Base(value)
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

// escalateFlagPresent reports whether any escalate_flags from a pattern are
// present in the command unit value. When true, the allow pattern abstains and
// the unit falls through to Claude Code's own permission check.
func escalateFlagPresent(escalateFlags []string, value string) bool {
	if len(escalateFlags) == 0 {
		return false
	}
	tokens := strings.Fields(value)
	if len(tokens) <= 1 {
		return false
	}
	for _, tok := range tokens[1:] {
		for _, ef := range escalateFlags {
			if flagTokenMatches(tok, ef) {
				return true
			}
		}
	}
	return false
}

// flagTokenMatches reports whether an argv token matches a flag specifier.
//
//   - Long flags (--foo): match exactly or with an attached value (--foo=bar).
//   - Short flags (-x): match exactly or bundled with other single-letter flags (-xyz).
func flagTokenMatches(token, flag string) bool {
	switch {
	case strings.HasPrefix(flag, "--"):
		// Long flag: exact or --flag=value
		return token == flag || strings.HasPrefix(token, flag+"=")
	case len(flag) == 2 && flag[0] == '-':
		// Short single-char flag: exact or bundled (e.g. -ni contains -i)
		if token == flag {
			return true
		}
		// Bundled: token must start with '-' (not '--') and consist entirely of letters.
		if len(token) > 2 && token[0] == '-' && token[1] != '-' {
			for _, c := range token[1:] {
				if !unicode.IsLetter(c) {
					return false
				}
			}
			return strings.ContainsRune(token[1:], rune(flag[1]))
		}
	}
	return false
}

func unitCoveredByRule(cr compiledRule, u parser.CheckableUnit) (bool, string) {
	switch u.Kind {
	case parser.UnitCommand:
		for _, cp := range cr.allow {
			if cp.match(u.Value) {
				// escalate_flags: if any listed flag is present, this pattern
				// abstains — the unit is not covered and falls through to Claude Code.
				if escalateFlagPresent(cp.p.EscalateFlags, u.Value) {
					continue
				}
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
	result := os.Expand(s, func(name string) string {
		val, ok := env[name]
		if !ok {
			allResolved = false
			return ""
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
