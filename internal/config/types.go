package config

import "fmt"

// PatternType defines how a pattern string is interpreted.
type PatternType string

const (
	PatternExact    PatternType = "exact"
	PatternPrefix   PatternType = "prefix"
	PatternGlob     PatternType = "glob"
	PatternWordGlob PatternType = "word_glob"
	PatternRegex    PatternType = "regex"
)

// UnknownVariableAction defines behavior when shell variables are found in a command.
type UnknownVariableAction string

const (
	// VariableActionDeny rejects the command if any variable is present.
	VariableActionDeny UnknownVariableAction = "deny"
	// VariableActionWarn allows the command but writes a WARN-level audit entry.
	VariableActionWarn UnknownVariableAction = "warn"
	// VariableActionAllow silently permits commands with variables.
	VariableActionAllow UnknownVariableAction = "allow"
)

// Pattern is a single allow or deny pattern within a rule.
type Pattern struct {
	// Type determines how Pattern is matched. Defaults to "glob" if unset.
	Type    PatternType `toml:"type"`
	Pattern string      `toml:"pattern"`
	// EscalateFlags lists flags that, when present in a matching command, cause
	// this allow pattern to abstain — the unit falls through to Claude Code's
	// own permission check rather than being pre-approved. Only meaningful on
	// allow patterns; ignored on deny patterns.
	// Short single-char flags (e.g. "-i") also match when bundled (e.g. "-ni").
	// Long flags (e.g. "--in-place") also match with an attached value (e.g. "--in-place=.bak").
	EscalateFlags []string `toml:"escalate_flags"`
}

// UnmarshalText lets a bare TOML string ("git log") decode as a glob Pattern.
// This means allow = ["git log"] and allow = [{type="glob", pattern="git log"}]
// are equivalent.
func (p *Pattern) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		p.Type = PatternGlob
		p.Pattern = v
	case map[string]interface{}:
		if t, ok := v["type"].(string); ok {
			p.Type = PatternType(t)
		} else {
			p.Type = PatternGlob
		}
		if pat, ok := v["pattern"].(string); ok {
			p.Pattern = pat
		}
		if raw, ok := v["escalate_flags"].([]interface{}); ok {
			for _, f := range raw {
				if s, ok := f.(string); ok {
					p.EscalateFlags = append(p.EscalateFlags, s)
				}
			}
		}
	}
	if p.Type == "" {
		p.Type = PatternGlob
	}
	switch p.Type {
	case PatternExact, PatternPrefix, PatternGlob, PatternWordGlob, PatternRegex:
		// valid
	default:
		return fmt.Errorf("unknown pattern type %q: must be one of exact, prefix, glob, word_glob, regex", p.Type)
	}
	return nil
}

// Rule is one entry in the ordered rule list. All deny patterns across all
// rules are evaluated before allow patterns (two-pass model).
type Rule struct {
	Name        string    `toml:"name"`
	Description string    `toml:"description"`
	Allow       []Pattern `toml:"allow"`
	Deny        []Pattern `toml:"deny"`
	AllowRead   []string  `toml:"allow_read"`
	DenyRead    []string  `toml:"deny_read"`
	AllowWrite  []string  `toml:"allow_write"`
	DenyWrite   []string  `toml:"deny_write"`
	// VariableAction overrides the global default for this rule.
	// Empty string means "use global default".
	VariableAction UnknownVariableAction `toml:"unknown_variable_action"`
	// DenySubshells, when true, causes any command unit containing a subshell
	// $(...) or backtick expansion to be denied by this rule, regardless of
	// allow patterns. Useful for rules that should only match literal commands
	// with no shell interpretation.
	DenySubshells *bool `toml:"deny_subshells"`
	// ExpandVariables, when true, causes the engine to resolve environment
	// variables in a unit's value before matching this rule's allow and deny
	// patterns. If any variable in the unit is not set in the environment,
	// this rule cannot cover the unit (fail-closed). Defaults to false.
	ExpandVariables bool `toml:"expand_variables"`
	// StripCommandPath, when true, strips the directory prefix from the first
	// token of a command unit before matching allow and deny patterns. This
	// allows a rule with pattern "sed" to match both "sed" and "/usr/bin/sed".
	// Overrides the global default when set. Defaults to nil (use global default).
	StripCommandPath *bool `toml:"strip_command_path"`
}

// EffectiveDenySubshells returns whether subshells should be denied,
// using the global default if the rule doesn't override it.
func (c *Config) EffectiveDenySubshells(r *Rule) bool {
	if r != nil && r.DenySubshells != nil {
		return *r.DenySubshells
	}
	return c.Defaults.DenySubshells
}

// Defaults holds global configuration defaults.
type Defaults struct {
	LogFile               string                `toml:"log_file"`
	LogFormat             string                `toml:"log_format"`      // "text" | "json"
	LogMaxSizeMB          int                   `toml:"log_max_size_mb"` // rotate at this many MB; 0 = disabled
	LogMaxFiles           int                   `toml:"log_max_files"`   // rotated copies to keep
	UnknownVariableAction UnknownVariableAction `toml:"unknown_variable_action"`
	AllowSudo             bool                  `toml:"allow_sudo"`
	SubshellDepthLimit    int                   `toml:"subshell_depth_limit"`
	// DenySubshells, when true globally, causes any unit with a subshell to be
	// denied unless a rule explicitly overrides with deny_subshells = false.
	DenySubshells bool `toml:"deny_subshells"`
	// StripCommandPath, when true globally, strips the directory prefix from the
	// first token of a command unit before pattern matching. Allows rules written
	// with bare command names (e.g. "sed") to match full-path invocations
	// (e.g. "/usr/bin/sed"). Defaults to false.
	StripCommandPath bool `toml:"strip_command_path"`
}

// Config is the top-level configuration structure.
type Config struct {
	Defaults Defaults `toml:"defaults"`
	Rules    []Rule   `toml:"rules"`
}

// EffectiveStripCommandPath returns whether path stripping is enabled for a rule,
// using the global default if the rule doesn't override it.
func (c *Config) EffectiveStripCommandPath(r *Rule) bool {
	if r != nil && r.StripCommandPath != nil {
		return *r.StripCommandPath
	}
	return c.Defaults.StripCommandPath
}

// EffectiveVariableAction returns the variable action for a rule,
// falling back to the global default.
func (c *Config) EffectiveVariableAction(r *Rule) UnknownVariableAction {
	if r != nil && r.VariableAction != "" {
		return r.VariableAction
	}
	if c.Defaults.UnknownVariableAction != "" {
		return c.Defaults.UnknownVariableAction
	}
	return VariableActionDeny
}
