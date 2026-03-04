package config

// PatternType defines how a pattern string is interpreted.
type PatternType string

const (
	PatternExact  PatternType = "exact"
	PatternPrefix PatternType = "prefix"
	PatternGlob   PatternType = "glob"
	PatternRegex  PatternType = "regex"
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
	}
	if p.Type == "" {
		p.Type = PatternGlob
	}
	return nil
}

// Rule is one entry in the ordered rule list. All deny patterns across all
// rules are evaluated before allow patterns (two-pass model).
type Rule struct {
	Name        string                `toml:"name"`
	Description string                `toml:"description"`
	Allow       []Pattern             `toml:"allow"`
	Deny        []Pattern             `toml:"deny"`
	AllowRead   []string              `toml:"allow_read"`
	DenyRead    []string              `toml:"deny_read"`
	AllowWrite  []string              `toml:"allow_write"`
	DenyWrite   []string              `toml:"deny_write"`
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
	LogFormat             string                `toml:"log_format"` // "text" | "json"
	UnknownVariableAction UnknownVariableAction `toml:"unknown_variable_action"`
	AllowSudo             bool                  `toml:"allow_sudo"`
	SubshellDepthLimit    int                   `toml:"subshell_depth_limit"`
	// DenySubshells, when true globally, causes any unit with a subshell to be
	// denied unless a rule explicitly overrides with deny_subshells = false.
	DenySubshells bool `toml:"deny_subshells"`
}

// Config is the top-level configuration structure.
type Config struct {
	Defaults Defaults `toml:"defaults"`
	Rules    []Rule   `toml:"rules"`
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
