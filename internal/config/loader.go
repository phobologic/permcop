package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// warnBroadAllowRules emits a stderr warning for any rule that combines
// unknown_variable_action=allow with a broad allow pattern ("*" or "**").
// Such rules silently permit any command or file path containing a variable
// regardless of what the variable expands to, which is almost always a
// misconfiguration. Checks r.Allow (command patterns), r.AllowRead, and
// r.AllowWrite (file glob patterns).
func warnBroadAllowRules(cfg *Config) {
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if cfg.EffectiveVariableAction(r) != VariableActionAllow {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule[%d]", i)
		}
		warned := false
		for _, p := range r.Allow {
			if p.Pattern == "*" || p.Pattern == "**" {
				fmt.Fprintf(os.Stderr,
					"permcop: warning: rule %q: unknown_variable_action=allow with broad pattern %q is high risk\n",
					name, p.Pattern)
				warned = true
				break
			}
		}
		if warned {
			continue
		}
		for _, p := range r.AllowRead {
			if p == "*" || p == "**" {
				fmt.Fprintf(os.Stderr,
					"permcop: warning: rule %q: unknown_variable_action=allow with broad allow_read pattern %q is high risk\n",
					name, p)
				warned = true
				break
			}
		}
		if warned {
			continue
		}
		for _, p := range r.AllowWrite {
			if p == "*" || p == "**" {
				fmt.Fprintf(os.Stderr,
					"permcop: warning: rule %q: unknown_variable_action=allow with broad allow_write pattern %q is high risk\n",
					name, p)
				break
			}
		}
	}
}

const (
	globalConfigPath = ".config/permcop/config.toml"
	projectFileName  = ".permcop.toml"
)

// Load reads the global config and optionally merges a per-project overlay.
// Project rules are prepended (evaluated before global rules).
// If the global config does not exist, returns a deny-everything config.
// If the global config exists but cannot be parsed, returns an error.
func Load(cwd string) (*Config, error) {
	global, err := loadFile(globalConfigPath, true)
	if err != nil {
		return nil, fmt.Errorf("global config: %w", err)
	}

	project, err := findAndLoadProject(cwd)
	if err != nil {
		return nil, fmt.Errorf("project config: %w", err)
	}

	merged := merge(global, project)
	if err := applyDefaults(merged); err != nil {
		return nil, err
	}
	warnBroadAllowRules(merged)
	return merged, nil
}

// LoadFile loads a config from an explicit path (used by validate command).
func LoadFile(path string) (*Config, error) {
	cfg, err := loadFile(path, false)
	if err != nil {
		return nil, err
	}
	if err := applyDefaults(cfg); err != nil {
		return nil, err
	}
	warnBroadAllowRules(cfg)
	return cfg, nil
}

func loadFile(relOrAbsPath string, missingOK bool) (*Config, error) {
	path := relOrAbsPath
	if !filepath.IsAbs(path) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, relOrAbsPath)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && missingOK {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// findAndLoadProject walks from cwd up to home dir looking for .permcop.toml.
// Walking stops at a git repository root (.git directory) to prevent a
// .permcop.toml planted in a parent directory from weakening deny rules for
// unrelated projects (confused-deputy / directory-traversal class of issue).
func findAndLoadProject(cwd string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	dir := cwd
	for {
		candidate := filepath.Join(dir, projectFileName)
		if _, err := os.Stat(candidate); err == nil {
			return loadFile(candidate, false)
		}

		// Stop at the git repository root so that a .permcop.toml in a
		// parent directory cannot override rules for projects inside this repo.
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}

		if dir == home || dir == filepath.Dir(dir) {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil, nil
}

// merge combines a project config overlay with the global config.
// Project rules are prepended; project defaults override global defaults where set.
func merge(global *Config, project *Config) *Config {
	if project == nil {
		return global
	}

	result := &Config{}

	// Project rules first (higher priority in evaluation)
	result.Rules = append(result.Rules, project.Rules...)
	result.Rules = append(result.Rules, global.Rules...)

	// Start with global defaults, project overrides where non-zero
	result.Defaults = global.Defaults
	if project.Defaults.LogFile != "" {
		result.Defaults.LogFile = project.Defaults.LogFile
	}
	if project.Defaults.LogFormat != "" {
		result.Defaults.LogFormat = project.Defaults.LogFormat
	}
	if project.Defaults.UnknownVariableAction != "" {
		result.Defaults.UnknownVariableAction = project.Defaults.UnknownVariableAction
	}
	if project.Defaults.AllowSudo {
		result.Defaults.AllowSudo = true
	}
	if project.Defaults.SubshellDepthLimit != 0 {
		result.Defaults.SubshellDepthLimit = project.Defaults.SubshellDepthLimit
	}

	return result
}

func applyDefaults(cfg *Config) error {
	if cfg.Defaults.LogFormat == "" {
		cfg.Defaults.LogFormat = "text"
	}
	if cfg.Defaults.UnknownVariableAction == "" {
		cfg.Defaults.UnknownVariableAction = VariableActionDeny
	}
	if cfg.Defaults.SubshellDepthLimit == 0 {
		cfg.Defaults.SubshellDepthLimit = 3
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	if cfg.Defaults.LogFile == "" {
		cfg.Defaults.LogFile = filepath.Join(home, ".local", "share", "permcop", "audit.log")
	} else {
		clean := filepath.Clean(cfg.Defaults.LogFile)
		if !strings.HasPrefix(clean, home+string(filepath.Separator)) {
			return fmt.Errorf("log_file %q must be inside the user home directory; project configs may not redirect the audit log to system paths", cfg.Defaults.LogFile)
		}
	}
	return nil
}
