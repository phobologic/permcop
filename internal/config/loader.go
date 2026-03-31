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
	globalConfigPath      = ".config/permcop/config.toml"
	globalLocalConfigPath = ".config/permcop/config.local.toml"
	projectFileName       = ".permcop.toml"
	projectLocalFileName  = ".permcop.local.toml"
)

// Load reads up to four config layers and merges them in priority order:
//
//  1. project-local  (.permcop.local.toml — gitignored personal overlay)
//  2. project-shared (.permcop.toml       — committed team policy)
//  3. global-local   (~/.config/permcop/config.local.toml)
//  4. global-shared  (~/.config/permcop/config.toml)
//
// Missing files are silently skipped. Parse errors are fatal.
// DenySubshells is global-only: project layers cannot override it.
func Load(cwd string) (*Config, error) {
	globalShared, err := loadFile(globalConfigPath, true)
	if err != nil {
		return nil, fmt.Errorf("global config: %w", err)
	}
	globalLocal, err := loadFile(globalLocalConfigPath, true)
	if err != nil {
		return nil, fmt.Errorf("global local config: %w", err)
	}

	projectShared, projectLocal, err := findAndLoadProject(cwd)
	if err != nil {
		return nil, fmt.Errorf("project config: %w", err)
	}

	merged := mergeAll(projectLocal, projectShared, globalLocal, globalShared)
	// DenySubshells is global-only: project layers cannot disable it.
	merged.Defaults.DenySubshells = globalShared.Defaults.DenySubshells || globalLocal.Defaults.DenySubshells

	if err := applyDefaults(merged); err != nil {
		return nil, err
	}
	warnBroadAllowRules(merged)
	return merged, nil
}

// LoadFile loads a config from an explicit path (used by validate command).
// Relative paths are resolved against the current working directory.
func LoadFile(path string) (*Config, error) {
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getwd: %w", err)
		}
		path = filepath.Join(cwd, path)
	}
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

// findAndLoadProject walks from cwd upward (stopping at .git or home) looking
// for .permcop.toml (shared) and .permcop.local.toml (local). Both files are
// loaded from the first directory that contains either. Walking stops at the
// git root to prevent a config planted in a parent directory from weakening
// deny rules for projects inside the repo (confused-deputy/traversal issue).
func findAndLoadProject(cwd string) (shared, local *Config, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}

	dir := cwd
	for {
		sharedPath := filepath.Join(dir, projectFileName)
		localPath := filepath.Join(dir, projectLocalFileName)
		_, sharedMissing := os.Stat(sharedPath)
		_, localMissing := os.Stat(localPath)

		if sharedMissing == nil || localMissing == nil {
			if sharedMissing == nil {
				shared, err = loadFile(sharedPath, false)
				if err != nil {
					return nil, nil, err
				}
			}
			if localMissing == nil {
				local, err = loadFile(localPath, false)
				if err != nil {
					return nil, nil, err
				}
			}
			return shared, local, nil
		}

		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		if dir == home || dir == filepath.Dir(dir) {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil, nil, nil
}

// mergeAll combines configs in priority order: first layer = highest priority.
// Rules are appended in layer order (first layer's rules evaluated first).
// Defaults take the first non-zero value scanning layers in order.
// DenySubshells is intentionally excluded — Load sets it from global layers only.
func mergeAll(layers ...*Config) *Config {
	result := &Config{}
	for _, layer := range layers {
		if layer == nil {
			continue
		}
		result.Rules = append(result.Rules, layer.Rules...)
	}
	for _, layer := range layers {
		if layer == nil {
			continue
		}
		if result.Defaults.LogFile == "" && layer.Defaults.LogFile != "" {
			result.Defaults.LogFile = layer.Defaults.LogFile
		}
		if result.Defaults.LogFormat == "" && layer.Defaults.LogFormat != "" {
			result.Defaults.LogFormat = layer.Defaults.LogFormat
		}
		if result.Defaults.UnknownVariableAction == "" && layer.Defaults.UnknownVariableAction != "" {
			result.Defaults.UnknownVariableAction = layer.Defaults.UnknownVariableAction
		}
		if !result.Defaults.AllowSudo && layer.Defaults.AllowSudo {
			result.Defaults.AllowSudo = true
		}
		if result.Defaults.SubshellDepthLimit == 0 && layer.Defaults.SubshellDepthLimit != 0 {
			result.Defaults.SubshellDepthLimit = layer.Defaults.SubshellDepthLimit
		}
		if result.Defaults.LogMaxSizeMB == 0 && layer.Defaults.LogMaxSizeMB != 0 {
			result.Defaults.LogMaxSizeMB = layer.Defaults.LogMaxSizeMB
		}
		if result.Defaults.LogMaxFiles == 0 && layer.Defaults.LogMaxFiles != 0 {
			result.Defaults.LogMaxFiles = layer.Defaults.LogMaxFiles
		}
	}
	return result
}

// merge is kept for backward compatibility with existing callers and tests.
func merge(global, project *Config) *Config {
	if project == nil {
		return global
	}
	return mergeAll(project, global)
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
	if cfg.Defaults.LogMaxSizeMB == 0 {
		cfg.Defaults.LogMaxSizeMB = 10
	}
	if cfg.Defaults.LogMaxFiles == 0 {
		cfg.Defaults.LogMaxFiles = 5
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	if strings.HasPrefix(cfg.Defaults.LogFile, "~/") {
		cfg.Defaults.LogFile = filepath.Join(home, cfg.Defaults.LogFile[2:])
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
