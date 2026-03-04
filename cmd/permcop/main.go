package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
	"github.com/mikecafarella/permcop/internal/hook"
	"github.com/mikecafarella/permcop/internal/importer"
	"github.com/mikecafarella/permcop/internal/parser"
	"github.com/mikecafarella/permcop/internal/rules"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

const usage = `permcop — Claude Code bash permission enforcer

Usage:
  permcop check                           Read Claude Code hook JSON from stdin, exit 0 (allow) or 2 (deny)
  permcop explain <cmd>                   Dry-run: show rule evaluation without logging or blocking
  permcop validate [file]                 Validate config file (default: ~/.config/permcop/config.toml)
  permcop init                            Set up Claude Code hook and create starter config
  permcop import-claude-settings [file]   Convert Claude Code permission rules to permcop TOML
  permcop version                         Print version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("permcop %s\n", version)
		os.Exit(0)
	case "check":
		runCheck()
	case "explain":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: permcop explain <command>")
			os.Exit(1)
		}
		runExplain(strings.Join(os.Args[2:], " "))
	case "validate":
		path := ""
		if len(os.Args) >= 3 {
			path = os.Args[2]
		}
		runValidate(path)
	case "init":
		runInit()
	case "import-claude-settings":
		path := ""
		if len(os.Args) >= 3 {
			path = os.Args[2]
		}
		runImportClaudeSettings(path)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// runCheck is the main hook entry point. It reads JSON from stdin, evaluates the
// tool call, writes a human-readable reason to stdout on deny, and exits 0 or 2.
// All failures — including unrecognized hook format — are fail-closed (deny) and logged.
func runCheck() {
	cwd, err := os.Getwd()
	if err != nil {
		// Fail-closed: cannot determine CWD means file path resolution is unsafe.
		// Log to stdout (deny channel) before the audit logger is available.
		fmt.Fprintf(os.Stdout, "permcop: cannot determine working directory: %v\n", err)
		os.Exit(2)
	}

	// Load config early so we can log everything, including hook parse failures.
	cfg, cfgErr := config.Load(cwd)
	if cfgErr != nil {
		fmt.Fprintf(os.Stdout, "permcop: config unavailable: %v\n", cfgErr)
		os.Exit(2)
	}

	logger := audit.New(cfg.Defaults.LogFile, cfg.Defaults.LogFormat)

	denyAndExit := func(reason string) {
		_ = logger.Log(audit.Entry{
			Timestamp:       time.Now(),
			Decision:        audit.DecisionDeny,
			Reason:          reason,
			OriginalCommand: "(unknown — hook input error)",
		})
		fmt.Fprintln(os.Stdout, reason)
		os.Exit(2)
	}

	in, err := hook.ReadInput(os.Stdin)
	if err != nil {
		denyAndExit(fmt.Sprintf("permcop: unrecognized hook input format: %v", err))
	}

	engine := rules.New(cfg, logger)
	var result *rules.Result

	switch in.Kind {
	case hook.ToolBash:
		if in.Bash == nil || in.Bash.Command == "" {
			denyAndExit("permcop: empty command in Bash hook input")
		}
		result, err = engine.Check(in.Bash.Command, cwd)
		if err != nil {
			denyAndExit(fmt.Sprintf("permcop: check error: %v", err))
		}

	case hook.ToolRead:
		if in.File == nil || in.File.FilePath == "" {
			denyAndExit("permcop: empty file_path in Read hook input")
		}
		path := absolutePath(in.File.FilePath, cwd)
		result, err = engine.CheckFile(path, parser.UnitReadFile)
		if err != nil {
			denyAndExit(fmt.Sprintf("permcop: check error: %v", err))
		}

	case hook.ToolWrite, hook.ToolEdit, hook.ToolMultiEdit:
		if in.File == nil || in.File.FilePath == "" {
			denyAndExit(fmt.Sprintf("permcop: empty file_path in %s hook input", in.Kind))
		}
		path := absolutePath(in.File.FilePath, cwd)
		result, err = engine.CheckFile(path, parser.UnitWriteFile)
		if err != nil {
			denyAndExit(fmt.Sprintf("permcop: check error: %v", err))
		}

	default:
		// Unknown tool — permcop doesn't govern it, allow through.
		os.Exit(0)
	}

	exitWithResult(result)
}

func exitWithResult(result *rules.Result) {
	if result.Allowed {
		os.Exit(0)
	}
	reason := result.Reason
	if result.DecidingRule != "" {
		reason = fmt.Sprintf("blocked by rule %q", result.DecidingRule)
		if result.DecidingPattern != "" {
			reason += fmt.Sprintf(" (pattern: %s)", result.DecidingPattern)
		}
		if result.DecidingUnit != nil {
			reason += fmt.Sprintf(" — matched unit: %q", result.DecidingUnit.Value)
		}
	}
	fmt.Fprintln(os.Stdout, reason)
	os.Exit(2)
}

// absolutePath resolves a path relative to cwd if it isn't already absolute.
func absolutePath(path, cwd string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(cwd, path)
}

// runExplain performs a dry-run evaluation and prints a human-readable trace.
func runExplain(command string) {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot determine working directory: %v\n", err)
		os.Exit(1)
	}
	cfg, err := config.Load(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Null logger for explain (no file writes)
	logger := audit.New(os.DevNull, "text")
	engine := rules.New(cfg, logger)

	// Print parsed units first
	parsed := parser.Parse(command, cwd, cfg.Defaults.SubshellDepthLimit)
	if parsed.ParseError != nil {
		fmt.Printf("PARSE ERROR: %v\n", parsed.ParseError)
		fmt.Println("Result: DENY (parse error)")
		return
	}

	fmt.Printf("Command:  %s\n", command)
	fmt.Printf("Units:    ")
	for i, u := range parsed.Units {
		if i > 0 {
			fmt.Print(", ")
		}
		flags := ""
		if u.HasVariable {
			flags += "[var]"
		}
		if u.HasSubshell {
			flags += "[subshell]"
		}
		fmt.Printf("[%s %s%s]", u.Kind, u.Value, flags)
	}
	fmt.Println()
	fmt.Println()

	result, err := engine.Check(command, cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check error: %v\n", err)
		os.Exit(1)
	}

	if result.Allowed {
		fmt.Printf("Result:   ALLOW\n")
		if result.DecidingRule != "" {
			fmt.Printf("Rule:     %q\n", result.DecidingRule)
		}
		if result.DecidingPattern != "" {
			fmt.Printf("Pattern:  %s\n", result.DecidingPattern)
		}
		if result.DecidingUnit != nil {
			fmt.Printf("Hit unit: %s\n", result.DecidingUnit.Value)
		}
		if result.Reason != "" {
			fmt.Printf("Warning:  %s\n", result.Reason)
		}
	} else {
		fmt.Printf("Result:   DENY\n")
		if result.Reason != "" {
			fmt.Printf("Reason:   %s\n", result.Reason)
		}
		if result.DecidingRule != "" {
			fmt.Printf("Rule:     %q\n", result.DecidingRule)
		}
		if result.DecidingPattern != "" {
			fmt.Printf("Pattern:  %s\n", result.DecidingPattern)
		}
		if result.DecidingUnit != nil {
			fmt.Printf("Hit unit: %s\n", result.DecidingUnit.Value)
		}
	}
}

// runValidate parses the config file and reports any errors.
func runValidate(path string) {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".config", "permcop", "config.toml")
	}

	cfg, err := config.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OK: %s\n", path)
	fmt.Printf("  %d rules\n", len(cfg.Rules))
	for i, r := range cfg.Rules {
		fmt.Printf("  [%d] %q  allow=%d deny=%d allow_read=%d deny_read=%d allow_write=%d deny_write=%d\n",
			i, r.Name,
			len(r.Allow), len(r.Deny),
			len(r.AllowRead), len(r.DenyRead),
			len(r.AllowWrite), len(r.DenyWrite),
		)
	}
}

// runInit sets up the Claude Code hook and creates a starter config.
func runInit() {
	home, _ := os.UserHomeDir()

	// 1. Create starter config
	cfgDir := filepath.Join(home, ".config", "permcop")
	cfgPath := filepath.Join(cfgDir, "config.toml")

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.MkdirAll(cfgDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "create config dir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(cfgPath, []byte(starterConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created starter config: %s\n", cfgPath)
	} else {
		fmt.Printf("Config already exists, skipping: %s\n", cfgPath)
	}

	// 2. Wire up the Claude Code hook in the user's global settings
	claudeSettingsDir := filepath.Join(home, ".claude")
	claudeSettingsPath := filepath.Join(claudeSettingsDir, "settings.json")

	if err := os.MkdirAll(claudeSettingsDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "create .claude dir: %v\n", err)
		os.Exit(1)
	}

	if err := addHookToSettings(claudeSettingsPath); err != nil {
		fmt.Fprintf(os.Stderr, "update Claude settings: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Hook registered in: %s\n", claudeSettingsPath)
	fmt.Println()
	fmt.Println("Done! Edit your config to add rules:")
	fmt.Printf("  %s\n", cfgPath)
	fmt.Println()
	fmt.Println("Test with:")
	fmt.Println("  permcop explain 'git status'")
}

// addHookToSettings upserts the permcop PreToolUse hook into Claude's settings.json.
func addHookToSettings(path string) error {
	var settings map[string]interface{}

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read settings: %w", err)
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse settings.json: %w", err)
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Tools that permcop governs. Each gets its own matcher entry.
	// permcop check reads tool_name from the hook JSON and routes internally.
	toolMatchers := []string{"Bash", "Read", "Write", "Edit", "MultiEdit"}
	permcopHook := map[string]interface{}{
		"type":    "command",
		"command": "permcop check",
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
		settings["hooks"] = hooks
	}

	existing, _ := hooks["PreToolUse"].([]interface{})

	// Check if permcop is already wired for all tools
	alreadyWired := map[string]bool{}
	for _, e := range existing {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		matcher, _ := em["matcher"].(string)
		innerHooks, _ := em["hooks"].([]interface{})
		for _, h := range innerHooks {
			hm, ok := h.(map[string]interface{})
			if ok && hm["command"] == "permcop check" {
				alreadyWired[matcher] = true
			}
		}
	}

	added := 0
	for _, tool := range toolMatchers {
		if alreadyWired[tool] {
			continue
		}
		existing = append(existing, map[string]interface{}{
			"matcher": tool,
			"hooks":   []interface{}{permcopHook},
		})
		added++
	}

	if added == 0 {
		fmt.Printf("All hooks already registered in: %s\n", path)
		return nil
	}

	hooks["PreToolUse"] = existing

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}

// runImportClaudeSettings reads Claude Code's settings.json permissions and
// prints equivalent permcop TOML [[rules]] blocks to stdout.
// If --append is passed as the second argument, the output is appended to the
// global permcop config file instead of being printed.
func runImportClaudeSettings(settingsPath string) {
	home, _ := os.UserHomeDir()
	if settingsPath == "" {
		settingsPath = filepath.Join(home, ".claude", "settings.json")
	}

	result, err := importer.FromFile(settingsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import error: %v\n", err)
		os.Exit(1)
	}

	// Print warnings
	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	// Print skipped entries
	for _, s := range result.Skipped {
		fmt.Fprintf(os.Stderr, "skipped (no permcop equivalent): %s\n", s)
	}

	if len(result.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "No rules to import.")
		return
	}

	toml := importer.RulesToTOML(result.Rules)

	fmt.Printf("# Imported from: %s\n", settingsPath)
	fmt.Printf("# Add these rule(s) to your permcop config.\n")
	fmt.Printf("# NOTE: permcop requires a single rule to cover ALL units of a command\n")
	fmt.Printf("# (command + any redirects). Review and adjust before using.\n\n")
	fmt.Print(toml)

	fmt.Fprintf(os.Stderr, "\nImported %d rule(s). Review the output above and append to your config:\n", len(result.Rules))
	fmt.Fprintf(os.Stderr, "  permcop import-claude-settings >> ~/.config/permcop/config.toml\n")
}

const starterConfig = `# permcop configuration
# All commands are denied by default.
# Rules are evaluated in order.
# Pass 1: if ANY deny pattern matches ANY command unit -> DENY
# Pass 2: if ALL command units are covered by a single rule's allow patterns -> ALLOW
# Otherwise: DENY

[defaults]
log_file = "~/.local/share/permcop/audit.log"
log_format = "text"              # "text" or "json"
unknown_variable_action = "deny" # "deny", "warn" (allow + log), or "allow"
allow_sudo = false
deny_subshells = false           # set true to block $(...) in all commands
subshell_depth_limit = 3

# Example rules — uncomment and adapt as needed:

# [[rules]]
# name = "Allow safe git operations"
# allow = [
#   { type = "prefix", pattern = "git log" },
#   { type = "prefix", pattern = "git diff" },
#   { type = "exact",  pattern = "git status" },
#   { type = "glob",   pattern = "git show *" },
# ]
# deny = [
#   { type = "prefix", pattern = "git push" },
#   { type = "regex",  pattern = "^git\\s+.*--force" },
# ]

# [[rules]]
# name = "Read project source"
# allow_read = ["./src/**", "./tests/**"]
# deny_read  = ["./.env"]

# [[rules]]
# name = "Write to tmp only"
# allow_write = ["/tmp/**"]
`
