package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
	"github.com/mikecafarella/permcop/internal/hook"
	"github.com/mikecafarella/permcop/internal/importer"
	"github.com/mikecafarella/permcop/internal/interactive"
	"github.com/mikecafarella/permcop/internal/parser"
	"github.com/mikecafarella/permcop/internal/rules"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

const usage = `permcop — Claude Code bash permission enforcer

Usage:
  permcop check [--no-interactive]                Read Claude Code hook JSON from stdin, exit 0 (allow) or 2 (deny)
                                                  Prompts to add a rule when TTY available and command hits default deny
  permcop explain <cmd>                           Dry-run: show rule evaluation without logging or blocking
  permcop validate [file]                         Validate config (default: ~/.config/permcop/config.toml)
  permcop init [--global]                         Set up Claude Code hook and create config
  permcop import-claude-settings [--global] [--shared] [--dry-run] [file]
                                                  Import Claude Code permissions to permcop TOML
  permcop version                                 Print version
  permcop help                                    Show this help message

Config files (merged in priority order, highest first):
  .permcop.local.toml              project local  (gitignored; personal overlay)
  .permcop.toml                    project shared (committed; team policy)
  ~/.config/permcop/config.local.toml  global local
  ~/.config/permcop/config.toml        global shared
  Audit log: ~/.local/share/permcop/audit.log
`

const usageImportClaudeSettings = `permcop import-claude-settings — Convert Claude Code permissions to permcop TOML

Usage:
  permcop import-claude-settings [--global] [--shared] [--dry-run] [sourcefile]

Flags:
  --global    Use global config scope (~/.config/permcop/) instead of project
  --shared    Write to the shared (committed) config instead of the local variant
  --dry-run   Print the generated TOML to stdout without writing anything
  --help      Show this help message

Default behavior (no flags):
  Source:  .claude/settings.json + .claude/settings.local.json (merged, searched upward)
  Dest:    .permcop.local.toml in CWD  (gitignored personal overlay)

With --shared:
  Dest:    .permcop.toml in CWD

With --global:
  Dest:    ~/.config/permcop/config.local.toml

With --global --shared:
  Dest:    ~/.config/permcop/config.toml

If [sourcefile] is given, it overrides the default source path.

If the destination file already exists, the generated rules are shown and
you are prompted for confirmation before anything is written. Use --dry-run
to review output without being prompted.

Examples:
  permcop import-claude-settings                  # project mode
  permcop import-claude-settings --global         # global mode
  permcop import-claude-settings --dry-run        # preview only
  permcop import-claude-settings ~/other.json     # custom source, project dest
  permcop import-claude-settings --global --dry-run
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		if len(os.Args) >= 3 && os.Args[2] == "import-claude-settings" {
			fmt.Fprint(os.Stdout, usageImportClaudeSettings)
		} else {
			fmt.Fprint(os.Stdout, usage)
		}
		os.Exit(0)
	case "version", "--version", "-v":
		fmt.Printf("permcop %s\n", version)
		os.Exit(0)
	case "check":
		noInteractive := false
		for _, arg := range os.Args[2:] {
			if arg == "--no-interactive" {
				noInteractive = true
			}
		}
		runCheck(noInteractive)
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
		global := len(os.Args) >= 3 && os.Args[2] == "--global"
		runInit(global)
	case "import-claude-settings":
		var global, dryRun, shared bool
		var sourcePath string
		for _, arg := range os.Args[2:] {
			switch arg {
			case "--global":
				global = true
			case "--dry-run":
				dryRun = true
			case "--shared":
				shared = true
			case "--help", "-h":
				fmt.Fprint(os.Stdout, usageImportClaudeSettings)
				os.Exit(0)
			default:
				if strings.HasPrefix(arg, "-") {
					fmt.Fprintf(os.Stderr, "unknown flag: %s\n\n%s", arg, usageImportClaudeSettings)
					os.Exit(1)
				}
				sourcePath = arg
			}
		}
		runImportClaudeSettings(global, dryRun, shared, sourcePath)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

// runCheck is the main hook entry point. It reads JSON from stdin, evaluates the
// tool call, writes a human-readable reason to stdout on deny, and exits 0 or 2.
// All failures — including unrecognized hook format — are fail-closed (deny) and logged.
// When noInteractive is false and a TTY is available, default-deny results trigger
// an interactive prompt that can save a new rule and allow the command.
func runCheck(noInteractive bool) {
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
	defer logger.Close()

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

	engine, err := rules.New(cfg, logger)
	if err != nil {
		denyAndExit(fmt.Sprintf("permcop: invalid config pattern: %v", err))
	}
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

	// Interactive flow: when a command falls through to default deny and a TTY
	// is available, offer to add a rule to .permcop.local.toml and allow this
	// invocation. Explicit deny matches, parse errors, and sudo blocks skip
	// this path and are denied immediately.
	if !result.Allowed && result.DefaultDeny && !noInteractive {
		localCfgPath := filepath.Join(cwd, ".permcop.local.toml")
		ok, err := interactive.PromptAndAdd(result, localCfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "permcop: interactive prompt error: %v\n", err)
			// fall through to deny
		} else if ok {
			// Rule was written — reload config and re-evaluate.
			cfg2, err := config.Load(cwd)
			if err == nil {
				engine2, err := rules.New(cfg2, logger)
				if err == nil {
					var result2 *rules.Result
					switch in.Kind {
					case hook.ToolBash:
						result2, _ = engine2.Check(in.Bash.Command, cwd)
					case hook.ToolRead:
						result2, _ = engine2.CheckFile(absolutePath(in.File.FilePath, cwd), parser.UnitReadFile)
					case hook.ToolWrite, hook.ToolEdit, hook.ToolMultiEdit:
						result2, _ = engine2.CheckFile(absolutePath(in.File.FilePath, cwd), parser.UnitWriteFile)
					}
					if result2 != nil && result2.Allowed {
						os.Exit(0)
					}
				}
			}
			// Rule was saved but re-evaluation didn't allow — deny and let the user investigate.
			fmt.Fprintln(os.Stdout, "permcop: rule saved but command still not covered; check your config")
			os.Exit(2)
		}
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

// absolutePath resolves a path relative to cwd, then canonicalizes it by
// evaluating symlinks so that glob rules anchored to the project directory
// cannot be bypassed via symlinks or .. sequences.
func absolutePath(path, cwd string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Path may not exist yet (e.g. a new file being written); return the
		// lexically-cleaned absolute path so deny-by-default still applies.
		return path
	}
	return resolved
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
	defer logger.Close()
	engine, err := rules.New(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: invalid pattern: %v\n", err)
		os.Exit(1)
	}

	result, err := engine.Check(command, cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check error: %v\n", err)
		os.Exit(1)
	}

	// Parse errors are surfaced via result.Reason (engine is fail-closed).
	if !result.Allowed && strings.HasPrefix(result.Reason, "command parse error:") {
		fmt.Printf("PARSE ERROR: %v\n", strings.TrimPrefix(result.Reason, "command parse error: "))
		fmt.Println("Result: DENY (parse error)")
		return
	}

	fmt.Printf("Command:  %s\n", command)
	fmt.Printf("Units:    ")
	for i, u := range result.Units {
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
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "home dir: %v\n", err)
			os.Exit(1)
		}
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
// If global is true, write to ~/.config/permcop/config.toml and register the
// hook in ~/.claude/settings.json; otherwise write .permcop.toml in the
// current working directory and register the hook in .claude/settings.local.json
// (gitignored, machine-local).
func runInit(global bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "home dir: %v\n", err)
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "working directory: %v\n", err)
		os.Exit(1)
	}

	// 1. Determine config path (ask shared vs local)
	var cfgPath string
	if global {
		cfgDir := filepath.Join(home, ".config", "permcop")
		if err := os.MkdirAll(cfgDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "create config dir: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Create global config as:")
		fmt.Printf("  [1] Shared (%s) — used in all sessions\n", filepath.Join(cfgDir, "config.toml"))
		fmt.Printf("  [2] Local  (%s) — personal overlay\n", filepath.Join(cfgDir, "config.local.toml"))
		if promptChoice("Choice [1/2] (default: 1): ", 2) == 2 {
			cfgPath = filepath.Join(cfgDir, "config.local.toml")
		} else {
			cfgPath = filepath.Join(cfgDir, "config.toml")
		}
	} else {
		if _, err := os.Stat(filepath.Join(cwd, ".git")); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: no .git directory in %s; creating config here anyway\n", cwd)
		}
		fmt.Println("Create project config as:")
		fmt.Printf("  [1] Shared (.permcop.toml)       — committed to repo; team policy\n")
		fmt.Printf("  [2] Local  (.permcop.local.toml) — gitignored; personal overlay\n")
		if promptChoice("Choice [1/2] (default: 1): ", 2) == 2 {
			cfgPath = filepath.Join(cwd, ".permcop.local.toml")
		} else {
			cfgPath = filepath.Join(cwd, ".permcop.toml")
		}
	}

	fmt.Printf("Config path: %s\n", cfgPath)

	// 2. Create starter config if not present
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, []byte(starterConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Created starter config: %s\n", cfgPath)
	} else {
		fmt.Printf("Config already exists, skipping: %s\n", cfgPath)
	}

	// 2b. Offer to gitignore the local config file
	if !global && strings.HasSuffix(cfgPath, ".permcop.local.toml") {
		offerGitignore(cwd, ".permcop.local.toml")
	}

	// 3. Wire up the Claude Code hook. In project mode, write to
	// .claude/settings.local.json (gitignored) so the hook is machine-local
	// and doesn't affect other projects. In global mode, write to
	// ~/.claude/settings.json so the hook applies to all sessions.
	var claudeSettingsPath string
	if global {
		claudeSettingsDir := filepath.Join(home, ".claude")
		if err := os.MkdirAll(claudeSettingsDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "create .claude dir: %v\n", err)
			os.Exit(1)
		}
		claudeSettingsPath = filepath.Join(claudeSettingsDir, "settings.json")
	} else {
		claudeDir := filepath.Join(cwd, ".claude")
		if err := os.MkdirAll(claudeDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "create .claude dir: %v\n", err)
			os.Exit(1)
		}
		claudeSettingsPath = filepath.Join(claudeDir, "settings.local.json")
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

	// Only hook Bash by default. Claude Code's own permission system already
	// gates Read/Write/Edit/MultiEdit; adding permcop on top of those tools
	// creates deny-by-default friction for internal operations (plans, memory,
	// config edits) with little security benefit. Users who want file-tool
	// coverage can add the extra matchers manually.
	toolMatchers := []string{"Bash"}
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

	// Capture the original file's permissions so we can restore them on the
	// replacement. Claude's settings.json may contain sensitive data (API keys,
	// hook commands), so we preserve whatever restricted mode was set. If the
	// file does not exist yet, default to 0600 (owner read/write only).
	origMode := fs.FileMode(0600)
	if fi, err := os.Stat(path); err == nil {
		origMode = fi.Mode()
	}

	// Write atomically: temp file in the same directory, then rename.
	// os.Rename is atomic on POSIX when src and dst share a filesystem,
	// preventing corruption if the process is interrupted mid-write.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".settings-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, origMode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// runImportClaudeSettings converts Claude Code's settings.json permissions to
// permcop TOML and writes them to the appropriate config file.
// Default destination is the local config variant (.permcop.local.toml /
// config.local.toml) since imported permissions are personal by nature.
// Use --shared to write to the committed shared config instead.
func runImportClaudeSettings(global, dryRun, shared bool, sourcePath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "home dir: %v\n", err)
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "working directory: %v\n", err)
		os.Exit(1)
	}

	// Resolve source paths (both settings.json and settings.local.json are
	// merged so that permissions split across the two files are all imported).
	var sourcePaths []string
	if sourcePath != "" {
		sourcePaths = []string{sourcePath}
	} else if global {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(home, ".claude", name)
			if _, err := os.Stat(p); err == nil {
				sourcePaths = append(sourcePaths, p)
			}
		}
		if len(sourcePaths) == 0 {
			fmt.Fprintln(os.Stderr, "error: neither ~/.claude/settings.json nor ~/.claude/settings.local.json found")
			os.Exit(1)
		}
	} else {
		sourcePaths = findProjectClaudeSettings(cwd)
		if len(sourcePaths) == 0 {
			fmt.Fprintln(os.Stderr, "error: .claude/settings.json not found (searched from CWD to git root); use --global or provide a path")
			os.Exit(1)
		}
	}

	// Resolve dest path. Default is the local variant since imported
	// permissions are personal; use --shared for the committed shared config.
	var destPath string
	switch {
	case global && shared:
		destPath = filepath.Join(home, ".config", "permcop", "config.toml")
	case global:
		destPath = filepath.Join(home, ".config", "permcop", "config.local.toml")
	case shared:
		destPath = filepath.Join(cwd, ".permcop.toml")
	default:
		destPath = filepath.Join(cwd, ".permcop.local.toml")
	}

	result, err := importer.FromFiles(sourcePaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import error: %v\n", err)
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	for _, s := range result.Skipped {
		fmt.Fprintf(os.Stderr, "skipped (no permcop equivalent): %s\n", s)
	}

	if len(result.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "No rules to import.")
		return
	}

	content := fmt.Sprintf("# Imported from: %s\n", strings.Join(sourcePaths, ", ")) +
		"# NOTE: each unit in a command (subcommands, redirects) must be covered\n" +
		"# by at least one rule, but different units can match different rules.\n" +
		"# Review and adjust before using.\n\n" +
		importer.RulesToTOML(result.Rules)

	if dryRun {
		fmt.Fprintf(os.Stderr, "Source: %s\n", strings.Join(sourcePaths, ", "))
		fmt.Fprintf(os.Stderr, "Dest:   %s (dry-run; not written)\n", destPath)
		fmt.Print(content)
		return
	}

	// Check if content is already present in dest
	existing, readErr := os.ReadFile(destPath)
	if readErr == nil && strings.Contains(string(existing), content) {
		fmt.Fprintln(os.Stderr, "Nothing new to add.")
		return
	}

	// If dest exists, prompt for confirmation
	if readErr == nil {
		if !confirmAppend(destPath, content) {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return
		}
	}

	f, err := os.OpenFile(destPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", destPath, err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := fmt.Fprint(f, "\n"+content); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", destPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Wrote %d rule(s) to %s\n", len(result.Rules), destPath)

	// Offer to gitignore the local config if we wrote to a project-local file.
	if !global && !shared {
		offerGitignore(cwd, ".permcop.local.toml")
	}
}

// findProjectClaudeSettings walks from cwd upward (stopping at .git or home)
// looking for .claude/settings.json and/or .claude/settings.local.json. It
// returns all files found at the first directory level that contains either
// file, so that both are merged by the caller. Returns nil if neither is found
// at any level.
func findProjectClaudeSettings(cwd string) []string {
	home, _ := os.UserHomeDir()
	dir := cwd
	for {
		var found []string
		for _, name := range []string{"settings.json", "settings.local.json"} {
			candidate := filepath.Join(dir, ".claude", name)
			if _, err := os.Stat(candidate); err == nil {
				found = append(found, candidate)
			}
		}
		if len(found) > 0 {
			return found
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		if dir == home || dir == filepath.Dir(dir) {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// promptChoice prints prompt and reads a number in [1..n]. Returns 1 on empty
// input (default) or invalid input.
func promptChoice(prompt string, n int) int {
	fmt.Print(prompt)
	var resp string
	fmt.Scanln(&resp)
	resp = strings.TrimSpace(resp)
	if resp == "" {
		return 1
	}
	for i := 1; i <= n; i++ {
		if resp == fmt.Sprintf("%d", i) {
			return i
		}
	}
	return 1
}

// offerGitignore checks whether filename is already in CWD/.gitignore and, if
// not and a .git directory exists, prompts the user to add it.
func offerGitignore(cwd, filename string) {
	if _, err := os.Stat(filepath.Join(cwd, ".git")); err != nil {
		return // not a git repo
	}
	gitignorePath := filepath.Join(cwd, ".gitignore")
	existing, _ := os.ReadFile(gitignorePath)
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == filename {
			return // already present
		}
	}
	fmt.Printf("Add %s to .gitignore? [Y/n] ", filename)
	var resp string
	fmt.Scanln(&resp)
	if strings.ToLower(strings.TrimSpace(resp)) == "n" {
		return
	}
	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not update .gitignore: %v\n", err)
		return
	}
	defer f.Close()
	entry := filename + "\n"
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		entry = "\n" + entry
	}
	if _, err := fmt.Fprint(f, entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write .gitignore: %v\n", err)
	}
}

// confirmAppend prints the content to be appended with a + prefix per line,
// then prompts the user for confirmation. Returns true only if the user types y or Y.
func confirmAppend(destPath, content string) bool {
	fmt.Printf("Will append to %s:\n\n", destPath)
	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		fmt.Printf("  + %s\n", line)
	}
	fmt.Printf("\nAppend? [y/N] ")
	var resp string
	fmt.Scanln(&resp)
	return strings.ToLower(strings.TrimSpace(resp)) == "y"
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
