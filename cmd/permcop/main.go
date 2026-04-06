package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/mikecafarella/permcop/internal/audit"
	"github.com/mikecafarella/permcop/internal/config"
	"github.com/mikecafarella/permcop/internal/hook"
	"github.com/mikecafarella/permcop/internal/importer"
	"github.com/mikecafarella/permcop/internal/parser"
	"github.com/mikecafarella/permcop/internal/rules"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

func writeHookDecision(decision, reason string) {
	out := hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

const usage = `permcop — Claude Code bash permission enforcer

Usage:
  permcop check                                   Read Claude Code hook JSON from stdin, exit 0 (allow) or 2 (deny)
  permcop explain <cmd>                           Dry-run: show rule evaluation without logging or blocking
  permcop validate [file]                         Validate config (default: ~/.config/permcop/config.toml)
  permcop init [--global]                         Set up Claude Code hook and create config
  permcop import-claude-settings [--global] [--shared] [--dry-run] [file]
                                                  Import Claude Code permissions to permcop TOML
  permcop suggest [--n N] [--global] [--shared] [--dry-run]
                                                  Propose rules for commands with no matching rule
  permcop version                                 Print version
  permcop help                                    Show this help message

Config files (merged in priority order, highest first):
  .permcop.local.toml              project local  (gitignored; personal overlay)
  .permcop.toml                    project shared (committed; team policy)
  ~/.config/permcop/config.local.toml  global local
  ~/.config/permcop/config.toml        global shared
  Audit log: ~/.local/share/permcop/projects/<name>/audit.log  (per-project, set by init)
             ~/.local/share/permcop/audit.log                  (global default)
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

const usageSuggest = `permcop suggest — Propose rules for commands that had no matching rule

Usage:
  permcop suggest [--n N] [--global] [--shared] [--dry-run] [--log path]

Flags:
  --n N       Number of recent unmatched commands to surface (default: 20)
  --global    Use global config scope (~/.config/permcop/) instead of project
  --shared    Write to the shared (committed) config instead of the local variant
  --dry-run   Print generated TOML to stdout; do not open editor or write
  --log path  Override audit log path
  --help      Show this help message

Default destination (no flags): .permcop.local.toml in CWD

Interactive TUI (TTY):
  j / ↓        move down
  k / ↑        move up
  e / Enter    open $EDITOR for the focused command, confirm, return to list
  Space        mark focused command as skipped (toggle)
  q            quit and write all confirmed rules
  Esc / Ctrl+C quit without writing

Examples:
  permcop suggest              # interactive pager: browse, edit, confirm
  permcop suggest --dry-run    # preview generated TOML for all recent misses
  permcop suggest --n 50       # surface last 50 unmatched commands
  permcop suggest --global     # target global config
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		if len(os.Args) >= 3 && os.Args[2] == "import-claude-settings" {
			fmt.Print(usageImportClaudeSettings)
		} else {
			fmt.Print(usage)
		}
		os.Exit(0)
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
		global := len(os.Args) >= 3 && os.Args[2] == "--global"
		runInit(global)
	case "suggest":
		runSuggest(os.Args[2:])
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
				fmt.Print(usageImportClaudeSettings)
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
// tool call, and writes a structured JSON decision to stdout before exiting 0.
// All failures — including unrecognized hook format — are fail-closed (deny) and logged.
func runCheck() {
	cwd, err := os.Getwd()
	if err != nil {
		// Fail-closed: cannot determine CWD means file path resolution is unsafe.
		writeHookDecision("deny", fmt.Sprintf("permcop: cannot determine working directory: %v", err))
		os.Exit(0)
	}

	// Load config early so we can log everything, including hook parse failures.
	cfg, cfgErr := config.Load(cwd)
	if cfgErr != nil {
		writeHookDecision("deny", fmt.Sprintf("permcop: config unavailable: %v", cfgErr))
		os.Exit(0)
	}

	logger := audit.New(cfg.Defaults.LogFile, cfg.Defaults.LogFormat, cfg.Defaults.LogMaxSizeMB, cfg.Defaults.LogMaxFiles)

	denyAndExit := func(reason string) {
		_ = logger.Log(audit.Entry{
			Timestamp:       time.Now(),
			Decision:        audit.DecisionDeny,
			Reason:          reason,
			OriginalCommand: "(unknown — hook input error)",
		})
		writeHookDecision("deny", reason)
		os.Exit(0)
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

	// No rule matched — output nothing and exit 0 so Claude Code's own
	// permission system handles the decision. Still log for audit trail.
	if result.FallThrough {
		_ = logger.Log(audit.Entry{
			Timestamp:       time.Now(),
			Decision:        audit.DecisionPassThrough,
			Reason:          "no matching rule; deferred to Claude Code",
			OriginalCommand: result.OriginalCommand,
			Units:           result.Units,
			RuleMatches:     result.RuleMatches,
		})
		os.Exit(0)
	}

	exitWithResult(result)
}

func exitWithResult(result *rules.Result) {
	if result.Allowed {
		writeHookDecision("allow", "")
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
	writeHookDecision("deny", reason)
	os.Exit(0)
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
	logger := audit.New(os.DevNull, "text", 0, 0)
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

	switch {
	case result.Allowed:
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
	case result.FallThrough:
		fmt.Printf("Result:   PASS (no matching rule — deferred to Claude Code)\n")
		for _, m := range result.RuleMatches {
			for _, sk := range m.SkippedRules {
				fmt.Printf("          skipped: rule=%q — %s\n", sk.Rule, sk.Reason)
			}
		}
	default:
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

// validatePatterns constructs a rules engine from cfg to catch invalid glob and
// regex patterns. Returns an error describing the first bad pattern, or nil.
func validatePatterns(cfg *config.Config) error {
	_, err := rules.New(cfg, nil)
	return err
}

// validateTOMLFragment parses a TOML rule fragment and checks that all patterns
// compile. Used by openEditorLoop before accepting user edits.
func validateTOMLFragment(tomlData string) error {
	cfg, err := config.ParseFragment(tomlData)
	if err != nil {
		return err
	}
	return validatePatterns(cfg)
}

// buildSuggestHeader returns the comment block written at the top of a suggest
// editor temp file. If validationErr is non-nil, it is included prominently.
func buildSuggestHeader(cmd string, passUnits []string, validationErr error) string {
	var h strings.Builder
	if validationErr != nil {
		h.WriteString("# ERROR — rule not saved. Fix the problem below and save, or clear the file to skip:\n")
		fmt.Fprintf(&h, "#   %v\n", validationErr)
		h.WriteString("#\n")
	}
	fmt.Fprintf(&h, "# Suggested rule for: %s\n", cmd)
	if len(passUnits) > 0 && (len(passUnits) != 1 || passUnits[0] != cmd) {
		fmt.Fprintf(&h, "# Unmatched units: %s\n", strings.Join(passUnits, ", "))
	}
	h.WriteString("# Edit as needed, then save and quit.\n\n")
	return h.String()
}

// openEditorLoop opens $EDITOR on a temp file containing tomlContent, validates
// the result after each save, and loops until the content is valid or the user
// clears the file. On each failed validation, the error is shown as a comment
// at the top of the file when the editor is re-opened, with the user's edits
// preserved. Returns the validated TOML and true, or ("", false) if the user
// cleared the content to skip.
func openEditorLoop(cmd string, passUnits []string, initialTOML string) (string, bool) {
	tmp, err := os.CreateTemp("", "permcop-suggest-*.toml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp file: %v\n", err)
		return "", false
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpName) }()

	editorBin := os.Getenv("EDITOR")
	if editorBin == "" {
		editorBin = "vi"
	}

	var validationErr error
	currentTOML := initialTOML
	for {
		header := buildSuggestHeader(cmd, passUnits, validationErr)
		if werr := os.WriteFile(tmpName, []byte(header+currentTOML), 0600); werr != nil {
			fmt.Fprintf(os.Stderr, "write temp file: %v\n", werr)
			return "", false
		}

		edCmd := exec.Command(editorBin, tmpName)
		edCmd.Stdin = os.Stdin
		edCmd.Stdout = os.Stdout
		edCmd.Stderr = os.Stderr
		if rerr := edCmd.Run(); rerr != nil {
			fmt.Fprintf(os.Stderr, "editor exited with error: %v\n", rerr)
		}

		content, rerr := os.ReadFile(tmpName)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "read temp file: %v\n", rerr)
			return "", false
		}
		edited := stripSuggestHeader(string(content))
		if strings.TrimSpace(edited) == "" {
			return "", false
		}

		if verr := validateTOMLFragment(edited); verr != nil {
			validationErr = verr
			currentTOML = edited // preserve user's edits across iterations
			continue
		}

		return edited, true
	}
}

// runValidate parses and validates config files, then checks that all rule
// patterns compile correctly.
//
// With no argument: shows all four config layers active from the current
// directory and validates each present file, then validates the merged config.
//
// With an explicit path: validates that single file.
func runValidate(path string) {
	if path != "" {
		runValidateSingleFile(path)
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "permcop: cannot determine working directory: %v\n", err)
		os.Exit(1)
	}

	layers, err := config.FindLayers(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "permcop: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Config layers active from %s (highest priority first):\n\n", cwd)
	anyPresent := false
	failed := false
	for _, layer := range layers {
		if !layer.Exists {
			fmt.Printf("  %-16s %s\n                   (not present)\n\n", layer.Label, layer.Path)
			continue
		}
		anyPresent = true
		cfg, loadErr := config.LoadFile(layer.Path)
		if loadErr != nil {
			fmt.Printf("  %-16s %s\n                   INVALID: %v\n\n", layer.Label, layer.Path, loadErr)
			failed = true
			continue
		}
		patErr := validatePatterns(cfg)
		if patErr != nil {
			fmt.Printf("  %-16s %s\n                   INVALID: %v\n\n", layer.Label, layer.Path, patErr)
			failed = true
			continue
		}
		fmt.Printf("  %-16s %s\n                   OK — %d rules, all patterns valid\n\n", layer.Label, layer.Path, len(cfg.Rules))
	}

	if !anyPresent {
		fmt.Println("No config files found. Run `permcop init` to create one.")
		os.Exit(0)
	}
	if failed {
		os.Exit(1)
	}

	// Validate the merged config (catches interaction effects and confirms the
	// full engine can be constructed).
	merged, err := config.Load(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Merged config INVALID: %v\n", err)
		os.Exit(1)
	}
	if err := validatePatterns(merged); err != nil {
		fmt.Fprintf(os.Stderr, "Merged config INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Merged: %d rules total — all patterns valid\n", len(merged.Rules))
}

// runValidateSingleFile validates one explicit config file path.
func runValidateSingleFile(path string) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	if err := validatePatterns(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %s\n", path)
	fmt.Printf("  %d rules, all patterns valid\n", len(cfg.Rules))
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
		fmt.Printf("  [1] Local  (%s) — personal overlay\n", filepath.Join(cfgDir, "config.local.toml"))
		fmt.Printf("  [2] Shared (%s) — used in all sessions\n", filepath.Join(cfgDir, "config.toml"))
		if promptChoice("Choice [1/2] (default: 1): ", 2) == 2 {
			cfgPath = filepath.Join(cfgDir, "config.toml")
		} else {
			cfgPath = filepath.Join(cfgDir, "config.local.toml")
		}
	} else {
		if _, err := os.Stat(filepath.Join(cwd, ".git")); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: no .git directory in %s; creating config here anyway\n", cwd)
		}
		fmt.Println("Create project config as:")
		fmt.Printf("  [1] Local  (.permcop.local.toml) — gitignored; personal overlay\n")
		fmt.Printf("  [2] Shared (.permcop.toml)       — committed to repo; team policy\n")
		if promptChoice("Choice [1/2] (default: 1): ", 2) == 2 {
			cfgPath = filepath.Join(cwd, ".permcop.toml")
		} else {
			cfgPath = filepath.Join(cwd, ".permcop.local.toml")
		}
	}

	fmt.Printf("Config path: %s\n", cfgPath)

	// 2. Create starter config if not present
	logFile := "~/.local/share/permcop/audit.log"
	if !global {
		base := filepath.Base(cwd)
		if base == "" || base == "." {
			base = "project"
		}
		logFile = fmt.Sprintf("~/.local/share/permcop/projects/%s/audit.log", base)
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, []byte(starterConfigFor(logFile)), 0600); err != nil {
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
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, origMode); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
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
	switch {
	case sourcePath != "":
		sourcePaths = []string{sourcePath}
	case global:
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
	default:
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
	if _, err := fmt.Fprint(f, "\n"+content); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "write %s: %v\n", destPath, err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close %s: %v\n", destPath, err)
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
	_, _ = fmt.Scanln(&resp)
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
	_, _ = fmt.Scanln(&resp)
	if strings.ToLower(strings.TrimSpace(resp)) == "n" {
		return
	}
	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not update .gitignore: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()
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
// cmdEntry holds aggregated information about a command seen in the audit log.
type cmdEntry struct {
	command   string
	count     int
	lastSeen  time.Time
	passUnits []string // unit values with no matching allow rule, from most recent entry
}

func confirmAppend(destPath, content string) bool {
	fmt.Printf("Will append to %s:\n\n", destPath)
	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		fmt.Printf("  + %s\n", line)
	}
	fmt.Printf("\nAppend? [y/N] ")
	var resp string
	_, _ = fmt.Scanln(&resp)
	return strings.ToLower(strings.TrimSpace(resp)) == "y"
}

// runSuggest reads recent PASS entries from the audit log, lets the user pick
// which commands to convert to rules, opens $EDITOR for each draft, and appends
// confirmed rules to the appropriate config file.
func runSuggest(args []string) {
	n := 20
	var global, dryRun, shared bool
	var logOverride string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--global":
			global = true
		case arg == "--shared":
			shared = true
		case arg == "--dry-run":
			dryRun = true
		case arg == "--help" || arg == "-h":
			fmt.Print(usageSuggest)
			os.Exit(0)
		case arg == "--n":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --n requires a value")
				os.Exit(1)
			}
			i++
			if _, err := fmt.Sscan(args[i], &n); err != nil || n <= 0 {
				fmt.Fprintln(os.Stderr, "error: --n must be a positive integer")
				os.Exit(1)
			}
		case strings.HasPrefix(arg, "--n="):
			val := strings.TrimPrefix(arg, "--n=")
			if _, err := fmt.Sscan(val, &n); err != nil || n <= 0 {
				fmt.Fprintln(os.Stderr, "error: --n must be a positive integer")
				os.Exit(1)
			}
		case arg == "--log":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --log requires a value")
				os.Exit(1)
			}
			i++
			logOverride = args[i]
		case strings.HasPrefix(arg, "--log="):
			logOverride = strings.TrimPrefix(arg, "--log=")
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n\n%s", arg, usageSuggest)
			os.Exit(1)
		}
	}

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

	// Determine audit log path.
	logPath := logOverride
	if logPath == "" {
		cfg, cfgErr := config.Load(cwd)
		if cfgErr == nil {
			logPath = cfg.Defaults.LogFile
		}
		if logPath == "" {
			logPath = filepath.Join(home, ".local", "share", "permcop", "audit.log")
		}
	}

	// Determine dest config path (same logic as import-claude-settings).
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

	// Read PASS entries.
	entries, err := audit.ReadPASSEntries(logPath, n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read audit log: %v\n", err)
		os.Exit(1)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "No unmatched commands found in the audit log.")
		return
	}

	// Deduplicate by OriginalCommand, most-recent-first.
	seen := map[string]*cmdEntry{}
	var ordered []string
	for _, e := range entries {
		cmd := e.OriginalCommand
		pu := passUnitsFrom(e)
		if s, ok := seen[cmd]; ok {
			s.count++
			if e.Timestamp.After(s.lastSeen) {
				s.lastSeen = e.Timestamp
				s.passUnits = pu
			}
		} else {
			seen[cmd] = &cmdEntry{command: cmd, count: 1, lastSeen: e.Timestamp, passUnits: pu}
			ordered = append(ordered, cmd)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		return seen[ordered[i]].lastSeen.After(seen[ordered[j]].lastSeen)
	})

	if dryRun {
		fmt.Println("Commands deferred to Claude Code (no permcop rule matched):")
		fmt.Println()
		for i, cmd := range ordered {
			s := seen[cmd]
			fmt.Printf("  %2d.  %-45s %d×  last seen %s\n",
				i+1, labelForEntry(cmd, s.passUnits), s.count, timeAgo(s.lastSeen))
		}
		fmt.Println()
		fmt.Println("# Generated rules (dry-run):")
		fmt.Println()
		for _, cmd := range ordered {
			suggested := suggestRulesForUnits(seen[cmd].passUnits, cmd)
			fmt.Print(importer.RulesToTOML(suggested))
		}
		return
	}

	// Prompt for selection and editing.
	var confirmedTOML []string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		confirmedTOML = runSuggestTUI(ordered, seen, destPath)
	} else {
		fmt.Println("Commands deferred to Claude Code (no permcop rule matched):")
		fmt.Println()
		for i, cmd := range ordered {
			s := seen[cmd]
			fmt.Printf("  %2d.  %-45s %d×  last seen %s\n",
				i+1, labelForEntry(cmd, s.passUnits), s.count, timeAgo(s.lastSeen))
		}
		fmt.Println()
		fmt.Printf("Add rules for [1-%d, all, none]: ", len(ordered))
		reader := bufio.NewReader(os.Stdin)
		selInput, _ := reader.ReadString('\n')
		idxs := parseSelection(strings.TrimSpace(selInput), len(ordered))
		var selected []int
		for _, i := range idxs {
			selected = append(selected, i-1)
		}
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, "No commands selected.")
			return
		}
		for _, idx := range selected {
			cmd := ordered[idx]
			passUnits := seen[cmd].passUnits
			suggested := suggestRulesForUnits(passUnits, cmd)
			tomlContent := importer.RulesToTOML(suggested)

			edited, ok := openEditorLoop(cmd, passUnits, tomlContent)
			if !ok {
				fmt.Fprintln(os.Stderr, "Empty content; skipping.")
				continue
			}
			if confirmAppend(destPath, edited) {
				confirmedTOML = append(confirmedTOML, edited)
			}
		}
	}

	if len(confirmedTOML) == 0 {
		return
	}

	// Append all confirmed rules in one write.
	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "create config dir: %v\n", err)
		os.Exit(1)
	}
	f, err := os.OpenFile(destPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", destPath, err)
		os.Exit(1)
	}
	for _, content := range confirmedTOML {
		if _, err := fmt.Fprint(f, "\n"+content); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "write %s: %v\n", destPath, err)
			os.Exit(1)
		}
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close %s: %v\n", destPath, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d rule(s) to %s\n", len(confirmedTOML), destPath)

	if !global && !shared {
		offerGitignore(cwd, ".permcop.local.toml")
	}
}

// suggestRule generates a draft permcop Rule for the given command.
func suggestRule(command string) config.Rule {
	tokens := strings.Fields(command)
	var name string
	var pattern config.Pattern

	switch {
	case len(tokens) == 0:
		name = "Allow command"
		pattern = config.Pattern{Type: config.PatternExact, Pattern: command}
	case len(tokens) <= 2:
		name = "Allow " + strings.Join(tokens, " ")
		pattern = config.Pattern{Type: config.PatternExact, Pattern: command}
	default:
		name = "Allow " + tokens[0] + " " + tokens[1]
		pattern = config.Pattern{Type: config.PatternGlob, Pattern: tokens[0] + " " + tokens[1] + " *"}
	}

	return config.Rule{
		Name:        name,
		Description: "Auto-generated by permcop suggest",
		Allow:       []config.Pattern{pattern},
	}
}

// passUnitsFrom returns the unit values from e that had no matching allow rule.
// Handles both text-format entries (Action == "pass") and JSON-format entries
// (Action == "deny" with empty Rule), as well as legacy entries with empty Action.
func passUnitsFrom(e audit.Entry) []string {
	var units []string
	for _, m := range e.RuleMatches {
		if m.Action != "allow" {
			units = append(units, m.Unit)
		}
	}
	return units
}

// labelForEntry returns a display label for cmd, annotating with [→ unit] when
// the pass units differ from the full command (i.e., the command is a chain and
// only some sub-commands are unmatched).
func labelForEntry(cmd string, passUnits []string) string {
	if len(passUnits) > 0 && (len(passUnits) != 1 || passUnits[0] != cmd) {
		return fmt.Sprintf("%s  [→ %s]", cmd, strings.Join(passUnits, ", "))
	}
	return cmd
}

// suggestRulesForUnits generates draft permcop Rules for each pass unit.
// If passUnits is empty, falls back to generating a rule for the full command.
func suggestRulesForUnits(passUnits []string, fallback string) []config.Rule {
	targets := passUnits
	if len(targets) == 0 {
		targets = []string{fallback}
	}
	rules := make([]config.Rule, 0, len(targets))
	for _, unit := range targets {
		rules = append(rules, suggestRule(unit))
	}
	return rules
}

// timeAgo returns a human-readable description of how long ago t was.
func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case d < 24*time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case d < 48*time.Hour:
		return "yesterday"
	default:
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%d days ago", days)
	}
}

// tuiItemStatus tracks per-item state in the suggest TUI.
const (
	tuiUnvisited = 0
	tuiConfirmed = 1
	tuiSkipped   = -1
)

// tuiState holds all mutable state for the suggest pager TUI.
type tuiState struct {
	items  []string
	seen   map[string]*cmdEntry
	status []int    // tuiUnvisited / tuiConfirmed / tuiSkipped per item
	toml   []string // confirmed TOML per item (meaningful only when status==tuiConfirmed)
	cursor int
	offset int
	termW  int
	termH  int
	viewH  int // rows available for list items = termH - 9 (header+blank+sep+detail+sep+footer)
}

// clampOffset ensures cursor is visible in the viewport.
func (t *tuiState) clampOffset() {
	if t.cursor < t.offset {
		t.offset = t.cursor
	}
	if t.cursor >= t.offset+t.viewH {
		t.offset = t.cursor - t.viewH + 1
	}
	if t.offset < 0 {
		t.offset = 0
	}
	max := len(t.items) - t.viewH
	if max < 0 {
		max = 0
	}
	if t.offset > max {
		t.offset = max
	}
}

func (t *tuiState) statusChar(i int) string {
	switch t.status[i] {
	case tuiConfirmed:
		return "✓"
	case tuiSkipped:
		return "-"
	default:
		return " "
	}
}

const (
	tuiPrefixCols = 6 // "  [ ] "
	tuiDetailH    = 4 // detail panel height: command + count/time + units + blank
)

func (t *tuiState) formatRow(i int) string {
	available := t.termW - tuiPrefixCols - 1
	if available < 10 {
		available = 10
	}
	cmdLabel := t.items[i]
	runes := []rune(cmdLabel)
	if len(runes) > available {
		runes = append(runes[:available-1], '…')
		cmdLabel = string(runes)
	}
	return fmt.Sprintf("  [%s] %s", t.statusChar(i), cmdLabel)
}

func (t *tuiState) renderDetail() {
	i := t.cursor
	cmd := t.items[i]
	entry := t.seen[cmd]

	// Line 1: full command, truncated to terminal width.
	maxW := t.termW - 4
	if maxW < 10 {
		maxW = 10
	}
	cmdDisplay := cmd
	if runes := []rune(cmdDisplay); len(runes) > maxW {
		cmdDisplay = string(append(runes[:maxW-1], '…'))
	}
	fmt.Printf("\033[K  %s\r\n", cmdDisplay)

	// Line 2: count + last seen.
	fmt.Printf("\033[K  %d×  ·  last seen %s\r\n", entry.count, timeAgo(entry.lastSeen))

	// Line 3: pass units, only when they differ from the command itself.
	if len(entry.passUnits) > 0 && (len(entry.passUnits) != 1 || entry.passUnits[0] != cmd) {
		unitsStr := strings.Join(entry.passUnits, ", ")
		maxU := t.termW - 7
		if maxU < 10 {
			maxU = 10
		}
		if runes := []rune(unitsStr); len(runes) > maxU {
			unitsStr = string(append(runes[:maxU-1], '…'))
		}
		fmt.Printf("\033[K  → %s\r\n", unitsStr)
	} else {
		fmt.Print("\033[K\r\n")
	}

	// Line 4: blank padding.
	fmt.Print("\033[K\r\n")
}

func (t *tuiState) render() {
	fmt.Print("\033[H")
	fmt.Printf("\033[K  Commands without permcop rules (%d total):\r\n", len(t.items))
	fmt.Print("\033[K\r\n")

	end := t.offset + t.viewH
	if end > len(t.items) {
		end = len(t.items)
	}
	for i := t.offset; i < end; i++ {
		line := t.formatRow(i)
		fmt.Print("\033[K")
		if i == t.cursor {
			fmt.Printf("\033[1;7m%s\033[0m\r\n", line)
		} else {
			fmt.Printf("%s\r\n", line)
		}
	}
	// Blank out any leftover lines from a previous render (e.g. after resize).
	for i := end - t.offset; i < t.viewH; i++ {
		fmt.Print("\033[K\r\n")
	}

	// Separator + detail panel.
	fmt.Printf("\033[K%s\r\n", strings.Repeat("─", t.termW))
	t.renderDetail()
	fmt.Printf("\033[K%s\r\n", strings.Repeat("─", t.termW))

	pos := fmt.Sprintf("%d/%d", t.cursor+1, len(t.items))
	fmt.Printf("\033[K  \033[2m<e/Enter> edit  <Space> skip  <j/k> navigate  <q> quit   %s\033[0m", pos)
}

// editItem drops out of raw mode, opens $EDITOR for item idx, shows confirm
// prompt, then re-enters raw mode. state is updated in place.
func (t *tuiState) editItem(idx int, destPath string, state **term.State) {
	cmd := t.items[idx]
	entry := t.seen[cmd]
	fd := int(os.Stdin.Fd())

	// Restore cooked mode so editor and confirm prompt work normally.
	if *state != nil {
		term.Restore(fd, *state) //nolint:errcheck
		*state = nil
	}
	fmt.Print("\033[2J\033[H") // clear screen before editor takes over

	suggested := suggestRulesForUnits(entry.passUnits, cmd)
	tomlContent := importer.RulesToTOML(suggested)

	edited, ok := openEditorLoop(cmd, entry.passUnits, tomlContent)
	if !ok {
		fmt.Fprintln(os.Stderr, "Empty content; skipping.")
	} else if confirmAppend(destPath, edited) {
		t.status[idx] = tuiConfirmed
		t.toml[idx] = edited
	}

	// Re-enter raw mode and redraw.
	*state, _ = term.MakeRaw(fd)
	fmt.Print("\033[2J\033[H")
}

// runSuggestTUI runs the full-screen pager TUI for permcop suggest.
// Returns TOML strings for all confirmed rules.
func runSuggestTUI(ordered []string, seen map[string]*cmdEntry, destPath string) []string {
	fd := int(os.Stdin.Fd())

	w, h, err := term.GetSize(fd)
	if err != nil || w <= 0 {
		w = 80
	}
	if err != nil || h <= 0 {
		h = 24
	}

	// Layout: header(1) + blank(1) + list(viewH) + sep(1) + detail(tuiDetailH) + sep(1) + footer(1) = viewH + 6 + tuiDetailH
	viewH := h - 6 - tuiDetailH
	if viewH < 2 {
		viewH = 2
	}

	t := &tuiState{
		items:  ordered,
		seen:   seen,
		status: make([]int, len(ordered)),
		toml:   make([]string, len(ordered)),
		termW:  w,
		termH:  h,
		viewH:  viewH,
	}

	var state *term.State
	state, _ = term.MakeRaw(fd)
	defer func() {
		if state != nil {
			term.Restore(fd, state) //nolint:errcheck
		}
	}()

	fmt.Print("\033[2J\033[H") // initial clear

	buf := make([]byte, 16)
	for {
		t.render()
		n, rerr := os.Stdin.Read(buf)
		if rerr != nil {
			break
		}
		b := buf[:n]

		switch {
		case len(b) == 1 && b[0] == 'q':
			// Quit and write confirmed rules.
			fmt.Print("\r\n")
			var out []string
			for i, s := range t.status {
				if s == tuiConfirmed {
					out = append(out, t.toml[i])
				}
			}
			return out

		case len(b) == 1 && (b[0] == 3 /* Ctrl+C */ || b[0] == 27 /* Esc */):
			// Discard — exit without writing.
			fmt.Print("\r\n")
			return nil

		case len(b) == 1 && (b[0] == 'e' || b[0] == 13 /* Enter */):
			t.editItem(t.cursor, destPath, &state)

		case len(b) == 1 && b[0] == ' ':
			if t.status[t.cursor] == tuiSkipped {
				t.status[t.cursor] = tuiUnvisited
			} else {
				t.status[t.cursor] = tuiSkipped
			}

		case len(b) == 1 && b[0] == 'j':
			if t.cursor < len(t.items)-1 {
				t.cursor++
				t.clampOffset()
			}

		case len(b) == 1 && b[0] == 'k':
			if t.cursor > 0 {
				t.cursor--
				t.clampOffset()
			}

		case len(b) >= 3 && b[0] == 27 && b[1] == '[' && b[2] == 'B': // Down arrow
			if t.cursor < len(t.items)-1 {
				t.cursor++
				t.clampOffset()
			}

		case len(b) >= 3 && b[0] == 27 && b[1] == '[' && b[2] == 'A': // Up arrow
			if t.cursor > 0 {
				t.cursor--
				t.clampOffset()
			}
		}
	}
	return nil
}

// parseSelection parses a selection string into sorted 1-based indices.
// Supports: "all", "none"/empty, numbers (1), ranges (1-3), comma-separated.
func parseSelection(input string, n int) []int {
	input = strings.TrimSpace(input)
	if input == "" || strings.EqualFold(input, "none") {
		return nil
	}
	if strings.EqualFold(input, "all") {
		result := make([]int, n)
		for i := range result {
			result[i] = i + 1
		}
		return result
	}

	seen := map[int]bool{}
	var result []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if dash := strings.Index(part, "-"); dash > 0 {
			var lo, hi int
			fmt.Sscan(part[:dash], &lo)   //nolint:errcheck
			fmt.Sscan(part[dash+1:], &hi) //nolint:errcheck
			for i := lo; i <= hi; i++ {
				if i >= 1 && i <= n && !seen[i] {
					seen[i] = true
					result = append(result, i)
				}
			}
		} else {
			var num int
			fmt.Sscan(part, &num) //nolint:errcheck
			if num >= 1 && num <= n && !seen[num] {
				seen[num] = true
				result = append(result, num)
			}
		}
	}
	sort.Ints(result)
	return result
}

// stripSuggestHeader removes the leading comment lines and blank lines that
// runSuggest writes to the temp file before opening the editor, so that only
// the TOML rule content is written to the config file.
func stripSuggestHeader(s string) string {
	lines := strings.Split(s, "\n")
	start := 0
	for start < len(lines) {
		t := strings.TrimSpace(lines[start])
		if t == "" || strings.HasPrefix(t, "#") {
			start++
		} else {
			break
		}
	}
	return strings.Join(lines[start:], "\n")
}

func starterConfigFor(logFile string) string {
	return strings.Replace(
		starterConfig,
		`"~/.local/share/permcop/audit.log"`,
		fmt.Sprintf("%q", logFile),
		1,
	)
}

const starterConfig = `# permcop configuration
# Rules are evaluated in order.
# Pass 1: if ANY deny pattern matches ANY command unit -> DENY
# Pass 2: if ALL command units are covered by allow patterns -> ALLOW
# No match -> PASS (deferred to Claude Code's own permission system)

[defaults]
log_file = "~/.local/share/permcop/audit.log"
log_format = "text"              # "text" or "json"
# log_max_size_mb = 10           # rotate when log exceeds this size (0 = never rotate)
# log_max_files   = 5            # number of rotated copies to keep
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
