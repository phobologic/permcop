// Package interactive provides the default-deny interactive prompt flow.
// When permcop denies a command because no allow rule matched, it opens
// /dev/tty and offers to write a new rule to .permcop.local.toml.
// In non-TTY environments (CI, pipes) it returns silently so the normal
// deny path is unaffected.
package interactive

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mikecafarella/permcop/internal/config"
	"github.com/mikecafarella/permcop/internal/parser"
	"github.com/mikecafarella/permcop/internal/rules"
)

// PromptAndAdd asks the user whether to add a rule covering the denied unit.
// If approved (with optional editor step), the rule is appended to targetPath.
// Returns (true, nil) if the rule was saved, (false, nil) if the user declined
// or no TTY is available, or (false, err) on an I/O error after the user approved.
func PromptAndAdd(result *rules.Result, targetPath string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, nil // no TTY — silent deny unchanged
	}
	defer tty.Close()

	unit := result.DecidingUnit
	if unit == nil {
		return false, nil
	}

	draftRule := generateDraftRule(result, unit)
	draftTOML := ruleToTOML(draftRule)

	fmt.Fprintf(os.Stderr, "\npermcop: default deny — no rule covers: %s\n", formatUnit(unit))
	fmt.Fprintf(os.Stderr, "  will save to: %s\n\n", targetPath)

	reader := bufio.NewReader(tty)

	for {
		fmt.Fprintf(tty, "Add a rule? [y/e/N] ")
		line, _ := reader.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))

		switch answer {
		case "n", "":
			return false, nil

		case "y":
			if err := appendToFile(targetPath, draftTOML); err != nil {
				return false, fmt.Errorf("write rule: %w", err)
			}
			fmt.Fprintf(os.Stderr, "\npermcop: rule saved. Allowing this invocation.\n")
			return true, nil

		case "e":
			// Show the draft before opening the editor.
			fmt.Fprintf(os.Stderr, "\nDraft rule:\n")
			for _, l := range strings.Split(strings.TrimRight(draftTOML, "\n"), "\n") {
				fmt.Fprintf(os.Stderr, "  %s\n", l)
			}
			fmt.Fprintf(os.Stderr, "\n")

			edited, err := openEditor(draftTOML, tty)
			if err != nil {
				fmt.Fprintf(os.Stderr, "permcop: editor error: %v\n\n", err)
				continue
			}

			// Validate the edited TOML by parsing it.
			var cfg config.Config
			if _, err := toml.Decode(edited, &cfg); err != nil {
				fmt.Fprintf(os.Stderr, "permcop: invalid TOML: %v\n\n", err)
				draftTOML = edited // preserve edits for the next round
				continue
			}
			if len(cfg.Rules) == 0 {
				fmt.Fprintf(os.Stderr, "permcop: no [[rules]] found in edited content\n\n")
				draftTOML = edited
				continue
			}

			if err := appendToFile(targetPath, edited); err != nil {
				return false, fmt.Errorf("write rule: %w", err)
			}
			fmt.Fprintf(os.Stderr, "\npermcop: rule saved. Allowing this invocation.\n")
			return true, nil

		default:
			fmt.Fprintf(tty, "Please enter y, e, or N.\n")
		}
	}
}

// generateDraftRule builds a minimal allow rule for the denied unit.
// For commands, it generates an exact match on the full command value.
// For file paths, it generates allow_read or allow_write with the exact path.
// Exact match is the safest starting point; the user can widen in the editor.
func generateDraftRule(result *rules.Result, unit *parser.CheckableUnit) config.Rule {
	switch unit.Kind {
	case parser.UnitCommand:
		return config.Rule{
			Name:  commandName(unit.Value),
			Allow: []config.Pattern{{Type: config.PatternExact, Pattern: unit.Value}},
		}
	case parser.UnitReadFile:
		return config.Rule{
			Name:      filepath.Base(unit.Value),
			AllowRead: []string{unit.Value},
		}
	case parser.UnitWriteFile:
		return config.Rule{
			Name:       filepath.Base(unit.Value),
			AllowWrite: []string{unit.Value},
		}
	}
	return config.Rule{Name: "unnamed"}
}

// commandName returns a short name derived from the first two words of a
// command string (e.g. "git push origin main" → "git push").
func commandName(cmd string) string {
	words := strings.Fields(cmd)
	if len(words) == 0 {
		return "unnamed"
	}
	if len(words) >= 2 {
		return words[0] + " " + words[1]
	}
	return words[0]
}

// formatUnit returns a human-readable label for a unit for display in prompts.
func formatUnit(unit *parser.CheckableUnit) string {
	switch unit.Kind {
	case parser.UnitReadFile:
		return fmt.Sprintf("read %q", unit.Value)
	case parser.UnitWriteFile:
		return fmt.Sprintf("write %q", unit.Value)
	default:
		return fmt.Sprintf("%q", unit.Value)
	}
}

// ruleToTOML renders a single config.Rule as a [[rules]] TOML block.
// The format matches the style used by the importer for consistency.
func ruleToTOML(r config.Rule) string {
	var sb strings.Builder
	sb.WriteString("[[rules]]\n")
	sb.WriteString(fmt.Sprintf("name = %q\n", r.Name))

	if len(r.Allow) > 0 {
		sb.WriteString("allow = [\n")
		for _, p := range r.Allow {
			sb.WriteString(fmt.Sprintf("  { type = %q, pattern = %q },\n", p.Type, p.Pattern))
		}
		sb.WriteString("]\n")
	}
	if len(r.AllowRead) > 0 {
		sb.WriteString("allow_read = [\n")
		for _, p := range r.AllowRead {
			sb.WriteString(fmt.Sprintf("  %q,\n", p))
		}
		sb.WriteString("]\n")
	}
	if len(r.AllowWrite) > 0 {
		sb.WriteString("allow_write = [\n")
		for _, p := range r.AllowWrite {
			sb.WriteString(fmt.Sprintf("  %q,\n", p))
		}
		sb.WriteString("]\n")
	}
	sb.WriteString("\n")
	return sb.String()
}

// openEditor writes content to a temp file, opens $EDITOR (fallback: vi),
// and returns the file's contents after the editor exits. tty is used as the
// editor's stdin/stdout/stderr so it works correctly in hook context where
// the process's stdin has been consumed by the hook JSON payload.
func openEditor(content string, tty *os.File) (string, error) {
	f, err := os.CreateTemp("", "permcop-rule-*.toml")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpName := f.Name()
	defer os.Remove(tmpName)

	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return "", fmt.Errorf("write temp file: %w", err)
	}
	f.Close()

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command(editor, tmpName)
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("editor exited: %w", err)
	}

	data, err := os.ReadFile(tmpName)
	if err != nil {
		return "", fmt.Errorf("read edited file: %w", err)
	}
	return string(data), nil
}

// appendToFile appends content to path, creating the file if it doesn't exist.
// A blank separator line is prepended when appending to a non-empty file.
func appendToFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > 0 {
		content = "\n" + content
	}
	_, err = fmt.Fprint(f, content)
	return err
}
