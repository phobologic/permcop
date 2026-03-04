// Package importer converts Claude Code permission rules into permcop config rules.
package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mikecafarella/permcop/internal/config"
)

// ClaudeSettings is the subset of Claude Code's settings.json we care about.
type ClaudeSettings struct {
	Permissions ClaudePermissions `json:"permissions"`
}

// ClaudePermissions holds the allow/deny/ask rule lists.
type ClaudePermissions struct {
	Allow []string `json:"allow"`
	Ask   []string `json:"ask"`
	Deny  []string `json:"deny"`
}

// ImportResult holds the converted rules and any warnings from the import.
type ImportResult struct {
	Rules    []config.Rule
	Warnings []string
	Skipped  []string // rules that couldn't be translated
}

// FromFile reads a Claude Code settings.json file and converts its permission
// rules to permcop rules.
func FromFile(path string) (*ImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var settings ClaudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return Convert(settings.Permissions)
}

// Convert translates Claude Code permission entries into permcop rules.
// It produces one rule grouping all Bash allows/denies, and separate rules
// for file-access (Read/Edit) allows/denies. Unrecognised tool types are
// reported in the Skipped field.
func Convert(perms ClaudePermissions) (*ImportResult, error) {
	result := &ImportResult{}

	// Collect parsed entries per tool type
	bashAllow := []string{}
	bashDeny := []string{}
	readAllow := []string{}
	readDeny := []string{}
	writeAllow := []string{}
	writeDeny := []string{}

	for _, entry := range perms.Allow {
		tool, pattern, ok := parseEntry(entry)
		if !ok {
			result.Skipped = append(result.Skipped, entry)
			continue
		}
		switch tool {
		case "Bash":
			bashAllow = append(bashAllow, pattern)
		case "Read":
			readAllow = append(readAllow, pattern)
		case "Edit", "Write", "MultiEdit":
			writeAllow = append(writeAllow, pattern)
		default:
			result.Skipped = append(result.Skipped, entry)
		}
	}

	for _, entry := range perms.Deny {
		tool, pattern, ok := parseEntry(entry)
		if !ok {
			result.Skipped = append(result.Skipped, entry)
			continue
		}
		switch tool {
		case "Bash":
			bashDeny = append(bashDeny, pattern)
		case "Read":
			readDeny = append(readDeny, pattern)
		case "Edit", "Write", "MultiEdit":
			writeDeny = append(writeDeny, pattern)
		default:
			result.Skipped = append(result.Skipped, entry)
		}
	}

	// "ask" rules become warnings — permcop has no interactive mode.
	for _, entry := range perms.Ask {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("ask rule %q has no permcop equivalent — omitted (consider adding to allow or deny)", entry))
	}

	// Build permcop rules
	if len(bashAllow) > 0 || len(bashDeny) > 0 {
		rule := config.Rule{
			Name:        "Imported bash rules (from Claude Code settings)",
			Description: "Automatically imported from Claude Code permissions.allow/deny",
		}
		for _, p := range bashAllow {
			rule.Allow = append(rule.Allow, toPattern(p))
		}
		for _, p := range bashDeny {
			rule.Deny = append(rule.Deny, toPattern(p))
		}
		result.Rules = append(result.Rules, rule)
	}

	if len(readAllow) > 0 || len(readDeny) > 0 || len(writeAllow) > 0 || len(writeDeny) > 0 {
		rule := config.Rule{
			Name:        "Imported file access rules (from Claude Code settings)",
			Description: "Automatically imported from Claude Code Read/Edit permissions",
			AllowRead:   readAllow,
			DenyRead:    readDeny,
			AllowWrite:  writeAllow,
			DenyWrite:   writeDeny,
		}
		result.Rules = append(result.Rules, rule)
	}

	if len(result.Rules) == 0 && len(result.Skipped) == 0 {
		result.Warnings = append(result.Warnings, "no translatable permission rules found in Claude Code settings")
	}

	return result, nil
}

// parseEntry splits a Claude Code rule string like "Bash(git log *)" into
// ("Bash", "git log *", true). A bare "Bash" (no parentheses) returns
// ("Bash", "*", true) meaning match everything.
func parseEntry(entry string) (tool, pattern string, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", "", false
	}

	idx := strings.Index(entry, "(")
	if idx == -1 {
		// Bare tool name, e.g. "Bash" — matches everything
		return entry, "*", true
	}

	tool = entry[:idx]
	rest := entry[idx+1:]
	if !strings.HasSuffix(rest, ")") {
		// Malformed entry
		return "", "", false
	}
	pattern = rest[:len(rest)-1]
	return tool, pattern, true
}

// toPattern converts a Claude Code glob string to a permcop Pattern.
// Claude Code uses "*" glob syntax which maps directly to our glob type.
func toPattern(pattern string) config.Pattern {
	return config.Pattern{
		Type:    config.PatternGlob,
		Pattern: pattern,
	}
}

// RulesToTOML renders a slice of rules as TOML [[rules]] blocks for insertion
// into a permcop config file.
func RulesToTOML(rules []config.Rule) string {
	var sb strings.Builder
	for _, r := range rules {
		sb.WriteString("[[rules]]\n")
		sb.WriteString(fmt.Sprintf("name = %q\n", r.Name))
		if r.Description != "" {
			sb.WriteString(fmt.Sprintf("description = %q\n", r.Description))
		}

		if len(r.Allow) > 0 {
			sb.WriteString("allow = [\n")
			for _, p := range r.Allow {
				sb.WriteString(fmt.Sprintf("  { type = %q, pattern = %q },\n", p.Type, p.Pattern))
			}
			sb.WriteString("]\n")
		}

		if len(r.Deny) > 0 {
			sb.WriteString("deny = [\n")
			for _, p := range r.Deny {
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

		if len(r.DenyRead) > 0 {
			sb.WriteString("deny_read = [\n")
			for _, p := range r.DenyRead {
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

		if len(r.DenyWrite) > 0 {
			sb.WriteString("deny_write = [\n")
			for _, p := range r.DenyWrite {
				sb.WriteString(fmt.Sprintf("  %q,\n", p))
			}
			sb.WriteString("]\n")
		}

		sb.WriteString("\n")
	}
	return sb.String()
}
