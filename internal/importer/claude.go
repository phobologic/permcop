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
	return FromFiles([]string{path})
}

// FromFiles reads one or more Claude Code settings files, merges their
// permission entries, and converts the result to permcop rules. This mirrors
// how Claude Code itself combines settings.json and settings.local.json.
func FromFiles(paths []string) (*ImportResult, error) {
	var merged ClaudePermissions
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var settings ClaudeSettings
		if err := json.Unmarshal(data, &settings); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		merged.Allow = append(merged.Allow, settings.Permissions.Allow...)
		merged.Ask = append(merged.Ask, settings.Permissions.Ask...)
		merged.Deny = append(merged.Deny, settings.Permissions.Deny...)
	}
	return Convert(merged)
}

// Convert translates Claude Code permission entries into permcop rules.
// Bash entries are grouped by the first word of the command pattern into
// separate named rules (e.g. "Imported: git", "Imported: make"). Wildcard
// and unparseable patterns land in "Imported: (other)", always emitted last.
// File-access entries (Read/Edit/Write) produce a single "Imported: file access"
// rule. Unrecognised tool types are reported in the Skipped field.
func Convert(perms ClaudePermissions) (*ImportResult, error) {
	result := &ImportResult{}

	// bashGroup holds patterns collected under one command-prefix key.
	type bashGroup struct {
		allow []config.Pattern
		deny  []config.Pattern
	}
	bashGroups := map[string]*bashGroup{}
	var bashOrder []string // insertion order; "(other)" is appended last

	addBash := func(prefix string, p config.Pattern, isDeny bool) {
		if _, ok := bashGroups[prefix]; !ok {
			bashGroups[prefix] = &bashGroup{}
			if prefix != "(other)" {
				bashOrder = append(bashOrder, prefix)
			}
		}
		if isDeny {
			bashGroups[prefix].deny = append(bashGroups[prefix].deny, p)
		} else {
			bashGroups[prefix].allow = append(bashGroups[prefix].allow, p)
		}
	}

	var readAllow, readDeny, writeAllow, writeDeny []string

	for _, entry := range perms.Allow {
		tool, pattern, ok := parseEntry(entry)
		if !ok {
			result.Skipped = append(result.Skipped, entry)
			continue
		}
		switch tool {
		case "Bash":
			addBash(groupPrefix(pattern), toPattern(pattern), false)
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
			addBash(groupPrefix(pattern), toPattern(pattern), true)
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

	// Emit one rule per bash group; "(other)" always goes last.
	if _, hasOther := bashGroups["(other)"]; hasOther {
		bashOrder = append(bashOrder, "(other)")
	}
	for _, prefix := range bashOrder {
		g := bashGroups[prefix]
		result.Rules = append(result.Rules, config.Rule{
			Name:        "Imported: " + prefix,
			Description: "Automatically imported from Claude Code permissions",
			Allow:       g.allow,
			Deny:        g.deny,
		})
	}

	if len(readAllow) > 0 || len(readDeny) > 0 || len(writeAllow) > 0 || len(writeDeny) > 0 {
		result.Rules = append(result.Rules, config.Rule{
			Name:        "Imported: file access",
			Description: "Automatically imported from Claude Code Read/Edit permissions",
			AllowRead:   readAllow,
			DenyRead:    readDeny,
			AllowWrite:  writeAllow,
			DenyWrite:   writeDeny,
		})
	}

	if len(result.Rules) == 0 && len(result.Skipped) == 0 {
		result.Warnings = append(result.Warnings, "no translatable permission rules found in Claude Code settings")
	}

	return result, nil
}

// groupPrefix extracts the first whitespace-delimited word of a glob pattern
// for use as a bash rule group key. A leading "./" is stripped so that
// "./permcop" and "permcop" land in the same group. Returns "(other)" for
// wildcards or empty patterns.
func groupPrefix(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimPrefix(pattern, "./")
	if pattern == "" || pattern == "*" {
		return "(other)"
	}
	if idx := strings.IndexAny(pattern, " \t:"); idx > 0 {
		pattern = pattern[:idx]
	}
	if pattern == "" || pattern == "*" {
		return "(other)"
	}
	return pattern
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
// Claude Code uses "*" glob syntax which maps directly to our glob type,
// except that a trailing ":*" wildcard maps to a prefix match so that the
// base command (with no arguments) is also covered.
//
//	"make install:*"    → { type = "prefix", pattern = "make install" }
//	"git log:--oneline" → { type = "glob",   pattern = "git log --oneline" }
//	"npm run test"      → { type = "glob",   pattern = "npm run test" }
func toPattern(pattern string) config.Pattern {
	if strings.HasSuffix(pattern, ":*") {
		return config.Pattern{
			Type:    config.PatternPrefix,
			Pattern: pattern[:len(pattern)-2],
		}
	}
	return config.Pattern{
		Type:    config.PatternGlob,
		Pattern: translateClaudePattern(pattern),
	}
}

// translateClaudePattern converts Claude Code's colon-separated argument syntax
// to permcop's space-separated glob format.
//
//	"git log:--oneline" → "git log --oneline"
//	"npm run test"      → "npm run test"  (unchanged, no colon)
func translateClaudePattern(pattern string) string {
	if idx := strings.Index(pattern, ":"); idx >= 0 {
		return pattern[:idx] + " " + pattern[idx+1:]
	}
	return pattern
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
