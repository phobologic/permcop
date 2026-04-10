package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/phobologic/permcop/internal/parser"
)

// ReadPASSEntries reads the audit log file and any rotated copies (.1, .2, …),
// returning up to limit PASS entries sorted most-recent-first.
// If limit <= 0, all PASS entries are returned.
func ReadPASSEntries(logPath string, limit int) ([]Entry, error) {
	paths := []string{logPath}
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%d", logPath, i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		paths = append(paths, p)
	}

	var all []Entry
	for _, p := range paths {
		entries, err := readPASSFromFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		all = append(all, entries...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// readPASSFromFile reads a single log file and returns all PASS entries.
func readPASSFromFile(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")

	// Auto-detect format from first non-empty line.
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var probe map[string]interface{}
		if json.Unmarshal([]byte(line), &probe) == nil {
			return parseJSONLines(lines)
		}
		return parseTextLines(lines)
	}
	return nil, nil // empty file
}

// parseJSONLines parses a JSON-format audit log, returning PASS entries.
func parseJSONLines(lines []string) ([]Entry, error) {
	var entries []Entry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue // skip malformed lines
		}
		if obj["decision"] != string(DecisionPassThrough) {
			continue
		}

		tsStr, _ := obj["timestamp"].(string)
		t, _ := time.Parse(time.RFC3339, tsStr)
		cmd, _ := obj["original_command"].(string)
		cwd, _ := obj["cwd"].(string)

		var units []parser.CheckableUnit
		if us, ok := obj["units"].([]interface{}); ok {
			for _, u := range us {
				if s, ok := u.(string); ok {
					units = append(units, parser.CheckableUnit{Value: s})
				}
			}
		}

		var matches []RuleMatch
		if ms, ok := obj["rule_matches"].([]interface{}); ok {
			for _, m := range ms {
				mm, ok := m.(map[string]interface{})
				if !ok {
					continue
				}
				rule, _ := mm["rule"].(string)
				pattern, _ := mm["pattern"].(string)
				unit, _ := mm["unit"].(string)
				action, _ := mm["action"].(string)
				matches = append(matches, RuleMatch{
					Rule:    rule,
					Pattern: pattern,
					Unit:    unit,
					Action:  action,
				})
			}
		}

		entries = append(entries, Entry{
			Timestamp:       t,
			Decision:        DecisionPassThrough,
			OriginalCommand: cmd,
			CWD:             cwd,
			Units:           units,
			RuleMatches:     matches,
		})
	}
	return entries, nil
}

// parseTextLines parses a text-format audit log, returning PASS entries.
func parseTextLines(lines []string) ([]Entry, error) {
	var entries []Entry
	var current *Entry

	flush := func() {
		if current != nil && current.Decision == DecisionPassThrough {
			entries = append(entries, *current)
		}
		current = nil
	}

	for _, line := range lines {
		if isTextHeader(line) {
			flush()
			current = parseTextHeader(line)
			continue
		}
		if current == nil {
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(trimmed, "original: "):
			current.OriginalCommand = strings.TrimPrefix(trimmed, "original: ")
		case strings.HasPrefix(trimmed, "cwd:"):
			current.CWD = strings.TrimSpace(strings.TrimPrefix(trimmed, "cwd:"))
		case strings.HasPrefix(trimmed, "units:"):
			unitStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "units:"))
			for len(unitStr) > 0 {
				v, rest := extractBracket(unitStr)
				if v == "" {
					break
				}
				current.Units = append(current.Units, parser.CheckableUnit{Value: v})
				unitStr = strings.TrimSpace(rest)
			}
		case strings.HasPrefix(trimmed, "pass   ["):
			v, _ := extractBracket(trimmed[len("pass   "):])
			if v != "" {
				current.RuleMatches = append(current.RuleMatches, RuleMatch{
					Unit:   v,
					Action: "pass",
				})
			}
		}
	}
	flush()
	return entries, nil
}

// isTextHeader reports whether line is an audit log header line.
// Header lines start with a timestamp (YYYY-MM-DDTHH:...) at column 0.
func isTextHeader(line string) bool {
	if len(line) < 11 || line[0] == ' ' || line[0] == '\t' {
		return false
	}
	return line[4] == '-' && line[7] == '-' && line[10] == 'T'
}

// parseTextHeader parses the decision and timestamp from a header line.
func parseTextHeader(line string) *Entry {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	t, err := time.Parse(time.RFC3339, parts[0])
	if err != nil {
		return nil
	}
	return &Entry{Timestamp: t, Decision: Decision(parts[1])}
}

// extractBracket extracts the value inside the first [...] in s,
// returning the value and the remaining string after ].
func extractBracket(s string) (value, rest string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return "", s
	}
	end := strings.Index(s, "]")
	if end < 0 {
		return "", s
	}
	return s[1:end], s[end+1:]
}
