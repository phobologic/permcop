package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mikecafarella/permcop/internal/parser"
)

// Decision is the outcome of a permission check.
type Decision string

const (
	DecisionAllow       Decision = "ALLOW"
	DecisionDeny        Decision = "DENY"
	DecisionWarn        Decision = "WARN" // allowed but with variable warning
	DecisionPassThrough Decision = "PASS" // no rule matched; deferred to Claude Code
)

// RuleMatch records how one unit was evaluated.
type RuleMatch struct {
	Rule    string // rule name; empty string = "default-deny"
	Pattern string // matched pattern; empty for default-deny
	Unit    string // the unit value (expanded if applicable)
	Action  string // "allow" or "deny"
}

// Entry captures everything about a single permission decision.
type Entry struct {
	Timestamp       time.Time
	Decision        Decision
	Reason          string
	DecidingRule    string                // name of the rule that made the call; empty if no rule matched
	DecidingPattern string                // pattern string that matched; empty if safety check triggered
	DecidingUnit    *parser.CheckableUnit // the specific unit that triggered the decision
	OriginalCommand string
	Units           []parser.CheckableUnit
	RuleMatches     []RuleMatch // per-unit match details; populated by the engine
}

// Logger writes audit entries to a file.
type Logger struct {
	path   string
	format string // "text" or "json"
	mu     sync.Mutex
	file   *os.File // nil until first Log()
}

// New creates a Logger. The log file and its parent directories are created
// on the first write (lazy), so construction never fails.
func New(path, format string) *Logger {
	if format == "" {
		format = "text"
	}
	return &Logger{path: path, format: format}
}

// Log writes an entry to the audit log.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
			return fmt.Errorf("create log dir: %w", err)
		}
		f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open log: %w", err)
		}
		l.file = f
	}

	var (
		line string
		err  error
	)
	if l.format == "json" {
		line, err = jsonLine(e)
	} else {
		line = textLine(e)
	}
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(l.file, line)
	return err
}

// Close releases the underlying file handle. It is safe to call on a Logger
// that has never written (no-op). After Close, the Logger may not be used.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// textLine formats an entry as human-readable structured text.
func textLine(e Entry) string {
	ts := e.Timestamp.Local().Format(time.RFC3339)

	// Header line
	var header strings.Builder
	header.WriteString(fmt.Sprintf("%s %s", ts, e.Decision))
	if e.DecidingRule != "" {
		header.WriteString(fmt.Sprintf("  rule=%q", e.DecidingRule))
	}
	if e.DecidingPattern != "" {
		header.WriteString(fmt.Sprintf(" pattern=%q", e.DecidingPattern))
	}
	if e.Reason != "" && e.DecidingRule == "" {
		// Only print reason standalone when no rule matched (safety checks, no-match)
		header.WriteString(fmt.Sprintf("  reason=%q", e.Reason))
	}

	var sb strings.Builder
	sb.WriteString(header.String())
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  original: %s\n", e.OriginalCommand))

	if len(e.Units) > 0 {
		unitStrs := make([]string, len(e.Units))
		for i, u := range e.Units {
			unitStrs[i] = fmt.Sprintf("[%s]", u.Value)
		}
		sb.WriteString(fmt.Sprintf("  units:    %s\n", strings.Join(unitStrs, " ")))
	}

	if e.DecidingUnit != nil {
		sb.WriteString(fmt.Sprintf("  hit:      %s\n", e.DecidingUnit.Value))
	}

	if len(e.RuleMatches) > 0 {
		sb.WriteString("  matches:\n")
		for _, m := range e.RuleMatches {
			if m.Action == "allow" {
				sb.WriteString(fmt.Sprintf("    allow  [%s]  rule=%q  pattern=%q\n", m.Unit, m.Rule, m.Pattern))
			} else if m.Rule == "" {
				if e.Decision == DecisionPassThrough {
					sb.WriteString(fmt.Sprintf("    pass   [%s]  (no rule — deferred to Claude Code)\n", m.Unit))
				} else {
					sb.WriteString(fmt.Sprintf("    deny   [%s]  (default deny)\n", m.Unit))
				}
			} else {
				sb.WriteString(fmt.Sprintf("    deny   [%s]  rule=%q  pattern=%q\n", m.Unit, m.Rule, m.Pattern))
			}
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}

// jsonLine formats an entry as a single JSON object.
func jsonLine(e Entry) (string, error) {
	obj := map[string]interface{}{
		"timestamp": e.Timestamp.Local().Format(time.RFC3339),
		"decision":  string(e.Decision),
	}
	if e.DecidingRule != "" {
		obj["deciding_rule"] = e.DecidingRule
	}
	if e.DecidingPattern != "" {
		obj["deciding_pattern"] = e.DecidingPattern
	}
	if e.Reason != "" {
		obj["reason"] = e.Reason
	}
	if e.DecidingUnit != nil {
		obj["deciding_unit"] = e.DecidingUnit.Value
	}
	obj["original_command"] = e.OriginalCommand

	unitVals := make([]string, len(e.Units))
	for i, u := range e.Units {
		unitVals[i] = u.Value
	}
	obj["units"] = unitVals

	if len(e.RuleMatches) > 0 {
		matches := make([]map[string]string, len(e.RuleMatches))
		for i, m := range e.RuleMatches {
			matches[i] = map[string]string{
				"rule":    m.Rule,
				"pattern": m.Pattern,
				"unit":    m.Unit,
				"action":  m.Action,
			}
		}
		obj["rule_matches"] = matches
	}

	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
