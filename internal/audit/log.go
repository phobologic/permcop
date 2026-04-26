package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phobologic/permcop/internal/parser"
)

// Decision is the outcome of a permission check.
type Decision string

const (
	DecisionAllow       Decision = "ALLOW"
	DecisionDeny        Decision = "DENY"
	DecisionWarn        Decision = "WARN" // allowed but with variable warning
	DecisionPassThrough Decision = "PASS" // no rule matched; deferred to Claude Code
)

// SkippedRule records a rule that was considered for a unit but could not cover
// it, along with the reason it was skipped. Used for diagnostic output on
// pass-through decisions.
type SkippedRule struct {
	Rule   string // rule name
	Reason string // why the rule was skipped (e.g. "expand_variables: $VAR not in env")
}

// RuleMatch records how one unit was evaluated.
type RuleMatch struct {
	Rule         string        // rule name; empty string = "default-deny"
	Pattern      string        // matched pattern; empty for default-deny
	Unit         string        // the unit value (expanded if applicable)
	Action       string        // "allow" or "deny"
	SkippedRules []SkippedRule // rules skipped during coverage check; non-nil only for pass-through units
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
	CWD             string // working directory of the process that invoked the hook
	Units           []parser.CheckableUnit
	RuleMatches     []RuleMatch // per-unit match details; populated by the engine
	Diagnostics     []string    // engine-level warnings attached to every entry while they are active
}

// Logger writes audit entries to a file.
type Logger struct {
	path     string
	format   string // "text" or "json"
	maxBytes int64  // 0 = rotation disabled
	maxFiles int
	mu       sync.Mutex
	file     *os.File // nil until first Log()
}

// New creates a Logger. The log file and its parent directories are created
// on the first write (lazy), so construction never fails.
// maxSizeMB and maxFiles control rotation; pass 0 for either to disable rotation.
func New(path, format string, maxSizeMB, maxFiles int) *Logger {
	if format == "" {
		format = "text"
	}
	var maxBytes int64
	if maxSizeMB > 0 && maxFiles > 0 {
		maxBytes = int64(maxSizeMB) * 1024 * 1024
	}
	return &Logger{path: path, format: format, maxBytes: maxBytes, maxFiles: maxFiles}
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

	if l.maxBytes > 0 {
		if info, err := l.file.Stat(); err == nil && info.Size() >= l.maxBytes {
			l.rotate() // errors are ignored; logging continues on un-rotated file
		}
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

	// Acquire exclusive lock: serialises writes across concurrent processes.
	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock log: %w", err)
	}
	_, err = fmt.Fprintln(l.file, line)
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return err
}

// rotate closes the current log file, shifts existing numbered files up by one,
// deletes any file that would exceed maxFiles, then opens a fresh log file.
// Errors are ignored (fail-open): a rotation failure must not block audit writes.
func (l *Logger) rotate() {
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}

	// Delete the file that would be pushed beyond maxFiles.
	oldest := fmt.Sprintf("%s.%d", l.path, l.maxFiles)
	os.Remove(oldest) //nolint:errcheck

	// Shift existing rotated files: path.N-1 → path.N (in reverse order).
	for i := l.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.path, i)
		dst := fmt.Sprintf("%s.%d", l.path, i+1)
		os.Rename(src, dst) //nolint:errcheck
	}

	// Rename the current log to path.1.
	os.Rename(l.path, l.path+".1") //nolint:errcheck

	// Open a fresh log file.
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		l.file = f
	}
	// On error l.file stays nil; the next Log() call will reopen the file.
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
	fmt.Fprintf(&header, "%s %s", ts, e.Decision)
	if e.DecidingRule != "" {
		fmt.Fprintf(&header, "  rule=%q", e.DecidingRule)
	}
	if e.DecidingPattern != "" {
		fmt.Fprintf(&header, " pattern=%q", e.DecidingPattern)
	}
	if e.Reason != "" && e.DecidingRule == "" {
		// Only print reason standalone when no rule matched (safety checks, no-match)
		fmt.Fprintf(&header, "  reason=%q", e.Reason)
	}

	var sb strings.Builder
	sb.WriteString(header.String())
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "  original: %s\n", e.OriginalCommand)
	if e.CWD != "" {
		fmt.Fprintf(&sb, "  cwd:      %s\n", e.CWD)
	}

	if len(e.Units) > 0 {
		unitStrs := make([]string, len(e.Units))
		for i, u := range e.Units {
			unitStrs[i] = fmt.Sprintf("[%s]", u.Value)
		}
		fmt.Fprintf(&sb, "  units:    %s\n", strings.Join(unitStrs, " "))
	}

	if e.DecidingUnit != nil {
		fmt.Fprintf(&sb, "  hit:      %s\n", e.DecidingUnit.Value)
	}

	if len(e.RuleMatches) > 0 {
		sb.WriteString("  matches:\n")
		for _, m := range e.RuleMatches {
			switch {
			case m.Action == "allow":
				fmt.Fprintf(&sb, "    allow  [%s]  rule=%q  pattern=%q\n", m.Unit, m.Rule, m.Pattern)
			case m.Rule == "":
				if e.Decision == DecisionPassThrough {
					fmt.Fprintf(&sb, "    pass   [%s]  (no rule — deferred to Claude Code)\n", m.Unit)
					for _, sk := range m.SkippedRules {
						fmt.Fprintf(&sb, "      skipped: rule=%q — %s\n", sk.Rule, sk.Reason)
					}
				} else {
					fmt.Fprintf(&sb, "    deny   [%s]  (default deny)\n", m.Unit)
				}
			default:
				fmt.Fprintf(&sb, "    deny   [%s]  rule=%q  pattern=%q\n", m.Unit, m.Rule, m.Pattern)
			}
		}
	}

	for _, d := range e.Diagnostics {
		fmt.Fprintf(&sb, "  diag: %s\n", d)
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
	if e.CWD != "" {
		obj["cwd"] = e.CWD
	}

	unitVals := make([]string, len(e.Units))
	for i, u := range e.Units {
		unitVals[i] = u.Value
	}
	obj["units"] = unitVals

	if len(e.RuleMatches) > 0 {
		matches := make([]map[string]interface{}, len(e.RuleMatches))
		for i, m := range e.RuleMatches {
			match := map[string]interface{}{
				"rule":    m.Rule,
				"pattern": m.Pattern,
				"unit":    m.Unit,
				"action":  m.Action,
			}
			if len(m.SkippedRules) > 0 {
				skipped := make([]map[string]string, len(m.SkippedRules))
				for j, sk := range m.SkippedRules {
					skipped[j] = map[string]string{
						"rule":   sk.Rule,
						"reason": sk.Reason,
					}
				}
				match["skipped_rules"] = skipped
			}
			matches[i] = match
		}
		obj["rule_matches"] = matches
	}

	if len(e.Diagnostics) > 0 {
		obj["diagnostics"] = e.Diagnostics
	}

	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
