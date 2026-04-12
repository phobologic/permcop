package rules

import (
	"os"
	"testing"

	"github.com/phobologic/permcop/internal/config"
	"github.com/phobologic/permcop/internal/parser"
)

func TestCheckFile_AllowRead(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:      "read tmp",
			AllowRead: []string{"/tmp/**"},
		},
	}, nil)

	r, err := e.CheckFile("/tmp/foo.txt", parser.UnitReadFile, "/my/cwd")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Errorf("expected ALLOW for read in /tmp, got DENY: %s", r.Reason)
	}
	if r.CWD != "/my/cwd" {
		t.Errorf("expected CWD=%q in audit entry, got %q", "/my/cwd", r.CWD)
	}
}

func TestCheckFile_DenyRead(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:      "read tmp not secrets",
			AllowRead: []string{"/tmp/**"},
			DenyRead:  []string{"/tmp/secrets/**"},
		},
	}, nil)

	// Allowed path
	r, _ := e.CheckFile("/tmp/ok.txt", parser.UnitReadFile, "")
	if !r.Allowed {
		t.Errorf("expected ALLOW for /tmp/ok.txt, got DENY: %s", r.Reason)
	}

	// Denied path
	r2, _ := e.CheckFile("/tmp/secrets/key.pem", parser.UnitReadFile, "")
	if r2.Allowed {
		t.Error("expected DENY for /tmp/secrets/key.pem, got ALLOW")
	}
	if r2.DecidingRule != "read tmp not secrets" {
		t.Errorf("wrong deciding rule: %q", r2.DecidingRule)
	}
}

func TestCheckFile_AllowWrite(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{
			Name:       "write builds",
			AllowWrite: []string{"/tmp/build/**"},
		},
	}, nil)

	r, _ := e.CheckFile("/tmp/build/output.bin", parser.UnitWriteFile, "")
	if !r.Allowed {
		t.Errorf("expected ALLOW for write in /tmp/build, got DENY: %s", r.Reason)
	}

	r2, _ := e.CheckFile("/tmp/other.txt", parser.UnitWriteFile, "")
	if r2.Allowed {
		t.Error("expected DENY for write outside /tmp/build, got ALLOW")
	}
}

func TestCheckFile_ReadRuleDoesNotCoverWrite(t *testing.T) {
	t.Parallel()

	// allow_read should not grant write permission
	e := newTestEngine(t, []config.Rule{
		{
			Name:      "read only",
			AllowRead: []string{"/tmp/**"},
		},
	}, nil)

	r, _ := e.CheckFile("/tmp/foo.txt", parser.UnitWriteFile, "")
	if r.Allowed {
		t.Error("expected DENY: allow_read should not cover write operations")
	}
}

func TestCheckFile_DefaultDeny(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, nil, nil)

	r, _ := e.CheckFile("/etc/passwd", parser.UnitReadFile, "")
	if r.Allowed {
		t.Error("expected DENY for /etc/passwd with no rules")
	}
}

func TestCheckFile_EmptyPath(t *testing.T) {
	t.Parallel()

	e := newTestEngine(t, []config.Rule{
		{Name: "allow all reads", AllowRead: []string{"**"}},
	}, nil)

	r, _ := e.CheckFile("", parser.UnitReadFile, "")
	if r.Allowed {
		t.Error("expected DENY for empty path")
	}
}

func TestEngine_TildeExpansion(t *testing.T) {
	t.Parallel()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("os.UserHomeDir() unavailable:", err)
	}

	e := newTestEngine(t, []config.Rule{
		{
			Name:     "deny ssh keys",
			DenyRead: []string{"~/.ssh/**"},
		},
	}, nil)

	// A path inside ~/.ssh should be denied.
	sshKey := homeDir + "/.ssh/id_rsa"
	r, _ := e.CheckFile(sshKey, parser.UnitReadFile, "")
	if r.Allowed {
		t.Errorf("expected DENY for %s with deny_read=[~/.ssh/**], got ALLOW", sshKey)
	}

	// An unrelated path should not be denied (falls through to default deny, but not by this rule).
	other := homeDir + "/Documents/notes.txt"
	r2, _ := e.CheckFile(other, parser.UnitReadFile, "")
	if r2.Allowed {
		t.Error("expected DENY for unrelated path (no allow rule), got ALLOW")
	}
	if r2.DecidingRule != "" {
		// The deny came from "no matching allow rule", not from our deny_read rule.
		t.Logf("deciding rule for unrelated path: %q (reason: %s)", r2.DecidingRule, r2.Reason)
	}
}

func TestCheckFile_AuditLog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logPath := dir + "/audit.log"

	e := newTestEngine(t, []config.Rule{
		{Name: "read tmp", AllowRead: []string{"/tmp/**"}},
	}, &config.Defaults{
		LogFile:               logPath,
		LogFormat:             "text",
		UnknownVariableAction: config.VariableActionDeny,
		SubshellDepthLimit:    3,
	})

	_, _ = e.CheckFile("/tmp/test.txt", parser.UnitReadFile, "")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected audit log entry, got empty file")
	}
}
