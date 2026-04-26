package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/phobologic/permcop/internal/audit"
	"github.com/phobologic/permcop/internal/config"
	"github.com/phobologic/permcop/internal/rules"
)

func TestWriteExplainResult_PathScopeSkippedRule(t *testing.T) {
	t.Parallel()

	rule := config.Rule{
		Name:      "cp-proj",
		Allow:     []config.Pattern{{Type: config.PatternPrefix, Pattern: "cp"}},
		PathScope: []string{"/proj"},
	}
	cfg := &config.Config{Rules: []config.Rule{rule}}
	logger := audit.New(os.DevNull, "text", 0, 0)
	engine, err := rules.New(cfg, logger, "")
	if err != nil {
		t.Fatal(err)
	}

	const cmd = "cp /etc/passwd /proj/dest"
	result, err := engine.Check(cmd, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !result.FallThrough {
		t.Fatalf("expected FallThrough result, got Allowed=%v", result.Allowed)
	}

	var buf bytes.Buffer
	writeExplainResult(&buf, cmd, result)

	got := buf.String()
	const wantReason = "path_scope: /etc/passwd not under any scope entry"
	if !strings.Contains(got, wantReason) {
		t.Errorf("explain output missing path_scope reason %q\ngot:\n%s", wantReason, got)
	}
}
