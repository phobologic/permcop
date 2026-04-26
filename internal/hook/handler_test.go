package hook

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadInput_ValidBash(t *testing.T) {
	t.Parallel()

	input := `{"tool_name":"Bash","tool_input":{"command":"git status","description":"check status"}}`
	got, err := ReadInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadInput: %v", err)
	}
	if got.Kind != ToolBash {
		t.Errorf("Kind: got %q, want %q", got.Kind, ToolBash)
	}
	if got.Bash == nil {
		t.Fatal("Bash: got nil")
	}
	if got.Bash.Command != "git status" {
		t.Errorf("Command: got %q, want %q", got.Bash.Command, "git status")
	}
}

func TestReadInput_ValidRead(t *testing.T) {
	t.Parallel()

	input := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/foo.txt"}}`
	got, err := ReadInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadInput: %v", err)
	}
	if got.Kind != ToolRead {
		t.Errorf("Kind: got %q, want %q", got.Kind, ToolRead)
	}
	if got.File == nil || got.File.FilePath != "/tmp/foo.txt" {
		t.Errorf("File.FilePath: got %v", got.File)
	}
}

func TestReadInput_UnknownTool(t *testing.T) {
	t.Parallel()

	input := `{"tool_name":"UnknownTool","tool_input":{}}`
	got, err := ReadInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadInput: %v", err)
	}
	if got.Kind != ToolUnknown {
		t.Errorf("Kind: got %q, want ToolUnknown", got.Kind)
	}
}

func TestReadInput_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := ReadInput(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Errorf("expected *ParseError, got %T", err)
	}
}

func TestReadInput_ExceedsLimit(t *testing.T) {
	t.Parallel()

	// Build a payload just over 1 MiB.
	oversized := bytes.Repeat([]byte("x"), maxHookInputSize+1)
	_, err := ReadInput(bytes.NewReader(oversized))
	if err == nil {
		t.Fatal("expected error for oversized input, got nil")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if !strings.Contains(pe.Cause.Error(), "exceeds") {
		t.Errorf("expected 'exceeds' in error, got: %v", pe.Cause)
	}
	// RawInput must be capped at maxHookInputSize, not the full oversized slice.
	if int64(len(pe.RawInput)) > maxHookInputSize {
		t.Errorf("RawInput len %d exceeds cap %d", len(pe.RawInput), maxHookInputSize)
	}
}

func TestReadInput_CwdPopulated(t *testing.T) {
	t.Parallel()

	input := `{"tool_name":"Bash","tool_input":{"command":"ls","description":"list"},"cwd":"/home/user/project"}`
	got, err := ReadInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadInput: %v", err)
	}
	if got.Cwd != "/home/user/project" {
		t.Errorf("Cwd: got %q, want %q", got.Cwd, "/home/user/project")
	}
}

func TestReadInput_CwdMissing(t *testing.T) {
	t.Parallel()

	input := `{"tool_name":"Bash","tool_input":{"command":"ls","description":"list"}}`
	got, err := ReadInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadInput: %v", err)
	}
	if got.Cwd != "" {
		t.Errorf("Cwd: got %q, want empty string", got.Cwd)
	}
}

func TestReadInput_AtLimit(t *testing.T) {
	t.Parallel()

	// Exactly at the limit — should succeed (or fail with JSON parse, not size error).
	atLimit := bytes.Repeat([]byte("x"), maxHookInputSize)
	_, err := ReadInput(bytes.NewReader(atLimit))
	if err != nil {
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Fatalf("expected *ParseError, got %T", err)
		}
		// Must be a JSON parse error, not a size error.
		if strings.Contains(pe.Cause.Error(), "exceeds") {
			t.Errorf("payload at exactly limit should not trigger size error: %v", pe.Cause)
		}
	}
}
