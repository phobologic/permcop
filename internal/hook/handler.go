// Package hook handles the Claude Code PreToolUse hook protocol.
package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ToolKind classifies the Claude Code tool being called.
type ToolKind string

const (
	ToolBash      ToolKind = "Bash"
	ToolRead      ToolKind = "Read"
	ToolWrite     ToolKind = "Write"
	ToolEdit      ToolKind = "Edit"
	ToolMultiEdit ToolKind = "MultiEdit"
	ToolUnknown   ToolKind = "unknown"
)

// Input is the raw hook JSON, decoded into the common envelope.
type Input struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// BashInput holds the Bash tool's parameters.
type BashInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// FileInput holds the file path parameter shared by Read, Write, Edit, MultiEdit.
type FileInput struct {
	FilePath string `json:"file_path"`
}

// ParsedInput is the result of decoding a hook request into a typed value.
type ParsedInput struct {
	Kind ToolKind
	Bash *BashInput
	File *FileInput
}

// ParseError is returned when the hook input cannot be decoded.
// It includes the raw bytes received so callers can log them for debugging.
type ParseError struct {
	Cause    error
	RawInput []byte
}

func (e *ParseError) Error() string {
	raw := e.RawInput
	const maxSnippet = 200
	if len(raw) > maxSnippet {
		raw = append(raw[:maxSnippet:maxSnippet], "...(truncated)"...)
	}
	return fmt.Sprintf("unrecognized hook input format: %v\nreceived: %s", e.Cause, raw)
}

func (e *ParseError) Unwrap() error { return e.Cause }

const maxHookInputSize = 1 << 20 // 1 MiB

// ReadInput decodes the hook JSON from r and returns a ParsedInput.
// On failure it returns a *ParseError containing the raw bytes received.
// Inputs larger than maxHookInputSize are rejected to prevent memory exhaustion.
func ReadInput(r io.Reader) (*ParsedInput, error) {
	lr := io.LimitReader(r, maxHookInputSize+1)
	raw, err := io.ReadAll(lr)
	if err != nil {
		return nil, &ParseError{Cause: fmt.Errorf("read stdin: %w", err), RawInput: raw}
	}
	if int64(len(raw)) > maxHookInputSize {
		return nil, &ParseError{
			Cause:    fmt.Errorf("input exceeds %d bytes", maxHookInputSize),
			RawInput: raw[:maxHookInputSize],
		}
	}

	var envelope Input
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&envelope); err != nil {
		return nil, &ParseError{Cause: err, RawInput: raw}
	}

	kind := ToolKind(envelope.ToolName)
	parsed := &ParsedInput{Kind: kind}

	switch kind {
	case ToolBash:
		var bi BashInput
		if err := json.Unmarshal(envelope.ToolInput, &bi); err != nil {
			return nil, &ParseError{Cause: fmt.Errorf("decode Bash input: %w", err), RawInput: raw}
		}
		parsed.Bash = &bi

	case ToolRead, ToolWrite, ToolEdit, ToolMultiEdit:
		var fi FileInput
		if err := json.Unmarshal(envelope.ToolInput, &fi); err != nil {
			return nil, &ParseError{Cause: fmt.Errorf("decode %s input: %w", kind, err), RawInput: raw}
		}
		parsed.File = &fi

	default:
		// Unknown tool — caller decides how to handle (typically allow through,
		// since permcop only governs what it knows about).
		parsed.Kind = ToolUnknown
	}

	return parsed, nil
}
