# permcop — Project Conventions

## Project structure

```
cmd/permcop/main.go          CLI entrypoint (check, explain, validate, init, import-claude-settings, version)
internal/config/             Config types and loader (TOML, global + per-project overlay)
internal/parser/             Shell AST parsing via mvdan.cc/sh/v3
internal/rules/              Two-pass rule evaluation engine
internal/audit/              Structured audit logging (text + JSON)
internal/hook/               Claude Code PreToolUse hook protocol (stdin JSON)
internal/importer/           Claude Code settings.json → permcop TOML converter
```

## Development commands

```bash
make build      # build ./permcop binary
make install    # go install to $GOPATH/bin
make test       # go test -race ./...
make lint       # golangci-lint run ./...
make fmt        # goimports -w .
make cover      # coverage report → coverage.html
```

## Key conventions

- **Deny by default** — no config or no matching rule = deny. Never silently allow.
- **Fail-closed** — config errors, parse errors, unknown hook formats all → deny + audit log.
- **Two-pass engine** — Pass 1: deny scan (any deny match = immediate deny). Pass 2: allow scan (all units must be covered by a single rule). See `internal/rules/engine.go`.
- **Single-rule coverage** — all parsed units of a command must be covered by ONE rule's allow patterns. Cross-rule allow splitting is intentionally not supported (security property).
- **Shell parsing** — use `mvdan.cc/sh/v3` for AST parsing, never regex-split commands.
- **Pattern types** — `exact`, `prefix`, `glob`, `regex`. Bare strings in config default to `glob`.

## Config locations

- Global: `~/.config/permcop/config.toml`
- Per-project: `.permcop.toml` (searched from CWD upward to home; project rules prepend global rules)
- Audit log: `~/.local/share/permcop/audit.log` (default)

## Testing

- Table-driven tests, stdlib `testing` only
- Use `t.TempDir()` for filesystem isolation
- No external services, no network calls
- Run `go test -race ./...` — race detector is always on in CI

## Go conventions

Follow the rules in `~/.claude/CLAUDE.md` (global Go rules). Additionally:
- Module path: `github.com/mikecafarella/permcop`
- `goimports` import grouping: stdlib > third-party > local (with blank line separators)
