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
- **Two-pass engine** — Pass 1: deny scan (any deny match = immediate deny). Pass 2: allow scan (each unit independently finds any covering rule; all units must be covered). See `internal/rules/engine.go`.
- **Per-unit coverage** — each unit in a command independently finds any rule that covers it; different units can be covered by different rules. A "write zone" rule can cover write units across many command rules.
- **Shell parsing** — use `mvdan.cc/sh/v3` for AST parsing, never regex-split commands.
- **`expand_variables`** — per-rule opt-in; resolves `$VAR`/`${VAR}` from env before matching. Fail-closed: if any variable is missing from env, that rule cannot cover the unit. `CheckableUnit.Variables []string` tracks variable names found (without `$`).
- **`path_scope`** — match only when all path-args resolve within this directory subtree (see README).

## Config locations

- Global: `~/.config/permcop/config.toml`
- Per-project: `.permcop.toml` (searched from CWD upward to home; project rules prepend global rules)
- Audit log: `~/.local/share/permcop/audit.log` (default)

## Release notes

Releases are cut by pushing an annotated tag (`vX.Y.Z`); goreleaser pipes the
tag body straight into the GitHub release via `{{ .TagBody }}`. Tag bodies
follow this shape:

1. **Movie-style title + tagline.** One line in the format
   `*The Project Root Job* — Permission boundaries just got a whole lot badder!`
   The title is a stylized 70s-cop-movie name; the tagline is a punchy
   one-liner promising what's new. The name "permcop" puns on *perm* (the
   permanent curly haircut, hence the mascot) and *cop* — lean into the
   haircut and the beat-cop voice ("Freeze!", "Book 'em", "Case closed").
2. **Promo blurb (1–3 sentences).** Campy cop-show voice aimed at friends and
   social sharing — funny, but the headline feature still has to be legible
   to someone who's never used the tool.
3. **Blank line, then plain-language body** under `## Highlights`, `## Fixes`,
   and `## Docs` (omit sections that don't apply). Cover every user-facing
   change since the previous tag — features, behavior changes, fixes, doc
   updates — in plain prose, not commit-log shorthand.

Draft the tag body in `.tmp/vX.Y.Z-tag.txt`, create the tag with
`git tag -a vX.Y.Z -F .tmp/vX.Y.Z-tag.txt`, and let the user push.

## Go conventions

Follow the rules in `~/.claude/CLAUDE.md` (global Go rules). Additionally:
- Module path: `github.com/phobologic/permcop`
- `goimports` import grouping: stdlib > third-party > local (with blank line separators)
