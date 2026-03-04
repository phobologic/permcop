# permcop

A rule-based permission enforcer for [Claude Code](https://claude.ai/code). Intercepts Claude Code tool calls via PreToolUse hooks and evaluates them against an ordered, deny-by-default rule set.

## How it works

permcop integrates as a Claude Code hook. Before Claude runs any Bash command or accesses any file, the hook invokes `permcop check`, which:

1. Parses the command into constituent units (chained commands, subshells, redirects)
2. Runs a **two-pass evaluation** against your config:
   - **Pass 1 — Deny scan:** if any deny pattern matches any unit across all rules → DENY
   - **Pass 2 — Allow scan:** each unit independently finds any rule that covers it; if all units are covered → ALLOW
   - **Default:** DENY (no match = blocked)
3. Logs every decision to an audit log
4. Exits `0` (allow) or `2` (deny) — Claude Code sees the exit code and acts accordingly

## Installation

```bash
go install github.com/mikecafarella/permcop/cmd/permcop@latest
permcop init
```

`permcop init` creates a starter config at `~/.config/permcop/config.toml` and wires the hook into `~/.claude/settings.json`.

## Config

Config lives at `~/.config/permcop/config.toml` (global) and optionally `.permcop.toml` in a project directory (project rules are evaluated first).

```toml
[defaults]
log_file = "~/.local/share/permcop/audit.log"
log_format = "text"              # "text" or "json"
unknown_variable_action = "deny" # "deny" | "warn" | "allow"
allow_sudo = false
deny_subshells = false
subshell_depth_limit = 3

# Rules are evaluated in order.
# Pass 1: ANY deny pattern matching ANY unit → DENY immediately.
# Pass 2: each unit independently finds any rule that covers it; all must be covered → ALLOW.
# No match → DENY.

[[rules]]
name = "Allow safe git operations"
allow = [
  { type = "prefix", pattern = "git log" },
  { type = "prefix", pattern = "git diff" },
  { type = "exact",  pattern = "git status" },
  { type = "glob",   pattern = "git show *" },
]
deny = [
  { type = "prefix", pattern = "git push" },
  { type = "regex",  pattern = "^git\\s+.*--force" },
]

[[rules]]
name = "Read project source"
allow_read = ["./src/**", "./tests/**"]
deny_read  = ["./.env", "./secrets/**"]

[[rules]]
name = "Write build artifacts"
allow = [{ type = "prefix", pattern = "go build" }]
allow_write = ["/tmp/build/**"]
```

### Pattern types

| Type | Example | Behavior |
|------|---------|----------|
| `exact` | `git status` | Full string equality |
| `prefix` | `git log` | Matches `git log` or `git log <anything>` |
| `glob` | `go test *` | Shell glob (`*` = any segment, `**` = recursive) |
| `regex` | `^rm\s+-rf` | RE2 regular expression |

Bare strings default to `glob`. Pattern types apply to command strings; file paths always use glob.

### Variable and subshell handling

Commands containing `$VAR` or `$(...)` present an evaluation challenge because permcop can't know the runtime value at check time. Two mechanisms address this:

**`unknown_variable_action`** — controls what happens when a rule encounters a command with unresolved variables:

- `unknown_variable_action = "deny"` — reject the command (default, most secure)
- `unknown_variable_action = "warn"` — allow but write a WARN-level audit entry
- `unknown_variable_action = "allow"` — permit silently

Set globally in `[defaults]` or override per rule.

**`expand_variables = true`** (per-rule) — resolves `$VAR` and `${VAR}` from the environment before matching this rule's patterns. This lets you write precise allow/deny rules against actual expanded values:

```toml
[[rules]]
name = "Allow mv of $TARGET to /tmp"
expand_variables = true
allow = [{ type = "glob", pattern = "mv * /tmp/*" }]
```

With this rule, `mv $TARGET /tmp/out.txt` is checked as `mv /home/user/data.txt /tmp/out.txt` after resolving `TARGET` from the environment. Expansion applies to both deny and allow patterns for the rule — a deny pattern like `deny = ["mv * /home/**"]` will catch an expanded value that resolves into `/home/`.

If a variable is not set in the environment, the rule cannot cover the unit (fail-closed). Other rules without `expand_variables` still apply normally as fallbacks.

Similarly, `deny_subshells = true` blocks any command containing `$(...)` subshells.

### Per-unit coverage

Each parsed unit is evaluated independently against all rules. A chain like `echo hi > /tmp/out.txt` produces two units: the `echo` command and the `/tmp/out.txt` write. Each unit finds any rule that covers it — they don't need to be in the same rule.

This enables a "write zone" rule that applies broadly alongside specific command rules:

```toml
# Specific command rule — covers the "git log" command unit
[[rules]]
name  = "git reads"
allow = [{ type = "prefix", pattern = "git log" }]

# Write zone — covers write units for any command
[[rules]]
name        = "write zone"
allow_write = ["/tmp/**"]
```

With this config, `git log > /tmp/out.txt` is allowed: the command unit matches `git reads`, the write unit matches `write zone`.

To restrict specific file paths for a command, use `deny_write` in that command's rule — deny patterns from Pass 1 always win:

```toml
[[rules]]
name       = "echo to tmp"
allow      = [{ type = "prefix", pattern = "echo" }]
deny_write = ["/tmp/secrets/**"]
```

The same `allow_read`/`deny_read`/`allow_write`/`deny_write` patterns apply uniformly to both contexts: shell redirections inside Bash commands, and direct `Read`/`Write`/`Edit`/`MultiEdit` tool calls.

## Tools governed

permcop evaluates:

| Claude Code tool | What's checked |
|------------------|----------------|
| `Bash` | Full command parsed into units (chains, pipes, subshells, redirects) |
| `Read` | File path against `allow_read` / `deny_read` |
| `Write` | File path against `allow_write` / `deny_write` |
| `Edit` | File path against `allow_write` / `deny_write` |
| `MultiEdit` | File path against `allow_write` / `deny_write` |
| Everything else | Allowed through (permcop only governs what it knows about) |

## Commands

```
permcop check                         Hook entry point (stdin → exit 0/2)
permcop explain <command>             Dry-run: show rule evaluation
permcop validate [config-file]        Validate config syntax and structure
permcop init                          Wire hook + create starter config
permcop import-claude-settings [file] Convert Claude Code permissions to TOML
permcop version                       Print version
```

### explain

```
$ permcop explain 'git status && git push origin main'
Command:  git status && git push origin main
Units:    [command git status], [command git push origin main]

Result:   DENY
Reason:   matched deny pattern
Rule:     "Allow safe git operations"
Pattern:  prefix:git push
Hit unit: git push origin main
```

### import-claude-settings

Converts existing Claude Code permission rules (`~/.claude/settings.json`) to permcop TOML:

```bash
permcop import-claude-settings >> ~/.config/permcop/config.toml
```

Bash rules map to command `allow`/`deny` patterns. `Read`/`Edit` rules map to `allow_read`/`deny_read`/`allow_write`/`deny_write`. `ask` rules and non-file tools (WebFetch, MCP) are reported as warnings/skipped.

## Audit log

Every decision is logged to `~/.local/share/permcop/audit.log` (configurable).

**Text format (default):**
```
2026-03-04T04:58:13Z ALLOW  rule="Allow safe git operations" pattern="exact:git status"
  original: git status
  units:    [git status]
  hit:      git status

2026-03-04T04:58:20Z DENY  rule="Allow safe git operations" pattern="prefix:git push"
  original: git status && git push origin main
  units:    [git status] [git push origin main]
  hit:      git push origin main
```

**JSON format** (`log_format = "json"`): one object per line, suitable for `jq`.

## Hook wiring

`permcop init` adds entries like this to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash",      "hooks": [{"type": "command", "command": "permcop check"}]},
      {"matcher": "Read",      "hooks": [{"type": "command", "command": "permcop check"}]},
      {"matcher": "Write",     "hooks": [{"type": "command", "command": "permcop check"}]},
      {"matcher": "Edit",      "hooks": [{"type": "command", "command": "permcop check"}]},
      {"matcher": "MultiEdit", "hooks": [{"type": "command", "command": "permcop check"}]}
    ]
  }
}
```

## License

MIT — see [LICENSE](LICENSE).
