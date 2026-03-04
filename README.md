# permcop

A rule-based permission filter for [Claude Code](https://claude.ai/code). Intercepts Claude Code tool calls via PreToolUse hooks and evaluates them against an ordered rule set. Explicit deny rules block commands; explicit allow rules bypass Claude Code's approval prompt; everything else defers to Claude Code's own permission system.

## How it works

permcop integrates as a Claude Code hook. Before Claude runs any Bash command, the hook invokes `permcop check`, which:

1. Parses the command into constituent units (chained commands, subshells, redirects)
2. Runs a **two-pass evaluation** against your config:
   - **Pass 1 — Deny scan:** if any deny pattern matches any unit across all rules → DENY
   - **Pass 2 — Allow scan:** each unit independently finds any rule that covers it; if all units are covered → ALLOW
   - **Default:** PASS (no match = deferred to Claude Code's permission system)
3. Logs every decision to an audit log
4. Exits `0` (allow) or `2` (deny) — Claude Code sees the exit code and acts accordingly

## Installation

```bash
go install github.com/mikecafarella/permcop/cmd/permcop@latest
permcop init
```

`permcop init` creates a starter config at `.permcop.toml` in the current directory and wires the hook into `.claude/settings.local.json` (project-scoped, gitignored). Use `--global` to install machine-wide instead.

## Config

Config is layered across up to four files, merged in priority order:

| File | Scope | Commit? |
|------|-------|---------|
| `.permcop.local.toml` | project local | no — gitignore it |
| `.permcop.toml` | project shared | yes — team policy |
| `~/.config/permcop/config.local.toml` | global local | n/a |
| `~/.config/permcop/config.toml` | global shared | n/a |

All files are optional. Project files are searched upward from CWD, stopping at the git root. Rules from higher-priority files are evaluated first.

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
# No match → PASS (deferred to Claude Code's permission system).

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

An unknown `type` value (e.g. a typo like `"prefx"`) is rejected at config load time with a clear error — it will not silently create a non-matching rule.

File path patterns (`allow_read`, `deny_read`, `allow_write`, `deny_write`) support `~/` as a prefix, which is expanded to the user's home directory at engine startup:

```toml
[[rules]]
name = "Protect SSH keys"
deny_read = ["~/.ssh/**"]
```

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

The `allow_read`/`deny_read`/`allow_write`/`deny_write` patterns apply to file units produced by shell redirections inside Bash commands (e.g. `echo hi > /tmp/out.txt` produces a write unit for `/tmp/out.txt`). They do not apply to direct `Read`/`Write`/`Edit`/`MultiEdit` tool calls unless you explicitly add those matchers to the hook (see [Hook wiring](#hook-wiring)).

> **Design note — `allow_write` is a zone capability, not a per-command constraint**
>
> `allow_write` patterns are evaluated per-unit, like everything else: any write
> unit can be satisfied by *any* rule's `allow_write`, regardless of which rule
> covered the command unit. A "write zone" rule that allows `/tmp/**` applies
> equally to `echo`, `git log`, `go build`, or any other allowed command that
> redirects there.
>
> **permcop does not currently support scoped `allow_write`** — there is no way
> to say "only `go test` may write to `coverage.out`; other allowed commands may
> not redirect there." The `allow_write` in a rule is always a global zone grant,
> not tied to that rule's `allow` patterns.
>
> We're considering whether a scoped mode would be worth building. Under that
> model, a rule's `allow_write` would only cover write units whose command was
> *also* matched by that same rule's `allow` patterns. This would let you express
> intent like:
>
> ```toml
> # (hypothetical — not yet implemented)
> [[rules]]
> name = "go test writes coverage"
> scoped_write = true
> allow = [{ type = "prefix", pattern = "go test" }]
> allow_write = ["./coverage.out"]
> # echo pwned > coverage.out would be denied even if echo is allowed elsewhere
> ```
>
> If you have a use case where the current zone model falls short — or where
> scoped write constraints would meaningfully improve your security posture —
> please [open an issue](https://github.com/mikecafarella/permcop/issues) and
> describe it. Your feedback will shape whether and how this gets built.

## Tools governed

permcop is designed for **Bash**. That's where the real attack surface is: shell command parsing, chained commands, subshells, and redirects.

| Claude Code tool | Default | What's checked |
|------------------|---------|----------------|
| `Bash` | Hooked | Full command parsed into units (chains, pipes, subshells, redirects) |
| `Read` / `Write` / `Edit` / `MultiEdit` | Not hooked | File path against `allow_read`/`deny_read`/`allow_write`/`deny_write` (if hooked manually) |
| Everything else | Allowed through | permcop only governs what it knows about |

**Why not hook file tools by default?**

Claude Code already gates file operations through its own permission system (approval dialogs, `autoApprove` settings). Hooking file tools as well creates friction for Claude's internal operations — writing plan files, updating memory, editing config — with little added benefit. If something slips past Claude Code's file permission system, the blast radius is far smaller than an unchecked shell command anyway.

If you do want to gate file tool calls, add the matchers manually to your Claude settings (see [Hook wiring](#hook-wiring)). Without explicit allow rules covering those paths, operations will fall through to Claude Code's own prompt.

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

Converts existing Claude Code permission rules to permcop TOML. Both `settings.json` and `settings.local.json` are merged as sources:

```bash
permcop import-claude-settings           # → .permcop.local.toml (default: personal overlay)
permcop import-claude-settings --shared  # → .permcop.toml (committed team policy)
permcop import-claude-settings --global  # → ~/.config/permcop/config.local.toml
```

Bash rules map to command `allow`/`deny` patterns. `Read`/`Edit` rules map to `allow_read`/`deny_read`/`allow_write`/`deny_write`. `ask` rules and non-file tools (WebFetch, MCP) are reported as warnings/skipped.

The default destination is the local config variant because Claude Code permissions are typically personal — they accumulate per-machine and shouldn't be committed as team policy. Use `--shared` if you're deliberately setting project-wide rules.

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

2026-03-04T04:58:25Z PASS
  original: make build
  reason:   no matching rule; deferred to Claude Code
```

**JSON format** (`log_format = "json"`): one object per line, suitable for `jq`.

## Hook wiring

`permcop init` adds this entry to `.claude/settings.local.json` in the project directory:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "permcop check"}]}
    ]
  }
}
```

Only `Bash` is hooked by default. If you want to gate file tools as well, add the extra matchers manually — but read the caveat in [Tools governed](#tools-governed) first.

## License

MIT — see [LICENSE](LICENSE).
