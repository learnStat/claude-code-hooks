# claude-code-hooks

A collection of Python-based security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) that enforce deterministic guardrails on AI-assisted development workflows.

## Overview

Claude Code hooks provide deterministic control over Claude Code's behavior at key execution points — enforcing rules that the LLM cannot override, regardless of context or instruction. This repository contains production-ready hooks built around a clear design principle: **policy enforcement should be explicit, predictable, and independent of model judgment**.

---

## Hook: `sensitive_file_guard`

### Problem

Claude Code, like any agentic coding tool, operates with broad file system access by default. During development, this creates a tangible risk: the agent may read, modify, or expose sensitive files — environment configurations, private keys, and credentials — as part of routine task execution. This is not a model failure; it is an access boundary problem that requires a deterministic solution.

### Solution

A `PreToolUse` hook that intercepts Claude Code's `Read`, `Edit`, `Write`, and `Bash` tool calls before execution and blocks any operation targeting sensitive files. When blocked, Claude Code receives a structured error message explaining why the operation was denied, allowing it to suggest safe alternatives.

### Design Decisions

**Blocklist over allowlist**
A blocklist approach was chosen over an allowlist for developer ergonomics. An allowlist (only permit reads from approved directories) provides stronger security guarantees but introduces friction in everyday workflows. A blocklist targets the specific threat — known sensitive file patterns — without restricting general file access.

**Lenient Bash interception**
For the `Bash` tool, the hook applies a lenient matching strategy: it only blocks commands that are explicit read operations (`cat`, `grep`, `head`, `tail`, `less`, `more`, `awk`, `sed`) referencing `.env` files. Strict command string matching produces too many false positives in a solo development context. The tradeoff is accepted consciously.

**`.env.example` explicitly excluded**
`.env.example` is a safe, committed template file. Blocking it would interfere with legitimate scaffolding workflows. The hook checks the exact filename (for file path tools) and splits bash commands into tokens to inspect each argument's basename — distinguishing `.env.example` from `.env`, `.env.local`, `.env.prod`, and other live credential variants.

**Exit code 2 for structured feedback**
Claude Code's hook contract specifies that exit code 2 blocks the tool call and forwards `stderr` back to the model as feedback. This allows Claude Code to understand *why* it was blocked and suggest alternatives — rather than failing silently or confusing the user.

**Global scope**
The hook is registered in `~/.claude/settings.json` (global), not at the project level. Sensitive file protection is a developer-level concern that should apply uniformly across all projects, not be configured per repository.

### Protected Patterns

| Pattern | Covers |
|---|---|
| `.env`, `.env.*` | Environment configs (`.env.local`, `.env.prod`, `.env.staging`) |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Certificates and private keys |
| `id_rsa`, `id_ed25519` | SSH private keys |
| `*.pub` | SSH public keys |
| `credentials`, `credentials.json` | AWS, GCP credential files |
| `secrets.json`, `secrets.yaml` | Generic secrets files |
| `*.token` | Token files |

### Architecture

```
Claude Code (PreToolUse event)
        │
        ▼
  parse_hook_input()        # reads JSON payload from stdin
        │
        ▼
    should_block()          # routes to correct matching logic by tool_name
        │                   # returns (blocked: bool, target: str)
        ├── Read / Edit / Write → is_sensitive_file(file_path)
        │                         fnmatch against blocklist patterns
        │
        └── Bash            → is_sensitive_bash_command(command)
                              read-op detection + token-based .env matching
        │
        ▼
      main()                # exit 2 (block + stderr feedback) or exit 0 (allow)
```

Each unit is independently testable. `should_block` returns a `(blocked, target)` tuple, keeping decision logic separate from the side effect of exiting — which lives entirely in `main()`.

### Installation

**1. Copy the hook script to your global Claude hooks directory:**

```bash
mkdir -p ~/.claude/hooks
cp src/sensitive_file_guard.py ~/.claude/hooks/sensitive_file_guard.py
```

**2. Register the hook in `~/.claude/settings.json`:**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read|Edit|Write|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/sensitive_file_guard.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

**3. Verify the hook is active in Claude Code:**

```
/hooks
```

### Running Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers all three core functions (`is_sensitive_file`, `is_sensitive_bash_command`, `should_block`) across 25 cases including edge cases like `.envrc`, `.env.example`, paths, and missing input fields.

### Extending the Blocklist

To add additional sensitive file patterns, edit the `SENSITIVE_PATTERNS` list in `sensitive_file_guard.py`:

```python
SENSITIVE_PATTERNS = [
    ".env",
    ".env.*",
    # add your patterns here — fnmatch syntax supported
    "*.tfvars",          # Terraform variable files
    ".npmrc",            # npm credentials
]
```

Patterns use Python's `fnmatch` syntax. Matching is performed against the filename only, not the full path.


## Attribution

Built collaboratively with [Claude](https://claude.ai) (Anthropic). Requirements, design decisions, iterative refinements, and testing were driven by the author. Claude served as a coding partner and instructor throughout the process.