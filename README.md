# claude-code-hooks

## About

A Claude Code `PreToolUse` hook that blocks accidental access to sensitive files (`.env`, private keys, credentials) before tool calls execute.

When Claude Code runs a tool, it pipes the tool name and input as JSON to this script via stdin. The script evaluates the request and either allows it (exit 0) or blocks it with an error message (exit 2).

## How It Works

**For Read / Edit / Write tools** — blocked if the target file path matches any sensitive pattern.

**For Bash** — blocked if the command is a read-class operation (`cat`, `grep`, `head`, `tail`, `less`, `more`, `awk`, `sed`) targeting a `.env` file. `.env.example` is explicitly allowed.

**Sensitive file patterns blocked:**
- `.env`, `.env.*`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `id_rsa`, `id_ed25519`, `*.pub`
- `credentials`, `credentials.json`
- `secrets.json`, `secrets.yaml`
- `*.token`

## Project Structure

```
claude-code-hooks/
├── src/
│   └── sensitive_file_guard.py   # Hook implementation
├── outcomes/                      # Output directory
└── README.md
```

## Installing the Hook

Add the following to your Claude Code settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/claude-code-hooks/src/sensitive_file_guard.py"
          }
        ]
      }
    ]
  }
}
```

Replace `/path/to/claude-code-hooks` with the actual path to this repository.

## Testing the Hook Manually

```bash
# Should be BLOCKED
echo '{"tool_name": "Read", "tool_input": {"file_path": "/project/.env"}}' \
  | python3 src/sensitive_file_guard.py

# Should be ALLOWED
echo '{"tool_name": "Read", "tool_input": {"file_path": "/project/.env.example"}}' \
  | python3 src/sensitive_file_guard.py
```
