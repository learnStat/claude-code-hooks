import fnmatch
import json
import os
import sys
import re


# ---------------------------------------------------------------------------
# Blocklist: patterns matched against file paths (Read, Edit, Write tools)
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "*.pub",
    "credentials",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "*.token",
]

# ---------------------------------------------------------------------------
# Bash: read-class commands that should not touch .env files
# ---------------------------------------------------------------------------

BASH_READ_COMMANDS = {"cat", "grep", "head", "tail", "less", "more", "awk", "sed"}

# ---------------------------------------------------------------------------
# Env-dump detection: variable name fragments that indicate secrets
# ---------------------------------------------------------------------------

SECRET_VAR_FRAGMENTS = [
    "ANTHROPIC", "API_KEY", "SECRET", "PASSWORD", "TOKEN",
    "PRIVATE_KEY", "AWS_", "OPENAI", "GITHUB_TOKEN", "DATABASE_URL",
]


def is_sensitive_file(file_path: str) -> bool:
    """Return True if file_path matches any sensitive pattern."""
    name = os.path.basename(file_path)
    if name == ".env.example":
        return False
    return any(fnmatch.fnmatch(name, p) for p in SENSITIVE_PATTERNS)

def is_env_dump_command(command: str) -> bool:
    """
    Block bare env/printenv/export and env piped to other commands.
    Allows env VAR=value cmd (legitimate subprocess use) and export VAR=value.
    """
    parts = command.strip().split()
    if not parts:
        return False

    cmd, args = parts[0], parts[1:]

    if cmd in ("printenv", "export"):
        return len(args) == 0

    if cmd == "env":
        if not args:
            return True
        # env | grep ... — piped dump
        if args[0] == "|":
            return True
        # env VAR=value some_command — find first non-assignment token
        for arg in args:
            if "=" not in arg:
                return False  # found a real command to run, legitimate use
        return True  # only VAR=value args, no command — treat as dump

    return False


def references_secret_var(command: str) -> bool:
    """Block commands that explicitly name a known secret variable fragment."""
    upper_cmd = command.upper()
    return any(fragment in upper_cmd for fragment in SECRET_VAR_FRAGMENTS)


def is_sensitive_bash_command(command: str) -> bool:
    """
    Return True if a bash command should be blocked:
    - env-dump commands (env, printenv, export bare or piped)
    - commands referencing known secret variable names
    - read-class commands targeting .env files
    """
    if is_env_dump_command(command) or references_secret_var(command):
        return True

    parts = command.strip().split()
    if not parts or parts[0] not in BASH_READ_COMMANDS:
        return False

    for token in parts[1:]:
        name = os.path.basename(token.strip("\"'"))
        if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            return True

    return False

def parse_hook_input() -> dict:
    """
    Read and parse the JSON payload Claude Code sends via stdin.
    Returns the parsed dict, or exits cleanly if input is invalid.
    """

    try:
        raw = sys.stdin.read()
        return json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

def should_block(hook_input: dict) -> tuple[bool, str]:
    """
    Route to the correct matching logic based on tool_name.
    Returns (blocked, target) where target is used in the error message.
    """
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name in ("Read", "Edit", "Write"):
        file_path = tool_input.get("file_path", "")
        return is_sensitive_file(file_path), file_path

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return is_sensitive_bash_command(command), command

    return False, ""


def main():
    hook_input = parse_hook_input()
    blocked, target = should_block(hook_input)
    if blocked:
        print(
            f"BLOCKED by sensitive-file-guard: '{target}' matches a sensitive file policy. "
            "Do not read, write, or execute commands against sensitive files such as "
            ".env, private keys, or credential files.",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

