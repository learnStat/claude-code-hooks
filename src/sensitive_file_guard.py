import fnmatch
import re
import json
import sys


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


def is_sensitive_file(file_path: str)->bool:
    """Return True if file_path matches any sensitive pattern."""
    filename = file_path.split("/")[-1]
    for pattern in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(filename,pattern):
            return True
    
    return False

def is_sensitive_bash_command(command: str)-> bool:
    """
    Return True if a bash command is a read-class operation
    referencing a .env file (but not .env.example).
    """
    base_command = command.strip().split()[0] if command.strip() else ""

    if base_command not in BASH_READ_COMMANDS:
        return False
    
    env_pattern = re.compile(r'\.env(\.\w+)?')
    matches = env_pattern.findall(command)

    for suffix in matches:
        if suffix ==".example":
            continue
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

def should_block(hook_input: dict) -> bool:
    """
    Route to the correct matching logic based on tool_name.
    Returns True if the tool call should be blocked.
    """
    tool_name = hook_input.get("tool_name","")
    tool_input = hook_input.get("tool_input","")

    if tool_name in ("Read", "Edit","Write"):
        file_path = tool_input.get("file_path","")
        return is_sensitive_file(file_path)
    if tool_name == "Bash":
        command = tool_input.get("command","")
        return is_sensitive_bash_command(command)
    
    return False

def handle_decision(hook_input:dict) -> None:
    """
    Act on the block decision. Exit 2 to block, exit 0 to allow.
    """

    tool_name = hook_input.get("tool_name","")
    tool_input = hook_input.get("tool_input","")

    if should_block(hook_input):
        if tool_name == "Bash":
            target = tool_input.get("command","")
        else:
            target =tool_input.get("file_path","")
        
        print(
            f"BLOCKED by sensitive-file-guard: '{target}' matches a sensitive file policy. "
            "Do not read, write, or execute commands against sensitive files such as "
            ".env, private keys, or credential files.",
            file=sys.stderr
        )
        sys.exit(2)

    sys.exit(0)

def main():
    hook_input = parse_hook_input()
    handle_decision(hook_input)


if __name__ == "__main__":
    main()

