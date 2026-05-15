from __future__ import annotations

import asyncio
import os
import pathlib
import re
import time

DESCRIPTION = (
    "Run a shell command in an isolated per-agent sandbox. "
    "/workspace is the agent's private writable directory. "
    "/shared is the common upload directory (read-only): files written by upload_file or write_file are visible here. "
    "Supports pipes, redirects, and multi-command chains."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["command"],
    "properties": {
        "command": {
            "type": "string",
            "description": "Shell command to run (e.g. 'jq .items[].name data.json | sort | uniq -c').",
        },
        "timeout": {
            "type": "integer",
            "description": f"Max seconds to wait (default {os.environ.get('MCP_SHELL_TIMEOUT', '30')}, max 120).",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))
# Agent workspaces are kept outside _UPLOAD_DIR so that mounting _UPLOAD_DIR as
# /shared does not expose one agent's private workspace to another agent.
_WORKSPACE_BASE = pathlib.Path(os.environ.get("MCP_WORKSPACE_DIR", "/tmp/mcp-workspaces"))
_DEFAULT_TIMEOUT = int(os.environ.get("MCP_SHELL_TIMEOUT", "30"))
_MAX_OUTPUT = int(os.environ.get("MCP_SHELL_MAX_OUTPUT", "50000"))

_ALLOWLIST_ENV = os.environ.get("MCP_SHELL_ALLOWLIST", "")

_DEFAULT_ALLOWED = {
    "jq", "duckdb", "sqlite3",
    "python3", "python",
    "grep", "egrep", "fgrep", "awk", "gawk", "sed",
    "sort", "uniq", "cut", "tr", "head", "tail", "wc",
    "cat", "tee", "paste", "join", "comm", "diff",
    "ls", "find", "stat", "file", "md5sum", "sha256sum",
    "curl", "wget",
    "gzip", "gunzip", "zcat", "zip", "unzip", "tar",
    "pdftotext", "pandoc",
    "echo", "printf", "date", "bc", "xargs",
}

if _ALLOWLIST_ENV == "*":
    _ALLOWLIST: set[str] | None = None
elif _ALLOWLIST_ENV:
    _ALLOWLIST = {c.strip() for c in _ALLOWLIST_ENV.split(",") if c.strip()}
else:
    _ALLOWLIST = _DEFAULT_ALLOWED


def _workspace(agent_id: str) -> pathlib.Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", agent_id) or "default"
    d = _WORKSPACE_BASE / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def _check(command: str) -> None:
    if _ALLOWLIST is None:
        return
    # Split on all shell command separators including newlines and backticks,
    # which sh -c treats identically to semicolons.
    for segment in re.split(r"[|;&\n\r`]|\$\(|\$\{", command):
        words = segment.strip().split()
        if not words:
            continue
        name = os.path.basename(words[0])
        if name and name not in _ALLOWLIST:
            raise PermissionError(
                f"Command not permitted: {name!r}. "
                f"Set MCP_SHELL_ALLOWLIST env var to expand permissions."
            )


def _bwrap_cmd(command: str, workspace: pathlib.Path) -> list[str]:
    args = [
        "bwrap",
        "--new-session",
        "--die-with-parent",
        "--clearenv",
        "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv", "HOME", "/workspace",
        "--setenv", "LANG", "en_US.UTF-8",
        "--setenv", "TERM", "xterm",
        "--setenv", "UPLOAD_DIR", "/workspace",
        "--setenv", "SHARED_DIR", "/shared",
        # Core system — read-only
        "--ro-bind", "/usr", "/usr",
    ]

    # Handle merged-usr layout (Debian 12+): /bin, /lib etc. are symlinks → /usr/...
    # On older layouts they are real directories. Handle both.
    for path in ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"):
        p = pathlib.Path(path)
        if p.is_symlink():
            args += ["--symlink", os.readlink(path), path]
        elif p.is_dir():
            args += ["--ro-bind", path, path]

    # /etc: needed for DNS resolution, TLS certs, dynamic linker cache.
    # In Docker, /etc contains no operator secrets (those live in env vars, which
    # we've cleared above). Bind read-only so tools like curl and python work.
    args += ["--ro-bind", "/etc", "/etc"]

    # Kernel virtual filesystems
    args += [
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]

    # Shared space — read-only so shell can read files written by other agents
    # (via write_file/upload_file) but cannot corrupt or delete them.
    args += ["--ro-bind", str(_UPLOAD_DIR), "/shared"]

    # Agent workspace — the only writable location in the sandbox.
    # Mounted at /workspace; the agent cannot navigate above it.
    args += [
        "--bind", str(workspace), "/workspace",
        "--chdir", "/workspace",
    ]

    args += ["sh", "-c", command]
    return args


def _run(command: str, workspace: pathlib.Path, timeout: int) -> str:
    import subprocess

    _check(command)

    cmd = _bwrap_cmd(command, workspace)

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "bwrap not found — rebuild the Docker image to install bubblewrap."
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - t0
        return f"$ {command}\n--- timed out after {elapsed:.1f}s ---"

    elapsed = time.monotonic() - t0
    stdout = proc.stdout.rstrip("\n")
    stderr = proc.stderr.rstrip("\n")

    parts: list[str] = [f"$ {command}"]
    if stdout:
        if len(stdout) > _MAX_OUTPUT:
            stdout = stdout[:_MAX_OUTPUT] + f"\n[truncated — {len(proc.stdout) - _MAX_OUTPUT:,} chars omitted]"
        parts.append(stdout)
    if stderr:
        parts.append(f"--- stderr ---\n{stderr}")
    parts.append(f"--- exit {proc.returncode} ({elapsed:.2f}s)")

    return "\n".join(parts)


async def execute(arguments: dict) -> str:
    command: str = arguments["command"]
    agent_id: str = arguments.get("_agent_id", "default")
    timeout = min(int(arguments.get("timeout") or _DEFAULT_TIMEOUT), 120)
    workspace = _workspace(agent_id)
    return await asyncio.to_thread(_run, command, workspace, timeout)
