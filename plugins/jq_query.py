# Requirements: jq — install with: pip install jq
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import pathlib
import urllib.parse

import httpx

DESCRIPTION = (
    "Fetch JSON from a public URL or a file in the upload directory and apply a jq filter, "
    "returning only the result. Use when the payload is too large to pass through context."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["source", "filter"],
    "properties": {
        "source": {
            "type": "string",
            "description": (
                "Public https:// URL, or a bare filename in the upload directory "
                "(e.g. 'data.json'). Arbitrary file paths and private/internal URLs are not permitted."
            ),
        },
        "filter": {
            "type": "string",
            "description": "jq filter (e.g. '.items[].name', '.[] | select(.active)', '[.users[] | {id, email}]').",
        },
        "max_chars": {
            "type": "integer",
            "description": "Truncate output (default 50000 chars).",
        },
    },
}

_DEFAULT_MAX = 50_000
_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))

# RFC-1918, loopback, link-local, and other non-routable ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _is_private(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # hostname — block obvious internal names
        h = host.lower().rstrip(".")
        return h in ("localhost", "metadata", "169.254.169.254") or h.endswith(".local") or h.endswith(".internal")


def _validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// URLs are permitted, got: {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL has no host")
    if _is_private(host):
        raise PermissionError(f"Requests to private/internal hosts are not permitted: {host!r}")


def _resolve_file(filename: str) -> pathlib.Path:
    safe = pathlib.Path(filename).name
    if not safe or safe in (".", ".."):
        raise ValueError(f"Invalid filename: {filename!r}")
    p = (_UPLOAD_DIR / safe).resolve()
    if not str(p).startswith(str(_UPLOAD_DIR.resolve())):
        raise PermissionError("Path outside upload directory")
    if not p.exists():
        raise FileNotFoundError(f"{filename!r} not found in upload directory.")
    return p


async def _load(source: str) -> str:
    if source.startswith(("http://", "https://")):
        _validate_url(source)
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            resp = await client.get(source, headers={"User-Agent": "mcp-wrapper-plugin/1.0"})
            resp.raise_for_status()
        return resp.text
    # Treat as a bare filename in the upload directory
    return _resolve_file(source).read_text()


def _run(data_str: str, filter_expr: str) -> str:
    import jq  # deferred so missing dep only raises on call

    data = json.loads(data_str)
    results = jq.compile(filter_expr).input(data).all()
    if len(results) == 1:
        return json.dumps(results[0], indent=2, ensure_ascii=False)
    return json.dumps(results, indent=2, ensure_ascii=False)


async def execute(arguments: dict) -> str:
    source: str = arguments["source"]
    filter_expr: str = arguments["filter"]
    max_chars = int(arguments.get("max_chars") or _DEFAULT_MAX)

    data_str = await _load(source)
    result = await asyncio.to_thread(_run, data_str, filter_expr)

    if len(result) > max_chars:
        result = (
            result[:max_chars]
            + f"\n\n[truncated — {len(result) - max_chars:,} chars omitted;"
            + " refine your filter or increase max_chars]"
        )
    return result
