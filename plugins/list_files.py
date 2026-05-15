from __future__ import annotations

import datetime
import os
import pathlib

DESCRIPTION = "List files in the upload directory with name, size, and modified time."

INPUT_SCHEMA = {
    "type": "object",
    "properties": {},
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


async def execute(arguments: dict) -> str:
    if not _UPLOAD_DIR.exists():
        return f"Upload directory {_UPLOAD_DIR} does not exist yet. Use upload_file to add files."

    entries = sorted(
        (p for p in _UPLOAD_DIR.iterdir() if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not entries:
        return f"No files in {_UPLOAD_DIR}. Use upload_file to add files."

    count = len(entries)
    lines = [f"{count} file{'s' if count != 1 else ''} in {_UPLOAD_DIR}/\n"]
    for p in entries:
        stat = p.stat()
        size = _fmt_size(stat.st_size)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        lines.append(f"  {p.name:<44} {size:>10}  {mtime}")
    lines.append(f"\nPrefix paths with: {_UPLOAD_DIR}/")
    return "\n".join(lines)
