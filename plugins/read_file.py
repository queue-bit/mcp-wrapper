from __future__ import annotations

import os
import pathlib

DESCRIPTION = (
    "Read a text file from the upload directory. "
    "For Excel use xlsx_to_csv; for PDFs use pdf_to_text."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename (e.g. 'data.csv').",
        },
        "max_chars": {
            "type": "integer",
            "description": "Maximum characters to return (default 100000).",
        },
        "offset": {
            "type": "integer",
            "description": "Character offset for pagination (default 0).",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))
_DEFAULT_MAX = 100_000


async def execute(arguments: dict) -> str:
    safe_name = pathlib.Path(arguments["filename"]).name
    if not safe_name or safe_name in (".", ".."):
        raise ValueError(f"Invalid filename: {arguments['filename']!r}")

    path = _UPLOAD_DIR / safe_name
    if not path.exists():
        raise FileNotFoundError(f"{safe_name} not found in upload directory. Call list_files to see available files.")

    max_chars = int(arguments.get("max_chars") or _DEFAULT_MAX)
    offset = int(arguments.get("offset") or 0)

    text = path.read_text(errors="replace")
    total = len(text)
    chunk = text[offset: offset + max_chars]

    if offset + max_chars < total:
        remaining = total - (offset + max_chars)
        return (
            chunk
            + f"\n\n[truncated — {remaining:,} chars remaining;"
            + f" call again with offset={offset + max_chars} to continue]"
        )
    return chunk
