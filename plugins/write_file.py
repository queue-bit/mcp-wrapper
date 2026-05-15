from __future__ import annotations

import os
import pathlib

DESCRIPTION = "Write text content to a file in the upload directory, creating or overwriting it. Returns the saved path."

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename", "content"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename including extension (e.g. 'output.csv').",
        },
        "content": {
            "type": "string",
            "description": "Text content to write.",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))


async def execute(arguments: dict) -> str:
    safe_name = pathlib.Path(arguments["filename"]).name
    if not safe_name or safe_name in (".", ".."):
        raise ValueError(f"Invalid filename: {arguments['filename']!r}")

    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    path = _UPLOAD_DIR / safe_name
    encoded = arguments["content"].encode()
    path.write_bytes(encoded)
    return f"Wrote {len(encoded):,} bytes to {path}"
