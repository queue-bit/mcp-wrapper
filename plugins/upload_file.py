from __future__ import annotations

import base64
import os
import pathlib

DESCRIPTION = (
    "Save a base64-encoded file to the upload directory and return its path. "
    "Use before xlsx_to_csv, pdf_to_text, read_file, or other path-based tools."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename", "content_base64"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename including extension (e.g. 'report.xlsx').",
        },
        "content_base64": {
            "type": "string",
            "description": "Base64-encoded file content.",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))


async def execute(arguments: dict) -> str:
    raw_filename: str = arguments["filename"]
    content_b64: str = arguments["content_base64"]

    # Strip any path components — only keep the bare filename
    safe_name = pathlib.Path(raw_filename).name
    if not safe_name or safe_name in (".", ".."):
        raise ValueError(f"Invalid filename: {raw_filename!r}")

    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # Accept standard and URL-safe base64, with or without padding
    try:
        data = base64.b64decode(content_b64, validate=False)
    except Exception as exc:
        raise ValueError(f"content_base64 is not valid base64: {exc}") from exc

    dest = _UPLOAD_DIR / safe_name
    dest.write_bytes(data)

    return str(dest)
