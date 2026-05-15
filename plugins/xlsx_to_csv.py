# Requirements: openpyxl — install with: pip install openpyxl
from __future__ import annotations

import asyncio
import csv
import io
import os
import pathlib

DESCRIPTION = "Read an Excel (.xlsx) file from the upload directory and return its contents as CSV."

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename in the upload directory (e.g. 'data.xlsx').",
        },
        "sheet": {
            "type": "string",
            "description": "Sheet name (omit for the first/active sheet).",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))


def _resolve(filename: str) -> pathlib.Path:
    safe = pathlib.Path(filename).name
    if not safe or safe in (".", ".."):
        raise ValueError(f"Invalid filename: {filename!r}")
    p = (_UPLOAD_DIR / safe).resolve()
    if not str(p).startswith(str(_UPLOAD_DIR.resolve())):
        raise PermissionError("Path outside upload directory")
    return p


def _convert(path: pathlib.Path, sheet_name: str | None) -> str:
    import openpyxl  # deferred so missing dep only raises on call, not at load time

    wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
    ws = wb[sheet_name] if sheet_name else wb.active
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in ws.iter_rows(values_only=True):
        writer.writerow(["" if v is None else v for v in row])
    wb.close()
    return buf.getvalue()


async def execute(arguments: dict) -> str:
    path = _resolve(arguments["filename"])
    if not path.exists():
        raise FileNotFoundError(f"{arguments['filename']!r} not found in upload directory.")
    sheet = arguments.get("sheet")
    return await asyncio.to_thread(_convert, path, sheet)
