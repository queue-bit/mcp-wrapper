# Requirements: openpyxl — install with: pip install openpyxl
from __future__ import annotations

import asyncio
import csv
import io

DESCRIPTION = (
    "Read an Excel (.xlsx) file from the local filesystem and return its contents as CSV text. "
    "Specify a sheet name to target a specific sheet; omit to use the first (active) sheet."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["path"],
    "properties": {
        "path": {
            "type": "string",
            "description": "Absolute path to the .xlsx file on the local filesystem",
        },
        "sheet": {
            "type": "string",
            "description": "Sheet name to convert (omit for the first/active sheet)",
        },
    },
}


def _convert(path: str, sheet_name: str | None) -> str:
    import openpyxl  # deferred so missing dep only raises on call, not at load time

    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb[sheet_name] if sheet_name else wb.active
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in ws.iter_rows(values_only=True):
        writer.writerow(["" if v is None else v for v in row])
    wb.close()
    return buf.getvalue()


async def execute(arguments: dict) -> str:
    path = arguments["path"]
    sheet = arguments.get("sheet")
    return await asyncio.to_thread(_convert, path, sheet)
