# Requirements: pypdf — install with: pip install "pypdf>=4"
from __future__ import annotations

import asyncio
import os
import pathlib

DESCRIPTION = "Extract text from a PDF in the upload directory. Use pages to limit output."

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename in the upload directory (e.g. 'report.pdf').",
        },
        "pages": {
            "type": "string",
            "description": "Pages to extract: range ('1-5'), single ('3'), or list ('1,4,7'). Omit for all.",
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


def _parse_pages(spec: str, total: int) -> list[int]:
    indices: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            indices.update(range(int(a) - 1, min(int(b), total)))
        elif part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < total:
                indices.add(idx)
    return sorted(indices)


def _extract(path: pathlib.Path, pages_spec: str | None) -> str:
    import pypdf  # deferred so missing dep only raises on call, not import

    reader = pypdf.PdfReader(str(path))
    total = len(reader.pages)
    page_indices = _parse_pages(pages_spec, total) if pages_spec else list(range(total))

    parts: list[str] = []
    for i in page_indices:
        text = (reader.pages[i].extract_text() or "").strip()
        if text:
            parts.append(f"--- Page {i + 1} ---\n{text}")

    header = f"[{len(page_indices)} of {total} page{'s' if total != 1 else ''} extracted]"
    return header + "\n\n" + "\n\n".join(parts)


async def execute(arguments: dict) -> str:
    path = _resolve(arguments["filename"])
    if not path.exists():
        raise FileNotFoundError(f"{arguments['filename']!r} not found in upload directory.")
    return await asyncio.to_thread(_extract, path, arguments.get("pages"))
