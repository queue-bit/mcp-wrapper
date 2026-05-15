# Requirements: duckdb — install with: pip install duckdb
from __future__ import annotations

import asyncio
import os
import pathlib

DESCRIPTION = (
    "Run SQL against a CSV file in the upload directory using DuckDB. "
    "Table name is 'data'. Use when the file is too large to read in full."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["filename", "query"],
    "properties": {
        "filename": {
            "type": "string",
            "description": "Bare filename in the upload directory (e.g. 'sales.csv').",
        },
        "query": {
            "type": "string",
            "description": "SQL query; table name is 'data' (e.g. 'SELECT region, SUM(revenue) FROM data GROUP BY 1').",
        },
    },
}

_UPLOAD_DIR = pathlib.Path(os.environ.get("MCP_UPLOAD_DIR", "/tmp/mcp-uploads"))


def _validate_query(query: str) -> None:
    stripped = query.strip().upper()
    if not stripped.startswith("SELECT"):
        raise ValueError("Only SELECT queries are permitted.")
    # Block keywords that could access external resources or execute code.
    _BLOCKED = ("COPY", "EXPORT", "IMPORT", "INSTALL", "LOAD", "ATTACH", "DETACH", "CALL", "PRAGMA")
    for kw in _BLOCKED:
        if kw in stripped:
            raise ValueError(f"Keyword {kw!r} is not permitted in queries.")


def _run(csv_path: str, query: str) -> str:
    import duckdb  # deferred so missing dep only raises on call

    _validate_query(query)

    conn = duckdb.connect(database=":memory:")
    # Disable all extensions to prevent read_csv_auto('/etc/...') style attacks
    # and httpfs-based exfiltration.
    conn.execute("SET autoinstall_known_extensions = false")
    conn.execute("SET autoload_known_extensions = false")
    conn.execute(f"CREATE VIEW data AS SELECT * FROM read_csv_auto(?)", [csv_path])
    rel = conn.execute(query)

    cols = [desc[0] for desc in rel.description]
    rows = rel.fetchall()

    if not rows:
        return f"Query returned 0 rows.\nColumns: {', '.join(cols)}"

    str_rows = [
        ["NULL" if v is None else str(v) for v in row]
        for row in rows
    ]
    col_widths = [
        max(len(c), max(len(r[i]) for r in str_rows))
        for i, c in enumerate(cols)
    ]

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header = "| " + " | ".join(c.ljust(col_widths[i]) for i, c in enumerate(cols)) + " |"

    lines = [sep, header, sep]
    for row in str_rows:
        lines.append("| " + " | ".join(v.ljust(col_widths[i]) for i, v in enumerate(row)) + " |")
    lines.append(sep)
    lines.append(f"\n{len(rows)} row{'s' if len(rows) != 1 else ''}")
    return "\n".join(lines)


async def execute(arguments: dict) -> str:
    safe_name = pathlib.Path(arguments["filename"]).name
    if not safe_name or safe_name in (".", ".."):
        raise ValueError(f"Invalid filename: {arguments['filename']!r}")

    path = _UPLOAD_DIR / safe_name
    if not path.exists():
        raise FileNotFoundError(
            f"{safe_name} not found in upload directory. Call list_files to see available files."
        )

    return await asyncio.to_thread(_run, str(path), arguments["query"])
