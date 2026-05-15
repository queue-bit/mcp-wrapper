# Requirements: httpx (already a mcp-wrapper dependency)
from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser

import httpx

DESCRIPTION = (
    "Convert a URL or HTML string to Markdown, stripping navigation and scripts. "
    "Prefer over fetch_body when page structure (headings, links, lists) matters."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["source"],
    "properties": {
        "source": {
            "type": "string",
            "description": "URL (http/https) or raw HTML string.",
        },
        "max_chars": {
            "type": "integer",
            "description": "Truncate output (default 50000 chars).",
        },
    },
}

_DEFAULT_MAX = 50_000

# Tags whose entire subtree is dropped
_SKIP = frozenset({
    "script", "style", "head", "noscript", "template",
    "nav", "header", "footer", "aside", "iframe", "svg", "form",
})

_HEADINGS = {
    "h1": "#", "h2": "##", "h3": "###",
    "h4": "####", "h5": "#####", "h6": "######",
}

_EMPHASIS = {"strong": "**", "b": "**", "em": "*", "i": "*"}

_BLOCK = frozenset({
    "p", "div", "section", "article", "main",
    "figure", "figcaption", "details", "summary",
})


class _Converter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._buf: list[str] = []
        self._skip: int = 0          # nesting depth of skipped subtrees
        self._pre: int = 0           # nesting depth of <pre>
        self._pending_nl: int = 0    # deferred blank lines (collapsed)
        self._list: list[str] = []   # "ul" / "ol" stack
        self._counters: list[int] = []
        # Each entry: (href_or_None, did_we_emit_open_bracket)
        self._links: list[tuple[str | None, bool]] = []

    def _nl(self, n: int = 2) -> None:
        self._pending_nl = max(self._pending_nl, n)

    def _emit(self, s: str) -> None:
        if not s:
            return
        if self._pending_nl:
            self._buf.append("\n" * self._pending_nl)
            self._pending_nl = 0
        self._buf.append(s)

    # ------------------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in _SKIP:
            self._skip += 1
            return
        if self._skip:
            return

        a = dict(attrs)

        if tag in _HEADINGS:
            self._nl(2)
            self._emit(_HEADINGS[tag] + " ")
        elif tag == "p":
            self._nl(2)
        elif tag in _BLOCK:
            self._nl(1)
        elif tag == "br":
            self._nl(1)
        elif tag == "hr":
            self._nl(2)
            self._emit("---")
            self._nl(2)
        elif tag == "pre":
            self._pre += 1
            self._nl(2)
            self._emit("```")
            self._nl(1)
        elif tag == "code" and not self._pre:
            self._emit("`")
        elif tag in _EMPHASIS:
            self._emit(_EMPHASIS[tag])
        elif tag == "a":
            href = a.get("href", "")
            valid = bool(href) and not href.startswith("javascript:")
            if valid:
                self._emit("[")
                self._links.append((href, True))
            else:
                self._links.append((None, False))
        elif tag == "img":
            alt = a.get("alt", "").strip()
            src = a.get("src", "")
            if alt:
                self._emit(f"![{alt}]({src})")
        elif tag == "ul":
            self._list.append("ul")
            self._counters.append(0)
            self._nl(1)
        elif tag == "ol":
            self._list.append("ol")
            self._counters.append(0)
            self._nl(1)
        elif tag == "li":
            self._nl(1)
            indent = "  " * (len(self._list) - 1)
            if self._list and self._list[-1] == "ol":
                self._counters[-1] += 1
                self._emit(f"{indent}{self._counters[-1]}. ")
            else:
                self._emit(f"{indent}- ")
        elif tag == "blockquote":
            self._nl(2)
        elif tag == "table":
            self._nl(2)
        elif tag == "tr":
            self._nl(1)
            self._emit("| ")
        elif tag in ("th", "td"):
            pass  # separator appended on close

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP:
            if self._skip:
                self._skip -= 1
            return
        if self._skip:
            return

        if tag in _HEADINGS:
            self._nl(2)
        elif tag == "p":
            self._nl(2)
        elif tag in _BLOCK:
            self._nl(1)
        elif tag == "pre":
            if self._pre:
                self._pre -= 1
            self._nl(1)
            self._emit("```")
            self._nl(2)
        elif tag == "code" and not self._pre:
            self._emit("`")
        elif tag in _EMPHASIS:
            self._emit(_EMPHASIS[tag])
        elif tag == "a":
            if self._links:
                href, opened = self._links.pop()
                if opened and href:
                    self._emit(f"]({href})")
        elif tag in ("ul", "ol"):
            if self._list:
                self._list.pop()
            if self._counters:
                self._counters.pop()
            self._nl(1)
        elif tag == "li":
            self._nl(1)
        elif tag in ("th", "td"):
            self._emit(" |")
        elif tag == "tr":
            self._nl(1)
        elif tag == "table":
            self._nl(2)

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._pre:
            # Preserve whitespace verbatim inside code blocks
            if self._pending_nl:
                self._buf.append("\n" * self._pending_nl)
                self._pending_nl = 0
            self._buf.append(data)
            return
        text = re.sub(r"[ \t\r\n]+", " ", data)
        # Drop a lone space at the start of a block
        cur = "".join(self._buf)
        if text == " " and (not cur or cur.endswith("\n") or self._pending_nl):
            return
        self._emit(text)

    def result(self) -> str:
        out = "".join(self._buf)
        out = re.sub(r"\n{3,}", "\n\n", out)
        return out.strip()


def _convert(html: str) -> str:
    p = _Converter()
    p.feed(html)
    return p.result()


async def execute(arguments: dict) -> str:
    source: str = arguments["source"]
    max_chars = int(arguments.get("max_chars") or _DEFAULT_MAX)

    if source.startswith(("http://", "https://")):
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            resp = await client.get(source, headers={"User-Agent": "mcp-wrapper-plugin/1.0"})
            resp.raise_for_status()
        html = resp.text
    else:
        html = source

    md = await asyncio.to_thread(_convert, html)

    if len(md) > max_chars:
        md = md[:max_chars] + f"\n\n[truncated — {len(md) - max_chars:,} chars omitted; use max_chars to get more]"
    return md
