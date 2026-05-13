# Requirements: httpx (already a mcp-wrapper dependency)
from __future__ import annotations

from html.parser import HTMLParser

import httpx

DESCRIPTION = (
    "Fetch a webpage and return only the visible text content of its <body>, "
    "with <script>, <style>, and <head> content removed."
)

INPUT_SCHEMA = {
    "type": "object",
    "required": ["url"],
    "properties": {
        "url": {
            "type": "string",
            "description": "The URL to fetch",
        },
    },
}


class _BodyTextExtractor(HTMLParser):
    _SKIP = {"script", "style", "head", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__()
        self._in_body = False
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "body":
            self._in_body = True
        if self._in_body and tag in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if self._in_body and tag in self._SKIP and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "body":
            self._in_body = False

    def handle_data(self, data: str) -> None:
        if self._in_body and self._skip_depth == 0:
            text = data.strip()
            if text:
                self._parts.append(text)

    @property
    def text(self) -> str:
        return "\n".join(self._parts)


async def execute(arguments: dict) -> str:
    url = arguments["url"]
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        resp = await client.get(url, headers={"User-Agent": "mcp-wrapper-plugin/1.0"})
        resp.raise_for_status()
    parser = _BodyTextExtractor()
    parser.feed(resp.text)
    return parser.text or resp.text
