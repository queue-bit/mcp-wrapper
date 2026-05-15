from __future__ import annotations

"""Transport-agnostic MCP JSON-RPC client.

Supports two transports:
  http  — single POST per request (streamable HTTP / plain JSON-RPC)
  sse   — persistent GET stream + session-scoped POST (MCP SSE transport)
"""

import asyncio
import json
import logging
import uuid
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTTP transport (streamable HTTP / JSON-RPC POST)
# ---------------------------------------------------------------------------

async def _http_request(
    url: str,
    token: str | None,
    method: str,
    params: dict | None,
    timeout: float,
) -> dict:
    auth: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
    body: dict = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
    if params is not None:
        body["params"] = params
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.post(
            url,
            json=body,
            headers={**auth, "Content-Type": "application/json", "Accept": "application/json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# SSE transport (MCP SSE: persistent GET stream + session POST)
# ---------------------------------------------------------------------------

async def _sse_request(
    url: str,
    token: str | None,
    method: str,
    params: dict | None,
    timeout: float,
) -> dict:
    """One-shot MCP request via SSE transport.

    Protocol:
      1. GET url  →  server streams events
      2. First event: type=endpoint, data=<messages_url>
      3. POST messages_url with JSON-RPC body
      4. Server sends type=message event with JSON-RPC response
    """
    auth: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}
    req_id = str(uuid.uuid4())
    body: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        body["params"] = params

    # Queue carries (event_type, data) tuples; None signals stream end.
    queue: asyncio.Queue[tuple[str | None, str] | None] = asyncio.Queue()

    async def _stream() -> None:
        try:
            # Resolve same-origin redirects only, preserving the Authorization header.
            # Cross-domain redirects are ignored — they are typically CDN affinity
            # hops that don't host the actual MCP endpoint.
            resolved = url
            resolved_host = urlparse(url).netloc
            async with httpx.AsyncClient(follow_redirects=False) as resolver:
                for _ in range(5):
                    r = await resolver.get(
                        resolved,
                        headers={**auth, "Accept": "text/event-stream"},
                        timeout=10.0,
                    )
                    if r.is_redirect:
                        location = str(r.headers.get("location", ""))
                        if urlparse(location).netloc != resolved_host:
                            log.debug("SSE: ignoring cross-domain redirect to %s", location)
                            break
                        resolved = location
                        log.debug("SSE redirect: %s → %s", url, resolved)
                    else:
                        break

            async with httpx.AsyncClient(follow_redirects=False) as c:
                async with c.stream(
                    "GET",
                    resolved,
                    headers={**auth, "Accept": "text/event-stream", "Cache-Control": "no-cache"},
                    timeout=httpx.Timeout(timeout, connect=10.0),
                ) as resp:
                    resp.raise_for_status()
                    current_event: str | None = None
                    async for raw in resp.aiter_lines():
                        line = raw.strip()
                        if not line:
                            current_event = None
                        elif line.startswith("event:"):
                            current_event = line[6:].strip()
                        elif line.startswith("data:"):
                            await queue.put((current_event, line[5:].strip()))
                            current_event = None
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.warning("SSE stream error for %s: %s", url, exc)
        finally:
            await queue.put(None)

    task = asyncio.create_task(_stream())
    try:
        # --- Step 1: wait for endpoint event ---
        messages_url: str | None = None
        while messages_url is None:
            item = await asyncio.wait_for(queue.get(), timeout=10.0)
            if item is None:
                raise RuntimeError("SSE stream closed before sending endpoint event")
            evt_type, data = item
            if evt_type == "endpoint":
                parsed = urlparse(url)
                if data.startswith("/"):
                    messages_url = f"{parsed.scheme}://{parsed.netloc}{data}"
                elif data.startswith("http"):
                    messages_url = data
                else:
                    messages_url = urljoin(url, data)

        # --- Step 2: POST the JSON-RPC request ---
        async with httpx.AsyncClient(follow_redirects=True) as post_client:
            post_resp = await post_client.post(
                messages_url,
                json=body,
                headers={**auth, "Content-Type": "application/json"},
                timeout=10.0,
            )
            if post_resp.status_code not in (200, 202):
                post_resp.raise_for_status()

        # --- Step 3: read response from SSE stream ---
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            remaining = max(0.5, deadline - asyncio.get_event_loop().time())
            item = await asyncio.wait_for(queue.get(), timeout=remaining)
            if item is None:
                raise RuntimeError("SSE stream closed without a response")
            _, data = item
            try:
                msg = json.loads(data)
                if isinstance(msg, dict) and msg.get("id") == req_id:
                    return msg
            except json.JSONDecodeError:
                continue

        raise TimeoutError(f"No SSE response within {timeout}s")

    finally:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def mcp_request(
    url: str,
    token: str | None,
    transport: str,
    method: str,
    params: dict | None = None,
    timeout: float = 30.0,
) -> dict:
    """Send one MCP JSON-RPC request using the specified transport."""
    if transport == "sse":
        return await _sse_request(url, token, method, params, timeout)
    return await _http_request(url, token, method, params, timeout)
