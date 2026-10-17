"""Containment actuator behind ArmorIQ (Phase V2 Graduated Ladder).

ArmorIQ authorizes containment tools:
1. quarantine_agent: Full agent quarantine.
2. downgrade_session: Surgical session downgrade (strip write/admin tools).
3. route_to_shadow: Route session to synthetic Mirage sandbox.
4. rollback_session: Execute compensating rollback of session mutations.

This FastMCP server carries out the directives by calling VIGIL's internal containment
endpoints with a shared secret. VIGIL refuses containment calls that do not carry the secret.

Run:     python -m backend.app.policies.containment_mcp     (streamable HTTP at http://HOST:PORT/mcp)
Expose:  register with ArmorIQ, like any other MCP server.
"""
from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
load_dotenv()

import httpx
from mcp.server.fastmcp import FastMCP

HOST = os.getenv("CONTAINMENT_MCP_HOST", "127.0.0.1")
PORT = int(os.getenv("CONTAINMENT_MCP_PORT", "8790"))
VIGIL_INTERNAL_URL = os.getenv("VIGIL_INTERNAL_URL", "http://127.0.0.1:8000")
CONTAINMENT_SECRET = os.getenv("CONTAINMENT_SECRET", "")

app = FastMCP("vigil-containment", host=HOST, port=PORT)
app.settings.stateless_http = True
if hasattr(app.settings, "transport_security") and app.settings.transport_security:
    app.settings.transport_security.enable_dns_rebinding_protection = False


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=VIGIL_INTERNAL_URL, timeout=10.0)


@app.tool()
async def quarantine_agent(agent_id: str, reason: str, score: float = 0.0) -> dict:
    """Quarantine one agent in VIGIL. Call only after ArmorIQ has authorized the call."""
    if not CONTAINMENT_SECRET:
        return {"status": "refused", "detail": "CONTAINMENT_SECRET is not set on the containment server"}
    if not agent_id or len(agent_id) > 128:
        return {"status": "refused", "detail": "invalid agent_id"}
    async with _client() as client:
        response = await client.post(
            "/internal/containment/quarantine",
            json={"agent_id": agent_id, "reason": reason, "score": score},
            headers={"X-Containment-Secret": CONTAINMENT_SECRET},
        )
    if response.status_code != 200:
        return {"status": "error", "http_status": response.status_code}
    return {"status": "quarantined", "agent_id": agent_id}


@app.tool()
async def downgrade_session(session_id: str, reason: str, score: float = 0.0) -> dict:
    """Surgically downgrade a session to read-only capabilities in VIGIL. Call only after ArmorIQ authorization."""
    if not CONTAINMENT_SECRET:
        return {"status": "refused", "detail": "CONTAINMENT_SECRET is not set on the containment server"}
    if not session_id or len(session_id) > 128:
        return {"status": "refused", "detail": "invalid session_id"}
    async with _client() as client:
        response = await client.post(
            "/internal/containment/downgrade",
            json={"session_id": session_id, "reason": reason, "score": score},
            headers={"X-Containment-Secret": CONTAINMENT_SECRET},
        )
    if response.status_code != 200:
        return {"status": "error", "http_status": response.status_code}
    return {"status": "downgraded", "session_id": session_id}


@app.tool()
async def route_to_shadow(session_id: str, reason: str, score: float = 0.0) -> dict:
    """Transparently redirect a session to synthetic Mirage sandbox data. Call only after ArmorIQ authorization."""
    if not CONTAINMENT_SECRET:
        return {"status": "refused", "detail": "CONTAINMENT_SECRET is not set on the containment server"}
    if not session_id or len(session_id) > 128:
        return {"status": "refused", "detail": "invalid session_id"}
    async with _client() as client:
        response = await client.post(
            "/internal/containment/shadow",
            json={"session_id": session_id, "reason": reason, "score": score},
            headers={"X-Containment-Secret": CONTAINMENT_SECRET},
        )
    if response.status_code != 200:
        return {"status": "error", "http_status": response.status_code}
    return {"status": "shadow_routed", "session_id": session_id}


@app.tool()
async def rollback_session(session_id: str, reason: str, score: float = 0.0) -> dict:
    """Trigger compensating rollback of actions in a session. Call only after ArmorIQ authorization."""
    if not CONTAINMENT_SECRET:
        return {"status": "refused", "detail": "CONTAINMENT_SECRET is not set on the containment server"}
    if not session_id or len(session_id) > 128:
        return {"status": "refused", "detail": "invalid session_id"}
    async with _client() as client:
        response = await client.post(
            "/internal/containment/rollback",
            json={"session_id": session_id, "reason": reason, "score": score},
            headers={"X-Containment-Secret": CONTAINMENT_SECRET},
        )
    if response.status_code != 200:
        return {"status": "error", "http_status": response.status_code}
    return {"status": "rollback_triggered", "session_id": session_id}


if __name__ == "__main__":
    app.run(transport="streamable-http")
