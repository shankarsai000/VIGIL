"""Authentication for VIGIL's write endpoints, the WebSocket, and the containment callback.

Fail closed: when a secret is not configured, the protected routes refuse to run (HTTP 503) instead of running
open. Secrets are compared in constant time.
"""
from __future__ import annotations

import hmac
from typing import Optional

from fastapi import HTTPException, Request

from ..config import settings

OPERATOR_HEADER = "X-VIGIL-Operator-Key"
CONTAINMENT_HEADER = "X-Containment-Secret"


def _matches(presented: Optional[str], expected: str) -> bool:
    if not expected or not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def operator_key_valid(presented: Optional[str]) -> bool:
    """Used by the WebSocket, which passes its key as a query parameter."""
    return _matches(presented, settings.operator_api_key)


def require_operator(request: Request) -> None:
    """FastAPI dependency for write endpoints."""
    if not settings.operator_api_key:
        raise HTTPException(status_code=503, detail="OPERATOR_API_KEY is not configured; write endpoints are disabled.")
    if not _matches(request.headers.get(OPERATOR_HEADER), settings.operator_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid operator key.")


def require_containment_secret(request: Request) -> None:
    """Only the containment MCP server may call the containment callback."""
    if not settings.containment_secret:
        raise HTTPException(status_code=503, detail="CONTAINMENT_SECRET is not configured.")
    if not _matches(request.headers.get(CONTAINMENT_HEADER), settings.containment_secret):
        raise HTTPException(status_code=401, detail="Invalid containment secret.")
