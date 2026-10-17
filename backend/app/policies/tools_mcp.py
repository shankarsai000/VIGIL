"""FastMCP tool server for customer_bot operations (vigil-tools).

Exposes:
- order_status: Safe, legitimate business query tool.
- billing_database: Sensitive database query tool. Supports transparent shadow routing
  to Mirage synthetic database when session is under SHADOW_SANDBOX containment directive.

Runs on streamable HTTP on port 8791.
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP
from ..runtime.mirage import mirage_db
from ..policies.containment_ladder import ContainmentTier, SessionContainmentManager

logger = logging.getLogger("vigil.tools_mcp")

HOST = os.getenv("TOOLS_MCP_HOST", "127.0.0.1")
PORT = int(os.getenv("TOOLS_MCP_PORT", "8791"))

app = FastMCP("vigil-tools", host=HOST, port=PORT)
app.settings.stateless_http = True
if hasattr(app.settings, "transport_security") and app.settings.transport_security:
    app.settings.transport_security.enable_dns_rebinding_protection = False

# Active containment manager for session routing directives
containment_manager = SessionContainmentManager()


@app.tool()
async def order_status(order_id: str) -> dict:
    """Check shipment and processing status for an order."""
    return {
        "order_id": order_id,
        "status": "PROCESSING",
        "carrier": "ExpressPost",
        "tracking_number": f"TRK-{abs(hash(order_id)) % 1000000}",
    }


@app.tool()
async def billing_database(query: str, session_id: str = "default") -> dict:
    """Execute administrative database lookup against billing ledgers.
    
    If the session is flagged for SHADOW_SANDBOX containment, execution is transparently
    routed to the synthetic Mirage database without touching real sandbox records.
    """
    tier = containment_manager.get_tier(session_id)
    if tier in (ContainmentTier.SHADOW_SANDBOX, ContainmentTier.QUARANTINE_ROLLBACK):
        logger.info("[Shadow Routing] Session %s routed to Mirage synthetic database", session_id)
        return mirage_db.query(query, session_id=session_id)

    # Real sandbox database response
    return {
        "source": "REAL_SANDBOX_DATABASE",
        "status": "success",
        "session_id": session_id,
        "query": query,
        "rows_returned": 2,
        "sample": [
            {"account_id": "REAL-ACT-9901", "invoice_id": "INV-1001", "amount": 450.00, "status": "PAID"},
            {"account_id": "REAL-ACT-9902", "invoice_id": "INV-1002", "amount": 1200.50, "status": "PENDING"},
        ],
    }


if __name__ == "__main__":
    app.run(transport="streamable-http")
