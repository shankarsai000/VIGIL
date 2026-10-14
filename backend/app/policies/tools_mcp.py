"""FastMCP tool server for customer_bot operations (vigil-tools).

Exposes:
- order_status: Safe, legitimate business query tool.
- billing_database: Sensitive database query tool (target for policy loop demonstration).

Runs on streamable HTTP on port 8791.
"""

from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP

HOST = os.getenv("TOOLS_MCP_HOST", "127.0.0.1")
PORT = int(os.getenv("TOOLS_MCP_PORT", "8791"))

app = FastMCP("vigil-tools", host=HOST, port=PORT)
app.settings.stateless_http = True
if hasattr(app.settings, "transport_security") and app.settings.transport_security:
    app.settings.transport_security.enable_dns_rebinding_protection = False


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
async def billing_database(query: str) -> dict:
    """Execute administrative database lookup against billing ledgers."""
    return {
        "status": "success",
        "query": query,
        "rows_returned": 3,
        "sample": [
            {"invoice_id": "INV-1001", "amount": 450.00, "status": "PAID"},
            {"invoice_id": "INV-1002", "amount": 1200.50, "status": "PENDING"},
        ],
    }


if __name__ == "__main__":
    app.run(transport="streamable-http")
