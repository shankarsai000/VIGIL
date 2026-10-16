"""FastMCP tool server for VIGIL Phase M5 (vigil-tools).

Exposes:
- billing_database(query: str): Sensitive billing database lookup tool.
- order_status(order_id: str): Benign order shipment status tool.

Runs on streamable HTTP on port 8791.
In live mode, exposed via Cloudflare tunnel to ArmorIQ customer proxy.
"""

from __future__ import annotations

import os
import sys
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
        "status": "DELIVERED",
        "carrier": "ExpressPost",
        "tracking_number": f"TRK-{abs(hash(order_id)) % 1000000:06d}",
        "estimated_delivery": "2026-10-16T12:00:00Z",
    }


@app.tool()
async def billing_database(query: str) -> dict:
    """Execute database lookup against billing ledgers."""
    return {
        "status": "success",
        "query": query,
        "rows_returned": 2,
        "records": [
            {"account_id": "ACC-9921", "balance_usd": 450.00, "status": "ACTIVE"},
            {"account_id": "ACC-9922", "balance_usd": 1285.50, "status": "OVERDUE"},
        ],
    }


if __name__ == "__main__":
    print(f"Starting vigil-tools FastMCP server on http://{HOST}:{PORT}")
    app.run(transport="streamable-http")
