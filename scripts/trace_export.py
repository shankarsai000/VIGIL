"""VIGIL Trace Exporter — Action Records to JSONL.

Extracts redacted ActionRecords from the registry database and exports them
to JSONL for offline policy replay, counterfactual synthesis, and safety validation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.runtime.registry import AgentRegistry


async def export_traces(
    db_path: str,
    output_path: str,
    agent_id: Optional[str] = None,
    label: Optional[str] = None,
    limit: Optional[int] = None,
) -> int:
    """Exports action records from registry database to JSONL."""
    registry = AgentRegistry(db_path)
    await registry.init_db()

    query = "SELECT * FROM action_records"
    conditions = []
    params = []
    if agent_id:
        conditions.append("agent_id = ?")
        params.append(agent_id)
    if label:
        conditions.append("label = ?")
        params.append(label)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY ts ASC"
    if limit:
        query += f" LIMIT {int(limit)}"

    rows = await registry.db.fetch(query, tuple(params))
    
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    count = 0
    label_counts = {}

    with open(output_path, "w", encoding="utf-8") as f:
        for r in rows:
            shape_val = r["arg_shape"]
            shape_obj = json.loads(shape_val) if isinstance(shape_val, str) else shape_val
            doc = {
                "record_id": r["record_id"],
                "trace_id": r["trace_id"],
                "tenant_id": r["tenant_id"],
                "agent_id": r["agent_id"],
                "ts": r["ts"],
                "mcp_id": r["mcp_id"],
                "tool": r["tool"],
                "event_type": r["event_type"],
                "arg_shape": shape_obj,
                "provenance": r["provenance"],
                "prev_tool": r["prev_tool"],
                "observed_decision": r["observed_decision"],
                "label": r["label"],
                "label_source": r["label_source"],
                "incident_id": r["incident_id"],
            }
            f.write(json.dumps(doc) + "\n")
            count += 1
            lbl = r["label"]
            label_counts[lbl] = label_counts.get(lbl, 0) + 1

    await registry.db.close()
    print(f"Exported {count} action records to {output_path}")
    print(f"Label breakdown: {label_counts}")
    return count


def main():
    parser = argparse.ArgumentParser(description="Export action records to JSONL")
    parser.add_argument("--db", default=os.getenv("DATABASE_URL", "vigil.db"), help="Database path or URL")
    parser.add_argument("--output", "-o", default="evidence/action_traces.jsonl", help="Output JSONL path")
    parser.add_argument("--agent", default=None, help="Filter by agent_id")
    parser.add_argument("--label", default=None, help="Filter by label (ATTACK | BENIGN_ASSUMED | UNLABELLED)")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of records to export")

    args = parser.parse_args()
    asyncio.run(
        export_traces(
            db_path=args.db,
            output_path=args.output,
            agent_id=args.agent,
            label=args.label,
            limit=args.limit,
        )
    )


if __name__ == "__main__":
    main()
