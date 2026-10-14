import logging
from typing import Dict, Any, List

logger = logging.getLogger("vigil.services.graph")

class GraphService:
    """Orchestrates agent relationship nodes, authorized tools, and live data delegation vectors."""

    def __init__(self):
        # Default authorized delegation vectors
        self._delegations = {
            "customer_bot": ["analytics_agent"],
            "analytics_agent": ["billing_agent"],
            "billing_agent": []
        }

    def get_authorized_delegations(self, agent_id: str) -> List[str]:
        """Returns the list of other agents this agent is authorized to delegate to."""
        return self._delegations.get(agent_id, [])

    def verify_delegation(self, source_agent: str, target_agent: str) -> bool:
        """Verifies if a delegation path from source to target is authorized by compliance standards."""
        allowed = self.get_authorized_delegations(source_agent)
        return target_agent in allowed

    def get_entire_graph(self) -> Dict[str, Any]:
        """Generates a complete layout representation of VIGIL's system-wide node-link relations."""
        nodes = []
        links = []
        
        # Build layout mapping
        agents = ["customer_bot", "analytics_agent", "billing_agent"]
        tools = {
            "customer_bot": ["search_knowledge_base", "send_email", "create_ticket"],
            "analytics_agent": ["query_database", "generate_report", "read_analytics"],
            "billing_agent": ["read_invoices", "process_refund", "send_receipt"]
        }

        # 1. Append Agent nodes
        for a in agents:
            nodes.append({
                "id": a,
                "type": "agent",
                "label": a.replace("_", " ").upper()
            })
            
            # 2. Append Allowed Tools nodes and tool links
            for t in tools.get(a, []):
                nodes.append({
                    "id": f"tool-{a}-{t}",
                    "type": "tool",
                    "label": t.replace("_", " ").upper()
                })
                links.append({
                    "source": a,
                    "target": f"tool-{a}-{t}",
                    "type": "tool_authorization"
                })
                
            # 3. Append allowed delegations links
            for target in self._delegations.get(a, []):
                links.append({
                    "source": a,
                    "target": target,
                    "type": "agent_delegation"
                })

        return {
            "nodes": nodes,
            "links": links
        }

# Singleton service instance
graph_service = GraphService()
