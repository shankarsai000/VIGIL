import logging
import time
from typing import List, Dict, Any, Set
from ..app.runtime.models import AttackGraphNode, AttackGraphEdge, AgentStatus

logger = logging.getLogger("vigil.services.attack_graph")

class AttackGraphService:
    """Manages agent-to-agent delegation graphs, predicting threat propagation path and blast radius."""
    
    def __init__(self, registry):
        self.registry = registry

    async def record_delegation(self, source_agent_id: str, target_agent_id: str, initial_probability: float = 0.7) -> AttackGraphEdge:
        """Records a delegation path between two agents, updating edge weight/count."""
        # Find existing edge
        edges = await self.registry.get_attack_graph_edges()
        existing_edge = next((e for e in edges if e.source_agent_id == source_agent_id and e.target_agent_id == target_agent_id), None)
        
        if existing_edge:
            existing_edge.delegation_count += 1
            # Adjust propagation probability slightly upwards as interaction frequency increases
            existing_edge.propagation_probability = min(0.99, existing_edge.propagation_probability + 0.02)
            existing_edge.updated_at = time.time()
            edge = existing_edge
        else:
            edge = AttackGraphEdge(
                source_agent_id=source_agent_id,
                target_agent_id=target_agent_id,
                propagation_probability=initial_probability,
                delegation_count=1,
                updated_at=time.time()
            )
            
        await self.registry.save_attack_graph_edge(edge)
        
        # Ensure nodes exist
        nodes = await self.registry.get_attack_graph_nodes()
        if not any(n.agent_id == source_agent_id for n in nodes):
            await self.registry.save_attack_graph_node(AttackGraphNode(
                node_id=source_agent_id,
                agent_id=source_agent_id,
                compromise_likelihood=0.0,
                state="NORMAL",
                updated_at=time.time()
            ))
        if not any(n.agent_id == target_agent_id for n in nodes):
            await self.registry.save_attack_graph_node(AttackGraphNode(
                node_id=target_agent_id,
                agent_id=target_agent_id,
                compromise_likelihood=0.0,
                state="NORMAL",
                updated_at=time.time()
            ))
            
        return edge

    async def analyze_incident_propagation(self, triggering_agent_id: str, trigger_score: float) -> Dict[str, Any]:
        """Calculates compromise propagation likelihood across the agent graph starting from a compromised agent.
        
        Uses BFS traversal to propagate compromise likelihood.
        """
        nodes = await self.registry.get_attack_graph_nodes()
        edges = await self.registry.get_attack_graph_edges()
        
        node_map = {n.agent_id: n for n in nodes}
        
        # Build adjacency list
        adj_list: Dict[str, List[AttackGraphEdge]] = {}
        for edge in edges:
            if edge.source_agent_id not in adj_list:
                adj_list[edge.source_agent_id] = []
            adj_list[edge.source_agent_id].append(edge)
            
        # Initialize queue for BFS
        # Queue item: (agent_id, current_propagation_likelihood)
        queue = [(triggering_agent_id, trigger_score)]
        visited: Dict[str, float] = {triggering_agent_id: trigger_score}
        
        while queue:
            curr_agent, curr_score = queue.pop(0)
            
            # Find downstream neighbors
            outbound_edges = adj_list.get(curr_agent, [])
            for edge in outbound_edges:
                neighbor = edge.target_agent_id
                # Propagation likelihood = parent_likelihood * edge_probability
                prop_score = curr_score * edge.propagation_probability
                
                # If we found a path with higher compromise probability, update it
                if neighbor not in visited or prop_score > visited[neighbor]:
                    visited[neighbor] = prop_score
                    # Only traverse further if score is significant (> 0.1)
                    if prop_score > 0.1:
                        queue.append((neighbor, prop_score))
                        
        # Save updated states to database
        impacted_nodes = []
        for agent_id, likelihood in visited.items():
            state = "COMPROMISED" if likelihood >= 0.8 else "SUSPECT" if likelihood >= 0.3 else "NORMAL"
            
            # If the triggering agent is the root, set state to COMPROMISED
            if agent_id == triggering_agent_id:
                state = "COMPROMISED"
                
            node = AttackGraphNode(
                node_id=agent_id,
                agent_id=agent_id,
                compromise_likelihood=likelihood,
                state=state,
                updated_at=time.time()
            )
            await self.registry.save_attack_graph_node(node)
            impacted_nodes.append(node)
            
        # Assemble visualization payload
        return {
            "nodes": [n.model_dump() for n in impacted_nodes],
            "edges": [e.model_dump() for e in edges],
            "trigger_agent": triggering_agent_id,
            "blast_radius": len([n for n in impacted_nodes if n.state in ("COMPROMISED", "SUSPECT")]),
            "timestamp": time.time()
        }

    async def isolate_attack_chain(self, triggering_agent_id: str) -> List[str]:
        """Identifies and quarantines all downstream agents potentially compromised in the attack chain."""
        analysis = await self.analyze_incident_propagation(triggering_agent_id, 1.0)
        isolated_agents = []
        
        for node_data in analysis["nodes"]:
            agent_id = node_data["agent_id"]
            state = node_data["state"]
            
            if state in ("COMPROMISED", "SUSPECT"):
                # Quarantine agent in registry
                agent = await self.registry.get_agent(agent_id)
                if agent and agent.status != AgentStatus.QUARANTINED:
                    agent.status = AgentStatus.QUARANTINED
                    await self.registry.register_agent(agent)
                    isolated_agents.append(agent_id)
                    logger.warning(f"ATTACK GRAPH ISOLATION: Quarantined downstream agent {agent_id} in chain.")
                    
        return isolated_agents
