import logging
import time
from typing import Tuple, List, Optional
from ..app.runtime.models import PromptMutationRecord

logger = logging.getLogger("vigil.services.prompt_mutation")

class PromptMutationService:
    """Detects adversarial mutations or drift in agent system/user prompts."""
    
    def __init__(self, registry):
        self.registry = registry

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _similarity_score(self, s1: str, s2: str, dist: int) -> float:
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1.0 - (dist / max_len)

    async def detect_mutation(self, agent_id: str, incoming_prompt: str, baseline_prompt: Optional[str] = None) -> Tuple[bool, float, int]:
        """Compares incoming prompt with baseline system prompt or historical configurations.
        
        Returns:
            Tuple[is_anomaly, similarity_score, levenshtein_distance]
        """
        # If no baseline prompt is provided, try to fetch the most recent normal prompt for this agent
        if not baseline_prompt:
            history = await self.registry.get_prompt_mutations(agent_id)
            if history:
                # Find the most recent non-anomalous prompt to use as baseline
                non_anomalous = [h for h in history if not h.is_anomaly]
                if non_anomalous:
                    baseline_prompt = non_anomalous[0].original_prompt
                else:
                    baseline_prompt = history[0].original_prompt
            else:
                # Fallback baseline prompt (simulated default system prompt)
                baseline_prompt = "You are a helpful, secure, and honest autonomous AI assistant. Adhere strictly to tool safety guidelines."

        dist = self._levenshtein_distance(baseline_prompt, incoming_prompt)
        sim = self._similarity_score(baseline_prompt, incoming_prompt, dist)
        
        # Mutation threshold: if prompt similarity is less than 0.70 (30% changed) or greater than 0.05 change (to detect subtle injections)
        # Usually, adversarial prompts are mutated but stay similar, or drift significantly.
        # Let's say if the prompt changed by more than 15% (similarity < 0.85), but isn't a completely new prompt (similarity > 0.3)
        # which indicates a structured mutation attempt.
        is_anomaly = 0.30 < sim < 0.85

        # Save record
        record = PromptMutationRecord(
            agent_id=agent_id,
            original_prompt=baseline_prompt,
            mutated_prompt=incoming_prompt,
            levenshtein_distance=dist,
            similarity_score=sim,
            is_anomaly=is_anomaly,
            timestamp=time.time()
        )
        await self.registry.log_prompt_mutation(record)
        
        if is_anomaly:
            logger.warning(f"PROMPT MUTATION DETECTED for agent {agent_id}. Similarity: {sim:.4f}, Levenshtein: {dist}")
            
        return is_anomaly, sim, dist
