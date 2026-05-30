import logging
import math
import time
from typing import Dict, Any, List
from ..app.runtime.models import BehavioralFootprintScore

logger = logging.getLogger("vigil.services.behavioral_spoofing")

class BehavioralSpoofingService:
    """Detects adversarial spoofing attempts where compromised agents mimic normal behavior patterns.
    
    Identifies robotic timing intervals, entropy suppression, and highly predictable tool usage loops.
    """
    
    def __init__(self, registry):
        self.registry = registry

    def _calculate_entropy(self, labels: List[str]) -> float:
        """Computes Shannon entropy of a list of categories."""
        if not labels:
            return 0.0
        counts = {}
        for l in labels:
            counts[l] = counts.get(l, 0) + 1
        entropy = 0.0
        total = len(labels)
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    async def analyze_behavioral_footprint(self, agent_id: str) -> BehavioralFootprintScore:
        """Analyzes historical telemetry for behavioral regularity to find adversarial mimicry/spoofing."""
        # Query recent events for agent
        events = []
        async with self.registry.db_connect() if hasattr(self.registry, 'db_connect') else self._db_conn() as db:
            db.row_factory = self._row_factory()
            async with db.execute(
                "SELECT event_type, target, payload, timestamp FROM events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 30",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                events = [dict(row) for row in rows]
                
        if len(events) < 5:
            # Not enough data, return a default low-risk score
            score = BehavioralFootprintScore(
                agent_id=agent_id,
                repetition_score=0.1,
                entropy_score=1.0, # High entropy is good
                timing_regularity=0.1,
                tool_predictability=0.1,
                spoofing_likelihood=0.1,
                updated_at=time.time()
            )
            await self.registry.save_behavioral_footprint_score(score)
            return score

        # 1. Repetition Score (e.g. identical payload ratio)
        payloads = [e["payload"] for e in events]
        unique_payloads = set(payloads)
        repetition_score = 1.0 - (len(unique_payloads) / len(payloads))

        # 2. Entropy Score (higher entropy = more random = lower spoofing risk)
        # We calculate payload-based category/word entropy
        words = []
        for p in payloads:
            words.extend(p.split())
        entropy_val = self._calculate_entropy(words)
        # Normalize entropy (typically between 0 and 8 for short texts)
        # Low entropy (e.g. < 2.0) means repetitive words/phrases
        normalized_entropy = min(8.0, max(0.1, entropy_val))
        entropy_suppression = 1.0 - (normalized_entropy / 8.0)

        # 3. Timing Regularity (Variance in time deltas)
        timestamps = [e["timestamp"] for e in events]
        time_deltas = []
        for i in range(len(timestamps) - 1):
            time_deltas.append(abs(timestamps[i] - timestamps[i+1]))
            
        mean_delta = sum(time_deltas) / len(time_deltas) if time_deltas else 0.0
        variance = sum((x - mean_delta) ** 2 for x in time_deltas) / len(time_deltas) if time_deltas else 0.0
        std_dev = math.sqrt(variance)
        
        # Timing regularity: if std_dev is very small compared to mean_delta, it's highly periodic (suspicious)
        if mean_delta > 0.1:
            coef_of_variation = std_dev / mean_delta
            # CV < 0.1 indicates extreme periodicity (robotic tick/heartbeat spoofing)
            timing_regularity = max(0.0, 1.0 - (coef_of_variation / 1.0))
        else:
            timing_regularity = 0.0

        # 4. Tool Usage Predictability (Transition predictability)
        tools = [e["target"] for e in events if e["event_type"] == "TOOL_CALL"]
        tool_predictability = 0.0
        if len(tools) >= 4:
            # Count transitions tool A -> tool B
            transitions = {}
            for i in range(len(tools) - 1):
                t1, t2 = tools[i], tools[i+1]
                transitions[t1] = transitions.get(t1, []) + [t2]
            
            # Predictability is measured by the max frequency of any transition
            max_p_sum = 0.0
            for t1, t2s in transitions.items():
                counts = {}
                for t2 in t2s:
                    counts[t2] = counts.get(t2, 0) + 1
                max_trans_count = max(counts.values())
                max_p_sum += max_trans_count / len(t2s)
            tool_predictability = max_p_sum / len(transitions) if transitions else 0.0

        # Calculate final spoofing likelihood (weighted average)
        spoofing_likelihood = (
            repetition_score * 0.25 +
            entropy_suppression * 0.25 +
            timing_regularity * 0.30 +
            tool_predictability * 0.20
        )
        
        # Safe clip
        spoofing_likelihood = min(1.0, max(0.0, spoofing_likelihood))

        score = BehavioralFootprintScore(
            agent_id=agent_id,
            repetition_score=round(repetition_score, 4),
            entropy_score=round(entropy_val, 4),
            timing_regularity=round(timing_regularity, 4),
            tool_predictability=round(tool_predictability, 4),
            spoofing_likelihood=round(spoofing_likelihood, 4),
            updated_at=time.time()
        )
        await self.registry.save_behavioral_footprint_score(score)
        
        if spoofing_likelihood > 0.7:
            logger.warning(f"BEHAVIORAL SPOOFING WARNING: Agent {agent_id} has high spoofing likelihood: {spoofing_likelihood:.4f}")
            
        return score

    def _db_conn(self):
        import aiosqlite
        return aiosqlite.connect(self.registry.db_path)

    def _row_factory(self):
        import aiosqlite
        return aiosqlite.Row
