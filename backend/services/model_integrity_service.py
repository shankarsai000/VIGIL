import logging
import math
import json
import time
from typing import Optional, List, Tuple
from ..app.runtime.models import ModelIntegrityBaseline, ModelIntegrityEvent

logger = logging.getLogger("vigil.services.model_integrity")

class ModelIntegrityService:
    """Monitors model integrity for VIGIL agents.
    
    Verifies that the weights, configurations, or embedding footprints
    have not been corrupted, drifted, or poisoned.
    """
    
    def __init__(self, registry):
        self.registry = registry
        
    def _parse_embeddings(self, emb_str: str) -> List[float]:
        try:
            return json.loads(emb_str)
        except Exception:
            return []

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot_product = sum(x * y for x, y in zip(a, b))
        magnitude_a = math.sqrt(sum(x * x for x in a))
        magnitude_b = math.sqrt(sum(y * y for y in b))
        if magnitude_a == 0.0 or magnitude_b == 0.0:
            return 0.0
        return dot_product / (magnitude_a * magnitude_b)

    async def initialize_baseline(self, agent_id: str, model_name: str, model_hash: str, embedding_baseline: List[float]) -> ModelIntegrityBaseline:
        """Establishes a model integrity baseline for an agent."""
        baseline = ModelIntegrityBaseline(
            agent_id=agent_id,
            model_name=model_name,
            model_hash=model_hash,
            embedding_baseline=json.dumps(embedding_baseline),
            updated_at=time.time()
        )
        await self.registry.save_model_integrity_baseline(baseline)
        logger.info(f"Initialized model integrity baseline for agent {agent_id} (Model: {model_name})")
        return baseline

    async def verify_integrity(self, agent_id: str, current_hash: str, current_embedding: Optional[List[float]] = None) -> Tuple[bool, float, List[ModelIntegrityEvent]]:
        """Verifies the agent's current model state against the registered baseline.
        
        Returns:
            Tuple[is_anomaly, max_drift_score, list_of_integrity_events]
        """
        baseline = await self.registry.get_model_integrity_baseline(agent_id)
        if not baseline:
            # Auto-initialize baseline if not present (simulated baseline for demo)
            default_emb = [0.1] * 128
            baseline = await self.initialize_baseline(
                agent_id=agent_id,
                model_name="default_agent_model",
                model_hash=current_hash or "default_hash_v1",
                embedding_baseline=current_embedding or default_emb
            )

        events = []
        is_anomaly = False
        max_drift = 0.0

        # 1. Hash Check
        if baseline.model_hash != current_hash:
            is_anomaly = True
            max_drift = 1.0
            event = ModelIntegrityEvent(
                agent_id=agent_id,
                metric_name="hash_mismatch",
                baseline_value=baseline.model_hash,
                current_value=current_hash,
                drift_score=1.0,
                timestamp=time.time()
            )
            await self.registry.log_model_integrity_event(event)
            events.append(event)
            logger.warning(f"MODEL INTEGRITY ALERT: Hash mismatch for agent {agent_id}. Baseline: {baseline.model_hash}, Current: {current_hash}")

        # 2. Embedding Drift Check
        if current_embedding:
            baseline_emb = self._parse_embeddings(baseline.embedding_baseline)
            sim = self._cosine_similarity(baseline_emb, current_embedding)
            drift_score = 1.0 - sim
            
            # Drift threshold of 0.15 (similarity < 0.85)
            if drift_score > 0.15:
                is_anomaly = True
                max_drift = max(max_drift, drift_score)
                event = ModelIntegrityEvent(
                    agent_id=agent_id,
                    metric_name="cosine_drift",
                    baseline_value=f"similarity_1.0",
                    current_value=f"similarity_{sim:.4f}",
                    drift_score=drift_score,
                    timestamp=time.time()
                )
                await self.registry.log_model_integrity_event(event)
                events.append(event)
                logger.warning(f"MODEL INTEGRITY ALERT: Cosine drift detected for agent {agent_id}. Drift: {drift_score:.4f} (Similarity: {sim:.4f})")

        return is_anomaly, max_drift, events
