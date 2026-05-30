"""VIGIL Hybrid Threat Detection Engine.

Implements VIGIL's 3-layer security evaluation pipeline integrated with
predictive ML telemetry and semantic NLP ArmorClaw transformer classification.
"""

import asyncio
import logging
import time
from typing import List, Tuple, Dict, Any, Set
import numpy as np

# Try importing sklearn
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from ..runtime.models import AgentEvent, AgentProfile, DetectionResult, ThreatType, Confidence
from ..config import settings
from ...services.telemetry_service import telemetry_service
from ...services.armorclaw_service import armorclaw_service
from ...services.scoring_service import scoring_service

logger = logging.getLogger("vigil.detector")

# Heuristic signature patterns
INJECTION_PATTERNS = [
    "ignore previous", 
    "ignore your", 
    "disregard instructions", 
    "you are now", 
    "pretend you are", 
    "act as if you", 
    "new instructions:", 
    "system prompt", 
    "jailbreak", 
    "dan mode", 
    "developer mode", 
    "bypass your", 
    "override your"
]

# Rule scores
SCORE_SCOPE_VIOLATION = 0.90
SCORE_INJECTION_SIGNATURE = 0.88
SCORE_UNAUTHORIZED_DELEGATION = 0.95
SCORE_MASS_DATA_READ = 0.80
MAX_PAYLOAD_BYTES = 100_000

# EWMA multipliers
SCORE_RATE_ANOMALY = 0.70
SCORE_VOLUME_ANOMALY = 0.65
CALL_RATE_MULTIPLIER = 3.0
PAYLOAD_MULTIPLIER = 5.0

class RuleEngine:
    def evaluate(self, event: AgentEvent, profile: AgentProfile) -> Tuple[float, ThreatType]:
        payload_lower = event.payload.lower()
        for pattern in INJECTION_PATTERNS:
            if pattern in payload_lower:
                logger.warning(f"[Rule Engine] Prompt Injection signature matched: '{pattern}'")
                return SCORE_INJECTION_SIGNATURE, ThreatType.PROMPT_INJECTION

        if event.event_type.value == "TOOL_CALL" or event.event_type.value == "DATA_ACCESS":
            if event.target not in profile.permitted_tools:
                logger.warning(f"[Rule Engine] Scope violation tool: '{event.target}'")
                return SCORE_SCOPE_VIOLATION, ThreatType.PRIVILEGE_ESCALATION

        if event.event_type.value == "AGENT_DELEGATION":
            if event.target not in profile.permitted_agents:
                logger.warning(f"[Rule Engine] Unauthorized agent delegation: '{event.target}'")
                return SCORE_UNAUTHORIZED_DELEGATION, ThreatType.UNAUTHORIZED_DELEGATION

        if event.payload_size > MAX_PAYLOAD_BYTES:
            logger.warning(f"[Rule Engine] Size threshold exceeded: {event.payload_size} bytes")
            return SCORE_MASS_DATA_READ, ThreatType.DATA_EXFILTRATION

        return 0.0, ThreatType.NONE

class EWMABaseline:
    def __init__(self, alpha: float = 0.1, cold_start_threshold: int = 50):
        self.alpha = alpha
        self.cold_start_threshold = cold_start_threshold
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.counts: Dict[str, int] = {}

    def update(self, agent_id: str, metric: str, value: float) -> None:
        if agent_id not in self.baselines:
            self.baselines[agent_id] = {}
        if agent_id not in self.counts:
            self.counts[agent_id] = 0

        current_val = self.baselines[agent_id].get(metric)
        if current_val is None:
            self.baselines[agent_id][metric] = value
        else:
            self.baselines[agent_id][metric] = self.alpha * value + (1 - self.alpha) * current_val

    def increment_count(self, agent_id: str) -> None:
        self.counts[agent_id] = self.counts.get(agent_id, 0) + 1

    def evaluate(self, event: AgentEvent, profile: AgentProfile, stats: Dict[str, float]) -> Tuple[float, ThreatType]:
        agent_id = event.agent_id
        event_count = self.counts.get(agent_id, 0)

        if event_count < self.cold_start_threshold:
            return 0.0, ThreatType.NONE

        agent_baselines = self.baselines.get(agent_id, {})
        
        baseline_rate = agent_baselines.get("call_rate")
        current_rate = stats.get("call_rate", 0.0)
        if baseline_rate is not None and baseline_rate > 0:
            if current_rate > CALL_RATE_MULTIPLIER * baseline_rate:
                logger.warning(f"[EWMA] Call rate spike anomaly: {current_rate:.2f}/min")
                return SCORE_RATE_ANOMALY, ThreatType.RATE_ANOMALY

        baseline_payload = agent_baselines.get("avg_payload_size")
        current_payload = stats.get("avg_payload_size", 0.0)
        if baseline_payload is not None and baseline_payload > 0:
            if current_payload > PAYLOAD_MULTIPLIER * baseline_payload:
                logger.warning(f"[EWMA] Payload size anomaly: {current_payload:.2f} bytes")
                return SCORE_VOLUME_ANOMALY, ThreatType.VOLUME_ANOMALY

        return 0.0, ThreatType.NONE

class IsolationForestDetector:
    def __init__(self, min_events: int = 100, retrain_interval: int = 100):
        self.min_events = min_events
        self.retrain_interval = retrain_interval
        self.models: Dict[str, Any] = {}
        self.history: Dict[str, List[List[float]]] = {}
        self.new_samples: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    def add_sample(self, agent_id: str, features: List[float]) -> None:
        if agent_id not in self.history:
            self.history[agent_id] = []
            self.new_samples[agent_id] = 0

        self.history[agent_id].append(features)
        self.new_samples[agent_id] += 1

        total_samples = len(self.history[agent_id])
        if total_samples >= self.min_events and self.new_samples[agent_id] >= self.retrain_interval:
            self.new_samples[agent_id] = 0
            asyncio.create_task(self._retrain(agent_id))

    async def _retrain(self, agent_id: str) -> None:
        if not SKLEARN_AVAILABLE:
            return
        async with self._lock:
            try:
                data = list(self.history[agent_id])
                X = np.array(data)
                model = await asyncio.to_thread(
                    lambda: IsolationForest(contamination=0.05, random_state=42, n_estimators=100).fit(X)
                )
                self.models[agent_id] = model
                logger.info(f"[IForest] Model retrained successfully for {agent_id}.")
            except Exception as e:
                logger.error(f"[IForest] Error retraining model for {agent_id}: {e}")

    def score(self, agent_id: str, features: List[float]) -> float:
        if not SKLEARN_AVAILABLE or agent_id not in self.models:
            return 0.0
        try:
            model = self.models[agent_id]
            X = np.array([features])
            raw_score = model.score_samples(X)[0]
            score = float(np.clip((0.5 - raw_score) / 1.0, 0.0, 1.0))
            return score
        except Exception as e:
            return 0.0

class HybridDetector:
    def __init__(self, config: Any):
        self.config = config
        self.rule_engine = RuleEngine()
        self.ewma = EWMABaseline(
            alpha=config.ewma_alpha,
            cold_start_threshold=config.ewma_cold_start_threshold,
        )
        self.iforest = IsolationForestDetector(
            min_events=config.iforest_min_events,
            retrain_interval=config.iforest_retrain_interval,
        )

    async def detect(
        self,
        event: AgentEvent,
        profile: AgentProfile,
        stats: Dict[str, Any],
        v2_signals: Dict[str, float] = None,
    ) -> DetectionResult:
        """Runs the full hybrid detection pipeline.
        
        Args:
            event: The incoming agent event.
            profile: The agent's registered profile.
            stats: Window statistics (call_rate, avg_payload_size, etc.).
            v2_signals: Optional VIGIL 2.0 signals dict with keys:
                - prompt_mutation_score
                - capability_score
                - spoofing_score
        """
        agent_id = event.agent_id
        v2 = v2_signals or {}
        
        # 1. Local deterministic heuristic rules
        rule_score, rule_threat = self.rule_engine.evaluate(event, profile)
        
        # 2. Statistical sliding windows
        ewma_score, ewma_threat = self.ewma.evaluate(event, profile, stats)
        
        # 3. Local Isolation Forest & Telemetry Service predictive RF/IF
        features = [
            stats.get("call_rate", 0.0),
            float(event.payload_size),
            float(stats.get("delegation_count", 0)),
            float(stats.get("tool_diversity", 0)),
        ]
        self.iforest.add_sample(agent_id, features)
        iforest_base_score = self.iforest.score(agent_id, features)
        
        # Call telemetry service utilizing .pkl objects
        netflow_dict = {
            "pkt_rate": stats.get("call_rate", 0.0),
            "sbytes": float(event.payload_size),
            "trans_depth": float(stats.get("delegation_count", 0)),
            "service": float(stats.get("tool_diversity", 0))
        }
        telemetry_ml_score = telemetry_service.predict_anomaly(netflow_dict)
        iforest_score = max(iforest_base_score, telemetry_ml_score)
        
        # 4. NLP semantic inference via ArmorClaw V4
        armorclaw_score, armorclaw_label = armorclaw_service.predict_intent(event.payload)
        
        # 5. Extract VIGIL 2.0 signal dimensions
        prompt_mutation_score = v2.get("prompt_mutation_score", 0.0)
        capability_score = v2.get("capability_score", 0.0)
        spoofing_score = v2.get("spoofing_score", 0.0)
        
        # 6. Hybrid calculated scoring (v2 formula)
        final_score = scoring_service.calculate_threat_score_v2(
            rule_score=rule_score,
            ewma_score=ewma_score,
            iforest_score=iforest_score,
            armorclaw_score=armorclaw_score,
            prompt_mutation_score=prompt_mutation_score,
            capability_score=capability_score,
            spoofing_score=spoofing_score,
        )
        
        # Resolve highest threat mapping category
        threat_type = ThreatType.NONE

        # V2 signals take priority if they are strong
        if capability_score > 0.8:
            threat_type = ThreatType.CAPABILITY_VIOLATION
        elif prompt_mutation_score > 0.7:
            threat_type = ThreatType.PROMPT_MUTATION
        elif spoofing_score > 0.7:
            threat_type = ThreatType.BEHAVIORAL_SPOOFING
        elif rule_score > 0.0:
            threat_type = rule_threat
        elif ewma_score > 0.0:
            threat_type = ewma_threat
        elif armorclaw_score > 0.65 and armorclaw_label != "BENIGN_OPERATION":
            # Map NLP semantic intents
            if armorclaw_label == "PROMPT_INJECTION":
                threat_type = ThreatType.PROMPT_INJECTION
            elif armorclaw_label == "DATA_EXFILTRATION":
                threat_type = ThreatType.DATA_EXFILTRATION
            elif armorclaw_label == "TOOL_ABUSE":
                threat_type = ThreatType.PRIVILEGE_ESCALATION
        elif iforest_score > 0.65:
            threat_type = ThreatType.RATE_ANOMALY if stats.get("call_rate", 0.0) > profile.baseline_call_rate else ThreatType.VOLUME_ANOMALY
            
        confidence = Confidence.from_score(final_score)
        
        details = {
            "window_stats": stats,
            "sklearn_loaded": SKLEARN_AVAILABLE,
            "active_samples": len(self.iforest.history.get(agent_id, [])),
            "armorclaw_label": armorclaw_label,
            "armorclaw_score": armorclaw_score,
            "telemetry_ml_score": telemetry_ml_score,
            "prompt_mutation_score": prompt_mutation_score,
            "capability_score": capability_score,
            "spoofing_score": spoofing_score,
        }
        
        return DetectionResult(
            score=final_score,
            threat_type=threat_type,
            confidence=confidence,
            rule_score=rule_score,
            ewma_score=ewma_score,
            iforest_score=iforest_score,
            details=details,
        )

