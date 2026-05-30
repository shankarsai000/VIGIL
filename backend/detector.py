"""VIGIL Hybrid Threat Detection Engine.

Implements a 3-layer security evaluation pipeline:
1. Rule Engine: Deterministic, low-latency heuristic threat validation.
2. EWMA Statistical Baseline: Tracks per-agent metric anomalies against learned baselines.
3. Isolation Forest ML Layer: Multivariate anomaly detection via unsupervised learning.

Combines all layers to generate a normalized threat score and confidence level.
"""

import asyncio
import logging
import time
from typing import List, Tuple, Dict, Any, Set
import numpy as np

# Try importing sklearn, fallback gracefully if not installed
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from .models import AgentEvent, AgentProfile, DetectionResult, ThreatType, Confidence
from .config import settings

logger = logging.getLogger("vigil.detector")

# Injection Patterns
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

# Rule Engine Scores
SCORE_SCOPE_VIOLATION = 0.90
SCORE_INJECTION_SIGNATURE = 0.88
SCORE_UNAUTHORIZED_DELEGATION = 0.95
SCORE_MASS_DATA_READ = 0.80

# Rule Constants
MAX_PAYLOAD_BYTES = 100_000

# EWMA Scores & Multipliers
SCORE_RATE_ANOMALY = 0.70
SCORE_VOLUME_ANOMALY = 0.65
CALL_RATE_MULTIPLIER = 3.0
PAYLOAD_MULTIPLIER = 5.0


class RuleEngine:
    """Deterministic, heuristic rule engine for detecting immediate out-of-bounds agent activity."""

    def evaluate(self, event: AgentEvent, profile: AgentProfile) -> Tuple[float, ThreatType]:
        """Evaluates an event against deterministic security rules.

        Args:
            event: The observed AgentEvent.
            profile: The AgentProfile of the actor.

        Returns:
            A tuple of (score, ThreatType).
        """
        # 1. Injection signature checks (case-insensitive)
        payload_lower = event.payload.lower()
        for pattern in INJECTION_PATTERNS:
            if pattern in payload_lower:
                logger.warning(f"[Rule Engine] Prompt Injection detected. Match: '{pattern}'")
                return SCORE_INJECTION_SIGNATURE, ThreatType.PROMPT_INJECTION

        # 2. Scope violations (calling tool that is not permitted)
        if event.event_type.value == "TOOL_CALL" or event.event_type.value == "DATA_ACCESS":
            if event.target not in profile.permitted_tools:
                logger.warning(f"[Rule Engine] Scope violation. Target tool '{event.target}' not in permitted list: {profile.permitted_tools}")
                return SCORE_SCOPE_VIOLATION, ThreatType.PRIVILEGE_ESCALATION

        # 3. Unauthorized delegation
        if event.event_type.value == "AGENT_DELEGATION":
            if event.target not in profile.permitted_agents:
                logger.warning(f"[Rule Engine] Unauthorized delegation. Agent '{event.agent_id}' tried delegating to '{event.target}', permitted: {profile.permitted_agents}")
                return SCORE_UNAUTHORIZED_DELEGATION, ThreatType.UNAUTHORIZED_DELEGATION

        # 4. Mass data read / Data Exfiltration (excessive payload size)
        if event.payload_size > MAX_PAYLOAD_BYTES:
            logger.warning(f"[Rule Engine] Mass data read detected: {event.payload_size} bytes (limit: {MAX_PAYLOAD_BYTES})")
            return SCORE_MASS_DATA_READ, ThreatType.DATA_EXFILTRATION

        return 0.0, ThreatType.NONE


class EWMABaseline:
    """Per-agent adaptive baseline tracking via Exponentially Weighted Moving Average."""

    def __init__(self, alpha: float = 0.1, cold_start_threshold: int = 50):
        """Initializes EWMA tracker.

        Args:
            alpha: Smoothing factor, typically between 0.1 and 0.2.
            cold_start_threshold: Number of observations needed before active evaluation.
        """
        self.alpha = alpha
        self.cold_start_threshold = cold_start_threshold
        # Structure: baselines[agent_id][metric_name] = current_ewma_value
        self.baselines: Dict[str, Dict[str, float]] = {}
        # Structure: counts[agent_id] = total_events_seen
        self.counts: Dict[str, int] = {}

    def update(self, agent_id: str, metric: str, value: float) -> None:
        """Updates the EWMA baseline for a given metric.

        Args:
            agent_id: The agent identifier.
            metric: The name of the metric (e.g. 'call_rate', 'payload_size').
            value: The observed metric value.
        """
        if agent_id not in self.baselines:
            self.baselines[agent_id] = {}
        
        if agent_id not in self.counts:
            self.counts[agent_id] = 0

        current_val = self.baselines[agent_id].get(metric)
        if current_val is None:
            # Initialize with first value
            self.baselines[agent_id][metric] = value
        else:
            # S_t = alpha * Y_t + (1 - alpha) * S_{t-1}
            self.baselines[agent_id][metric] = self.alpha * value + (1 - self.alpha) * current_val

    def increment_count(self, agent_id: str) -> None:
        """Increments event counter for an agent."""
        self.counts[agent_id] = self.counts.get(agent_id, 0) + 1

    def evaluate(self, event: AgentEvent, profile: AgentProfile, stats: Dict[str, float]) -> Tuple[float, ThreatType]:
        """Compares current stats to the learned EWMA baseline.

        Args:
            event: AgentEvent under observation.
            profile: Agent profile.
            stats: Calculated metric statistics (call_rate, avg_payload_size, delegation_count).

        Returns:
            A tuple of (score, ThreatType).
        """
        agent_id = event.agent_id
        event_count = self.counts.get(agent_id, 0)

        # Cold start check: wait until baseline is stable
        if event_count < self.cold_start_threshold:
            return 0.0, ThreatType.NONE

        agent_baselines = self.baselines.get(agent_id, {})
        
        # 1. Call rate anomaly evaluation
        baseline_rate = agent_baselines.get("call_rate")
        current_rate = stats.get("call_rate", 0.0)
        if baseline_rate is not None and baseline_rate > 0:
            if current_rate > CALL_RATE_MULTIPLIER * baseline_rate:
                logger.warning(f"[EWMA] Call rate anomaly: {current_rate:.2f} calls/min (baseline: {baseline_rate:.2f} calls/min)")
                return SCORE_RATE_ANOMALY, ThreatType.RATE_ANOMALY

        # 2. Avg Payload size / Volume anomaly evaluation
        baseline_payload = agent_baselines.get("avg_payload_size")
        current_payload = stats.get("avg_payload_size", 0.0)
        if baseline_payload is not None and baseline_payload > 0:
            if current_payload > PAYLOAD_MULTIPLIER * baseline_payload:
                logger.warning(f"[EWMA] Volume anomaly: {current_payload:.2f} bytes avg (baseline: {baseline_payload:.2f} bytes avg)")
                return SCORE_VOLUME_ANOMALY, ThreatType.VOLUME_ANOMALY

        return 0.0, ThreatType.NONE


class IsolationForestDetector:
    """Multivariate Isolation Forest anomaly detector for behavioral profiling."""

    def __init__(self, min_events: int = 100, retrain_interval: int = 100):
        """Initializes IForest detector.

        Args:
            min_events: Minimum events required before enabling detector.
            retrain_interval: Number of new events between retrains.
        """
        self.min_events = min_events
        self.retrain_interval = retrain_interval
        
        # We retrain a single global model or per-agent models. Let's do a per-agent approach.
        # Structure: models[agent_id] = trained IsolationForest
        self.models: Dict[str, Any] = {}
        # Structure: history[agent_id] = list of feature vectors [call_rate, payload_size, delegation_count, tool_diversity]
        self.history: Dict[str, List[List[float]]] = {}
        # Structure: new_samples_since_retrain[agent_id] = int
        self.new_samples: Dict[str, int] = {}
        
        self._lock = asyncio.Lock()

    def add_sample(self, agent_id: str, features: List[float]) -> None:
        """Adds a feature sample and triggers async retraining if interval is hit.

        Args:
            agent_id: Agent identifier.
            features: [call_rate, payload_size, delegation_count, tool_diversity]
        """
        if agent_id not in self.history:
            self.history[agent_id] = []
            self.new_samples[agent_id] = 0

        self.history[agent_id].append(features)
        self.new_samples[agent_id] += 1

        total_samples = len(self.history[agent_id])
        if total_samples >= self.min_events and self.new_samples[agent_id] >= self.retrain_interval:
            self.new_samples[agent_id] = 0
            # Dispatch background retraining task
            asyncio.create_task(self._retrain(agent_id))

    async def _retrain(self, agent_id: str) -> None:
        """Retrains the Isolation Forest model for the agent in a background thread."""
        if not SKLEARN_AVAILABLE:
            return

        async with self._lock:
            try:
                data = list(self.history[agent_id])
                logger.info(f"[IForest] Retraining IsolationForest model for {agent_id} with {len(data)} samples...")
                
                # Defend against zero variance
                X = np.array(data)
                
                # Isolation Forest training in a thread pool to avoid blocking event loop
                model = await asyncio.to_thread(
                    lambda: IsolationForest(contamination=0.05, random_state=42, n_estimators=100).fit(X)
                )
                
                self.models[agent_id] = model
                logger.info(f"[IForest] Model retrained successfully for {agent_id}.")
            except Exception as e:
                logger.error(f"[IForest] Error retraining model for {agent_id}: {e}", exc_info=True)

    def score(self, agent_id: str, features: List[float]) -> float:
        """Calculates the anomaly score using the trained model.

        Args:
            agent_id: Agent identifier.
            features: Features list.

        Returns:
            Normalized anomaly score (0.0 to 1.0) where values > 0.65 are highly anomalous.
        """
        if not SKLEARN_AVAILABLE or agent_id not in self.models:
            return 0.0

        try:
            model = self.models[agent_id]
            X = np.array([features])
            
            # score_samples returns raw anomaly score (negative is anomaly, range is ~ [-1.0, 0.0])
            raw_score = model.score_samples(X)[0]
            
            # Map raw score [-1.0, 0.0] to a positive score [0.0, 1.0]
            # Lower score_samples output = more anomalous.
            # Anomaly threshold is usually around -0.5, let's map:
            # score close to 0 -> normal (e.g. 0.0 to 0.3)
            # score close to -1 -> highly anomalous (e.g. 0.7 to 1.0)
            score = float(np.clip((0.5 - raw_score) / 1.0, 0.0, 1.0))
            return score
        except Exception as e:
            logger.warning(f"[IForest] Scoring failed for {agent_id}: {e}")
            return 0.0


class HybridDetector:
    """Orchestrates VIGIL's multi-layered detection suite and combines their signals."""

    def __init__(self, config: Any):
        """Initializes the detector with config settings.

        Args:
            config: Config settings object containing weights and parameters.
        """
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
        self, event: AgentEvent, profile: AgentProfile, stats: Dict[str, Any]
    ) -> DetectionResult:
        """Processes an incoming event through all three layers and aggregates the outputs.

        Args:
            event: The observed AgentEvent.
            profile: Profile of the sending agent.
            stats: Precalculated metric window statistics.

        Returns:
            An integrated DetectionResult.
        """
        agent_id = event.agent_id
        
        # 1. Rule Engine evaluation
        rule_score, rule_threat = self.rule_engine.evaluate(event, profile)
        
        # 2. EWMA Baseline evaluation
        ewma_score, ewma_threat = self.ewma.evaluate(event, profile, stats)
        
        # 3. Isolation Forest evaluation
        # Feature vector: [call_rate, payload_size, delegation_count, tool_diversity]
        features = [
            stats.get("call_rate", 0.0),
            float(event.payload_size),
            float(stats.get("delegation_count", 0)),
            float(stats.get("tool_diversity", 0)),
        ]
        
        # Push feature sample into historical pool
        self.iforest.add_sample(agent_id, features)
        
        # Get Isolation Forest score
        iforest_score = self.iforest.score(agent_id, features)
        
        # 4. Aggregation
        # Final combined threat score using weighted average
        w_rule = self.config.weight_rule
        w_ewma = self.config.weight_ewma
        w_iforest = self.config.weight_iforest
        
        # If a deterministic rule is violated (rule_score > 0), we do not dilute the threat score
        # below the rule score. Otherwise, we calculate the combined weighted score.
        weighted_score = (w_rule * rule_score) + (w_ewma * ewma_score) + (w_iforest * iforest_score)
        if rule_score > 0.0:
            final_score = rule_score + (w_ewma * ewma_score) + (w_iforest * iforest_score)
        else:
            final_score = weighted_score
            
        final_score = float(np.clip(final_score, 0.0, 1.0))
        
        # Map threat type to highest contributing category
        threat_type = ThreatType.NONE
        if rule_score > 0.0:
            threat_type = rule_threat
        elif ewma_score > 0.0:
            threat_type = ewma_threat
        elif iforest_score > 0.65:
            # IForest flagged behavioral anomaly
            threat_type = ThreatType.RATE_ANOMALY if stats.get("call_rate", 0.0) > profile.baseline_call_rate else ThreatType.VOLUME_ANOMALY
            
        confidence = Confidence.from_score(final_score)
        
        details = {
            "window_stats": stats,
            "sklearn_loaded": SKLEARN_AVAILABLE,
            "active_samples": len(self.iforest.history.get(agent_id, [])),
        }
        
        result = DetectionResult(
            score=final_score,
            threat_type=threat_type,
            confidence=confidence,
            rule_score=rule_score,
            ewma_score=ewma_score,
            iforest_score=iforest_score,
            details=details,
        )
        
        logger.info(
            f"[Hybrid Detector] Finished evaluation for {agent_id}: Score={final_score:.2f}, "
            f"Rule={rule_score:.2f}, EWMA={ewma_score:.2f}, IForest={iforest_score:.2f}. "
            f"Decision={confidence.value} ({threat_type.value})"
        )
        
        return result
