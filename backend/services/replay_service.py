import os
import json
import logging
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger("vigil.services.replay")

REPLAY_DIR = "backend/storage/replay_logs/"

class ReplayService:
    """Manages recording and reconstructing interactive threat sandboxes chronologically."""

    def __init__(self):
        os.makedirs(REPLAY_DIR, exist_ok=True)

    def record_incident_timeline(self, incident_id: str, agent_id: str, threat_type: str, raw_payload: str, result: Dict[str, Any]) -> None:
        """Saves a chronological play-by-play execution sandbox log to local storage."""
        try:
            timeline = {
                "incident_id": incident_id,
                "agent_id": agent_id,
                "threat_type": threat_type,
                "timestamp": time.time(),
                "steps": [
                    {
                        "step": 0,
                        "label": "INJECTION",
                        "title": "Anomalous Payload Input",
                        "description": f"External agent called endpoint using a payload with length {len(raw_payload)} bytes.",
                        "raw_trace": raw_payload
                    },
                    {
                        "step": 1,
                        "label": "DETECTION",
                        "title": "Multi-Engine Threat Scan",
                        "description": f"Rule match verified {threat_type}. Aggregating scores.",
                        "raw_trace": json.dumps(result.get("detection_result", {}), indent=2)
                    },
                    {
                        "step": 2,
                        "label": "VERIFICATION",
                        "title": "ArmorIQ Compliance Verdict",
                        "description": f"Rule parsed policy limits. Policy action matched: {result.get('policy_decision', 'DENIED')}.",
                        "raw_trace": f"Policy decision: {result.get('policy_decision', 'DENIED')}\nRemediation verdict: ACTIVATE ISOLATION"
                    },
                    {
                        "step": 3,
                        "label": "CONTAINMENT",
                        "title": "Remediation Executed",
                        "description": f"VIGIL isolation dome triggered. Action took: {result.get('action_taken', 'QUARANTINE')}.",
                        "raw_trace": f"Containment Action: {result.get('action_taken', 'QUARANTINE')}\nAgent isolation index: OPTIMAL"
                    },
                    {
                        "step": 4,
                        "label": "EXPLANATION",
                        "title": "Forensic Sandbox Report",
                        "description": "Explainer report generated to explain context anomalies.",
                        "raw_trace": result.get("explanation", "LLM Explainer writing report...")
                    }
                ]
            }

            file_path = os.path.join(REPLAY_DIR, f"replay_{incident_id}.json")
            with open(file_path, "w") as f:
                json.dump(timeline, f, indent=4)
            logger.info(f"[Replay Service] Sandbox timeline written successfully for incident {incident_id}.")
        except Exception as e:
            logger.error(f"Failed to record sandbox timeline trace: {e}")

    def load_timeline(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a previously stored chronological timeline from local logs."""
        file_path = os.path.join(REPLAY_DIR, f"replay_{incident_id}.json")
        if not os.path.exists(file_path):
            logger.warning(f"Replay logs for incident {incident_id} not found.")
            return None
        
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse replay file {file_path}: {e}")
            return None

# Singleton service instance
replay_service = ReplayService()
