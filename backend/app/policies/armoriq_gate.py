"""ArmorIQ SDK integration and Policy Gate.

Acts as the visual intelligence & governance gateway for VIGIL. Evaluates agent intent,
verifies actions against the ArmorIQ policy engine, writes to immutable remote audit logs,
and falls back dynamically to local storage and mock policies under connectivity outages.
"""

import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
import httpx

from ..runtime.models import AgentProfile, ThreatContext, PolicyDecision, AuditEntry, ThreatType
from ..config import settings
from ..runtime.registry import AgentRegistry

logger = logging.getLogger("vigil.armoriq_gate")


class ArmorIQGate:
    """Policy validation gateway and audit reporter connected to ArmorIQ Platform."""

    def __init__(self, config: Any, registry: AgentRegistry):
        """Initializes the policy gate.

        Args:
            config: VigilSettings instance.
            registry: Local AgentRegistry for fallback storage.
        """
        self.config = config
        self.registry = registry
        self.client: Optional[httpx.AsyncClient] = None
        self._mock_mode = (config.armoriq_api_key == "mock") or (not config.armoriq_api_key)

    async def startup(self) -> None:
        """Initializes the shared httpx.AsyncClient with connection pooling."""
        if not self._mock_mode:
            logger.info("Initializing live ArmorIQ HTTP client pool...")
            limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
            headers = {
                "Authorization": f"Bearer {self.config.armoriq_api_key}",
                "Content-Type": "application/json",
            }
            self.client = httpx.AsyncClient(
                base_url=self.config.armoriq_base_url,
                headers=headers,
                limits=limits,
                timeout=5.0,
            )
        else:
            logger.info("ArmorIQ Gate started in MOCK mode. External requests will be mocked.")

    async def shutdown(self) -> None:
        """Closes the HTTP client pool."""
        if self.client:
            await self.client.aclose()
            logger.info("Closed ArmorIQ HTTP client pool.")

    async def register_agent(self, profile: AgentProfile) -> str:
        """Registers agent metadata with ArmorIQ identity store.

        Args:
            profile: AgentProfile to register.

        Returns:
            The ArmorIQ global identifier string.
        """
        if self._mock_mode:
            mock_id = f"armoriq_mock_{profile.agent_id}"
            logger.info(f"[ArmorIQ Gate] Registered agent {profile.agent_id} in Mock. Assigned ID: {mock_id}")
            return mock_id

        payload = {
            "agent_id": profile.agent_id,
            "name": profile.name,
            "permitted_tools": profile.permitted_tools,
            "permitted_agents": profile.permitted_agents,
            "baseline_call_rate": profile.baseline_call_rate,
        }

        try:
            response = await self.client.post("/v1/agents/register", json=payload)
            response.raise_for_status()
            data = response.json()
            armoriq_id = data.get("armoriq_id", f"armoriq_{profile.agent_id}")
            logger.info(f"[ArmorIQ Gate] Live registration success for {profile.agent_id}: {armoriq_id}")
            return armoriq_id
        except Exception as e:
            logger.error(f"[ArmorIQ Gate] Failed to register agent {profile.agent_id} on ArmorIQ: {e}")
            # Fallback identifier
            return f"armoriq_fallback_{profile.agent_id}"

    async def evaluate_policy(self, ctx: ThreatContext) -> PolicyDecision:
        """Verifies the proposed action with ArmorIQ Policy Engine.

        Uses exponential backoff retry on transient failures and returns ESCALATE on timeout.

        Args:
            ctx: ThreatContext for policy assessment.

        Returns:
            PolicyDecision (APPROVED, DENIED, or ESCALATE).
        """
        if self._mock_mode:
            logger.info(f"[ArmorIQ Gate] Evaluating policy in Mock for agent {ctx.agent_id} (Score: {ctx.score:.2f})")
            # Mock policy logic:
            # - Score >= 0.85 -> Critical threat. Remediate with Quarantine (APPROVED)
            # - Score 0.65 - 0.85 -> High threat. Needs verification (ESCALATE)
            # - Score < 0.65 -> Medium/Low threat. Approved to log/alert (APPROVED)
            if ctx.score >= 0.85:
                return PolicyDecision.APPROVED
            elif ctx.score >= 0.65:
                return PolicyDecision.ESCALATE
            else:
                return PolicyDecision.APPROVED

        payload = {
            "agent_id": ctx.agent_id,
            "threat_type": ctx.threat_type.value,
            "score": ctx.score,
            "proposed_action": ctx.proposed_action,
            "evidence": ctx.evidence,
            "timestamp": ctx.timestamp,
        }

        # Exponential backoff parameters
        max_attempts = 3
        base_delay = 0.5

        for attempt in range(1, max_attempts + 1):
            try:
                response = await self.client.post("/v1/intent/verify", json=payload)
                response.raise_for_status()
                data = response.json()
                
                # Parse policy decision mapping
                # Example JSON: {"approved": true, "escalate": false}
                is_approved = data.get("approved", True)
                is_escalate = data.get("escalate", False)

                if is_escalate:
                    return PolicyDecision.ESCALATE
                elif is_approved:
                    return PolicyDecision.APPROVED
                else:
                    return PolicyDecision.DENIED

            except httpx.TimeoutException:
                logger.warning(f"[ArmorIQ Gate] Timeout on attempt {attempt} verifying policy for agent {ctx.agent_id}")
                if attempt == max_attempts:
                    logger.error("[ArmorIQ Gate] All verification attempts timed out. Defaulting to PolicyDecision.ESCALATE")
                    return PolicyDecision.ESCALATE
            except httpx.HTTPStatusError as e:
                logger.error(f"[ArmorIQ Gate] HTTP error {e.response.status_code} on attempt {attempt}: {e.response.text}")
                # Switch to mock policy if authorized credentials failed (e.g. 401/403) so the demo doesn't break
                if e.response.status_code in (401, 403):
                    logger.warning("[ArmorIQ Gate] Auth credentials failed. Falling back to Mock decision logic.")
                    if ctx.score >= 0.85:
                        return PolicyDecision.APPROVED
                    elif ctx.score >= 0.65:
                        return PolicyDecision.ESCALATE
                    else:
                        return PolicyDecision.APPROVED
            except Exception as e:
                logger.error(f"[ArmorIQ Gate] Connection error on attempt {attempt}: {e}")
            
            # Delay before retry
            if attempt < max_attempts:
                await asyncio.sleep(base_delay * (2 ** (attempt - 1)))

        # Absolute fallback if loop exits with errors
        logger.error("[ArmorIQ Gate] Policy evaluation failed entirely. Escalating incident.")
        return PolicyDecision.ESCALATE

    async def log_audit(self, ctx: ThreatContext, decision: PolicyDecision, action: str) -> None:
        """Publishes an immutable security event audit entry.

        This task is dispatched asynchronously without blocking remediation.
        Always records the entry in the local database.

        Args:
            ctx: Triggering ThreatContext.
            decision: ArmorIQ Policy Decision reached.
            action: Final remediation action executed.
        """
        entry = AuditEntry(
            agent_id=ctx.agent_id,
            decision=decision,
            action=action,
            score=ctx.score,
            threat_type=ctx.threat_type,
            timestamp=time.time(),
            source="vigil",
        )

        # 1. Local SQLite backup (Always write)
        try:
            await self.registry.log_policy_decision(entry)
            logger.info(f"[ArmorIQ Gate] Logged audit entry to local registry: {entry.entry_id}")
        except Exception as e:
            logger.error(f"[ArmorIQ Gate] Failed to log audit locally: {e}")

        # 2. Remote Audit API write (Fire and forget task)
        if not self._mock_mode:
            asyncio.create_task(self._post_remote_audit(entry))

    async def _post_remote_audit(self, entry: AuditEntry) -> None:
        """Sends audit entry to remote endpoint in the background."""
        payload = {
            "entry_id": entry.entry_id,
            "agent_id": entry.agent_id,
            "decision": entry.decision.value,
            "action": entry.action,
            "score": entry.score,
            "threat_type": entry.threat_type.value,
            "timestamp": entry.timestamp,
            "source": entry.source,
        }
        try:
            response = await self.client.post("/v1/audit/log", json=payload)
            response.raise_for_status()
            logger.info(f"[ArmorIQ Gate] Posted remote audit entry: {entry.entry_id}")
        except Exception as e:
            logger.warning(f"[ArmorIQ Gate] Remote audit log post failed: {e}. Event saved in local database.")

    async def get_audit_log(self, limit: int = 50) -> List[AuditEntry]:
        """Fetches the latest audit log trail.

        Falls back gracefully to SQLite database on remote network issues.

        Args:
            limit: Maximum logs to retrieve.

        Returns:
            A list of AuditEntries.
        """
        if self._mock_mode:
            # In mock mode, always read local SQLite
            return await self.registry.get_audit_log(limit)

        try:
            response = await self.client.get(f"/v1/audit/logs?limit={limit}")
            response.raise_for_status()
            data = response.json()
            
            entries = []
            for item in data.get("entries", []):
                entries.append(
                    AuditEntry(
                        entry_id=item.get("entry_id"),
                        agent_id=item.get("agent_id"),
                        decision=PolicyDecision(item.get("decision", "APPROVED")),
                        action=item.get("action", "LOG"),
                        score=item.get("score", 0.0),
                        threat_type=ThreatType(item.get("threat_type", "NONE")),
                        timestamp=item.get("timestamp", time.time()),
                        source=item.get("source", "armoriq"),
                    )
                )
            return entries
        except Exception as e:
            logger.warning(f"[ArmorIQ Gate] Failed to fetch remote audit logs: {e}. Querying local SQLite database.")
            return await self.registry.get_audit_log(limit)
