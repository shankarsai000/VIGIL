import logging
import time
from typing import Tuple, List, Optional
from ..app.runtime.models import SupplyChainDependency, SupplyChainEvent

logger = logging.getLogger("vigil.services.supply_chain")

class SupplyChainService:
    """Verifies external package and dependency integrity for agent codebases."""
    
    def __init__(self, registry):
        self.registry = registry

    async def register_dependency(self, agent_id: str, name: str, version: str, expected_hash: str, certificate_subject: Optional[str] = None) -> SupplyChainDependency:
        """Registers a known-good package/dependency configuration."""
        dep = SupplyChainDependency(
            agent_id=agent_id,
            dependency_name=name,
            expected_version=version,
            expected_hash=expected_hash,
            certificate_subject=certificate_subject,
            registered_at=time.time()
        )
        await self.registry.save_supply_chain_dependency(dep)
        logger.info(f"Registered dependency baseline for {agent_id}: {name} (Version: {version})")
        return dep

    async def verify_dependency(self, agent_id: str, name: str, current_version: str, current_hash: str, certificate_subject: Optional[str] = None) -> Tuple[bool, List[SupplyChainEvent]]:
        """Verifies package signatures/hashes/versions against registered baselines."""
        dependencies = await self.registry.get_supply_chain_dependencies(agent_id)
        dep = next((d for d in dependencies if d.dependency_name == name), None)

        if not dep:
            # Auto-seed baseline on first check for demo completeness
            dep = await self.register_dependency(
                agent_id=agent_id,
                name=name,
                version=current_version,
                expected_hash=current_hash,
                certificate_subject=certificate_subject or "CN=TrustedAgentPublisher"
            )

        events = []
        is_anomaly = False

        # 1. Check Hash
        if dep.expected_hash != current_hash:
            is_anomaly = True
            event = SupplyChainEvent(
                agent_id=agent_id,
                dependency_name=name,
                current_version=current_version,
                current_hash=current_hash,
                issue_type="HASH_MISMATCH",
                timestamp=time.time()
            )
            await self.registry.log_supply_chain_event(event)
            events.append(event)
            logger.warning(f"SUPPLY CHAIN ALERT: Hash mismatch on dependency '{name}' for agent {agent_id}. Expected: {dep.expected_hash}, Got: {current_hash}")

        # 2. Check Cert Signer Mismatch
        if dep.certificate_subject and certificate_subject and dep.certificate_subject != certificate_subject:
            is_anomaly = True
            event = SupplyChainEvent(
                agent_id=agent_id,
                dependency_name=name,
                current_version=current_version,
                current_hash=current_hash,
                issue_type="CERT_INVALID",
                timestamp=time.time()
            )
            await self.registry.log_supply_chain_event(event)
            events.append(event)
            logger.warning(f"SUPPLY CHAIN ALERT: Certificate signature mismatch on '{name}' for agent {agent_id}. Expected: '{dep.certificate_subject}', Got: '{certificate_subject}'")

        # 3. Check Version Drift (e.g. downgrades)
        if dep.expected_version != current_version:
            # Simple version inequality warning
            event = SupplyChainEvent(
                agent_id=agent_id,
                dependency_name=name,
                current_version=current_version,
                current_hash=current_hash,
                issue_type="VERSION_DRIFT",
                timestamp=time.time()
            )
            await self.registry.log_supply_chain_event(event)
            events.append(event)
            logger.info(f"Supply chain info: Version change on '{name}' for agent {agent_id}. Expected: {dep.expected_version}, Got: {current_version}")

        return is_anomaly, events
