"""VIGIL API Service and Hub.

Serves as the primary operational gateway for the VIGIL Behavioral Immune System.
Provides REST endpoints for agent registration, telemetry observation, incident queries,
and threat simulation launcher. Orchestrates a WebSocket server hub broadcasting live
incidents, status transitions, and AI explainer payloads to dashboards in real-time.
"""

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import time
from typing import Set, Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from .app.config import settings
from .app.runtime.models import (
    AgentEvent,
    AgentProfile,
    AgentStatus,
    EventType,
    IncidentRecord,
    AuditEntry,
    PolicyDecision,
    WSEvent,
    WSEventType,
    ObservationResult,
    ApprovalStatus,
    ApprovalRequest,
)
from .app.runtime.registry import AgentRegistry
from .app.detection.detector import HybridDetector
from .app.policies.armoriq_gate import ArmorIQGate
from .app.remediation.remediation import RemediationExecutor
from .app.explainability.explainer import VIGILExplainer
from .app.telemetry.monitor import BehavioralMonitor
from .app.runtime.seed import seed_agents, seed_baseline_events
from .app.runtime.threat_sim import get_attack_event, list_attack_types
from .app.runtime.simulator import DynamicTrafficSimulator

# Telegram Governed Runtime
from .services.telegram_service import TelegramService
from .services.notification_service import NotificationService
from .app.policies.governance_router import GovernanceRouter
from .app.runtime.telegram_gateway import TelegramGateway

# VIGIL 2.0 services
from .services.model_integrity_service import ModelIntegrityService
from .services.prompt_mutation_service import PromptMutationService
from .services.attack_graph_service import AttackGraphService
from .services.capability_enforcer_service import CapabilityEnforcerService
from .services.supply_chain_service import SupplyChainService
from .services.auto_remediation_orchestrator import AutoRemediationOrchestrator
from .services.incident_verification_service import IncidentVerificationService
from .services.behavioral_spoofing_service import BehavioralSpoofingService
from .services.remediation_script_service import RemediationScriptService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vigil.main")


class ConnectionManager:
    """Manages active WebSockets connection pool with heartbeat capability."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts a WebSocket connection and registers it."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Active pool size: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        """Removes a closed WebSocket from the active pool."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Active pool size: {len(self.active_connections)}")

    async def send_personal(self, websocket: WebSocket, message: Dict[str, Any]) -> None:
        """Sends a JSON package to a specific client."""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.warning(f"Error sending message to client: {e}")
            self.disconnect(websocket)

    async def broadcast(self, event: WSEvent) -> None:
        """Sends a JSON event packet to all registered clients."""
        if not self.active_connections:
            return
        
        logger.info(f"Broadcasting WS event: {event.type.value} for {event.agent_id}")
        message = event.model_dump()
        
        # Create send tasks
        closed_sockets = []
        for ws in list(self.active_connections):
            try:
                await ws.send_text(json.dumps(message))
            except Exception as e:
                logger.warning(f"Failed to broadcast to socket: {e}")
                closed_sockets.append(ws)
                
        for ws in closed_sockets:
            self.disconnect(ws)


manager = ConnectionManager()


# Async global background tasks
async def event_consumer(event_bus: asyncio.Queue, manager: ConnectionManager) -> None:
    """Consumes generated WSEvents from the pipeline and broadcasts to dashboards."""
    logger.info("Event consumer task started.")
    try:
        while True:
            event: WSEvent = await event_bus.get()
            await manager.broadcast(event)
            event_bus.task_done()
    except asyncio.CancelledError:
        logger.info("Event consumer task cancelled.")
    except Exception as e:
        logger.error(f"Event consumer crashed: {e}", exc_info=True)


async def ws_heartbeat(manager: ConnectionManager, interval: int) -> None:
    """Dispatches a recurring keepalive ping to prevent client timeout disconnects."""
    logger.info(f"WebSocket heartbeat task running (Interval: {interval}s).")
    try:
        while True:
            await asyncio.sleep(interval)
            if manager.active_connections:
                heartbeat = {
                    "type": "HEARTBEAT",
                    "timestamp": time.time(),
                    "agent_id": "system",
                    "payload": {}
                }
                closed_sockets = []
                for ws in list(manager.active_connections):
                    try:
                        await ws.send_text(json.dumps(heartbeat))
                    except Exception:
                        closed_sockets.append(ws)
                for ws in closed_sockets:
                    manager.disconnect(ws)
    except asyncio.CancelledError:
        logger.info("WebSocket heartbeat task cancelled.")
    except Exception as e:
        logger.error(f"WebSocket heartbeat task error: {e}", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup seeding and graceful shutdown resources."""
    logger.info("Starting up VIGIL backend...")
    
    # 0. Programmatically extract model zip archives if missing
    import os
    import zipfile
    
    # Extract ArmorClaw V4 sequence classifier (5-class model)
    armorclaw_dir = "backend/models/armorclaw/v4"
    armorclaw_zip = "ARMORCLAW_V4_DEPLOYMENT.zip"
    if not os.path.exists(os.path.join(armorclaw_dir, "model.safetensors")):
        if os.path.exists(armorclaw_zip):
            logger.info(f"Programmatic Auto-Extraction: Extracting {armorclaw_zip} to {armorclaw_dir}...")
            os.makedirs(armorclaw_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(armorclaw_zip, "r") as z:
                    z.extractall(armorclaw_dir)
                logger.info(f"Successfully extracted {armorclaw_zip} to {armorclaw_dir}")
            except Exception as e:
                logger.error(f"Failed to auto-extract {armorclaw_zip}: {e}")
        else:
            logger.warning(f"Zip archive '{armorclaw_zip}' not found in the workspace.")

    # Extract VIGIL baseline deployment package (2-class model + metadata)
    runtime_dir = "backend/runtime"
    runtime_zip = "VIGIL_DEPLOYMENT_PACKAGE.zip"
    if not os.path.exists(os.path.join(runtime_dir, "armorclaw_model", "model.safetensors")):
        if os.path.exists(runtime_zip):
            logger.info(f"Programmatic Auto-Extraction: Extracting {runtime_zip} to {runtime_dir}...")
            os.makedirs(runtime_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(runtime_zip, "r") as z:
                    z.extractall(runtime_dir)
                logger.info(f"Successfully extracted {runtime_zip} to {runtime_dir}")
            except Exception as e:
                logger.error(f"Failed to auto-extract {runtime_zip}: {e}")
        else:
            logger.warning(f"Zip archive '{runtime_zip}' not found in the workspace.")
    
    # 1. Initialize Registry & DB
    registry = AgentRegistry(settings.vigil_db_path)
    await registry.init_db()
    
    # 2. Setup ArmorIQ Gate
    gate = ArmorIQGate(settings, registry)
    await gate.startup()
    
    # 3. Initialize Shared Queue Event Bus
    event_bus = asyncio.Queue()
    
    # 4. Instantiate modules
    explainer = VIGILExplainer(settings)
    detector = HybridDetector(settings)
    executor = RemediationExecutor(registry, gate, event_bus, explainer)
    
    # VIGIL 2.0 services
    model_integrity_service = ModelIntegrityService(registry)
    prompt_mutation_service = PromptMutationService(registry)
    attack_graph_service = AttackGraphService(registry)
    capability_enforcer_service = CapabilityEnforcerService(registry)
    supply_chain_service = SupplyChainService(registry)
    auto_remediation_orchestrator = AutoRemediationOrchestrator(registry, ws_broadcast_callback=event_bus.put)
    incident_verification_service = IncidentVerificationService(registry, ws_broadcast_callback=event_bus.put)
    behavioral_spoofing_service = BehavioralSpoofingService(registry)
    remediation_script_service = RemediationScriptService(registry)
    
    # Wire VIGIL 2.0 services into executor
    executor.incident_verification_service = incident_verification_service
    executor.auto_remediation_orchestrator = auto_remediation_orchestrator
    executor.attack_graph_service = attack_graph_service
    executor.remediation_script_service = remediation_script_service

    # Wire VIGIL 2.0 services into monitor
    monitor = BehavioralMonitor(
        registry,
        detector,
        executor,
        event_bus,
        prompt_mutation_service=prompt_mutation_service,
        capability_enforcer_service=capability_enforcer_service,
        behavioral_spoofing_service=behavioral_spoofing_service,
    )
    
    # Initialize Telegram components
    notification_service = NotificationService(registry)
    telegram_service = TelegramService(settings, registry, event_bus, executor)
    notification_service.telegram_service = telegram_service
    executor.notification_service = notification_service
    executor.settings = settings
    
    governance_router = GovernanceRouter(gate, registry, settings)
    telegram_gateway = TelegramGateway(registry, governance_router, executor, notification_service)
    telegram_gateway.detector = detector
    
    # 5. Populate Default Agents
    await seed_agents(registry)
    
    # Register agents on ArmorIQ
    agents_list = await registry.list_agents()
    for agent in agents_list:
        armoriq_id = await gate.register_agent(agent)
        agent.armoriq_id = armoriq_id
        await registry.register_agent(agent)
        
    # 6. Seed baseline events for EWMA training
    await seed_baseline_events(registry, monitor)
    
    # Store instances in app state
    app.state.registry = registry
    app.state.gate = gate
    app.state.event_bus = event_bus
    app.state.monitor = monitor
    app.state.executor = executor
    app.state.explainer = explainer
    app.state.telegram_service = telegram_service
    app.state.telegram_gateway = telegram_gateway
    app.state.governance_router = governance_router
    app.state.notification_service = notification_service
    
    # Store VIGIL 2.0 instances in app state
    app.state.model_integrity_service = model_integrity_service
    app.state.prompt_mutation_service = prompt_mutation_service
    app.state.attack_graph_service = attack_graph_service
    app.state.capability_enforcer_service = capability_enforcer_service
    app.state.supply_chain_service = supply_chain_service
    app.state.auto_remediation_orchestrator = auto_remediation_orchestrator
    app.state.incident_verification_service = incident_verification_service
    app.state.behavioral_spoofing_service = behavioral_spoofing_service
    app.state.remediation_script_service = remediation_script_service
    
    # 7. Start async background tasks
    await telegram_service.start()
    app.state.consumer_task = asyncio.create_task(event_consumer(event_bus, manager))
    app.state.heartbeat_task = asyncio.create_task(ws_heartbeat(manager, settings.ws_heartbeat_interval))
    
    # 8. Start Dynamic Real-Time Traffic Simulator
    simulator = DynamicTrafficSimulator(
        registry=registry,
        monitor=monitor,
        event_bus=event_bus,
        interval_seconds=1.0,
        attack_probability=0.60,
        quarantine_duration_seconds=12.0,
    )
    await simulator.start()
    app.state.simulator = simulator
    
    logger.info("VIGIL backend initialization completed successfully.")
    
    yield
    
    # Graceful Shutdown
    logger.info("Shutting down VIGIL backend...")
    await app.state.telegram_service.stop()
    await app.state.simulator.stop()
    app.state.consumer_task.cancel()
    app.state.heartbeat_task.cancel()
    await asyncio.gather(app.state.consumer_task, app.state.heartbeat_task, return_exceptions=True)
    
    await gate.shutdown()
    logger.info("VIGIL shutdown finished.")


app = FastAPI(
    title="VIGIL Security API",
    description="Behavioral Immune System for AI agent pipelines",
    version="1.0.0",
    lifespan=lifespan,
)

# Apply CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_slow_requests(request, call_next):
    """Intercepts requests to log performance and flag responses taking > 400ms."""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    if duration >= 0.400:
        logger.warning(
            f"Slow request detected: {request.method} {request.url.path} "
            f"took {duration:.3f}s (Response Status: {response.status_code})"
        )
    return response


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logger.error(f"Global server error: {exc}", exc_info=True)
    return {
        "error": type(exc).__name__,
        "message": str(exc),
        "timestamp": time.time(),
    }


# REST Routes
@app.get("/health")
async def health():
    """Simple API status checks with dynamic deployment metadata."""
    try:
        import os
        registry: AgentRegistry = app.state.registry
        agents = await registry.list_agents()
        
        deployment_info = {}
        metadata_path = "backend/runtime/metadata/model_info.json"
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r") as f:
                    deployment_info = json.load(f)
            except Exception as ex:
                logger.warning(f"Failed to parse deployment metadata: {ex}")
                
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "active_agents": len(agents),
            "deployment_info": deployment_info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")


@app.post("/observe", response_model=ObservationResult)
async def observe(event: AgentEvent):
    """Submits telemetry from an agent and evaluates safety constraints."""
    try:
        monitor: BehavioralMonitor = app.state.monitor
        result = await monitor.observe(event)
        return result
    except Exception as e:
        logger.error(f"Observe processing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agents/register")
async def register(profile: AgentProfile):
    """Registers or updates agent metadata."""
    try:
        registry: AgentRegistry = app.state.registry
        gate: ArmorIQGate = app.state.gate
        
        # Register in SQLite
        await registry.register_agent(profile)
        
        # Register in ArmorIQ
        armoriq_id = await gate.register_agent(profile)
        profile.armoriq_id = armoriq_id
        
        # Update with ID
        await registry.register_agent(profile)
        
        # Broadcast agent registration
        event_bus: asyncio.Queue = app.state.event_bus
        await event_bus.put(
            WSEvent(
                type=WSEventType.AGENT_UPDATE,
                agent_id=profile.agent_id,
                payload=profile.model_dump(mode="json"),
                timestamp=time.time(),
            )
        )
        return {"status": "success", "profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/agents")
async def list_agents():
    """Returns agent profiles loaded with live scores and telemetry counts."""
    try:
        registry: AgentRegistry = app.state.registry
        agents = await registry.list_agents()
        
        completed_agents = []
        for agent in agents:
            event_count = await registry.get_event_count(agent.agent_id)
            latest_events = await registry.get_events(agent.agent_id, limit=1)
            anomaly_score = latest_events[0]["score"] if latest_events else 0.0
            
            # Map into expanded dictionary representation
            data = agent.model_dump()
            data["anomaly_score"] = anomaly_score
            data["event_count"] = event_count
            
            # Format datetime
            data["registered_at"] = agent.registered_at.isoformat()
            
            completed_agents.append(data)
            
        return completed_agents
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/agents/{agent_id}/events")
async def get_events(agent_id: str, limit: int = 50):
    """Returns raw event historical records for an agent."""
    try:
        registry: AgentRegistry = app.state.registry
        return await registry.get_events(agent_id, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents")
async def list_incidents(limit: int = 50):
    """Returns active security threats logged."""
    try:
        registry: AgentRegistry = app.state.registry
        return await registry.get_incidents(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit")
async def fetch_audit_log(limit: int = 50):
    """Retrieves threat assessment history from ArmorIQ with database local fallback."""
    try:
        gate: ArmorIQGate = app.state.gate
        return await gate.get_audit_log(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/attack/{attack_type}")
async def trigger_attack(attack_type: str):
    """Hackathon demo simulator route. Fires predefined threat scenarios."""
    try:
        monitor: BehavioralMonitor = app.state.monitor
        # Fetch event
        event = get_attack_event(attack_type)
        
        # Fire pipeline in background, return HTTP 200 immediately to frontend
        asyncio.create_task(monitor.observe(event))
        return {
            "status": "attack_fired",
            "attack_type": attack_type,
            "agent_id": event.agent_id,
            "timestamp": event.timestamp,
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/telegram/status")
async def get_telegram_status():
    """Returns Telegram connection state and operational metadata."""
    try:
        telegram_service = app.state.telegram_service
        registry = app.state.registry
        pending = await registry.get_pending_approvals()
        active_sessions = await registry.get_telegram_session_count()
        
        bot_username = ""
        if telegram_service.application and telegram_service.application.bot:
            try:
                bot_info = await telegram_service.application.bot.get_me()
                bot_username = bot_info.username or ""
            except Exception:
                pass
                
        return {
            "connected": telegram_service.is_connected,
            "bot_username": bot_username,
            "active_sessions": active_sessions,
            "pending_approvals_count": len(pending),
            "sleep_mode": settings.telegram_sleep_mode,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/telegram/approvals")
async def get_telegram_approvals():
    """Returns the list of pending governance approval requests."""
    try:
        registry = app.state.registry
        return await registry.get_pending_approvals()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/telegram/users")
async def get_telegram_users():
    """Returns the active RBAC operator registry."""
    try:
        registry = app.state.registry
        return await registry.list_telegram_users()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/telegram/approvals/{request_id}/resolve")
async def resolve_approval(request_id: str, payload: dict):
    """Resolves a pending governance approval request directly from the VIGIL dashboard."""
    try:
        action = payload.get("action", "").lower()
        if action not in ["approve", "deny"]:
            raise HTTPException(status_code=400, detail="Invalid action. Must be 'approve' or 'deny'")
            
        registry = app.state.registry
        executor = app.state.executor
        
        import aiosqlite
        async with aiosqlite.connect(registry.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)) as cursor:
                req_row = await cursor.fetchone()
                
        if not req_row:
            raise HTTPException(status_code=404, detail="Approval request not found")
            
        if req_row["status"] in ["APPROVED", "DENIED"]:
            raise HTTPException(status_code=400, detail="Request already resolved")
            
        from .services.telegram_service import get_incident_by_id
        incident = await get_incident_by_id(registry, req_row["incident_id"])
        if not incident:
            raise HTTPException(status_code=404, detail="Associated incident not found")
            
        resolved_status = None
        
        if action == "approve":
            resolved_status = ApprovalStatus.APPROVED
            if incident.action_taken != "QUARANTINE":
                incident.action_taken = "QUARANTINE"
                await executor._execute_quarantine(req_row["agent_id"], incident)
                await app.state.event_bus.put(
                    WSEvent(
                        type=WSEventType.REMEDIATION_EXECUTED,
                        agent_id=req_row["agent_id"],
                        payload={"incident_id": incident.incident_id, "action": "QUARANTINE"},
                        timestamp=time.time()
                    )
                )
        elif action == "deny":
            resolved_status = ApprovalStatus.DENIED
            incident.action_taken = "LOG"
            await executor._execute_log(incident)
            await app.state.event_bus.put(
                WSEvent(
                    type=WSEventType.REMEDIATION_EXECUTED,
                    agent_id=req_row["agent_id"],
                    payload={"incident_id": incident.incident_id, "action": "LOG (DENIED)"},
                    timestamp=time.time()
                )
            )
            
        if resolved_status:
            await registry.resolve_approval_request(request_id, resolved_status, 0)
            
            from .app.runtime.models import GovernanceAction as ModelsGovernanceAction
            gov_action = ModelsGovernanceAction(
                request_id=request_id,
                telegram_user_id=0,
                action=action.upper(),
                reason="Resolved via VIGIL Web Dashboard UI",
            )
            await registry.log_governance_action(gov_action)
            
            telegram_service = app.state.telegram_service
            if telegram_service and telegram_service.is_connected and req_row["chat_id"] and req_row["telegram_message_id"]:
                try:
                    new_text = f"🛡 <b>VIGIL GOVERNANCE REQUEST RESOLVED</b>\n\n" \
                               f"<b>Agent Subject:</b> <code>{req_row['agent_id']}</code>\n" \
                               f"<b>Proposed Action:</b> <code>{req_row['proposed_action']}</code>\n\n" \
                               f"🛡 <b>Status:</b> ✅ Resolved via Web UI ({action.upper()})"
                    await telegram_service.application.bot.edit_message_text(
                        chat_id=req_row["chat_id"],
                        message_id=req_row["telegram_message_id"],
                        text=new_text,
                        parse_mode="HTML"
                    )
                except Exception as bot_err:
                    logger.warning(f"Failed to update Telegram message card: {bot_err}")
                    
            await telegram_service.broadcast_status()
            
        return {"status": "success", "resolved_to": action}
    except Exception as e:
        logger.error(f"Failed to resolve approval request: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/integrity/{agent_id}")
async def get_integrity(agent_id: str):
    try:
        registry = app.state.registry
        baseline = await registry.get_model_integrity_baseline(agent_id)
        events = await registry.get_model_integrity_events(agent_id)
        return {
            "baseline": baseline.model_dump() if baseline else None,
            "events": [e.model_dump() for e in events]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/attack-graph/{incident_id}")
async def get_attack_graph(incident_id: str):
    try:
        registry = app.state.registry
        attack_graph_service = app.state.attack_graph_service
        
        import aiosqlite
        async with aiosqlite.connect(registry.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT agent_id, score FROM incidents WHERE incident_id = ?", (incident_id,)) as cursor:
                row = await cursor.fetchone()
        
        if row:
            res = await attack_graph_service.analyze_incident_propagation(row["agent_id"], row["score"])
            return res
        else:
            nodes = await registry.get_attack_graph_nodes()
            edges = await registry.get_attack_graph_edges()
            return {
                "nodes": [n.model_dump() for n in nodes],
                "edges": [e.model_dump() for e in edges],
                "trigger_agent": None,
                "blast_radius": 0,
                "timestamp": time.time()
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/capabilities/{agent_id}")
async def get_capabilities(agent_id: str):
    try:
        registry = app.state.registry
        profile = await registry.get_capability_profile(agent_id)
        violations = await registry.get_capability_violations(agent_id)
        return {
            "profile": profile.model_dump() if profile else None,
            "violations": [v.model_dump() for v in violations]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/supply-chain/{agent_id}")
async def get_supply_chain(agent_id: str):
    try:
        registry = app.state.registry
        dependencies = await registry.get_supply_chain_dependencies(agent_id)
        events = await registry.get_supply_chain_events(agent_id)
        return {
            "dependencies": [d.model_dump() for d in dependencies],
            "events": [e.model_dump() for e in events]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/evidence/{incident_id}")
async def get_evidence(incident_id: str):
    try:
        registry = app.state.registry
        incident = await registry.get_tamper_proof_incident(incident_id)
        return incident.model_dump() if incident else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/remediation-chains/{incident_id}")
async def get_remediation_chain(incident_id: str):
    try:
        registry = app.state.registry
        chain = await registry.get_remediation_chain(incident_id)
        return chain.model_dump() if chain else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/spoofing/{agent_id}")
async def get_spoofing(agent_id: str):
    try:
        registry = app.state.registry
        score = await registry.get_behavioral_footprint_score(agent_id)
        return score.model_dump() if score else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/remediation-scripts/{incident_id}")
async def get_remediation_script(incident_id: str):
    try:
        registry = app.state.registry
        script = await registry.get_remediation_script(incident_id)
        return script.model_dump() if script else None
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/threat-intelligence")
async def get_threat_intelligence():
    try:
        registry = app.state.registry
        agents = await registry.list_agents()
        
        integrity_baselines = []
        all_integrity_events = []
        capability_profiles = []
        all_capability_violations = []
        supply_chain_dependencies = []
        all_supply_chain_events = []
        all_prompt_mutations = []
        spoofing_scores = []
        
        for agent in agents:
            agent_id = agent.agent_id
            
            baseline = await registry.get_model_integrity_baseline(agent_id)
            if baseline:
                integrity_baselines.append(baseline.model_dump())
            events = await registry.get_model_integrity_events(agent_id)
            all_integrity_events.extend([e.model_dump() for e in events])
            
            cap = await registry.get_capability_profile(agent_id)
            if cap:
                capability_profiles.append(cap.model_dump())
            violations = await registry.get_capability_violations(agent_id)
            all_capability_violations.extend([v.model_dump() for v in violations])
            
            deps = await registry.get_supply_chain_dependencies(agent_id)
            supply_chain_dependencies.extend([d.model_dump() for d in deps])
            dep_events = await registry.get_supply_chain_events(agent_id)
            all_supply_chain_events.extend([e.model_dump() for e in dep_events])
            
            mutations = await registry.get_prompt_mutations(agent_id)
            all_prompt_mutations.extend([m.model_dump() for m in mutations])
            
            sp_score = await registry.get_behavioral_footprint_score(agent_id)
            if sp_score:
                spoofing_scores.append(sp_score.model_dump())
                
        nodes = await registry.get_attack_graph_nodes()
        edges = await registry.get_attack_graph_edges()
        
        return {
            "integrity_baselines": integrity_baselines,
            "integrity_events": all_integrity_events,
            "capability_profiles": capability_profiles,
            "capability_violations": all_capability_violations,
            "supply_chain_dependencies": supply_chain_dependencies,
            "supply_chain_events": all_supply_chain_events,
            "prompt_mutations": all_prompt_mutations,
            "spoofing_scores": spoofing_scores,
            "attack_graph": {
                "nodes": [n.model_dump() for n in nodes],
                "edges": [e.model_dump() for e in edges]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket Router
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    """Manages long-lived client sockets for telemetry streaming."""
    await manager.connect(websocket)
    
    try:
        # Fetch initial dashboard context states
        registry: AgentRegistry = app.state.registry
        
        agents_data = await list_agents()
        incidents = await registry.get_incidents(limit=50)
        audit_log = await fetch_audit_log(limit=50)
        
        # Fetch initial Telegram states
        telegram_service = app.state.telegram_service
        pending_approvals = await registry.get_pending_approvals()
        telegram_users = await registry.list_telegram_users()
        active_sessions = await registry.get_telegram_session_count()
        
        bot_username = ""
        if telegram_service.application and telegram_service.application.bot:
            try:
                bot_info = await telegram_service.application.bot.get_me()
                bot_username = bot_info.username or ""
            except Exception:
                pass
                
        telegram_status = {
            "connected": telegram_service.is_connected,
            "bot_username": bot_username,
            "active_sessions": active_sessions,
            "pending_approvals_count": len(pending_approvals),
            "sleep_mode": settings.telegram_sleep_mode,
        }
        
        # Format lists
        incidents_data = [inc.model_dump() for inc in incidents]
        audit_data = [item.model_dump() for item in audit_log]
        
        # Send initial state package
        init_event = {
            "type": "INIT",
            "timestamp": time.time(),
            "agent_id": "system",
            "payload": {
                "agents": agents_data,
                "incidents": incidents_data,
                "audit": audit_data,
                "telegramStatus": telegram_status,
                "pendingApprovals": [appr.model_dump() for appr in pending_approvals],
                "telegramUsers": [u.model_dump() for u in telegram_users],
            }
        }
        await manager.send_personal(websocket, init_event)
        
        # Keep client connection open
        while True:
            # Dashboard doesn't need to post commands here, but keep read loop active
            data = await websocket.receive_text()
            logger.info(f"Received raw data from WS client: {data}")
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket endpoint crashed: {e}")
        manager.disconnect(websocket)
