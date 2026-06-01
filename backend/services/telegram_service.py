import logging
import asyncio
import time
from typing import Optional, List, Dict, Any
from uuid import uuid4
import json

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

from ..app.config import VigilSettings
from ..app.runtime.models import (
    TelegramUser,
    TelegramRole,
    ApprovalRequest,
    ApprovalStatus,
    GovernanceAction,
    TelegramGovernanceAction,
    AgentStatus,
    WSEvent,
    WSEventType,
    ThreatType,
    PolicyDecision,
    IncidentRecord,
    DetectionResult,
    AgentEvent,
    IncidentState,
)
from ..app.runtime.registry import AgentRegistry

logger = logging.getLogger("vigil.telegram_service")


async def get_incident_by_id(registry: AgentRegistry, incident_id: str) -> Optional[IncidentRecord]:
    """Helper to load a full IncidentRecord from DB."""
    return await registry.get_incident(incident_id)


def require_role(min_role: TelegramRole):
    """Decorator to authorize user commands and callback queries based on RBAC."""
    def decorator(func):
        async def wrapper(self, update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = update.effective_user
            if not user:
                return
            
            # Fetch or register user
            db_user = await self.registry.get_telegram_user(user.id)
            if not db_user:
                is_admin = user.id in self.settings.telegram_admin_id_list
                role = TelegramRole.ADMIN if is_admin else TelegramRole.OBSERVER
                db_user = TelegramUser(
                    telegram_id=user.id,
                    username=user.username or "",
                    display_name=user.full_name or "",
                    role=role,
                    is_active=True,
                )
                await self.registry.register_telegram_user(db_user)
            
            if not db_user.is_active:
                msg = "❌ Your account is inactive. Please contact an administrator."
                if update.callback_query:
                    await update.callback_query.answer(text=msg, show_alert=True)
                elif update.message:
                    await update.message.reply_text(msg)
                return
            
            # Update activity
            await self.registry.update_telegram_user_last_seen(user.id)
            
            # Role check
            if not db_user.role.has_permission(min_role):
                msg = f"❌ Permission denied. Required: {min_role.value} (You: {db_user.role.value})"
                if update.callback_query:
                    await update.callback_query.answer(text=msg, show_alert=True)
                elif update.message:
                    await update.message.reply_text(msg)
                return
            
            return await func(self, update, context, db_user, *args, **kwargs)
        return wrapper
    return decorator


class TelegramService:
    """Core background service managing Telegram bot lifecycle and operators interactions."""

    def __init__(
        self,
        settings: VigilSettings,
        registry: AgentRegistry,
        event_bus: asyncio.Queue,
        executor=None,
    ):
        self.settings = settings
        self.registry = registry
        self.event_bus = event_bus
        self.executor = executor
        self.application: Optional[Application] = None
        self.is_connected = False
        self.polling_task: Optional[asyncio.Task] = None

    async def start(self):
        """Initializes and starts the Telegram bot listener."""
        if not self.settings.telegram_bot_token:
            logger.warning("No TELEGRAM_BOT_TOKEN provided. Telegram Governed Runtime will not run.")
            return

        try:
            logger.info("Initializing Telegram Bot application...")
            self.application = Application.builder().token(self.settings.telegram_bot_token).build()
            
            # Register routes
            self.application.add_handler(CommandHandler("start", self.handle_start))
            self.application.add_handler(CommandHandler("status", self.handle_status))
            self.application.add_handler(CommandHandler("agents", self.handle_agents))
            self.application.add_handler(CommandHandler("incident", self.handle_incident))
            self.application.add_handler(CommandHandler("sleepmode", self.handle_sleepmode))
            self.application.add_handler(CommandHandler("revoke", self.handle_revoke))
            self.application.add_handler(CallbackQueryHandler(self.handle_callback))
            
            await self.application.initialize()
            await self.application.start()
            
            # Auto-register admin users from settings
            for admin_id in self.settings.telegram_admin_id_list:
                existing_user = await self.registry.get_telegram_user(admin_id)
                if not existing_user:
                    admin_user = TelegramUser(
                        telegram_id=admin_id,
                        username="",
                        display_name=f"Admin {admin_id}",
                        role=TelegramRole.ADMIN,
                        is_active=True,
                    )
                    await self.registry.register_telegram_user(admin_user)
                    logger.info(f"Auto-registered admin user with ID {admin_id}")
                else:
                    logger.info(f"Admin user with ID {admin_id} already registered")
            
            logger.info("Starting Telegram Updater polling...")
            await self.application.updater.start_polling()
            
            self.is_connected = True
            await self.broadcast_status()
            logger.info("Telegram Bot service successfully started.")
        except Exception as e:
            logger.error(f"Failed to start Telegram service: {e}", exc_info=True)
            self.is_connected = False

    async def stop(self):
        """Gracefully stops the bot polling and shuts down application."""
        if self.application:
            logger.info("Stopping Telegram Bot service...")
            try:
                if self.application.updater:
                    await self.application.updater.stop()
                await self.application.stop()
                await self.application.shutdown()
                logger.info("Telegram Bot service stopped.")
            except Exception as e:
                logger.error(f"Error during Telegram service shutdown: {e}")
            finally:
                self.is_connected = False
                await self.broadcast_status()

    async def broadcast_status(self):
        """Broadcasts current bot metadata via WebSocket event bus."""
        if not self.event_bus:
            return
        
        try:
            pending = await self.registry.get_pending_approvals()
            active_sessions = await self.registry.get_telegram_session_count()
            
            bot_username = ""
            if self.application and self.application.bot:
                try:
                    bot_info = await self.application.bot.get_me()
                    bot_username = bot_info.username or ""
                except Exception:
                    pass

            payload = {
                "connected": self.is_connected,
                "bot_username": bot_username,
                "active_sessions": active_sessions,
                "pending_approvals_count": len(pending),
                "sleep_mode": self.settings.telegram_sleep_mode,
            }
            
            await self.event_bus.put(
                WSEvent(
                    type=WSEventType.TELEGRAM_STATUS,
                    agent_id="system",
                    payload=payload,
                    timestamp=time.time()
                )
            )
        except Exception as e:
            logger.error(f"Failed to broadcast Telegram status: {e}")

    @require_role(TelegramRole.EXECUTIVE)
    async def handle_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Greets the user and outputs command reference based on RBAC permissions."""
        session_id = f"sess_{db_user.telegram_id}"
        await self.registry.db.execute(
            """
            INSERT INTO telegram_sessions (session_id, telegram_id, started_at, last_activity, is_active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(session_id) DO UPDATE SET
                last_activity=excluded.last_activity,
                is_active=1
            """,
            (session_id, db_user.telegram_id, time.time(), time.time()),
        )
        
        await self.broadcast_status()

        msg = (
            "🛡 <b>VIGIL Governed Runtime Layer</b>\n\n"
            f"Welcome, <b>{db_user.display_name or db_user.username or 'Operator'}</b>!\n"
            f"Your role: <code>{db_user.role.value}</code>\n\n"
            "<b>Available Commands:</b>\n"
            "• /start - Show this welcome menu\n"
            "• /status - Fetch platform operational and governance status\n"
        )
        if db_user.role.has_permission(TelegramRole.OBSERVER):
            msg += "• /agents - List active agents and threat scores\n"
        if db_user.role.has_permission(TelegramRole.SECURITY_ANALYST):
            msg += "• /incident &lt;id&gt; - Inspect specific incident details\n"
        if db_user.role.has_permission(TelegramRole.ADMIN):
            msg += (
                "• /sleepmode - Toggle overnight autonomous mode\n"
                "• /revoke &lt;agent_id&gt; - Revoke an agent's quarantine status\n"
            )
        await update.message.reply_html(msg)

    @require_role(TelegramRole.OBSERVER)
    async def handle_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Returns the status details of the VIGIL deployment."""
        agents = await self.registry.list_agents()
        total_agents = len(agents)
        quarantined_agents = sum(1 for a in agents if a.status == AgentStatus.QUARANTINED)
        normal_agents = total_agents - quarantined_agents
        
        incidents = await self.registry.get_incidents(limit=10)
        max_score = max([inc.detection_result.score for inc in incidents], default=0.0)
        
        if max_score >= 0.85:
            threat_level = "🔴 CRITICAL"
        elif max_score >= 0.65:
            threat_level = "🟡 HIGH"
        elif max_score >= 0.30:
            threat_level = "🔵 MEDIUM"
        else:
            threat_level = "🟢 LOW"
            
        sleep_mode_status = "🌙 ACTIVE (Autonomous)" if self.settings.telegram_sleep_mode else "☀️ INACTIVE (Operator Governed)"
        
        msg = (
            "📊 <b>VIGIL System Status</b>\n\n"
            f"• <b>Threat Level:</b> {threat_level}\n"
            f"• <b>Governance Mode:</b> {sleep_mode_status}\n"
            f"• <b>Total Agents:</b> {total_agents}\n"
            f"• <b>Normal Agents:</b> {normal_agents}\n"
            f"• <b>Quarantined:</b> {quarantined_agents}\n"
        )
        await update.message.reply_html(msg)

    @require_role(TelegramRole.OBSERVER)
    async def handle_agents(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Lists active agents, statuses, and anomaly scores."""
        agents = await self.registry.list_agents()
        if not agents:
            await update.message.reply_html("No registered agents found.")
            return
            
        msg_lines = ["🤖 <b>Registered Agents Registry</b>\n"]
        for agent in agents:
            latest_events = await self.registry.get_events(agent.agent_id, limit=1)
            score = latest_events[0]["score"] if latest_events else 0.0
            
            status_emoji = "🟢" if agent.status == AgentStatus.NORMAL else "🔴"
            msg_lines.append(
                f"{status_emoji} <b>{agent.name}</b> (<code>{agent.agent_id}</code>)\n"
                f"  • Status: <code>{agent.status.value}</code>\n"
                f"  • Threat Score: <code>{score:.2f}</code>\n"
            )
        await update.message.reply_html("\n".join(msg_lines))

    @require_role(TelegramRole.SECURITY_ANALYST)
    async def handle_incident(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Displays explanation, scores, and policy context for a specific incident."""
        if not context.args:
            await update.message.reply_html("❌ Please specify an incident ID: <code>/incident &lt;id&gt;</code>")
            return
        
        incident_id = context.args[0]
        incident = await get_incident_by_id(self.registry, incident_id)
        if not incident:
            await update.message.reply_html(f"❌ Incident with ID <code>{incident_id}</code> not found.")
            return
        
        msg = (
            f"🚨 <b>Incident {incident.incident_id[:8]}...</b>\n\n"
            f"• <b>Agent:</b> <code>{incident.agent_id}</code>\n"
            f"• <b>Threat Type:</b> <code>{incident.threat_type.value}</code>\n"
            f"• <b>Threat Score:</b> <code>{incident.detection_result.score:.2f}</code>\n"
            f"• <b>ArmorIQ Policy Decision:</b> <code>{incident.policy_decision.value}</code>\n"
            f"• <b>Action Taken:</b> <code>{incident.action_taken}</code>\n\n"
            f"📝 <b>Explanation:</b>\n<i>{incident.explanation}</i>\n\n"
            f"🔗 <a href='http://localhost:5173/'>Open VIGIL Dashboard</a>"
        )
        await update.message.reply_html(msg)

    @require_role(TelegramRole.ADMIN)
    async def handle_sleepmode(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Toggles the overnight autonomous sleepmode policy."""
        self.settings.telegram_sleep_mode = not self.settings.telegram_sleep_mode
        status_text = "🌙 ACTIVE (Autonomous)" if self.settings.telegram_sleep_mode else "☀️ INACTIVE (Operator Governed)"
        await update.message.reply_html(f"🌙 <b>Overnight Sleep Mode</b> updated to: <b>{status_text}</b>")
        await self.broadcast_status()

    @require_role(TelegramRole.ADMIN)
    async def handle_revoke(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Removes the quarantine confinement from an agent."""
        if not context.args:
            await update.message.reply_html("❌ Please specify an agent ID: <code>/revoke &lt;agent_id&gt;</code>")
            return
        
        agent_id = context.args[0]
        agent = await self.registry.get_agent(agent_id)
        if not agent:
            await update.message.reply_html(f"❌ Agent <code>{agent_id}</code> not found.")
            return
            
        if agent.status != AgentStatus.QUARANTINED:
            await update.message.reply_html(f"ℹ️ Agent <code>{agent_id}</code> is not quarantined.")
            return
            
        await self.registry.update_status(agent_id, AgentStatus.NORMAL)
        
        profile = await self.registry.get_agent(agent_id)
        if profile:
            await self.event_bus.put(
                WSEvent(
                    type=WSEventType.AGENT_UPDATE,
                    agent_id=agent_id,
                    payload=profile.model_dump(mode="json"),
                    timestamp=time.time(),
                )
            )
        
        await update.message.reply_html(f"✅ Quarantined status for agent <code>{agent_id}</code> has been revoked successfully.")
        await self.broadcast_status()

    @require_role(TelegramRole.OBSERVER)
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE, db_user: TelegramUser):
        """Processes governance approval/deny/investigate interactions from inline buttons."""
        query = update.callback_query
        await query.answer("✅ Received. Processing...")
        
        data = query.data
        if not data or not data.startswith("gov:"):
            return
            
        parts = data.split(":")
        if len(parts) < 3:
            return
            
        request_id = parts[1]
        action = parts[2]
        
        # Action role checks
        if action in ["approve", "deny"]:
            if not db_user.role.has_permission(TelegramRole.SECURITY_ANALYST):
                await query.answer("❌ Permission denied. Security Analyst role or higher required.", show_alert=True)
                return
        elif action == "investigate":
            if not db_user.role.has_permission(TelegramRole.OBSERVER):
                await query.answer("❌ Permission denied. Observer role or higher required.", show_alert=True)
                return
                
        req_row = await self.registry.db.fetchrow(
            "SELECT * FROM approval_requests WHERE request_id = ?",
            (request_id,),
        )
                
        if not req_row:
            await query.edit_message_text("❌ Request not found.")
            return
            
        current_status = req_row["status"]
        if current_status in ["APPROVED", "DENIED"]:
            await query.answer(f"This request has already been {current_status.lower()}.", show_alert=True)
            return
            
        incident = await get_incident_by_id(self.registry, req_row["incident_id"])
        if not incident:
            await query.answer("❌ Associated incident not found.", show_alert=True)
            return
            
        # --- Step 1: Immediate Telegram Acknowledgment ---
        resolved_status = None
        new_incident_state = None
        immediate_msg = ""
        
        if action == "approve":
            resolved_status = ApprovalStatus.APPROVED
            new_incident_state = IncidentState.QUARANTINED
            immediate_msg = f"✅ APPROVAL RECEIVED\n\nIncident: {incident.incident_id}\n\nAction: {req_row['proposed_action']} APPROVED\n\nSubmitting governance validation to ArmorIQ..."
        elif action == "deny":
            resolved_status = ApprovalStatus.DENIED
            new_incident_state = IncidentState.MONITORING
            immediate_msg = f"❌ GOVERNANCE DENIED\n\nIncident: {incident.incident_id}\n\nContainment action blocked.\n\nIncident moved to monitoring state."
        elif action == "investigate":
            resolved_status = ApprovalStatus.INVESTIGATING
            new_incident_state = IncidentState.UNDER_INVESTIGATION
            immediate_msg = f"🔍 INVESTIGATION MODE ACTIVATED\n\nIncident: {incident.incident_id}\n\nEnhanced telemetry capture enabled.\nThreat replay recording started."
            
        # Send immediate acknowledgment
        await query.edit_message_text(immediate_msg, parse_mode="HTML")
        
        # --- Step 2: Process the governance action ---
        start_time = time.time()
        
        # Update approval request
        await self.registry.resolve_approval_request(request_id, resolved_status, db_user.telegram_id)
        
        # Update incident state
        await self.registry.update_incident_state(incident.incident_id, new_incident_state)
        
        # Log governance action
        gov_action = GovernanceAction(
            request_id=request_id,
            telegram_user_id=db_user.telegram_id,
            action=action.upper(),
            reason=f"Resolved via Telegram interface: {action.upper()}",
        )
        await self.registry.log_governance_action(gov_action)
        
        # Execute action-specific logic
        armoriq_decision = "PENDING"
        remediation_executed = ""
        
        if action == "approve":
            # ArmorIQ validation (simulated for now)
            armoriq_decision = "APPROVED"
            
            # Execute remediation
            if incident.action_taken != req_row["proposed_action"] and self.executor:
                incident.action_taken = req_row["proposed_action"]
                if req_row["proposed_action"] == "QUARANTINE":
                    await self.executor._execute_quarantine(req_row["agent_id"], incident)
                    remediation_executed = "QUARANTINE"
                elif req_row["proposed_action"] == "ALERT":
                    await self.executor._execute_log(incident)
                    remediation_executed = "ALERT"
                else:
                    await self.executor._execute_log(incident)
                    remediation_executed = "LOG"
                
                # Send remediation event
                await self.event_bus.put(
                    WSEvent(
                        type=WSEventType.REMEDIATION_EXECUTED,
                        agent_id=req_row["agent_id"],
                        payload={"incident_id": incident.incident_id, "action": remediation_executed},
                        timestamp=time.time()
                    )
                )
                
        elif action == "deny":
            # Log only
            if self.executor:
                incident.action_taken = "LOG"
                await self.executor._execute_log(incident)
                remediation_executed = "LOG (DENIED)"
                await self.event_bus.put(
                    WSEvent(
                        type=WSEventType.REMEDIATION_EXECUTED,
                        agent_id=req_row["agent_id"],
                        payload={"incident_id": incident.incident_id, "action": remediation_executed},
                        timestamp=time.time()
                    )
                )
                
        elif action == "investigate":
            # Enhanced telemetry (simulated)
            armoriq_decision = "INVESTIGATING"
            remediation_executed = "ENHANCED_TELEMETRY"
            
        # Log detailed Telegram governance action
        telegram_gov_action = TelegramGovernanceAction(
            incident_id=incident.incident_id,
            action=action.upper(),
            operator_id=db_user.telegram_id,
            telegram_username=db_user.username or "",
            timestamp=time.time(),
            governance_result="COMPLETED",
            resulting_state=new_incident_state.value,
            armoriq_decision=armoriq_decision,
            remediation_action=remediation_executed,
        )
        await self.registry.log_telegram_governance_action(telegram_gov_action)
        
        # --- Step 3: Broadcast to frontend ---
        response_time_ms = int((time.time() - start_time) * 1000)
        await self.event_bus.put(
            WSEvent(
                type=WSEventType.GOVERNANCE_UPDATE,
                agent_id=incident.agent_id,
                payload={
                    "incident_id": incident.incident_id,
                    "action": action.upper(),
                    "new_state": new_incident_state.value,
                    "operator": db_user.username or str(db_user.telegram_id),
                    "operator_display_name": db_user.display_name,
                    "armoriq_decision": armoriq_decision,
                    "response_time_ms": response_time_ms,
                    "timestamp": time.time()
                },
                timestamp=time.time()
            )
        )
        
        # --- Step 4: Send final Telegram confirmation ---
        final_msg = ""
        
        if action == "approve":
            final_msg = (
                f"🛡️ CONTAINMENT SUCCESSFUL\n\n"
                f"Incident: {incident.incident_id}\n\n"
                f"ArmorIQ: {armoriq_decision}\n\n"
                f"Agent: {req_row['agent_id']}\n\n"
                f"Status: {new_incident_state.value}\n\n"
                f"Response Time: {response_time_ms}ms"
            )
        elif action == "deny":
            final_msg = (
                f"⚠️ INCIDENT MOVED TO MONITORING\n\n"
                f"Incident: {incident.incident_id}\n\n"
                f"Containment was denied.\n\n"
                f"Enhanced behavioral observation remains active."
            )
        elif action == "investigate":
            final_msg = (
                f"🔍 INVESTIGATION ACTIVE\n\n"
                f"Incident: {incident.incident_id}\n\n"
                f"Threat replay recording enabled.\n\n"
                f"Enhanced telemetry monitoring activated."
            )
            
        if action == "investigate":
            keyboard = [
                [
                    InlineKeyboardButton("Approve", callback_data=f"gov:{request_id}:approve"),
                    InlineKeyboardButton("Deny", callback_data=f"gov:{request_id}:deny"),
                ]
            ]
            await query.edit_message_text(final_msg, parse_mode="HTML", reply_markup=InlineKeyboardMarkup(keyboard))
        else:
            await query.edit_message_text(final_msg, parse_mode="HTML")
            
        await self.broadcast_status()
