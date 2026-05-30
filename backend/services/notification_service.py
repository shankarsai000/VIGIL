import logging
import time
from typing import Optional
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from ..app.runtime.models import (
    IncidentRecord,
    ApprovalRequest,
    NotificationRecord,
    TelegramRole,
)
from ..app.runtime.registry import AgentRegistry

logger = logging.getLogger("vigil.notification_service")


class NotificationService:
    """Governed alert broadcasting service directing incidents and approvals to Telegram operators."""

    def __init__(self, registry: AgentRegistry, telegram_service=None):
        self.registry = registry
        self._telegram_service = telegram_service

    @property
    def telegram_service(self):
        return self._telegram_service

    @telegram_service.setter
    def telegram_service(self, service):
        self._telegram_service = service

    async def broadcast_to_role(self, message: str, min_role: TelegramRole, reply_markup=None) -> int:
        """Sends a message to all active Telegram users meeting the minimum role requirements."""
        if not self.telegram_service or not self.telegram_service.is_connected:
            logger.warning("Telegram service not initialized/connected. Cannot broadcast notification.")
            return 0
            
        try:
            users = await self.registry.list_telegram_users()
        except Exception as e:
            logger.error(f"Failed to fetch telegram users for broadcasting: {e}")
            return 0
            
        sent_count = 0
        for user in users:
            if not user.is_active:
                continue
            if user.role.has_permission(min_role):
                try:
                    await self.telegram_service.application.bot.send_message(
                        chat_id=user.telegram_id,
                        text=message,
                        parse_mode="HTML",
                        reply_markup=reply_markup,
                    )
                    sent_count += 1
                except Exception as e:
                    logger.error(f"Failed to send Telegram notification to user {user.telegram_id}: {e}")
                    
        return sent_count

    async def send_alert(self, incident: IncidentRecord, threat_level: str) -> None:
        """Formats and broadcasts a security alert to all active OBSERVER+ operators."""
        msg = (
            f"🚨 <b>VIGIL {threat_level} ALERT</b>\n\n"
            f"<b>Agent:</b> <code>{incident.agent_id}</code>\n"
            f"<b>Threat:</b> <code>{incident.threat_type.value}</code>\n"
            f"<b>Threat Score:</b> <code>{incident.detection_result.score:.2f}</code>\n"
            f"<b>ArmorIQ Decision:</b> <code>{incident.policy_decision.value}</code>\n"
            f"<b>Action Taken:</b> <code>{incident.action_taken}</code>\n"
            f"<b>Incident ID:</b> <code>{incident.incident_id}</code>\n\n"
            f"🔗 <a href='http://localhost:5173/'>Open VIGIL Dashboard</a>"
        )
        await self.broadcast_to_role(msg, TelegramRole.OBSERVER)
        
        # Log notification records
        try:
            users = await self.registry.list_telegram_users()
            for user in users:
                if user.is_active and user.role.has_permission(TelegramRole.OBSERVER):
                    record = NotificationRecord(
                        incident_id=incident.incident_id,
                        chat_id=user.telegram_id,
                        notification_type="ALERT",
                        content_summary=f"VIGIL {threat_level} ALERT for {incident.agent_id}",
                        delivered=True,
                    )
                    await self.registry.log_notification(record)
        except Exception as e:
            logger.error(f"Failed to log notification records for incident alert: {e}")

    async def send_approval_card(self, approval_request: ApprovalRequest) -> None:
        """Sends an inline keyboard governance approval card to all active SECURITY_ANALYST+ operators."""
        msg = (
            f"🛡 <b>VIGIL GOVERNANCE APPROVAL REQUEST</b>\n\n"
            f"<b>Agent Subject:</b> <code>{approval_request.agent_id}</code>\n"
            f"<b>Threat Type:</b> <code>{approval_request.threat_type.value}</code>\n"
            f"<b>Threat Score:</b> <code>{approval_request.threat_score:.2f}</code>\n"
            f"<b>Proposed Containment:</b> <code>{approval_request.proposed_action}</code>\n\n"
            f"🚨 <i>Awaiting security operations response. Use buttons below to resolve:</i>"
        )
        
        keyboard = [
            [
                InlineKeyboardButton("Approve", callback_data=f"gov:{approval_request.request_id}:approve"),
                InlineKeyboardButton("Deny", callback_data=f"gov:{approval_request.request_id}:deny"),
            ],
            [
                InlineKeyboardButton("Investigate", callback_data=f"gov:{approval_request.request_id}:investigate")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if not self.telegram_service or not self.telegram_service.is_connected:
            logger.warning("Telegram service not initialized/connected. Saving approval request only.")
            await self.registry.create_approval_request(approval_request)
            return
            
        try:
            users = await self.registry.list_telegram_users()
        except Exception as e:
            logger.error(f"Failed to fetch telegram users for approval cards: {e}")
            await self.registry.create_approval_request(approval_request)
            return
            
        first_msg = True
        for user in users:
            if not user.is_active:
                continue
            if user.role.has_permission(TelegramRole.SECURITY_ANALYST):
                try:
                    sent_msg = await self.telegram_service.application.bot.send_message(
                        chat_id=user.telegram_id,
                        text=msg,
                        parse_mode="HTML",
                        reply_markup=reply_markup,
                    )
                    
                    if first_msg:
                        approval_request.chat_id = user.telegram_id
                        approval_request.telegram_message_id = sent_msg.message_id
                        await self.registry.create_approval_request(approval_request)
                        first_msg = False
                        
                    record = NotificationRecord(
                        incident_id=approval_request.incident_id,
                        chat_id=user.telegram_id,
                        notification_type="APPROVAL_CARD",
                        content_summary=f"Governance approval card for {approval_request.agent_id}",
                        delivered=True,
                    )
                    await self.registry.log_notification(record)
                except Exception as e:
                    logger.error(f"Failed to send approval card to user {user.telegram_id}: {e}")
                    
        if first_msg:
            # If no analyst got it, we still write it to the DB so it is in the queue
            await self.registry.create_approval_request(approval_request)

    async def send_threat_snapshot(self, incident: IncidentRecord) -> None:
        """Sends a text-based threat topology snapshot to Telegram operators."""
        snapshot = (
            f"📊 <b>THREAT SNAPSHOT</b>\n\n"
            f"<code>CustomerBot</code>\n"
            f"      ↓\n"
            f"<code>{incident.agent_id}</code>\n"
            f"      ↓\n"
            f"<code>{incident.event.target}</code>\n\n"
            f"❌ <b>STATUS: {incident.action_taken} BY VIGIL</b>\n"
            f"🛡 <b>ArmorIQ: {incident.policy_decision.value}</b>"
        )
        await self.broadcast_to_role(snapshot, TelegramRole.OBSERVER)

    async def escalate_incident(self, incident: IncidentRecord) -> None:
        """Urgent escalation flow for CRITICAL threats."""
        msg = (
            f"⚠️ <b>URGENT ESCALATION: CRITICAL THREAT DETECTED</b> ⚠️\n\n"
            f"<b>Agent:</b> <code>{incident.agent_id}</code>\n"
            f"<b>Threat Type:</b> <code>{incident.threat_type.value}</code>\n"
            f"<b>Threat Score:</b> <code>{incident.detection_result.score:.2f}</code>\n"
            f"<b>Action Awaiting Confirmation:</b> <code>{incident.action_taken}</code>\n\n"
            f"Immediate operator intervention recommended. Please review the pending approval card."
        )
        await self.broadcast_to_role(msg, TelegramRole.ADMIN)
