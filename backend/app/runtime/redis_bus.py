"""Redis event bus for cross-service telemetry fanout."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from redis.asyncio import Redis

from .models import WSEvent, WSEventType

logger = logging.getLogger("vigil.redis_bus")


class RedisEventBus:
    """Publishes VIGIL events to Redis channels for distributed fanout."""

    def __init__(self, host: str, port: int, db: int = 0, password: str = ""):
        self.host = host
        self.port = port
        self.db = db
        self.password = password or None
        self.client: Optional[Redis] = None
        self.is_connected = False

    async def connect(self) -> None:
        try:
            # Create client, then ping
            self.client = Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
            )
            # Wait for ping with timeout
            await asyncio.wait_for(self.client.ping(), timeout=1.0)
            self.is_connected = True
            logger.info("Redis event bus connected.")
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}, using mock mode.")
            self.client = None
            self.is_connected = False

    async def close(self) -> None:
        if self.client:
            await self.client.close()
            self.client = None
        self.is_connected = False

    def _channel_for_event(self, event_type: WSEventType) -> str:
        mapping = {
            WSEventType.INCIDENT_DETECTED: "incident_stream",
            WSEventType.GOVERNANCE_UPDATE: "governance_stream",
            WSEventType.ATTACK_GRAPH_UPDATE: "graph_updates",
            WSEventType.REMEDIATION_CHAIN_UPDATE: "replay_updates",
            WSEventType.TELEGRAM_STATUS: "telegram_events",
        }
        return mapping.get(event_type, "telemetry_stream")

    async def publish_event(self, event: WSEvent) -> None:
        if not self.is_connected or not self.client:
            return
        try:
            channel = self._channel_for_event(event.type)
            payload = json.dumps(event.model_dump())
            await asyncio.wait_for(
                self.client.publish(channel, payload),
                timeout=0.5
            )
        except Exception as e:
            logger.warning(f"Failed to publish event to Redis: {e}")
