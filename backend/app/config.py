"""VIGIL configuration module.

Centralizes all configuration via Pydantic Settings, loading values from
environment variables and .env files. Every tunable parameter in VIGIL
is defined here with sensible defaults.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class VigilSettings(BaseSettings):
    # ArmorIQ (SDK-based containment governance; see ENHANCEMENTS.md)
    # live: containment is authorized by ArmorIQ. disabled (default): quarantine is escalated to a human and
    # nothing is executed. local-demo: labelled deterministic thresholds, NOT ArmorIQ, not valid for submission.
    armoriq_mode: str = Field(default="disabled", description="live | disabled | local-demo")
    submission_mode: bool = Field(default=False, description="Enforce strict submission compliance (requires ARMORIQ_MODE=live)")
    armoriq_api_key: str = Field(default="", description="ArmorIQ API key (required for live mode)")
    armoriq_user_email: str = Field(default="", description="Principal the ArmorIQ SDK acts for (live mode)")
    armoriq_agent_id: str = Field(default="vigil-containment", description="ArmorIQ identity used by VIGIL")
    armoriq_containment_mcp_id: str = Field(default="vigil-containment", description="MCP server that carries out containment")
    armoriq_use_production: bool = Field(default=True, description="Use ArmorIQ production endpoints")
    armoriq_token_validity_seconds: int = Field(default=300, description="Lifetime of the containment intent token")
    audit_ledger_path: str = Field(default="backend/storage/audit_ledger.jsonl", description="Hash-chained audit ledger file")
    # Empty secrets make the protected routes refuse to run (fail closed).
    operator_api_key: str = Field(default="", description="Key for write endpoints and the WebSocket")
    containment_secret: str = Field(default="", description="Shared secret between the containment MCP server and VIGIL")
    vigil_internal_url: str = Field(default="http://127.0.0.1:8000", description="Where the containment MCP reaches VIGIL")
    
    # Anthropic
    anthropic_api_key: str = Field(default="", description="Anthropic API key for Claude explainer")
    
    # Database
    database_url: str = Field(
        default="postgresql://postgres:vigil_secure_password@postgres:5432/vigil_db",
        description="PostgreSQL connection string",
    )
    vigil_db_path: str = Field(default="vigil.db", description="Path to SQLite database (legacy)")

    # Redis
    redis_host: str = Field(default="redis", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_db: int = Field(default=0, description="Redis database index")
    redis_password: str = Field(default="", description="Redis password")
    
    # Logging
    vigil_log_level: str = Field(default="INFO", description="Logging level")
    
    # CORS
    cors_origins: str = Field(default="http://localhost:5173", description="Comma-separated CORS origins")
    
    # Detection thresholds
    ewma_alpha: float = Field(default=0.1, description="EWMA smoothing factor")
    ewma_cold_start_threshold: int = Field(default=50, description="Events before EWMA activates")
    iforest_min_events: int = Field(default=100, description="Events before IsolationForest activates")
    iforest_retrain_interval: int = Field(default=100, description="Events between IForest retraining")
    
    # Detection weights
    weight_rule: float = Field(default=0.60, description="Weight for rule engine layer")
    weight_ewma: float = Field(default=0.25, description="Weight for EWMA baseline layer")
    weight_iforest: float = Field(default=0.15, description="Weight for IsolationForest layer")
    
    # WebSocket
    ws_heartbeat_interval: int = Field(default=30, description="WebSocket heartbeat interval in seconds")
    
    # Telegram Governed Runtime (Legacy / Notification only)
    telegram_bot_token: str = Field(default="", description="Telegram Bot API token from BotFather")
    telegram_admin_ids: str = Field(default="", description="Comma-separated authorized Telegram admin user IDs")
    telegram_webhook_url: str = Field(default="", description="Webhook URL for production Telegram mode")
    telegram_polling_mode: bool = Field(default=True, description="Use polling (True) or webhook (False) for Telegram")
    telegram_sleep_mode: bool = Field(default=False, description="Overnight autonomous protection mode toggle")

    # Slack Governed Approvals (Phase SLACK-1)
    slack_bot_token: str = Field(default="", description="Slack Bot User OAuth Token (xoxb-...)")
    slack_signing_secret: str = Field(default="", description="Slack App Signing Secret")
    slack_app_token: str = Field(default="", description="Slack App-Level Token for Socket Mode (xapp-...)")
    slack_approval_channel: str = Field(default="", description="Slack channel ID for governance approvals")
    slack_allowed_email_domains: str = Field(default="corp.internal,example.com", description="Comma-separated allowed approver email domains")
    slack_mode: str = Field(default="http", description="http | socket")

    @property
    def slack_allowed_email_domain_list(self) -> list[str]:
        if not self.slack_allowed_email_domains:
            return []
        return [d.strip().lower() for d in self.slack_allowed_email_domains.split(",") if d.strip()]
    
    @property
    def telegram_admin_id_list(self) -> list[int]:
        if not self.telegram_admin_ids:
            return []
        return [int(uid.strip()) for uid in self.telegram_admin_ids.split(",") if uid.strip()]
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }
    
    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]


settings = VigilSettings()
