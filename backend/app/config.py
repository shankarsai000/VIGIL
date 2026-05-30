"""VIGIL configuration module.

Centralizes all configuration via Pydantic Settings, loading values from
environment variables and .env files. Every tunable parameter in VIGIL
is defined here with sensible defaults.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class VigilSettings(BaseSettings):
    # ArmorIQ
    armoriq_api_key: str = Field(default="mock", description="ArmorIQ API key")
    armoriq_base_url: str = Field(default="https://api.armoriq.ai", description="ArmorIQ base URL")
    
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
    
    # Telegram Governed Runtime
    telegram_bot_token: str = Field(default="", description="Telegram Bot API token from BotFather")
    telegram_admin_ids: str = Field(default="", description="Comma-separated authorized Telegram admin user IDs")
    telegram_webhook_url: str = Field(default="", description="Webhook URL for production Telegram mode")
    telegram_polling_mode: bool = Field(default=True, description="Use polling (True) or webhook (False) for Telegram")
    telegram_sleep_mode: bool = Field(default=False, description="Overnight autonomous protection mode toggle")
    
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
