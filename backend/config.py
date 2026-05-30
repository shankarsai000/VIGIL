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
    vigil_db_path: str = Field(default="vigil.db", description="Path to SQLite database")
    
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
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }
    
    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]


settings = VigilSettings()
