"""
PlexiChat Configuration System
==============================

Centralized configuration management using YAML.
"""

import os
import yaml
from typing import Dict, Any
from pathlib import Path
from pydantic import BaseModel, Field

# Define configuration models
class DatabaseConfig(BaseModel):
    path: str = "data/plexichat.db"
    pool_size: int = 20
    timeout: float = 30.0

class SecurityConfig(BaseModel):
    secret_key: str = "CHANGE_ME_IN_PROD"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    enable_mfa: bool = True

class LoggingConfig(BaseModel):
    file_path: str = "logs/plexichat.log"
    max_bytes: int = 10485760
    backup_count: int = 5
    json_format: bool = False

class AIConfig(BaseModel):
    enabled: bool = True
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: str = ""

class NetworkConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = ["*"]
    ssl_enabled: bool = False

class SystemConfig(BaseModel):
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"
    app_name: str = "PlexiChat"
    version: str = "a.1.1-100"

class Config(BaseModel):
    system: SystemConfig = Field(default_factory=SystemConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

_config_instance = None

def load_config(config_path: str = "config.yaml") -> Config:
    """Load configuration from a YAML file."""
    global _config_instance
    
    path = Path(config_path)
    if not path.exists():
        # Return default config if file doesn't exist
        _config_instance = Config()
        return _config_instance

    with open(path, "r") as f:
        config_data = yaml.safe_load(f) or {}

    _config_instance = Config(**config_data)
    return _config_instance

def get_config() -> Config:
    """Get the loaded configuration instance."""
    global _config_instance
    if _config_instance is None:
        return load_config()
    return _config_instance

# Global config instance
config = get_config()
