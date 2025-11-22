"""
PlexiChat Configuration System
==============================

Centralized configuration management using Pydantic.
Supports loading from environment variables and .env files.
"""

import os
from functools import lru_cache
from typing import Optional, List, Dict, Any
from pydantic import Field, BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

class DatabaseConfig(BaseModel):
    """Database configuration."""
    path: str = Field(default="data/plexichat.db", description="Path to SQLite database")
    pool_size: int = Field(default=20, description="Connection pool size")
    timeout: float = Field(default=30.0, description="Connection timeout in seconds")

class SecurityConfig(BaseModel):
    """Security configuration."""
    secret_key: str = Field(default="CHANGE_ME_IN_PROD", description="Secret key for JWT signing")
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30, description="Token expiration time")
    enable_mfa: bool = Field(default=True, description="Enable Multi-Factor Authentication")

class AIConfig(BaseModel):
    """AI/LLM configuration."""
    enabled: bool = Field(default=True, description="Enable AI features")
    provider: str = Field(default="openai", description="Default AI provider")
    api_key: Optional[str] = Field(default=None, description="API Key for AI provider")
    model: str = Field(default="gpt-4", description="Default model to use")

class NetworkConfig(BaseModel):
    """Network and API configuration."""
    host: str = Field(default="0.0.0.0", description="Host to bind to")
    port: int = Field(default=8000, description="Port to bind to")
    cors_origins: List[str] = Field(default=["*"], description="Allowed CORS origins")
    ssl_enabled: bool = Field(default=False, description="Enable SSL/TLS")

class SystemConfig(BaseModel):
    """General system configuration."""
    environment: str = Field(default="development", description="Environment (development, production)")
    debug: bool = Field(default=True, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    app_name: str = Field(default="PlexiChat", description="Application name")
    version: str = Field(default="2.0.0", description="Application version")

class Settings(BaseSettings):
    """
    Global Application Settings.
    Hierarchical configuration for all system components.
    """
    system: SystemConfig = Field(default_factory=SystemConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

    # Allow loading from .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore"
    )
    
    # Flattened accessors for backward compatibility or convenience
    @property
    def app_name(self) -> str:
        return self.system.app_name
        
    @property
    def version(self) -> str:
        return self.system.version

@lru_cache()
def get_config() -> Settings:
    """
    Get the cached configuration instance.
    """
    return Settings()
