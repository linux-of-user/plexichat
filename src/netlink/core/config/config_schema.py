"""
NetLink Configuration Schema Definitions

Dataclass-based configuration schemas with validation and type safety.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

@dataclass
class ServerConfig:
    """Server configuration schema."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    debug: bool = False
    auto_reload: bool = False
    access_log: bool = True
    ssl_enabled: bool = False
    ssl_cert_file: Optional[str] = None
    ssl_key_file: Optional[str] = None
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    max_request_size: int = 100 * 1024 * 1024  # 100MB
    timeout: int = 30
    keep_alive: int = 2

@dataclass
class DatabaseConfig:
    """Database configuration schema."""
    type: str = "sqlite"
    url: Optional[str] = None
    host: str = "localhost"
    port: int = 5432
    name: str = "netlink"
    username: Optional[str] = None
    password: Optional[str] = None
    pool_size: int = 10
    pool_timeout: int = 30
    echo: bool = False
    backup_enabled: bool = True
    backup_interval: int = 3600
    encryption_enabled: bool = True
    ssl_mode: str = "prefer"
    connection_timeout: int = 30
    query_timeout: int = 60

@dataclass
class SecurityConfig:
    """Security configuration schema."""
    secret_key: Optional[str] = None
    jwt_algorithm: str = "RS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_symbols: bool = True
    max_login_attempts: int = 5
    lockout_duration: int = 300
    mfa_enabled: bool = True
    mfa_methods: List[str] = field(default_factory=lambda: ["totp", "sms", "email"])
    biometric_enabled: bool = False
    rate_limiting: bool = True
    rate_limit_requests: int = 1000
    rate_limit_window: int = 60
    encryption_algorithm: str = "AES-256-GCM"
    hash_algorithm: str = "SHA-512"
    session_timeout: int = 3600
    csrf_protection: bool = True

@dataclass
class BackupConfig:
    """Backup configuration schema."""
    enabled: bool = True
    directory: str = "backups"
    encryption_enabled: bool = True
    compression_enabled: bool = True
    compression_algorithm: str = "zstd"
    distributed_enabled: bool = True
    shard_size_mb: int = 10
    redundancy_level: int = 2
    retention_days: int = 30
    auto_backup_interval: int = 3600
    backup_types: List[str] = field(default_factory=lambda: ["database", "files", "config"])
    verification_enabled: bool = True
    quantum_encryption: bool = True
    max_backup_size_gb: int = 100
    cleanup_threshold: float = 0.85

@dataclass
class ClusterConfig:
    """Cluster configuration schema."""
    enabled: bool = False
    node_id: Optional[str] = None
    node_name: Optional[str] = None
    discovery_method: str = "static"
    nodes: List[str] = field(default_factory=list)
    heartbeat_interval: int = 30
    election_timeout: int = 5000
    sync_interval: int = 300
    encryption_enabled: bool = True
    load_balancing: bool = True
    failover_enabled: bool = True
    consensus_algorithm: str = "raft"

@dataclass
class LoggingConfig:
    """Logging configuration schema."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "logs/netlink.log"
    max_size: str = "10MB"
    backup_count: int = 5
    console_enabled: bool = True
    file_enabled: bool = True
    structured_logging: bool = True
    log_requests: bool = False
    log_responses: bool = False
    log_sql: bool = False
    log_performance: bool = True
    log_security: bool = True

@dataclass
class AIConfig:
    """AI configuration schema."""
    enabled: bool = False
    providers: List[str] = field(default_factory=list)
    default_provider: Optional[str] = None
    api_keys: Dict[str, str] = field(default_factory=dict)
    models: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    max_retries: int = 3
    features: Dict[str, bool] = field(default_factory=lambda: {
        "chat_completion": False,
        "content_moderation": False,
        "translation": False,
        "summarization": False,
        "sentiment_analysis": False
    })
    rate_limits: Dict[str, int] = field(default_factory=dict)
    fallback_enabled: bool = True

@dataclass
class MonitoringConfig:
    """Monitoring configuration schema."""
    enabled: bool = True
    metrics_enabled: bool = True
    health_checks_enabled: bool = True
    performance_monitoring: bool = True
    error_tracking: bool = True
    log_aggregation: bool = True
    alerting_enabled: bool = False
    alert_channels: List[str] = field(default_factory=list)
    metrics_retention_days: int = 30
    health_check_interval: int = 30

@dataclass
class FeaturesConfig:
    """Features configuration schema."""
    backup_system: bool = True
    clustering: bool = False
    ai_integration: bool = False
    web_ui: bool = True
    api_docs: bool = True
    metrics: bool = True
    health_checks: bool = True
    file_sharing: bool = True
    voice_calling: bool = False
    video_calling: bool = False
    screen_sharing: bool = False
    real_time_collaboration: bool = False
    plugin_system: bool = False
    themes: bool = True

@dataclass
class LimitsConfig:
    """Limits configuration schema."""
    max_message_length: int = 10000
    max_file_size_mb: int = 100
    max_users: int = 10000
    rate_limit_per_minute: int = 1000
    max_concurrent_connections: int = 1000
    max_upload_size_mb: int = 500
    max_backup_size_gb: int = 100
    max_session_duration: int = 86400  # 24 hours
    max_api_requests_per_hour: int = 10000
    max_storage_per_user_gb: int = 10

@dataclass
class ApplicationConfig:
    """Application configuration schema."""
    name: str = "NetLink"
    version: str = "3.0.0"
    description: str = "Government-Level Secure Communication Platform"
    debug: bool = False
    environment: str = "production"
    timezone: str = "UTC"
    language: str = "en"
    theme: str = "default"
    maintenance_mode: bool = False

@dataclass
class NetLinkConfig:
    """Main NetLink configuration schema."""
    version: str = "3.0.0"
    environment: str = "development"
    
    # Core configuration sections
    application: ApplicationConfig = field(default_factory=ApplicationConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    features: FeaturesConfig = field(default_factory=FeaturesConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    
    # Additional settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and setup."""
        # Adjust settings based on environment
        if self.environment == "development":
            self.application.debug = True
            self.server.debug = True
            self.server.auto_reload = True
            self.database.echo = True
            self.logging.level = "DEBUG"
            self.logging.log_requests = True
            self.security.cors_origins = ["*"]
        elif self.environment == "production":
            self.application.debug = False
            self.server.debug = False
            self.server.auto_reload = False
            self.database.echo = False
            self.logging.level = "INFO"
            self.logging.log_requests = False
            self.security.cors_origins = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        from dataclasses import asdict
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetLinkConfig':
        """Create configuration from dictionary."""
        # Extract nested configurations
        config_data = {}
        
        for field_name, field_type in cls.__annotations__.items():
            if field_name in data:
                if hasattr(field_type, '__origin__') and field_type.__origin__ is Union:
                    # Handle Optional types
                    config_data[field_name] = data[field_name]
                elif hasattr(field_type, '__dataclass_fields__'):
                    # Handle dataclass fields
                    if isinstance(data[field_name], dict):
                        config_data[field_name] = field_type(**data[field_name])
                    else:
                        config_data[field_name] = data[field_name]
                else:
                    config_data[field_name] = data[field_name]
        
        return cls(**config_data)
    
    def validate(self) -> List[str]:
        """Validate configuration and return any issues."""
        issues = []
        
        # Validate server configuration
        if not (1 <= self.server.port <= 65535):
            issues.append(f"Invalid server port: {self.server.port}")
        
        # Validate database configuration
        if self.database.type not in ["sqlite", "postgresql", "mysql", "mariadb"]:
            issues.append(f"Unsupported database type: {self.database.type}")
        
        # Validate security configuration
        if not self.security.secret_key:
            issues.append("Security secret key is required")
        
        if self.security.password_min_length < 8:
            issues.append("Password minimum length must be at least 8 characters")
        
        # Validate backup configuration
        if self.backup.enabled and self.backup.shard_size_mb <= 0:
            issues.append("Backup shard size must be positive")
        
        # Validate logging configuration
        if self.logging.level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            issues.append(f"Invalid logging level: {self.logging.level}")
        
        return issues
    
    def get_database_url(self) -> str:
        """Get complete database URL."""
        if self.database.url:
            return self.database.url
        
        if self.database.type == "sqlite":
            return f"sqlite:///./data/{self.database.name}.db"
        elif self.database.type == "postgresql":
            auth = ""
            if self.database.username:
                auth = f"{self.database.username}"
                if self.database.password:
                    auth += f":{self.database.password}"
                auth += "@"
            return f"postgresql://{auth}{self.database.host}:{self.database.port}/{self.database.name}"
        elif self.database.type in ["mysql", "mariadb"]:
            auth = ""
            if self.database.username:
                auth = f"{self.database.username}"
                if self.database.password:
                    auth += f":{self.database.password}"
                auth += "@"
            return f"mysql://{auth}{self.database.host}:{self.database.port}/{self.database.name}"
        else:
            raise ValueError(f"Unsupported database type: {self.database.type}")
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.environment == "testing"
