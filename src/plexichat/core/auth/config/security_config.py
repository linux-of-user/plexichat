"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Security Configuration Module
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityLevel(Enum):
    """Security levels for different operations."""

    BASIC = "basic"
    STANDARD = "standard"
    HIGH = "high"
    CRITICAL = "critical"


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""

    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"


@dataclass
class SecurityConfig:
    """
    Advanced security configuration for authentication system.

    Features:
    - Multi-level security policies
    - Encryption algorithm selection
    - Key rotation policies
    - Security monitoring thresholds
    - Threat detection settings
    """

    # Security Level Configuration
    default_security_level: SecurityLevel = SecurityLevel.STANDARD
    operation_security_levels: Dict[str, SecurityLevel] = field(default_factory=dict)

    # Encryption Configuration
    encryption_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
    key_rotation_days: int = 90
    master_key_length: int = 32

    # MFA Configuration
    mfa_required_for_level: SecurityLevel = SecurityLevel.HIGH
    mfa_grace_period_minutes: int = 5
    mfa_max_attempts: int = 3

    # Session Security
    session_timeout_minutes: int = 60
    elevated_session_timeout_minutes: int = 15
    max_concurrent_sessions: int = 5
    session_inactivity_timeout_minutes: int = 30

    # Brute Force Protection
    brute_force_max_attempts: int = 5
    brute_force_lockout_minutes: int = 30
    brute_force_ip_whitelist: List[str] = field(default_factory=list)

    # Risk Assessment
    risk_score_threshold: float = 70.0
    suspicious_ip_threshold: int = 10
    unusual_location_threshold: float = 50.0

    # Audit Configuration
    audit_log_retention_days: int = 365
    security_event_retention_days: int = 90
    audit_all_operations: bool = True

    # Monitoring Configuration
    monitoring_enabled: bool = True
    alert_on_failed_attempts: bool = True
    alert_threshold_per_hour: int = 10

    # Advanced Security Features
    zero_trust_enabled: bool = True
    continuous_auth_enabled: bool = False
    behavioral_analysis_enabled: bool = False

    def __post_init__(self):
        """Initialize default operation security levels."""
        if not self.operation_security_levels:
            self.operation_security_levels = {
                "login": SecurityLevel.STANDARD,
                "password_change": SecurityLevel.HIGH,
                "role_assignment": SecurityLevel.CRITICAL,
                "system_config": SecurityLevel.CRITICAL,
                "user_deletion": SecurityLevel.CRITICAL,
                "api_access": SecurityLevel.BASIC,
                "file_upload": SecurityLevel.STANDARD,
            }

    @classmethod
    def from_env(cls) -> "SecurityConfig":
        """Create configuration from environment variables."""
        config = cls()

        # Security Level
        if level := os.getenv("AUTH_SECURITY_LEVEL"):
            try:
                config.default_security_level = SecurityLevel(level.lower())
            except ValueError:
                pass

        # Encryption
        if algo := os.getenv("AUTH_ENCRYPTION_ALGORITHM"):
            try:
                config.encryption_algorithm = EncryptionAlgorithm(algo.lower())
            except ValueError:
                pass

        # MFA Settings
        if mfa_level := os.getenv("AUTH_MFA_REQUIRED_LEVEL"):
            try:
                config.mfa_required_for_level = SecurityLevel(mfa_level.lower())
            except ValueError:
                pass

        # Session Settings
        if timeout := os.getenv("AUTH_SESSION_TIMEOUT_MINUTES"):
            try:
                config.session_timeout_minutes = int(timeout)
            except ValueError:
                pass

        # Risk Assessment
        if threshold := os.getenv("AUTH_RISK_THRESHOLD"):
            try:
                config.risk_score_threshold = float(threshold)
            except ValueError:
                pass

        return config

    def get_operation_security_level(self, operation: str) -> SecurityLevel:
        """Get security level for a specific operation."""
        return self.operation_security_levels.get(
            operation, self.default_security_level
        )

    def requires_mfa(self, operation: str) -> bool:
        """Check if MFA is required for an operation."""
        op_level = self.get_operation_security_level(operation)
        return op_level.value >= self.mfa_required_for_level.value

    def get_session_timeout(self, elevated: bool = False) -> int:
        """Get session timeout in minutes."""
        if elevated:
            return self.elevated_session_timeout_minutes
        return self.session_timeout_minutes

    def is_ip_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is in whitelist."""
        return ip_address in self.brute_force_ip_whitelist

    def should_alert_on_failures(self, failure_count: int) -> bool:
        """Check if we should alert on authentication failures."""
        return (
            self.alert_on_failed_attempts
            and failure_count >= self.alert_threshold_per_hour
        )


@dataclass
class ThreatDetectionConfig:
    """Configuration for threat detection and response."""

    # Anomaly Detection
    enable_anomaly_detection: bool = True
    anomaly_threshold: float = 0.8
    learning_period_days: int = 7

    # Geolocation Analysis
    enable_geolocation_check: bool = True
    allowed_countries: List[str] = field(
        default_factory=lambda: ["US", "GB", "DE", "FR", "CA"]
    )
    suspicious_country_penalty: float = 20.0

    # Device Fingerprinting
    enable_device_fingerprinting: bool = True
    device_trust_threshold: float = 0.7
    new_device_penalty: float = 25.0

    # Behavioral Analysis
    enable_behavioral_analysis: bool = False
    behavioral_model_path: Optional[str] = None
    behavioral_threshold: float = 0.6

    # Automated Response
    auto_block_suspicious: bool = False
    auto_block_threshold: float = 90.0
    auto_mfa_trigger_threshold: float = 75.0

    def __post_init__(self):
        """Initialize default values."""
        if not self.allowed_countries:
            self.allowed_countries = ["US", "GB", "DE", "FR", "CA"]


# Global instances
_security_config: Optional[SecurityConfig] = None
_threat_config: Optional[ThreatDetectionConfig] = None


def get_security_config() -> SecurityConfig:
    """Get the global security configuration."""
    global _security_config
    if _security_config is None:
        _security_config = SecurityConfig.from_env()
    return _security_config


def get_threat_detection_config() -> ThreatDetectionConfig:
    """Get the global threat detection configuration."""
    global _threat_config
    if _threat_config is None:
        _threat_config = ThreatDetectionConfig()
    return _threat_config


__all__ = [
    "SecurityConfig",
    "SecurityLevel",
    "EncryptionAlgorithm",
    "ThreatDetectionConfig",
    "get_security_config",
    "get_threat_detection_config",
]
