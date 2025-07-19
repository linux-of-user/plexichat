# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# Commented out invalid import: from ...security import (  # Import core security components from main security module)
from typing import Optional


# Replace invalid decimal literal like 2FA/MFA, with a valid string: "2FA/MFA",
# SSL/TLS,
# Advanced,
# Architecture,
# BehavioralAnalyzer,
# Comprehensive,
# Consolidates,
# Core,
# DatabaseEncryption,
# DataClassification,
# DDoS,
# Distributed,
# DistributedKeyManager,
# DistributedSecurityMonitor,
# Encrypt,
# EndpointType,
# EndToEndEncryption,
# EnhancedDDoSProtection,
# Features:,
# Input,
# InputSanitizer,
# KeyDomain,
# Let's,
# MonitoringScope,
# OAuth2/OIDC,
# OAuthProvider,
# Penetration,
# PenetrationTestingSystem,
# PlexiChat,
# Quantum-proof,
# QuantumEncryptionSystem,
# Rate,
# RateLimiter,
# Security,
# SecurityEvent,
# SecurityEventType,
# SecurityManager,
# SecurityMetrics,
# SecurityMonitor,
# SSLCertificateManager,
# System,
# This,
# ThreatLevel,
# ThreatPattern,
# Unified,
# VulnerabilityScanner,
# Zero-knowledge,
# """,
# -,
# .behavioral_analysis,
# .ddos_protection,
# .input_sanitization,
# .oauth_provider,
# .penetration_testing,
# .rate_limiting,
# .security_monitoring,
# .ssl_certificate_manager,
# .vulnerability_scanner,
# a,
# abuse,
# alerting,
# all,
# analysis,
# and,
# architecture,
# architecture.,
# assessment,
# authentication,
# authorization,
# behavioral,
# behavioral_analyzer,
# certificate,
# components,
# comprehensive,
# consolidates:,
# cryptography,
# database_encryption,
# ddos_protection,
# distributed_key_manager,
# e2e_encryption,
# encryption,
# from,
# government-level,
# import,
# injection,
# input_sanitizer,
# into,
# limiting,
# management,
# module,
# monitoring,
# multi-key,
# oauth_provider,
# penetration_tester,
# post-quantum,
# prevention,
# protection,
# provider,
# quantum-proof,
# quantum_encryption,
# rate_limiter,
# replaces,
# sanitization,
# security,
# security_manager,
# security_monitor,
# single,
# src/plexichat/app/core/security/,
# src/plexichat/app/security/,
# src/plexichat/security/,
# ssl_manager,
# support,
# system,
# testing,
# unified,
# vulnerability,
# vulnerability_scanner,
# with,
# zero-knowledge,

# Import consolidated security modules
# Note: advanced_authentication.py removed - functionality consolidated into core_system/auth/
__version__ = "4.0.0"
__all__ = [
    # Core security management
    "SecurityManager",
    "security_manager",

    # Quantum encryption
    "QuantumEncryptionSystem",
    "quantum_encryption",

    # Key management
    "DistributedKeyManager",
    "distributed_key_manager",
    "KeyDomain",

    # End-to-end encryption
    "EndToEndEncryption",
    "e2e_encryption",
    "EndpointType",

    # Database encryption
    "DatabaseEncryption",
    "database_encryption",
    "DataClassification",

    # Security monitoring
    "DistributedSecurityMonitor",
    "SecurityEvent",
    "SecurityMetrics",
    "ThreatPattern",
    "ThreatLevel",
    "MonitoringScope",
    "SecurityEventType",
    "SecurityMonitor",
    "security_monitor_enhanced",

    # Advanced authentication
    "AdvancedAuthenticationSystem",
    "advanced_auth",

    # DDoS protection
    "EnhancedDDoSProtection",
    "ddos_protection",

    # Penetration testing
    "PenetrationTestingSystem",
    "penetration_tester",

    # SSL management
    "SSLCertificateManager",
    "ssl_manager",

    # OAuth provider
    "OAuthProvider",
    "oauth_provider",

    # Input sanitization
    "InputSanitizer",
    "input_sanitizer",

    # Rate limiting
    "RateLimiter",
    "rate_limiter",

    # Behavioral analysis
    "BehavioralAnalyzer",
    "behavioral_analyzer",

    # Vulnerability scanning
    "VulnerabilityScanner",
    "vulnerability_scanner"
]

# Security system constants
SECURITY_SYSTEM_VERSION = "4.0.0"
MINIMUM_SECURITY_LEVEL = "GOVERNMENT"
QUANTUM_ENCRYPTION_REQUIRED = True
ZERO_KNOWLEDGE_ENABLED = True
PENETRATION_TESTING_ENABLED = True
BEHAVIORAL_ANALYSIS_ENABLED = True

# Security levels
SECURITY_LEVELS = {
    'BASIC': 1,
    'ENHANCED': 2,
    'GOVERNMENT': 3,
    'MILITARY': 4,
    'QUANTUM_PROOF': 5,
    'ZERO_KNOWLEDGE': 6
}

# Default security level for new installations
DEFAULT_SECURITY_LEVEL = SECURITY_LEVELS['QUANTUM_PROOF']

# Security configuration
SECURITY_CONFIG = {
    "encryption": {
        "quantum_resistant": True,
        "minimum_key_size": 4096,
        "key_rotation_hours": 24,
        "perfect_forward_secrecy": True
    },
    "authentication": {
        "require_2fa": True,
        "biometric_support": True,
        "session_timeout_minutes": 30,
        "max_failed_attempts": 3
    },
    "ddos_protection": {
        "enabled": True,
        "rate_limit_requests_per_minute": 100,
        "behavioral_analysis": True,
        "auto_blacklist": True
    },
    "penetration_testing": {
        "enabled": True,
        "automated_scans": True,
        "vulnerability_reporting": True,
        "compliance_checks": True
    },
    "ssl_management": {
        "auto_renewal": True,
        "lets_encrypt_enabled": True,
        "minimum_tls_version": "1.3",
        "hsts_enabled": True
    },
    "monitoring": {
        "real_time_alerts": True,
        "threat_intelligence": True,
        "audit_logging": True,
        "compliance_reporting": True
    }
}
