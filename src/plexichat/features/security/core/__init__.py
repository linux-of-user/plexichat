"""
PlexiChat Core Security System - Unified Security Architecture

Consolidates all security components into a single, comprehensive module
with government-level security, quantum-proof encryption, and zero-knowledge architecture.

This unified system replaces and consolidates:
- src/plexichat/security/
- src/plexichat/app/security/
- src/plexichat/app/core/security/

Features:
- Quantum-proof encryption with post-quantum cryptography
- Distributed multi-key security architecture
- Zero-knowledge authentication and authorization
- Advanced DDoS protection with behavioral analysis
- Penetration testing and vulnerability assessment
- SSL/TLS certificate management with Let's Encrypt
- OAuth2/OIDC provider with 2FA/MFA support
- Input sanitization and injection prevention
- Rate limiting and abuse prevention
- Comprehensive security monitoring and alerting
"""

# Import core security components from main security module
from ...security import (
    SecurityManager, security_manager,
    QuantumEncryptionSystem, quantum_encryption,
    DistributedKeyManager, distributed_key_manager, KeyDomain,
    EndToEndEncryption, e2e_encryption, EndpointType,
    DatabaseEncryption, database_encryption, DataClassification,
    DistributedSecurityMonitor, SecurityEvent, SecurityMetrics,
    ThreatPattern, ThreatLevel, MonitoringScope, SecurityEventType
)

# Import consolidated security modules
# Note: advanced_authentication.py removed - functionality consolidated into core_system/auth/
from .ddos_protection import EnhancedDDoSProtection, ddos_protection
from .penetration_testing import PenetrationTestingSystem, penetration_tester
from .ssl_certificate_manager import SSLCertificateManager, ssl_manager
from .oauth_provider import OAuthProvider, oauth_provider
from .input_sanitization import InputSanitizer, input_sanitizer
from .rate_limiting import RateLimiter, rate_limiter
from .behavioral_analysis import BehavioralAnalyzer, behavioral_analyzer
from .security_monitoring import SecurityMonitor, security_monitor
from .vulnerability_scanner import VulnerabilityScanner, vulnerability_scanner

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
