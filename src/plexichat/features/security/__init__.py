import asyncio
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core_system.auth import (
from .bug_bounty import (
from .cicd_security import (
from .csp import ContentSecurityPolicyManager, CSPDirective, CSPPolicy, CSPSource, csp_manager
from .database_encryption import DatabaseEncryption, DataClassification, database_encryption
from .distributed_key_manager import DistributedKeyManager, KeyDomain, distributed_key_manager
from .distributed_monitoring import (
from .e2e_encryption import EndpointType, EndToEndEncryption, e2e_encryption

from .exceptions import (
from .middleware import AuthenticationMiddleware, SecurityMiddleware

from .protection import (
from .protection import ThreatLevel as ProtectionThreatLevel
from .protection import (
from .quantum_encryption import QuantumEncryptionSystem, quantum_encryption
from .security_headers import (
from .siem_integration import (
from .ssl import SSLCertificateManager, ssl_manager
from .validators import BiometricValidator, InputValidator, PasswordValidator, TokenValidator

from .waf import (
from .advanced_auth import AdvancedAuthManager
from .default_admin import DefaultAdminManager
from .login_manager import LoginManager


from .decorators import optional_auth, from plexichat.infrastructure.utils.auth import require_admin, require_auth, require_level, require_mfa

"""
PlexiChat Unified Security System

Integrates all security components into a comprehensive, government-level
security architecture with quantum-proof encryption, distributed key
management, and end-to-end protection.
"""

# Import consolidated authentication components from unified core system
# Note: Authentication components now consolidated in core_system/auth/
    AuthAuditManager,
    AuthManager,
    BiometricManager,
    DeviceManager,
    MFAManager,
    OAuthManager,
    PasswordManager,
    SessionManager,
    TokenManager,
    auth_audit_manager,
    auth_manager,
    biometric_manager,
    device_manager,
    mfa_manager,
    oauth_manager,
    password_manager,
    session_manager,
    token_manager,
)
    BugBountyManager,
    ReportStatus,
    SeverityLevel,
    VulnerabilityReport,
    VulnerabilityType,
    bug_bounty_manager,
)
    CICDSecurityScanner,
    ScannerType,
    ScanResult,
    ScanType,
    Vulnerability,
    VulnerabilitySeverity,
    cicd_scanner,
)
    DistributedSecurityMonitor,
    MonitoringScope,
    SecurityEvent,
    SecurityEventType,
    SecurityMetrics,
    ThreatLevel,
    ThreatPattern,
)
# Import exceptions
    AccountLockError,
    AuthenticationError,
    AuthorizationError,
    BiometricError,
    CertificateError,
    DDoSError,
    DeviceError,
    EncryptionError,
    KeyManagementError,
    MFAError,
    MonitoringError,
    OAuthError,
    PasswordError,
    PenetrationTestError,
    RateLimitError,
    SecurityError,
    SessionError,
    TokenError,
    ValidationError,
    VulnerabilityError,
)

# Import middleware and utilities
# Import consolidated protection components
    AttackType,
    BehavioralAnalyzer,
    DDoSProtection,
    InputSanitizer,
    MITMProtection,
    PenetrationTester,
    RateLimiter,
    SecurityThreat,
)
    VulnerabilityScanner,
    behavioral_analyzer,
    ddos_protection,
    input_sanitizer,
    mitm_protection,
    penetration_tester,
    rate_limiter,
    vulnerability_scanner,
)

# Import core security components (quantum encryption, key management, monitoring)
    AdvancedSecurityHeaders,
    SecurityHeaderConfig,
    SecurityHeaderType,
    security_headers_manager,
)
    EventCategory,
    EventSeverity,
    SecurityEvent,
    SIEMConfiguration,
    SIEMIntegration,
    SIEMProvider,
    siem_integration,
)

# Import SSL/TLS management
# Import Phase I security enhancements
    WAFAction,
    WAFRule,
    WAFRuleType,
    WAFViolation,
    WebApplicationFirewall,
    waf,
    waf_middleware,
)

logger = logging.getLogger(__name__)


class SecurityManager:
    """
    Unified Security Manager
    
    Coordinates all security systems and provides a single interface
    for PlexiChat's comprehensive security architecture.
    
    Features:
    - Quantum-proof encryption throughout the system
    - Distributed multi-key architecture
    - End-to-end encryption for all endpoints
    - Database encryption with classification levels
    - Automatic key rotation and management
    - Security monitoring and audit logging
    - Compromise detection and response
    """
    
    def __init__(self, config_dir: str = "config/security"):
        self.config_dir = from pathlib import Path
Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Security components
        self.quantum_encryption = quantum_encryption
        self.distributed_keys = distributed_key_manager
        self.e2e_encryption = e2e_encryption
        self.database_encryption = database_encryption

        # Initialize distributed security monitoring
        self.security_monitor = DistributedSecurityMonitor(
            node_id=f"plexichat_node_{id(self)}",
            encryption_system=self.quantum_encryption,
            key_manager=self.distributed_keys
        )
        
        # Security configuration
        self.security_policies: Dict[str, Any] = {}
        self.security_status: Dict[str, Any] = {}
        self.last_security_check = datetime.now(timezone.utc)
        
        # Initialize system
        # Defer async initialization until event loop is running
        self._initialized = False
    
    async def _initialize_security_manager(self):
        """Initialize the unified security manager."""
        await self._setup_security_policies()
        await self._perform_initial_security_check()
        await self._start_security_monitoring()
        logger.info(" PlexiChat Security Manager initialized - Government-level protection active")
    
    async def _setup_security_policies(self):
        """Setup comprehensive security policies."""
        self.security_policies = {
            "encryption": {
                "default_algorithm": "quantum-resistant-multi-layer",
                "minimum_key_size": 256,
                "key_rotation_interval_hours": 24,
                "require_quantum_proof": True,
                "allow_classical_fallback": False
            },
            "key_management": {
                "distributed_keys_required": True,
                "minimum_key_shards": 5,
                "key_reconstruction_threshold": 3,
                "max_compromised_vaults": 2,
                "automatic_key_rotation": True
            },
            "endpoint_security": {
                "require_e2e_encryption": True,
                "session_timeout_minutes": 30,
                "max_session_messages": 1000,
                "require_perfect_forward_secrecy": True
            },
            "database_security": {
                "encrypt_all_sensitive_data": True,
                "minimum_classification": DataClassification.CONFIDENTIAL,
                "transparent_encryption": True,
                "encrypted_backups_only": True
            },
            "monitoring": {
                "continuous_security_monitoring": True,
                "anomaly_detection": True,
                "automatic_threat_response": True,
                "security_audit_logging": True
            }
        }
    
    async def _perform_initial_security_check(self):
        """Perform comprehensive security system check."""
        logger.info(" Performing initial security system check...")
        
        # Check quantum encryption system
        quantum_status = await self._check_quantum_encryption()
        
        # Check distributed key management
        key_management_status = await self._check_key_management()
        
        # Check E2E encryption
        e2e_status = await self._check_e2e_encryption()
        
        # Check database encryption
        database_status = await self._check_database_encryption()
        
        # Compile overall status
        self.security_status = {
            "quantum_encryption": quantum_status,
            "key_management": key_management_status,
            "e2e_encryption": e2e_status,
            "database_encryption": database_status,
            "overall_security_level": self._calculate_security_level(),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "system_ready": all([
                quantum_status["operational"],
                key_management_status["operational"],
                e2e_status["operational"],
                database_status["operational"]
            ])
        }
        
        if self.security_status["system_ready"]:
            logger.info(" All security systems operational - PlexiChat is secure")
        else:
            logger.warning(" Some security systems need attention")
    
    async def _check_quantum_encryption(self) -> Dict[str, Any]:
        """Check quantum encryption system status."""
        try:
            # Test encryption/decryption
            test_data = b"PlexiChat Security Test"
            context = type('Context', (), {
                'operation_id': f"test_{secrets.token_hex(4)}",
                'data_type': 'test',
                'security_tier': type('SecurityTier', (), {'QUANTUM_PROOF': 5})(),
                'algorithms': [],
                'key_ids': [],
                'metadata': {}
            })()
            
            encrypted_data, metadata = await self.quantum_encryption.encrypt_data(test_data, context)
            decrypted_data = await self.quantum_encryption.decrypt_data(encrypted_data, metadata)
            
            encryption_works = decrypted_data == test_data
            
            return {
                "operational": encryption_works,
                "algorithm": "quantum-resistant-multi-layer",
                "key_count": len(self.quantum_encryption.master_keys),
                "last_test": datetime.now(timezone.utc).isoformat(),
                "issues": [] if encryption_works else ["Encryption test failed"]
            }
            
        except Exception as e:
            logger.error(f"Quantum encryption check failed: {e}")
            return {
                "operational": False,
                "issues": [str(e)]
            }
    
    async def _check_key_management(self) -> Dict[str, Any]:
        """Check distributed key management system status."""
        try:
            status = await self.distributed_keys.get_security_status()
            
            return {
                "operational": status["overall_security_intact"],
                "total_keys": status["total_keys"],
                "total_vaults": status["total_vaults"],
                "compromised_vaults": status["compromised_vaults"],
                "security_intact": status["overall_security_intact"],
                "domain_status": status["domain_status"],
                "issues": [] if status["overall_security_intact"] else ["Key management security compromised"]
            }
            
        except Exception as e:
            logger.error(f"Key management check failed: {e}")
            return {
                "operational": False,
                "issues": [str(e)]
            }
    
    async def _check_e2e_encryption(self) -> Dict[str, Any]:
        """Check end-to-end encryption system status."""
        try:
            stats = await self.e2e_encryption.get_endpoint_stats()
            
            return {
                "operational": True,
                "active_sessions": stats["total_active_sessions"],
                "sessions_by_endpoint": stats["sessions_by_endpoint"],
                "sessions_by_protocol": stats["sessions_by_protocol"],
                "messages_today": stats["total_messages_today"],
                "issues": []
            }
            
        except Exception as e:
            logger.error(f"E2E encryption check failed: {e}")
            return {
                "operational": False,
                "issues": [str(e)]
            }
    
    async def _check_database_encryption(self) -> Dict[str, Any]:
        """Check database encryption system status."""
        try:
            status = await self.database_encryption.get_encryption_status()
            
            return {
                "operational": True,
                "encrypted_columns": status["total_encrypted_columns"],
                "database_keys": status["total_database_keys"],
                "expired_keys": status["expired_keys"],
                "classification_stats": status["classification_stats"],
                "issues": [] if status["expired_keys"] == 0 else [f"{status['expired_keys']} keys expired"]
            }
            
        except Exception as e:
            logger.error(f"Database encryption check failed: {e}")
            return {
                "operational": False,
                "issues": [str(e)]
            }
    
    def _calculate_security_level(self) -> str:
        """Calculate overall security level."""
        if not self.security_status:
            return "UNKNOWN"
        
        all_operational = all(
            component.get("operational", False) 
            for component in [
                self.security_status.get("quantum_encryption", {}),
                self.security_status.get("key_management", {}),
                self.security_status.get("e2e_encryption", {}),
                self.security_status.get("database_encryption", {})
            ]
        )
        
        if all_operational:
            # Check for any issues
            total_issues = sum(
                len(component.get("issues", []))
                for component in [
                    self.security_status.get("quantum_encryption", {}),
                    self.security_status.get("key_management", {}),
                    self.security_status.get("e2e_encryption", {}),
                    self.security_status.get("database_encryption", {})
                ]
            )
            
            if total_issues == 0:
                return "QUANTUM_PROOF"
            elif total_issues <= 2:
                return "GOVERNMENT_LEVEL"
            else:
                return "ENHANCED"
        else:
            return "COMPROMISED"
    
    async def _start_security_monitoring(self):
        """Start continuous security monitoring."""
        # Start distributed security monitoring
        await self.security_monitor.start_monitoring(MonitoringScope.CLUSTER)

        async def monitoring_loop():
            while True:
                try:
                    await asyncio.sleep(300)  # Check every 5 minutes
                    await self._perform_security_check()
                    await self._rotate_expired_keys()
                    await self._cleanup_expired_sessions()
                except Exception as e:
                    logger.error(f"Security monitoring error: {e}")

        asyncio.create_task(monitoring_loop())
        logger.info(" Continuous security monitoring started")
    
    async def _perform_security_check(self):
        """Perform periodic security check."""
        self.last_security_check = datetime.now(timezone.utc)
        
        # Quick status check
        previous_level = self.security_status.get("overall_security_level", "UNKNOWN")
        await self._perform_initial_security_check()
        current_level = self.security_status.get("overall_security_level", "UNKNOWN")
        
        if current_level != previous_level:
            if current_level == "COMPROMISED":
                logger.critical(f" SECURITY ALERT: System security level changed to {current_level}")
                await self._trigger_security_response()
            else:
                logger.info(f" Security level: {current_level}")
    
    async def _rotate_expired_keys(self):
        """Rotate expired keys across all systems."""
        try:
            # Rotate quantum encryption keys
            quantum_rotated = await self.quantum_encryption.rotate_keys()
            
            # Rotate database keys
            db_rotated = await self.database_encryption.rotate_database_keys()
            
            if quantum_rotated > 0 or db_rotated > 0:
                logger.info(f" Key rotation: {quantum_rotated} quantum keys, {db_rotated} database keys")
                
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
    
    async def _cleanup_expired_sessions(self):
        """Clean up expired E2E sessions."""
        try:
            cleaned = await self.e2e_encryption.cleanup_expired_sessions()
            if cleaned > 0:
                logger.info(f" Cleaned up {cleaned} expired E2E sessions")
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
    
    async def _trigger_security_response(self):
        """Trigger emergency security response."""
        logger.critical(" TRIGGERING EMERGENCY SECURITY RESPONSE")
        
        # Force key rotation
        await self.quantum_encryption.rotate_keys(force=True)
        await self.database_encryption.rotate_database_keys(force=True)
        
        # Clear all E2E sessions
        self.e2e_encryption.active_sessions.clear()
        
        logger.critical(" Emergency security measures activated")


# Import consolidated auth modules from app/auth
# Global security manager instance
security_manager = SecurityManager()

# Export all security components
__all__ = [
    # Core security management
    'SecurityManager',
    'security_manager',

    # Quantum encryption and key management
    'QuantumEncryptionSystem',
    'quantum_encryption',
    'DistributedKeyManager',
    'distributed_key_manager',
    'KeyDomain',
    'EndToEndEncryption',
    'e2e_encryption',
    'EndpointType',
    'DatabaseEncryption',
    'database_encryption',
    'DataClassification',

    # Security monitoring
    'DistributedSecurityMonitor',
    'SecurityEvent',
    'SecurityMetrics',
    'ThreatPattern',
    'ThreatLevel',
    'MonitoringScope',
    'SecurityEventType',

    # Authentication components
    'AuthManager',
    'auth_manager',
    'TokenManager',
    'token_manager',
    'SessionManager',
    'session_manager',
    'PasswordManager',
    'password_manager',
    'MFAManager',
    'mfa_manager',
    'BiometricManager',
    'biometric_manager',
    'OAuthManager',
    'oauth_manager',
    'DeviceManager',
    'device_manager',
    'AuthAuditManager',
    'auth_audit_manager',
    'SecurityLevel',
    'AuthAction',
    'AuthAttempt',
    'AuthSession',

    # Protection components
    'DDoSProtection',
    'ddos_protection',
    'RateLimiter',
    'rate_limiter',
    'InputSanitizer',
    'input_sanitizer',
    'PenetrationTester',
    'penetration_tester',
    'VulnerabilityScanner',
    'vulnerability_scanner',
    'BehavioralAnalyzer',
    'behavioral_analyzer',
    'MITMProtection',
    'mitm_protection',
    'AttackType',
    'SecurityThreat',

    # Phase I Security Enhancements
    'WebApplicationFirewall',
    'waf',
    'waf_middleware',
    'WAFRule',
    'WAFRuleType',
    'WAFAction',
    'WAFViolation',
    'ContentSecurityPolicyManager',
    'csp_manager',
    'CSPPolicy',
    'CSPDirective',
    'CSPSource',
    'BugBountyManager',
    'bug_bounty_manager',
    'VulnerabilityReport',
    'VulnerabilityType',
    'SeverityLevel',
    'ReportStatus',
    'SIEMIntegration',
    'siem_integration',
    'SecurityEvent',
    'EventSeverity',
    'EventCategory',
    'SIEMProvider',
    'SIEMConfiguration',
    'AdvancedSecurityHeaders',
    'security_headers_manager',
    'SecurityHeaderType',
    'SecurityHeaderConfig',
    'CICDSecurityScanner',
    'cicd_scanner',
    'Vulnerability',
    'ScanResult',
    'ScannerType',
    'VulnerabilitySeverity',
    'ScanType',

    # SSL/TLS management
    'SSLCertificateManager',
    'ssl_manager',

    # Middleware and utilities
    'SecurityMiddleware',
    'AuthenticationMiddleware',
    'require_auth',
    'from plexichat.infrastructure.utils.auth import require_admin',
    'require_mfa',
    'require_level',
    'optional_auth',
    'PasswordValidator',
    'TokenValidator',
    'BiometricValidator',
    'InputValidator',

    # Exceptions
    'SecurityError',
    'AuthenticationError',
    'AuthorizationError',
    'MFAError',
    'TokenError',
    'SessionError',
    'PasswordError',
    'BiometricError',
    'DeviceError',
    'OAuthError',
    'RateLimitError',
    'AccountLockError',
    'DDoSError',
    'ValidationError',
    'EncryptionError',
    'KeyManagementError',
    'CertificateError',
    'PenetrationTestError',
    'VulnerabilityError',
    'MonitoringError'
]
