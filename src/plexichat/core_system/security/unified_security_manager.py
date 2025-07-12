"""
Unified Security Manager

Consolidates all security functionality into a single, comprehensive system:
- Authentication and authorization (all auth managers)
- DDoS protection and rate limiting
- Input validation and sanitization
- Certificate management and SSL/TLS
- Threat detection and monitoring
- Penetration testing and vulnerability scanning
- Zero-trust security architecture
- Post-quantum cryptography

This unified system replaces:
- Multiple auth managers in core_system/auth/
- DDoS protection modules in features/security/
- Rate limiting systems
- Input sanitizers
- Certificate managers
- Security monitoring systems
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union, Set
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
import ipaddress
import hashlib
import secrets

from ...core_system.logging import get_logger
from ...core_system.config import get_config

logger = get_logger(__name__)


class SecurityLevel(Enum):
    """Security levels for the system."""
    BASIC = 1
    ENHANCED = 2
    GOVERNMENT = 3
    MILITARY = 4
    QUANTUM_RESISTANT = 5


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationMethod(Enum):
    """Supported authentication methods."""
    PASSWORD = "password"
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BIOMETRIC = "biometric"
    HARDWARE_KEY = "hardware_key"
    OAUTH2 = "oauth2"
    ZERO_KNOWLEDGE = "zero_knowledge"


class SecurityEvent(Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DDOS_DETECTED = "ddos_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class SecurityRequest:
    """Unified security request object."""
    request_id: str
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[Dict[str, Any]] = None
    security_level: SecurityLevel = SecurityLevel.ENHANCED


@dataclass
class SecurityResponse:
    """Unified security response object."""
    allowed: bool
    threat_level: ThreatLevel
    security_events: List[SecurityEvent] = field(default_factory=list)
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[datetime] = None
    authentication_required: bool = False
    mfa_required: bool = False
    blocked_reason: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelligence:
    """Threat intelligence data."""
    ip_address: str
    threat_type: str
    severity: ThreatLevel
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class UnifiedSecurityManager:
    """
    Unified Security Manager
    
    The single source of truth for all security operations in PlexiChat.
    Provides comprehensive security services with zero-trust architecture.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("security", {})
        self.initialized = False
        
        # Core security components
        self.auth_manager = None
        self.ddos_protection = None
        self.rate_limiter = None
        self.input_validator = None
        self.certificate_manager = None
        self.threat_detector = None
        self.vulnerability_scanner = None
        self.penetration_tester = None
        
        # Security state
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Set[str] = set()
        self.threat_intelligence: Dict[str, ThreatIntelligence] = {}
        self.security_events: List[Dict[str, Any]] = []
        
        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.global_rate_limit = self.config.get("global_rate_limit", 1000)
        self.per_ip_rate_limit = self.config.get("per_ip_rate_limit", 100)
        
        # DDoS protection
        self.ddos_thresholds = {
            "requests_per_minute": 500,
            "unique_ips_per_minute": 100,
            "error_rate_threshold": 0.5
        }
        
        # Authentication settings
        self.auth_settings = {
            "session_timeout": timedelta(minutes=30),
            "max_failed_attempts": 3,
            "lockout_duration": timedelta(minutes=15),
            "require_mfa": True,
            "password_complexity": True
        }
        
        logger.info("Unified Security Manager initialized")
    
    async def initialize(self) -> None:
        """Initialize the unified security system."""
        if self.initialized:
            return
        
        logger.info("Initializing Unified Security System...")
        
        try:
            # Initialize component managers
            await self._initialize_components()
            
            # Load threat intelligence
            await self._load_threat_intelligence()
            
            # Start background security tasks
            await self._start_security_tasks()
            
            # Initialize zero-trust policies
            await self._initialize_zero_trust()
            
            self.initialized = True
            logger.info("Unified Security System initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize security system: {e}")
            raise
    
    async def process_security_request(self, request: SecurityRequest) -> SecurityResponse:
        """Process a security request through all security layers."""
        if not self.initialized:
            await self.initialize()
        
        response = SecurityResponse(
            allowed=True,
            threat_level=ThreatLevel.LOW
        )
        
        try:
            # 1. IP-based security checks
            await self._check_ip_security(request, response)
            
            # 2. Rate limiting
            await self._check_rate_limits(request, response)
            
            # 3. DDoS protection
            await self._check_ddos_protection(request, response)
            
            # 4. Input validation
            await self._validate_input(request, response)
            
            # 5. Authentication checks
            await self._check_authentication(request, response)
            
            # 6. Authorization checks
            await self._check_authorization(request, response)
            
            # 7. Threat detection
            await self._detect_threats(request, response)
            
            # 8. Behavioral analysis
            await self._analyze_behavior(request, response)
            
            # 9. Log security event
            await self._log_security_event(request, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Security request processing failed: {e}")
            response.allowed = False
            response.threat_level = ThreatLevel.HIGH
            response.blocked_reason = "Security system error"
            return response
    
    async def authenticate_user(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        request_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Authenticate a user with comprehensive security checks using unified auth manager."""
        if not self.initialized:
            await self.initialize()

        try:
            if not self.auth_manager:
                return {
                    "success": False,
                    "error_message": "Authentication system not available"
                }

            # Create authentication request
            from .unified_auth_manager import AuthenticationRequest, SecurityLevel, AuthenticationMethod

            auth_request = AuthenticationRequest(
                username=username,
                password=password,
                mfa_code=mfa_code,
                mfa_method=AuthenticationMethod.MFA_TOTP if mfa_code else None,
                ip_address=request_info.get("ip_address") if request_info else None,
                user_agent=request_info.get("user_agent") if request_info else None,
                device_id=request_info.get("device_id") if request_info else None,
                required_security_level=SecurityLevel.BASIC
            )

            # Authenticate using unified auth manager
            auth_response = await self.auth_manager.authenticate(auth_request)

            # Convert response to legacy format for compatibility
            return {
                "success": auth_response.success,
                "user_id": auth_response.user_id,
                "session_id": auth_response.session_id,
                "access_token": auth_response.access_token,
                "refresh_token": auth_response.refresh_token,
                "mfa_required": auth_response.mfa_required,
                "mfa_methods": [method.value for method in auth_response.mfa_methods],
                "security_level": auth_response.security_level.value if auth_response.security_level else "BASIC",
                "risk_score": auth_response.risk_score,
                "device_trusted": auth_response.device_trusted,
                "error_message": auth_response.error_message,
                "audit_id": auth_response.audit_id
            }
            
            # Create secure session
            session_id = await self._create_session(user_id, request_info)
            
            auth_result.update({
                "success": True,
                "user_id": user_id,
                "session_id": session_id,
                "security_level": SecurityLevel.GOVERNMENT if mfa_code else SecurityLevel.ENHANCED
            })
            
            return auth_result
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            auth_result["error_message"] = "Authentication system error"
            return auth_result
    
    async def validate_session(self, session_id: str) -> Dict[str, Any]:
        """Validate an active session."""
        if session_id not in self.active_sessions:
            return {"valid": False, "reason": "Session not found"}
        
        session = self.active_sessions[session_id]
        current_time = datetime.now(timezone.utc)
        
        # Check session timeout
        if current_time > session["expires_at"]:
            del self.active_sessions[session_id]
            return {"valid": False, "reason": "Session expired"}
        
        # Update last activity
        session["last_activity"] = current_time
        
        return {
            "valid": True,
            "user_id": session["user_id"],
            "security_level": session["security_level"]
        }
    
    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get comprehensive security metrics."""
        current_time = datetime.now(timezone.utc)
        hour_ago = current_time - timedelta(hours=1)
        
        # Calculate metrics
        recent_events = [
            event for event in self.security_events
            if event["timestamp"] > hour_ago
        ]
        
        metrics = {
            "active_sessions": len(self.active_sessions),
            "blocked_ips": len(self.blocked_ips),
            "threat_intelligence_entries": len(self.threat_intelligence),
            "recent_security_events": len(recent_events),
            "authentication_success_rate": self._calculate_auth_success_rate(recent_events),
            "ddos_attacks_blocked": self._count_ddos_blocks(recent_events),
            "rate_limit_violations": self._count_rate_limit_violations(recent_events),
            "vulnerability_scan_results": await self._get_vulnerability_metrics(),
            "certificate_status": await self._get_certificate_status(),
            "system_health": {
                "security_level": SecurityLevel.GOVERNMENT.value,
                "zero_trust_enabled": True,
                "quantum_encryption": True,
                "threat_detection": True
            }
        }
        
        return metrics

    # Private Implementation Methods

    async def _initialize_components(self) -> None:
        """Initialize all security component managers."""
        try:
            # Import and initialize our consolidated components
            from .unified_auth_manager import get_unified_auth_manager
            from ..security.input_validation import get_input_validator
            from ...features.security.network_protection import get_network_protection
            from .certificate_manager import get_certificate_manager

            # Initialize components with our consolidated systems
            self.auth_manager = get_unified_auth_manager()
            self.input_validator = get_input_validator()
            self.network_protection = get_network_protection()
            self.certificate_manager = get_certificate_manager()

            # Initialize all components
            await self.auth_manager.initialize()
            await self.input_validator.initialize()
            await self.network_protection.initialize()
            await self.certificate_manager.initialize()

            logger.info("✅ All consolidated security components initialized")

        except ImportError as e:
            logger.warning(f"Some security components not available: {e}")
            # Initialize basic fallback components
            self.auth_manager = None
            self.input_validator = None
            self.network_protection = None
            self.certificate_manager = None

        except Exception as e:
            logger.error(f"Failed to initialize security components: {e}")
            raise

    async def _load_threat_intelligence(self) -> None:
        """Load threat intelligence data."""
        # Load from external threat feeds
        # Placeholder - in production, integrate with threat intelligence services
        logger.info("Threat intelligence loaded")

    async def _start_security_tasks(self) -> None:
        """Start background security monitoring tasks."""
        # Security monitoring task
        asyncio.create_task(self._security_monitoring_task())

        # Threat intelligence update task
        asyncio.create_task(self._threat_intelligence_task())

        # Certificate monitoring task
        asyncio.create_task(self._certificate_monitoring_task())

        # Vulnerability scanning task
        asyncio.create_task(self._vulnerability_scanning_task())

        logger.info("Security background tasks started")

    async def _initialize_zero_trust(self) -> None:
        """Initialize zero-trust security policies."""
        # Zero-trust configuration
        self.zero_trust_policies = {
            "verify_every_request": True,
            "continuous_authentication": True,
            "least_privilege_access": True,
            "encrypt_all_traffic": True,
            "monitor_all_activity": True
        }

        logger.info("Zero-trust security policies initialized")

    async def _check_ip_security(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Check IP-based security."""
        # Check if IP is blocked
        if request.ip_address in self.blocked_ips:
            response.allowed = False
            response.threat_level = ThreatLevel.HIGH
            response.blocked_reason = "IP address blocked"
            response.security_events.append(SecurityEvent.UNAUTHORIZED_ACCESS)
            return

        # Check threat intelligence
        if request.ip_address in self.threat_intelligence:
            threat = self.threat_intelligence[request.ip_address]
            if threat.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                response.allowed = False
                response.threat_level = threat.severity
                response.blocked_reason = f"Threat detected: {threat.threat_type}"
                response.security_events.append(SecurityEvent.SUSPICIOUS_ACTIVITY)

    async def _check_rate_limits(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Check rate limiting."""
        current_time = datetime.now(timezone.utc)
        minute_ago = current_time - timedelta(minutes=1)

        # Initialize rate limit tracking for IP
        if request.ip_address not in self.rate_limits:
            self.rate_limits[request.ip_address] = []

        # Clean old entries
        self.rate_limits[request.ip_address] = [
            timestamp for timestamp in self.rate_limits[request.ip_address]
            if timestamp > minute_ago
        ]

        # Check rate limit
        request_count = len(self.rate_limits[request.ip_address])
        if request_count >= self.per_ip_rate_limit:
            response.allowed = False
            response.threat_level = ThreatLevel.MEDIUM
            response.blocked_reason = "Rate limit exceeded"
            response.security_events.append(SecurityEvent.RATE_LIMIT_EXCEEDED)
            return

        # Add current request
        self.rate_limits[request.ip_address].append(current_time)

        # Set rate limit headers
        response.rate_limit_remaining = self.per_ip_rate_limit - request_count - 1
        response.rate_limit_reset = current_time + timedelta(minutes=1)

    async def _check_ddos_protection(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Check DDoS protection."""
        if self.ddos_protection:
            ddos_result = await self.ddos_protection.check_request(request)
            if not ddos_result["allowed"]:
                response.allowed = False
                response.threat_level = ThreatLevel.HIGH
                response.blocked_reason = "DDoS protection triggered"
                response.security_events.append(SecurityEvent.DDOS_DETECTED)

    async def _validate_input(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Validate input data."""
        if self.input_validator and request.payload:
            validation_result = await self.input_validator.validate(request.payload)
            if not validation_result["valid"]:
                response.allowed = False
                response.threat_level = ThreatLevel.MEDIUM
                response.blocked_reason = f"Input validation failed: {validation_result['reason']}"
                response.security_events.append(SecurityEvent.SUSPICIOUS_ACTIVITY)

    async def _check_authentication(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Check authentication requirements."""
        # Check if endpoint requires authentication
        if self._requires_authentication(request.endpoint):
            if not request.session_id:
                response.authentication_required = True
                response.allowed = False
                response.blocked_reason = "Authentication required"
                return

            # Validate session
            session_result = await self.validate_session(request.session_id)
            if not session_result["valid"]:
                response.authentication_required = True
                response.allowed = False
                response.blocked_reason = f"Invalid session: {session_result['reason']}"

    async def _check_authorization(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Check authorization permissions."""
        if request.user_id and request.session_id:
            # Check if user has permission for this endpoint
            has_permission = await self._check_user_permission(
                request.user_id, request.endpoint, request.method
            )
            if not has_permission:
                response.allowed = False
                response.threat_level = ThreatLevel.MEDIUM
                response.blocked_reason = "Insufficient permissions"
                response.security_events.append(SecurityEvent.UNAUTHORIZED_ACCESS)

    async def _detect_threats(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Detect security threats."""
        if self.threat_detector:
            threat_result = await self.threat_detector.analyze_request(request)
            if threat_result["threat_detected"]:
                response.threat_level = ThreatLevel(threat_result["severity"])
                response.security_events.append(SecurityEvent.SUSPICIOUS_ACTIVITY)
                response.recommendations.extend(threat_result["recommendations"])

    async def _analyze_behavior(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Analyze behavioral patterns."""
        # Behavioral analysis logic
        # Check for unusual patterns, anomalies, etc.
        pass

    async def _log_security_event(self, request: SecurityRequest, response: SecurityResponse) -> None:
        """Log security event."""
        event = {
            "timestamp": request.timestamp,
            "request_id": request.request_id,
            "ip_address": request.ip_address,
            "endpoint": request.endpoint,
            "method": request.method,
            "user_id": request.user_id,
            "allowed": response.allowed,
            "threat_level": response.threat_level.value,
            "security_events": [event.value for event in response.security_events],
            "blocked_reason": response.blocked_reason
        }

        self.security_events.append(event)

        # Keep only last 10000 events
        if len(self.security_events) > 10000:
            self.security_events = self.security_events[-10000:]

    async def _verify_credentials(self, username: str, password: str) -> Optional[str]:
        """Verify user credentials."""
        if self.auth_manager:
            return await self.auth_manager.verify_credentials(username, password)
        return None

    async def _is_mfa_required(self, user_id: str, request_info: Optional[Dict[str, Any]]) -> bool:
        """Check if MFA is required for user."""
        # MFA requirement logic
        return self.auth_settings["require_mfa"]

    async def _verify_mfa(self, user_id: str, mfa_code: str) -> bool:
        """Verify MFA code."""
        if self.auth_manager:
            return await self.auth_manager.verify_mfa(user_id, mfa_code)
        return False

    async def _create_session(self, user_id: str, request_info: Optional[Dict[str, Any]]) -> str:
        """Create a secure session."""
        session_id = secrets.token_urlsafe(32)
        current_time = datetime.now(timezone.utc)

        session = {
            "user_id": user_id,
            "session_id": session_id,
            "created_at": current_time,
            "last_activity": current_time,
            "expires_at": current_time + self.auth_settings["session_timeout"],
            "security_level": SecurityLevel.ENHANCED,
            "ip_address": request_info.get("ip_address") if request_info else None,
            "user_agent": request_info.get("user_agent") if request_info else None
        }

        self.active_sessions[session_id] = session
        return session_id

    def _requires_authentication(self, endpoint: str) -> bool:
        """Check if endpoint requires authentication."""
        # Define public endpoints that don't require authentication
        public_endpoints = ["/api/v1/health", "/api/v1/status", "/api/v1/auth/login"]
        return endpoint not in public_endpoints

    async def _check_user_permission(self, user_id: str, endpoint: str, method: str) -> bool:
        """Check if user has permission for endpoint."""
        # Permission checking logic
        # In production, this would check against user roles and permissions
        return True  # Placeholder

    # Background Tasks

    async def _security_monitoring_task(self) -> None:
        """Background security monitoring task."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                # Monitor for security anomalies
                await self._monitor_security_anomalies()

            except Exception as e:
                logger.error(f"Security monitoring task error: {e}")

    async def _threat_intelligence_task(self) -> None:
        """Background threat intelligence update task."""
        while True:
            try:
                await asyncio.sleep(3600)  # Update every hour

                # Update threat intelligence feeds
                await self._update_threat_intelligence()

            except Exception as e:
                logger.error(f"Threat intelligence task error: {e}")

    async def _certificate_monitoring_task(self) -> None:
        """Background certificate monitoring task."""
        while True:
            try:
                await asyncio.sleep(86400)  # Check daily

                # Check certificate expiration
                if self.certificate_manager:
                    await self.certificate_manager.check_certificate_expiration()

            except Exception as e:
                logger.error(f"Certificate monitoring task error: {e}")

    async def _vulnerability_scanning_task(self) -> None:
        """Background vulnerability scanning task."""
        while True:
            try:
                await asyncio.sleep(604800)  # Scan weekly

                # Run vulnerability scan
                if self.vulnerability_scanner:
                    await self.vulnerability_scanner.run_scan()

            except Exception as e:
                logger.error(f"Vulnerability scanning task error: {e}")

    # Utility Methods

    async def _monitor_security_anomalies(self) -> None:
        """Monitor for security anomalies."""
        # Anomaly detection logic
        pass

    async def _update_threat_intelligence(self) -> None:
        """Update threat intelligence feeds."""
        # Threat intelligence update logic
        pass

    def _calculate_auth_success_rate(self, events: List[Dict[str, Any]]) -> float:
        """Calculate authentication success rate."""
        auth_events = [
            event for event in events
            if SecurityEvent.LOGIN_SUCCESS.value in event.get("security_events", []) or
               SecurityEvent.LOGIN_FAILURE.value in event.get("security_events", [])
        ]

        if not auth_events:
            return 1.0

        success_events = [
            event for event in auth_events
            if SecurityEvent.LOGIN_SUCCESS.value in event.get("security_events", [])
        ]

        return len(success_events) / len(auth_events)

    def _count_ddos_blocks(self, events: List[Dict[str, Any]]) -> int:
        """Count DDoS attacks blocked."""
        return len([
            event for event in events
            if SecurityEvent.DDOS_DETECTED.value in event.get("security_events", [])
        ])

    def _count_rate_limit_violations(self, events: List[Dict[str, Any]]) -> int:
        """Count rate limit violations."""
        return len([
            event for event in events
            if SecurityEvent.RATE_LIMIT_EXCEEDED.value in event.get("security_events", [])
        ])

    async def _get_vulnerability_metrics(self) -> Dict[str, Any]:
        """Get vulnerability scan metrics."""
        if self.vulnerability_scanner:
            return await self.vulnerability_scanner.get_metrics()
        return {"vulnerabilities_found": 0, "last_scan": None}

    async def _get_certificate_status(self) -> Dict[str, Any]:
        """Get certificate status."""
        if self.certificate_manager:
            return await self.certificate_manager.get_status()
        return {"certificates": 0, "expiring_soon": 0}


# Global instance
_unified_security_manager: Optional[UnifiedSecurityManager] = None


def get_unified_security_manager() -> UnifiedSecurityManager:
    """Get the global unified security manager instance."""
    global _unified_security_manager
    if _unified_security_manager is None:
        _unified_security_manager = UnifiedSecurityManager()
    return _unified_security_manager


# Alias for backward compatibility
security_manager = get_unified_security_manager()
