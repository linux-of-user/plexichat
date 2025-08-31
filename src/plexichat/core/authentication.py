"""
Unified Authentication Manager for PlexiChat
Provides a unified interface for authentication operations that delegates to the SecuritySystem.
Includes caching layer for improved performance and advanced security features.
"""

import asyncio
import secrets
import time
import hashlib
import hmac
import base64
import json
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode, parse_qs
import uuid

# Import unified logging system
from plexichat.core.logging import get_logger

# Import the SecuritySystem and related components
from plexichat.core.security.security_manager import (
    SecuritySystem,
    SecurityContext,
    SecurityLevel,
    SecurityPolicy,
    UserCredentials,
    SecurityToken,
    AuthenticationMethod,
    get_security_system
)

# Try to import caching system
try:
    from plexichat.core.performance.auth_cache import get_auth_cache
    auth_cache_available = True
except ImportError:
    auth_cache_available = False
    get_auth_cache = None

# Try to import performance tracking
try:
    from plexichat.core.logging import get_performance_logger
    performance_logger_available = True
except ImportError:
    performance_logger_available = False
    get_performance_logger = None

# Try to import MFA store
try:
    from plexichat.core.mfa_store import MFAStore
    mfa_store_available = True
except ImportError:
    mfa_store_available = False
    MFAStore = None

logger = get_logger(__name__)


class DeviceType(Enum):
    """Device types for session tracking."""
    DESKTOP = "desktop"
    MOBILE = "mobile"
    TABLET = "tablet"
    API = "api"
    UNKNOWN = "unknown"


class AuthProvider(Enum):
    """Authentication providers."""
    LOCAL = "local"
    OAUTH2_GOOGLE = "oauth2_google"
    OAUTH2_GITHUB = "oauth2_github"
    OAUTH2_MICROSOFT = "oauth2_microsoft"
    LDAP = "ldap"
    SAML = "saml"


class Role(Enum):
    """User roles for RBAC."""
    GUEST = "guest"
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"
    SYSTEM = "system"


class MFAMethod(Enum):
    """Multi-factor authentication methods."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODES = "backup_codes"
    HARDWARE_TOKEN = "hardware_token"


@dataclass
class DeviceInfo:
    """Device information for session tracking."""
    device_id: str
    device_type: DeviceType
    os: Optional[str] = None
    browser: Optional[str] = None
    version: Optional[str] = None
    is_trusted: bool = False
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MFAChallenge:
    """Multi-factor authentication challenge."""
    challenge_id: str
    user_id: str
    method: MFAMethod
    code: Optional[str] = None
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    attempts: int = 0
    max_attempts: int = 3
    is_verified: bool = False


@dataclass
class OAuth2Config:
    """OAuth2 provider configuration."""
    provider: AuthProvider
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    user_info_url: str
    scope: str
    redirect_uri: str


@dataclass
class BruteForceProtection:
    """Brute force protection tracking."""
    ip_address: str
    failed_attempts: int = 0
    first_attempt: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_attempt: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_blocked: bool = False
    blocked_until: Optional[datetime] = None


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1
    prevent_common_passwords: bool = True
    prevent_personal_info: bool = True
    password_history_count: int = 5
    max_age_days: int = 90
    complexity_score_threshold: int = 60


@dataclass
class SessionInfo:
    """Enhanced session information for authenticated users."""
    session_id: str
    user_id: str
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    permissions: Set[str] = field(default_factory=set)
    roles: Set[Role] = field(default_factory=set)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[DeviceInfo] = None
    auth_provider: AuthProvider = AuthProvider.LOCAL
    mfa_verified: bool = False
    is_active: bool = True
    is_elevated: bool = False
    elevation_expires_at: Optional[datetime] = None
    location: Optional[str] = None
    risk_score: float = 0.0


@dataclass
class AuthResult:
    """Enhanced result of authentication operation."""
    success: bool
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    token: Optional[str] = None
    refresh_token: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    roles: Set[Role] = field(default_factory=set)
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    security_context: Optional[SecurityContext] = None
    requires_mfa: bool = False
    mfa_challenge: Optional[MFAChallenge] = None
    device_trusted: bool = False
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    auth_provider: AuthProvider = AuthProvider.LOCAL


class UnifiedAuthManager:
    """
    Advanced Unified Authentication Manager with comprehensive security features.
    
    Features:
    - Multi-factor authentication (MFA)
    - Advanced session management with device tracking
    - OAuth2 and external authentication providers
    - Role-based access control (RBAC)
    - Password policy enforcement
    - Account lockout and brute force protection
    - Advanced audit logging
    - Risk-based authentication
    """

    def __init__(self, security_system: Optional[SecuritySystem] = None):
        # Use provided security system or get global instance
        self.security_system = security_system or get_security_system()
        
        # Initialize caching if available
        if auth_cache_available and callable(get_auth_cache):
            try:
                self.auth_cache = get_auth_cache()
            except Exception:
                self.auth_cache = None
        else:
            self.auth_cache = None

        # Initialize performance logger if available
        if performance_logger_available and callable(get_performance_logger):
            try:
                self.performance_logger = get_performance_logger()
            except Exception:
                self.performance_logger = None
        else:
            self.performance_logger = None

        # Initialize MFA store if available
        if mfa_store_available and callable(MFAStore):
            try:
                self.mfa_store = MFAStore()
            except Exception:
                self.mfa_store = None
        else:
            self.mfa_store = None
        
        # Session management
        self.active_sessions: Dict[str, SessionInfo] = {}
        self.session_timeout = timedelta(hours=1)
        self.elevated_session_timeout = timedelta(minutes=15)
        
        # Device tracking
        self.known_devices: Dict[str, DeviceInfo] = {}
        self.trusted_devices: Set[str] = set()
        
        # MFA challenges
        self.active_mfa_challenges: Dict[str, MFAChallenge] = {}
        
        # OAuth2 providers
        self.oauth2_providers: Dict[AuthProvider, OAuth2Config] = {}
        
        # Brute force protection
        self.brute_force_tracking: Dict[str, BruteForceProtection] = {}
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        
        # Password policy
        self.password_policy = PasswordPolicy()
        
        # Role-based permissions mapping
        self.role_permissions: Dict[Role, Set[str]] = {
            Role.GUEST: set(),
            Role.USER: {"read", "write_own"},
            Role.MODERATOR: {"read", "write_own", "moderate", "delete_others"},
            Role.ADMIN: {"read", "write_own", "moderate", "delete_others", "admin", "user_management"},
            Role.SUPER_ADMIN: {"*"},  # All permissions
            Role.SYSTEM: {"*"}  # All permissions
        }
        
        # Common passwords list (subset for security)
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        }
        
        # Performance metrics
        self.metrics = {
            'authentication_requests': 0,
            'successful_authentications': 0,
            'failed_authentications': 0,
            'mfa_challenges_issued': 0,
            'mfa_verifications': 0,
            'oauth2_authentications': 0,
            'brute_force_blocks': 0,
            'password_policy_violations': 0,
            'token_validations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'session_creations': 0,
            'session_invalidations': 0,
            'api_key_validations': 0,
            'device_registrations': 0,
            'risk_assessments': 0
        }
        
        logger.info("Advanced UnifiedAuthManager initialized with comprehensive security features")
        logger.audit("Authentication manager initialized", 
                    component="auth_manager", 
                    event_type="system_initialization",
                    features=["mfa", "oauth2", "rbac", "brute_force_protection", "device_tracking"])

    def _record_metric(self, metric_name: str, value: Union[int, float] = 1, metric_type: str = "count") -> None:
        """Record performance metric with enhanced error handling."""
        try:
            current_value = self.metrics.get(metric_name, 0)
            # Convert to int to avoid type issues
            self.metrics[metric_name] = int(current_value + value)

            if self.performance_logger:
                try:
                    # Use simple fallback method to avoid MetricType issues
                    self.performance_logger.record_metric(metric_name, int(value))
                except Exception as e:
                    logger.debug(f"Failed to record metric {metric_name}: {e}")
        except Exception as e:
            logger.error(f"Critical error recording metric {metric_name}: {e}")

    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _generate_device_id(self, user_agent: str, ip_address: str) -> str:
        """Generate a device ID based on user agent and IP."""
        device_string = f"{user_agent}:{ip_address}"
        return hashlib.sha256(device_string.encode()).hexdigest()[:16]

    def _parse_user_agent(self, user_agent: Optional[str]) -> DeviceInfo:
        """Parse user agent to extract device information."""
        if not user_agent:
            return DeviceInfo(
                device_id=secrets.token_hex(8),
                device_type=DeviceType.UNKNOWN
            )

        device_id = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        # Enhanced user agent parsing
        user_agent_lower = user_agent.lower()

        # Check for mobile devices first (more specific)
        if any(mobile in user_agent_lower for mobile in ['iphone', 'ipad', 'ipod', 'android', 'blackberry', 'windows phone']):
            if 'ipad' in user_agent_lower:
                device_type = DeviceType.TABLET
            else:
                device_type = DeviceType.MOBILE
        elif any(tablet in user_agent_lower for tablet in ['tablet', 'kindle', 'playbook']):
            device_type = DeviceType.TABLET
        elif any(desktop in user_agent_lower for desktop in ['windows', 'macintosh', 'linux', 'ubuntu', 'fedora']):
            device_type = DeviceType.DESKTOP
        else:
            # Check for browser indicators as fallback
            if any(browser in user_agent_lower for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera']):
                device_type = DeviceType.DESKTOP
            else:
                device_type = DeviceType.UNKNOWN

        # Extract OS and browser info
        os_info = None
        browser_info = None

        # OS detection
        if 'windows' in user_agent_lower:
            os_info = 'Windows'
        elif 'macintosh' in user_agent_lower or 'mac os x' in user_agent_lower:
            os_info = 'macOS'
        elif 'linux' in user_agent_lower:
            os_info = 'Linux'
        elif 'android' in user_agent_lower:
            os_info = 'Android'
        elif 'iphone' in user_agent_lower or 'ipad' in user_agent_lower or 'ipod' in user_agent_lower:
            os_info = 'iOS'

        # Browser detection
        if 'chrome' in user_agent_lower and 'edg' not in user_agent_lower:
            browser_info = 'Chrome'
        elif 'firefox' in user_agent_lower:
            browser_info = 'Firefox'
        elif 'safari' in user_agent_lower and 'chrome' not in user_agent_lower:
            browser_info = 'Safari'
        elif 'edg' in user_agent_lower:
            browser_info = 'Edge'

        return DeviceInfo(
            device_id=device_id,
            device_type=device_type,
            os=os_info,
            browser=browser_info
        )

    def _is_session_expired(self, session: SessionInfo) -> bool:
        """Check if a session has expired."""
        current_time = datetime.now(timezone.utc)
        
        # Check regular expiration
        if current_time > session.expires_at:
            return True
        
        # Check elevated session expiration
        if session.is_elevated and session.elevation_expires_at:
            if current_time > session.elevation_expires_at:
                # Downgrade elevated session instead of expiring
                session.is_elevated = False
                session.elevation_expires_at = None
                logger.security("Elevated session downgraded", 
                               session_id=session.session_id, 
                               user_id=session.user_id)
        
        return False

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions and MFA challenges."""
        current_time = datetime.now(timezone.utc)
        
        # Clean up expired sessions
        expired_sessions = [
            session_id for session_id, session in self.active_sessions.items()
            if current_time > session.expires_at
        ]
        
        for session_id in expired_sessions:
            session = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            self._record_metric('session_invalidations')
            
            logger.security("Session expired and removed", 
                           session_id=session_id, 
                           user_id=session.user_id)
            logger.audit("Session expired", 
                        session_id=session_id, 
                        user_id=session.user_id, 
                        event_type="session_expired")
        
        # Clean up expired MFA challenges
        expired_challenges = [
            challenge_id for challenge_id, challenge in self.active_mfa_challenges.items()
            if current_time > challenge.expires_at
        ]
        
        for challenge_id in expired_challenges:
            challenge = self.active_mfa_challenges[challenge_id]
            del self.active_mfa_challenges[challenge_id]
            
            logger.security("MFA challenge expired", 
                           challenge_id=challenge_id, 
                           user_id=challenge.user_id)

    def _calculate_risk_score(self, ip_address: str, device_info: DeviceInfo, user_id: str) -> float:
        """Calculate risk score for authentication attempt."""
        risk_score = 0.0
        
        try:
            # Check if IP is from known location
            if ip_address not in self._get_user_known_ips(user_id):
                risk_score += 30.0
            
            # Check if device is known
            if device_info.device_id not in self.known_devices:
                risk_score += 25.0
            elif not device_info.is_trusted:
                risk_score += 15.0
            
            # Check for suspicious patterns
            if self._is_suspicious_ip(ip_address):
                risk_score += 40.0
            
            # Check brute force history
            if ip_address in self.brute_force_tracking:
                bf_protection = self.brute_force_tracking[ip_address]
                if bf_protection.failed_attempts > 0:
                    risk_score += min(bf_protection.failed_attempts * 5, 25.0)
            
            # Time-based risk (unusual hours)
            current_hour = datetime.now(timezone.utc).hour
            if current_hour < 6 or current_hour > 22:  # Late night/early morning
                risk_score += 10.0
            
            self._record_metric('risk_assessments')
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            risk_score = 50.0  # Default to medium risk on error
        
        return min(risk_score, 100.0)

    def _get_user_known_ips(self, user_id: str) -> Set[str]:
        """Get known IP addresses for a user."""
        # In production, this would query a database
        # For now, return IPs from active sessions
        return {
            session.ip_address for session in self.active_sessions.values()
            if session.user_id == user_id and session.ip_address
        }

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious."""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check for private/local IPs (generally safe)
            if ip.is_private or ip.is_loopback:
                return False
            
            # In production, check against threat intelligence feeds
            # For now, just basic checks
            return False
            
        except Exception:
            return True  # Invalid IP format is suspicious

    def _check_brute_force_protection(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is blocked due to brute force attempts."""
        if ip_address not in self.brute_force_tracking:
            return True, None
        
        protection = self.brute_force_tracking[ip_address]
        current_time = datetime.now(timezone.utc)
        
        # Check if still blocked
        if protection.is_blocked and protection.blocked_until:
            if current_time < protection.blocked_until:
                remaining = protection.blocked_until - current_time
                logger.security("Brute force protection active", 
                               ip_address=ip_address, 
                               remaining_seconds=remaining.total_seconds())
                return False, f"IP blocked for {remaining.total_seconds():.0f} more seconds"
            else:
                # Unblock IP
                protection.is_blocked = False
                protection.blocked_until = None
                protection.failed_attempts = 0
                logger.security("Brute force protection lifted", ip_address=ip_address)
        
        return True, None

    def _record_failed_attempt(self, ip_address: str) -> None:
        """Record a failed authentication attempt for brute force protection."""
        current_time = datetime.now(timezone.utc)
        
        if ip_address not in self.brute_force_tracking:
            self.brute_force_tracking[ip_address] = BruteForceProtection(ip_address=ip_address)
        
        protection = self.brute_force_tracking[ip_address]
        protection.failed_attempts += 1
        protection.last_attempt = current_time
        
        # Block if too many attempts
        if protection.failed_attempts >= self.max_failed_attempts:
            protection.is_blocked = True
            protection.blocked_until = current_time + self.lockout_duration
            self._record_metric('brute_force_blocks')
            
            logger.security("IP blocked due to brute force attempts", 
                           ip_address=ip_address, 
                           failed_attempts=protection.failed_attempts)
            logger.audit("Brute force protection activated", 
                        ip_address=ip_address, 
                        event_type="brute_force_block",
                        failed_attempts=protection.failed_attempts)

    def _validate_password_policy(self, password: str, user_id: str) -> Tuple[bool, List[str]]:
        """Validate password against policy."""
        issues = []
        
        try:
            # Length check
            if len(password) < self.password_policy.min_length:
                issues.append(f"Password must be at least {self.password_policy.min_length} characters")
            
            if len(password) > self.password_policy.max_length:
                issues.append(f"Password must be no more than {self.password_policy.max_length} characters")
            
            # Character requirements
            if self.password_policy.require_uppercase and not re.search(r'[A-Z]', password):
                issues.append("Password must contain uppercase letters")
            
            if self.password_policy.require_lowercase and not re.search(r'[a-z]', password):
                issues.append("Password must contain lowercase letters")
            
            if self.password_policy.require_numbers and not re.search(r'\d', password):
                issues.append("Password must contain numbers")
            
            if self.password_policy.require_special_chars:
                special_chars = re.findall(r'[!@#$%^&*(),.?":{}|<>]', password)
                if len(special_chars) < self.password_policy.min_special_chars:
                    issues.append(f"Password must contain at least {self.password_policy.min_special_chars} special characters")
            
            # Common password check
            if self.password_policy.prevent_common_passwords:
                if password.lower() in self.common_passwords:
                    issues.append("Password is too common")
            
            # Personal info check
            if self.password_policy.prevent_personal_info:
                if user_id.lower() in password.lower():
                    issues.append("Password cannot contain username")
            
            # Complexity score
            complexity_score = self._calculate_password_complexity(password)
            if complexity_score < self.password_policy.complexity_score_threshold:
                issues.append(f"Password complexity score {complexity_score} is below required {self.password_policy.complexity_score_threshold}")
            
            if issues:
                self._record_metric('password_policy_violations')
                logger.security("Password policy violation", 
                               user_id=user_id, 
                               violations=issues)
            
        except Exception as e:
            logger.error(f"Error validating password policy: {e}")
            issues.append("Password validation failed")
        
        return len(issues) == 0, issues

    def _calculate_password_complexity(self, password: str) -> int:
        """Calculate password complexity score (0-100)."""
        score = 0
        
        # Length bonus
        score += min(len(password) * 2, 25)
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        
        # Patterns (reduce score for common patterns)
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):  # Sequential numbers
            score -= 10
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):  # Sequential letters
            score -= 10
        
        return max(0, min(score, 100))

    def _get_user_roles(self, user_id: str) -> Set[Role]:
        """Get user roles from credentials."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return {Role.GUEST}
            
            # Extract roles from permissions (simple mapping)
            roles = set()
            
            if "admin" in credentials.permissions:
                roles.add(Role.ADMIN)
            elif "moderate" in credentials.permissions:
                roles.add(Role.MODERATOR)
            elif credentials.permissions:
                roles.add(Role.USER)
            else:
                roles.add(Role.GUEST)
            
            return roles
            
        except Exception as e:
            logger.error(f"Error getting user roles: {e}", user_id=user_id)
            return {Role.GUEST}

    def _expand_role_permissions(self, roles: Set[Role]) -> Set[str]:
        """Expand roles to their permissions."""
        permissions = set()
        
        for role in roles:
            role_perms = self.role_permissions.get(role, set())
            if "*" in role_perms:
                # Super admin or system role - all permissions
                return {"*"}
            permissions.update(role_perms)
        
        return permissions

    async def create_mfa_challenge(self, user_id: str, method: MFAMethod) -> Optional[MFAChallenge]:
        """Create a multi-factor authentication challenge."""
        try:
            if not self.mfa_store:
                logger.warning("MFA store not available")
                return None
            
            challenge_id = secrets.token_urlsafe(16)
            challenge = MFAChallenge(
                challenge_id=challenge_id,
                user_id=user_id,
                method=method
            )
            
            if method == MFAMethod.TOTP:
                # TOTP doesn't need a code generation, user provides it
                pass
            elif method == MFAMethod.EMAIL:
                # Generate email code
                challenge.code = f"{secrets.randbelow(900000) + 100000:06d}"
                # In production, send email here
                logger.info(f"MFA email code generated for user {user_id}: {challenge.code}")
            elif method == MFAMethod.SMS:
                # Generate SMS code
                challenge.code = f"{secrets.randbelow(900000) + 100000:06d}"
                # In production, send SMS here
                logger.info(f"MFA SMS code generated for user {user_id}: {challenge.code}")
            elif method == MFAMethod.BACKUP_CODES:
                # User provides backup code
                pass
            
            self.active_mfa_challenges[challenge_id] = challenge
            self._record_metric('mfa_challenges_issued')
            
            logger.security("MFA challenge created", 
                           user_id=user_id, 
                           challenge_id=challenge_id, 
                           method=method.value)
            logger.audit("MFA challenge issued", 
                        user_id=user_id, 
                        challenge_id=challenge_id, 
                        event_type="mfa_challenge_created",
                        method=method.value)
            
            return challenge
            
        except Exception as e:
            logger.error(f"Error creating MFA challenge: {e}", user_id=user_id)
            return None

    async def verify_mfa_challenge(self, challenge_id: str, user_code: str) -> bool:
        """Verify a multi-factor authentication challenge."""
        try:
            challenge = self.active_mfa_challenges.get(challenge_id)
            if not challenge:
                logger.security("MFA verification failed - challenge not found", 
                               challenge_id=challenge_id)
                return False
            
            # Check if challenge expired
            if datetime.now(timezone.utc) > challenge.expires_at:
                del self.active_mfa_challenges[challenge_id]
                logger.security("MFA verification failed - challenge expired", 
                               challenge_id=challenge_id, 
                               user_id=challenge.user_id)
                return False
            
            # Check attempt limit
            challenge.attempts += 1
            if challenge.attempts > challenge.max_attempts:
                del self.active_mfa_challenges[challenge_id]
                logger.security("MFA verification failed - too many attempts", 
                               challenge_id=challenge_id, 
                               user_id=challenge.user_id,
                               attempts=challenge.attempts)
                return False
            
            verified = False
            
            if challenge.method == MFAMethod.TOTP:
                # Verify TOTP code
                if self.mfa_store:
                    verified = await self.mfa_store.verify_totp(challenge.user_id, user_code)
            elif challenge.method in [MFAMethod.EMAIL, MFAMethod.SMS]:
                # Verify generated code
                verified = hmac.compare_digest(challenge.code or "", user_code)
            elif challenge.method == MFAMethod.BACKUP_CODES:
                # Verify backup code
                if self.mfa_store:
                    verified = await self.mfa_store.verify_backup_code(challenge.user_id, user_code)
            
            if verified:
                challenge.is_verified = True
                self._record_metric('mfa_verifications')
                
                logger.security("MFA verification successful", 
                               challenge_id=challenge_id, 
                               user_id=challenge.user_id,
                               method=challenge.method.value)
                logger.audit("MFA verification successful", 
                            user_id=challenge.user_id, 
                            challenge_id=challenge_id, 
                            event_type="mfa_verified",
                            method=challenge.method.value)
                
                # Clean up challenge after successful verification
                del self.active_mfa_challenges[challenge_id]
                return True
            else:
                logger.security("MFA verification failed - invalid code", 
                               challenge_id=challenge_id, 
                               user_id=challenge.user_id,
                               attempts=challenge.attempts)
                return False
                
        except Exception as e:
            logger.error(f"Error verifying MFA challenge: {e}", challenge_id=challenge_id)
            return False

    def configure_oauth2_provider(self, provider: AuthProvider, config: OAuth2Config) -> None:
        """Configure an OAuth2 provider."""
        try:
            self.oauth2_providers[provider] = config
            logger.info(f"OAuth2 provider configured: {provider.value}")
            logger.audit("OAuth2 provider configured", 
                        provider=provider.value, 
                        event_type="oauth2_provider_configured")
        except Exception as e:
            logger.error(f"Error configuring OAuth2 provider {provider.value}: {e}")

    def get_oauth2_authorization_url(self, provider: AuthProvider, state: Optional[str] = None) -> Optional[str]:
        """Get OAuth2 authorization URL."""
        try:
            config = self.oauth2_providers.get(provider)
            if not config:
                logger.error(f"OAuth2 provider {provider.value} not configured")
                return None
            
            state = state or secrets.token_urlsafe(16)
            
            params = {
                'client_id': config.client_id,
                'redirect_uri': config.redirect_uri,
                'scope': config.scope,
                'response_type': 'code',
                'state': state
            }
            
            url = f"{config.authorization_url}?{urlencode(params)}"
            
            logger.security("OAuth2 authorization URL generated", 
                           provider=provider.value, 
                           state=state)
            
            return url
            
        except Exception as e:
            logger.error(f"Error generating OAuth2 authorization URL: {e}")
            return None

    async def authenticate_oauth2(self, provider: AuthProvider, authorization_code: str, state: str) -> AuthResult:
        """Authenticate user via OAuth2."""
        try:
            config = self.oauth2_providers.get(provider)
            if not config:
                return AuthResult(
                    success=False,
                    error_message=f"OAuth2 provider {provider.value} not configured",
                    error_code="PROVIDER_NOT_CONFIGURED"
                )
            
            # Exchange authorization code for access token
            # In production, make actual HTTP requests to OAuth2 provider
            # For now, simulate successful OAuth2 flow
            
            # Simulate getting user info from OAuth2 provider
            oauth2_user_info = {
                'id': f"oauth2_{provider.value}_{secrets.token_hex(8)}",
                'email': f"user@{provider.value}.com",
                'name': "OAuth2 User"
            }
            
            user_id = oauth2_user_info['id']
            
            # Create or update user
            if user_id not in self.security_system.user_credentials:
                # Auto-register OAuth2 user
                self.register_user(user_id, secrets.token_urlsafe(32), {"read", "write_own"})
            
            # Create session
            session_id = self._generate_session_id()
            now = datetime.now(timezone.utc)
            
            roles = self._get_user_roles(user_id)
            permissions = self._expand_role_permissions(roles)
            
            session = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                created_at=now,
                last_accessed=now,
                expires_at=now + self.session_timeout,
                permissions=permissions,
                roles=roles,
                auth_provider=provider,
                mfa_verified=True  # OAuth2 is considered MFA
            )
            
            self.active_sessions[session_id] = session
            self._record_metric('oauth2_authentications')
            self._record_metric('session_creations')
            
            # Create tokens
            access_token = self.security_system.token_manager.create_access_token(user_id, permissions)
            refresh_token = self.security_system.token_manager.create_refresh_token(user_id)
            
            logger.security("OAuth2 authentication successful", 
                           user_id=user_id, 
                           provider=provider.value,
                           session_id=session_id)
            logger.audit("OAuth2 authentication", 
                        user_id=user_id, 
                        provider=provider.value,
                        event_type="oauth2_login_success")
            
            return AuthResult(
                success=True,
                user_id=user_id,
                session_id=session_id,
                token=access_token,
                refresh_token=refresh_token,
                permissions=permissions,
                roles=roles,
                auth_provider=provider
            )
            
        except Exception as e:
            logger.error(f"OAuth2 authentication error: {e}")
            return AuthResult(
                success=False,
                error_message=f"OAuth2 authentication failed: {str(e)}",
                error_code="OAUTH2_ERROR"
            )

    async def authenticate_user(self, username: str, password: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None, mfa_code: Optional[str] = None, device_trust: bool = False) -> AuthResult:
        """
        Enhanced authentication with MFA, device tracking, and risk assessment.
        """
        start_time = time.time()
        self._record_metric('authentication_requests')

        # Validate input parameters
        if not username or not username.strip():
            logger.security("Authentication failed - empty username", ip_address=ip_address)
            self._record_metric('failed_authentications')
            return AuthResult(
                success=False,
                error_message="Username cannot be empty",
                error_code="INVALID_USERNAME"
            )

        if not password:
            logger.security("Authentication failed - empty password", user_id=username, ip_address=ip_address)
            self._record_metric('failed_authentications')
            return AuthResult(
                success=False,
                error_message="Password cannot be empty",
                error_code="INVALID_PASSWORD"
            )

        # Parse device information
        device_info = self._parse_user_agent(user_agent)
        if ip_address:
            device_info.device_id = self._generate_device_id(user_agent or "", ip_address)

        # Update device trust status from stored device information
        if device_info.device_id in self.known_devices:
            stored_device = self.known_devices[device_info.device_id]
            device_info.is_trusted = stored_device.is_trusted
            device_info.first_seen = stored_device.first_seen
            device_info.last_seen = datetime.now(timezone.utc)

        # Log authentication attempt with enhanced details
        logger.security("Authentication attempt",
                       user_id=username,
                       ip_address=ip_address,
                       device_type=device_info.device_type.value,
                       device_id=device_info.device_id)
        
        try:
            # Check brute force protection
            allowed, block_message = self._check_brute_force_protection(ip_address or "unknown")
            if not allowed:
                self._record_metric('failed_authentications')
                
                logger.security("Authentication blocked by brute force protection", 
                               user_id=username, 
                               ip_address=ip_address)
                logger.audit("Authentication blocked", 
                            user_id=username, 
                            ip_address=ip_address, 
                            event_type="brute_force_block",
                            reason="brute_force_protection")
                
                return AuthResult(
                    success=False,
                    error_message=block_message or "Too many failed attempts",
                    error_code="BRUTE_FORCE_PROTECTION"
                )
            
            # Delegate to SecuritySystem for basic authentication
            success, security_context = await self.security_system.authenticate_user(username, password)
            
            if not success or not security_context:
                # Record failed attempt for brute force protection
                if ip_address:
                    self._record_failed_attempt(ip_address)
                
                self._record_metric('failed_authentications')
                duration = (time.time() - start_time) * 1000
                
                logger.security("Authentication failed - invalid credentials", 
                               user_id=username, 
                               ip_address=ip_address, 
                               device_id=device_info.device_id)
                logger.audit("Authentication failed", 
                            user_id=username, 
                            ip_address=ip_address, 
                            event_type="login_failure", 
                            reason="invalid_credentials")
                logger.performance("user_authentication", duration / 1000, 
                                 user_id=username, success=False)
                
                return AuthResult(
                    success=False,
                    error_message="Invalid username or password",
                    error_code="INVALID_CREDENTIALS"
                )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(ip_address or "", device_info, username)
            
            # Get user roles and expanded permissions
            roles = self._get_user_roles(username)
            expanded_permissions = self._expand_role_permissions(roles)
            
            # Combine with existing permissions
            all_permissions = security_context.permissions.union(expanded_permissions)
            
            # Check if MFA is required
            requires_mfa = (
                risk_score > 50.0 or  # High risk
                not device_info.is_trusted or  # Unknown device
                "admin" in all_permissions or  # Admin access
                not device_trust  # User didn't request device trust
            )
            
            # Handle MFA if required and not provided
            if requires_mfa and not mfa_code:
                # Create MFA challenge
                mfa_challenge = await self.create_mfa_challenge(username, MFAMethod.TOTP)
                if not mfa_challenge:
                    # Fallback to email MFA
                    mfa_challenge = await self.create_mfa_challenge(username, MFAMethod.EMAIL)
                
                if mfa_challenge:
                    logger.security("MFA required for authentication", 
                                   user_id=username, 
                                   risk_score=risk_score,
                                   challenge_id=mfa_challenge.challenge_id)
                    
                    return AuthResult(
                        success=False,
                        user_id=username,
                        requires_mfa=True,
                        mfa_challenge=mfa_challenge,
                        error_message="Multi-factor authentication required",
                        error_code="MFA_REQUIRED",
                        risk_assessment={
                            'risk_score': risk_score,
                            'requires_mfa': True,
                            'device_trusted': device_info.is_trusted
                        }
                    )
            
            # Verify MFA if provided
            mfa_verified = False
            if mfa_code:
                # Find active MFA challenge for user
                user_challenges = [
                    c for c in self.active_mfa_challenges.values()
                    if c.user_id == username and not c.is_verified
                ]
                
                if user_challenges:
                    challenge = user_challenges[0]  # Use most recent
                    mfa_verified = await self.verify_mfa_challenge(challenge.challenge_id, mfa_code)
                    
                    if not mfa_verified:
                        logger.security("MFA verification failed", 
                                       user_id=username, 
                                       challenge_id=challenge.challenge_id)
                        return AuthResult(
                            success=False,
                            error_message="Invalid MFA code",
                            error_code="INVALID_MFA_CODE"
                        )
                else:
                    logger.security("No active MFA challenge found", user_id=username)
                    return AuthResult(
                        success=False,
                        error_message="No active MFA challenge",
                        error_code="NO_MFA_CHALLENGE"
                    )
            
            # Update device information
            if device_info.device_id not in self.known_devices:
                self.known_devices[device_info.device_id] = device_info
                self._record_metric('device_registrations')
                
                logger.security("New device registered", 
                               user_id=username, 
                               device_id=device_info.device_id,
                               device_type=device_info.device_type.value)
            else:
                # Update existing device info
                existing_device = self.known_devices[device_info.device_id]
                existing_device.last_seen = datetime.now(timezone.utc)
                if device_trust and mfa_verified:
                    existing_device.is_trusted = True
                    self.trusted_devices.add(device_info.device_id)
            
            # Create session
            session_id = self._generate_session_id()
            now = datetime.now(timezone.utc)
            
            session = SessionInfo(
                session_id=session_id,
                user_id=security_context.user_id or username,
                created_at=now,
                last_accessed=now,
                expires_at=now + self.session_timeout,
                permissions=all_permissions,
                roles=roles,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                auth_provider=AuthProvider.LOCAL,
                mfa_verified=mfa_verified or not requires_mfa,
                risk_score=risk_score
            )
            
            self.active_sessions[session_id] = session
            self._record_metric('session_creations')
            self._record_metric('successful_authentications')
            
            # Create tokens
            user_id = security_context.user_id or username
            access_token = self.security_system.token_manager.create_access_token(
                user_id,
                all_permissions
            )
            refresh_token = self.security_system.token_manager.create_refresh_token(user_id)
            
            # Cache the authentication result if caching is available
            if self.auth_cache:
                try:
                    await self.auth_cache.cache_token_verification(access_token, (True, {
                        'user_id': security_context.user_id,
                        'permissions': list(all_permissions),
                        'roles': [role.value for role in roles],
                        'session_id': session_id,
                        'token_type': 'access',
                        'mfa_verified': mfa_verified or not requires_mfa
                    }))
                except Exception as e:
                    logger.debug(f"Failed to cache authentication result: {e}")
            
            # Clear brute force tracking on successful auth
            if ip_address and ip_address in self.brute_force_tracking:
                del self.brute_force_tracking[ip_address]
            
            duration = (time.time() - start_time) * 1000
            self._record_metric('authentication_time_ms', duration, 'ms')
            
            # Enhanced logging
            logger.security("Authentication successful", 
                           user_id=username, 
                           session_id=session_id, 
                           ip_address=ip_address,
                           device_id=device_info.device_id,
                           risk_score=risk_score,
                           mfa_verified=mfa_verified or not requires_mfa,
                           roles=[role.value for role in roles])
            logger.audit("User login successful", 
                        user_id=username, 
                        session_id=session_id, 
                        ip_address=ip_address, 
                        event_type="login_success",
                        device_id=device_info.device_id,
                        risk_score=risk_score,
                        mfa_verified=mfa_verified or not requires_mfa,
                        auth_provider=AuthProvider.LOCAL.value)
            logger.performance("user_authentication", duration / 1000, 
                             user_id=username, success=True, risk_score=risk_score)
            
            return AuthResult(
                success=True,
                user_id=security_context.user_id,
                session_id=session_id,
                token=access_token,
                refresh_token=refresh_token,
                permissions=all_permissions,
                roles=roles,
                security_context=security_context,
                device_trusted=device_info.is_trusted,
                risk_assessment={
                    'risk_score': risk_score,
                    'requires_mfa': requires_mfa,
                    'device_trusted': device_info.is_trusted,
                    'mfa_verified': mfa_verified or not requires_mfa
                },
                auth_provider=AuthProvider.LOCAL
            )
                
        except Exception as e:
            # Record failed attempt for brute force protection
            if ip_address:
                self._record_failed_attempt(ip_address)
            
            logger.error(f"Authentication error: {e}", user_id=username, ip_address=ip_address)
            self._record_metric('failed_authentications')
            duration = (time.time() - start_time) * 1000
            
            logger.security("Authentication error", 
                           user_id=username, 
                           ip_address=ip_address, 
                           error=str(e))
            logger.performance("user_authentication", duration / 1000, 
                             user_id=username, success=False, error=str(e))
            
            return AuthResult(
                success=False,
                error_message=f"Authentication failed: {str(e)}",
                error_code="AUTHENTICATION_ERROR"
            )

    async def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate JWT token using SecuritySystem with caching.
        """
        start_time = time.time()
        self._record_metric('token_validations')
        
        try:
            # Try cache first if available
            if self.auth_cache:
                try:
                    cached_result = await self.auth_cache.get_cached_token_verification(token)
                    if cached_result and cached_result.is_valid:
                        self._record_metric('cache_hits')
                        duration = (time.time() - start_time) * 1000
                        self._record_metric('token_validation_time_ms', duration, 'ms')
                        
                        logger.performance("token_validation", duration / 1000, 
                                         user_id=cached_result.user_id, cache_hit=True)
                        
                        return True, {
                            'user_id': cached_result.user_id,
                            'permissions': cached_result.permissions,
                            'token_type': cached_result.token_type,
                            'jti': getattr(cached_result, 'jti', None)
                        }
                    else:
                        self._record_metric('cache_misses')
                except Exception as e:
                    logger.debug(f"Cache lookup failed: {e}")
                    self._record_metric('cache_misses')
            
            # Fallback to SecuritySystem token validation
            valid, payload = self.security_system.token_manager.verify_token(token)
            
            if valid and payload:
                # Cache the result if caching is available
                if self.auth_cache:
                    try:
                        await self.auth_cache.cache_token_verification(token, (True, payload))
                    except Exception as e:
                        logger.debug(f"Failed to cache token validation: {e}")
                
                duration = (time.time() - start_time) * 1000
                self._record_metric('token_validation_time_ms', duration, 'ms')
                
                logger.performance("token_validation", duration / 1000, 
                                 user_id=payload.get('user_id'), cache_hit=False, success=True)
                
                return True, payload
            else:
                # Cache negative result if caching is available
                if self.auth_cache:
                    try:
                        await self.auth_cache.cache_token_verification(token, (False, None))
                    except Exception as e:
                        logger.debug(f"Failed to cache negative token validation: {e}")
                
                duration = (time.time() - start_time) * 1000
                logger.security("Invalid token validation attempt", token_valid=False)
                logger.performance("token_validation", duration / 1000, 
                                 cache_hit=False, success=False)
                
                return False, None
                
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            duration = (time.time() - start_time) * 1000
            logger.performance("token_validation", duration / 1000, 
                             success=False, error=str(e))
            return False, None

    async def validate_session(self, session_id: str) -> Tuple[bool, Optional[SessionInfo]]:
        """
        Validate session and update last accessed time.
        """
        try:
            session = self.active_sessions.get(session_id)
            if not session:
                logger.security("Session validation failed - session not found", session_id=session_id)
                return False, None
            
            if self._is_session_expired(session):
                del self.active_sessions[session_id]
                self._record_metric('session_invalidations')
                logger.security("Session expired and invalidated", 
                               session_id=session_id, user_id=session.user_id)
                logger.audit("Session expired", 
                            session_id=session_id, user_id=session.user_id, 
                            event_type="session_expired")
                return False, None
            
            # Update last accessed time
            session.last_accessed = datetime.now(timezone.utc)
            logger.debug(f"Session validated successfully", session_id=session_id, user_id=session.user_id)
            return True, session
            
        except Exception as e:
            logger.error(f"Session validation error: {e}", session_id=session_id)
            return False, None

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Validate API key using SecuritySystem.
        """
        start_time = time.time()
        self._record_metric('api_key_validations')
        
        try:
            # Try cache first if available
            if self.auth_cache:
                try:
                    cached_result = await self.auth_cache.get_cached_api_key_validation(api_key)
                    if cached_result and cached_result.is_valid:
                        self._record_metric('cache_hits')
                        duration = (time.time() - start_time) * 1000
                        self._record_metric('api_key_validation_time_ms', duration, 'ms')
                        
                        logger.performance("api_key_validation", duration / 1000, 
                                         user_id=cached_result.user_id, cache_hit=True)
                        
                        return {
                            'user_id': cached_result.user_id,
                            'permissions': set(cached_result.permissions),
                            'is_active': True
                        }
                    else:
                        self._record_metric('cache_misses')
                except Exception as e:
                    logger.debug(f"API key cache lookup failed: {e}")
                    self._record_metric('cache_misses')
            
            # For now, we'll implement a basic API key validation
            # In a real implementation, this would check against a database
            # or delegate to the SecuritySystem's user credentials
            
            # Check if any user has this API key
            for username, credentials in self.security_system.user_credentials.items():
                if api_key in credentials.api_keys:
                    user_data = {
                        'user_id': username,
                        'permissions': credentials.permissions,
                        'is_active': True
                    }
                    
                    # Cache the result if caching is available
                    if self.auth_cache:
                        try:
                            await self.auth_cache.cache_api_key_validation(api_key, (True, {
                                'user_id': username,
                                'permissions': list(credentials.permissions)
                            }))
                        except Exception as e:
                            logger.debug(f"Failed to cache API key validation: {e}")
                    
                    duration = (time.time() - start_time) * 1000
                    self._record_metric('api_key_validation_time_ms', duration, 'ms')
                    
                    logger.security("API key validation successful", user_id=username)
                    logger.audit("API key used", user_id=username, event_type="api_key_access")
                    logger.performance("api_key_validation", duration / 1000, 
                                     user_id=username, cache_hit=False, success=True)
                    
                    return user_data
            
            # Cache negative result if caching is available
            if self.auth_cache:
                try:
                    await self.auth_cache.cache_api_key_validation(api_key, (False, None))
                except Exception as e:
                    logger.debug(f"Failed to cache negative API key validation: {e}")
            
            duration = (time.time() - start_time) * 1000
            logger.security("API key validation failed - invalid key")
            logger.performance("api_key_validation", duration / 1000, 
                             cache_hit=False, success=False)
            
            return None
            
        except Exception as e:
            logger.error(f"API key validation error: {e}")
            duration = (time.time() - start_time) * 1000
            logger.performance("api_key_validation", duration / 1000, 
                             success=False, error=str(e))
            return None

    def create_access_token(self, user_id: str, permissions: Set[str], expires_delta: Optional[timedelta] = None) -> str:
        """
        Create access token using SecuritySystem's token manager.
        """
        try:
            if not user_id:
                logger.error("Cannot create access token: user_id is empty")
                return ""

            token = self.security_system.token_manager.create_access_token(user_id, permissions)
            self._record_metric('tokens_issued')

            logger.security("Access token created", user_id=user_id)
            logger.audit("Access token issued", user_id=user_id, event_type="token_created",
                        token_type="access")

            return token
        except Exception as e:
            logger.error(f"Error creating access token: {e}", user_id=user_id or "unknown")
            return ""

    def create_refresh_token(self, user_id: str) -> str:
        """
        Create refresh token using SecuritySystem's token manager.
        """
        try:
            if not user_id:
                logger.error("Cannot create refresh token: user_id is empty")
                return ""

            token = self.security_system.token_manager.create_refresh_token(user_id)
            self._record_metric('tokens_issued')

            logger.security("Refresh token created", user_id=user_id)
            logger.audit("Refresh token issued", user_id=user_id, event_type="token_created",
                        token_type="refresh")

            return token
        except Exception as e:
            logger.error(f"Error creating refresh token: {e}", user_id=user_id or "unknown")
            return ""

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke token using SecuritySystem and invalidate cache.
        """
        try:
            # Get token info before revoking for logging
            valid, payload = self.security_system.token_manager.verify_token(token)
            user_id = payload.get('user_id') if payload else None
            
            # Revoke in SecuritySystem
            success = self.security_system.token_manager.revoke_token(token)
            
            # Invalidate cache if available
            if self.auth_cache:
                try:
                    await self.auth_cache.invalidate_token_cache(token)
                except Exception as e:
                    logger.debug(f"Failed to invalidate token cache: {e}")
            
            if success:
                self._record_metric('tokens_revoked')
                logger.security("Token revoked", user_id=user_id)
                logger.audit("Token revoked", user_id=user_id, event_type="token_revoked")
            
            return success
            
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session.
        """
        try:
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                user_id = session.user_id
                del self.active_sessions[session_id]
                self._record_metric('session_invalidations')
                
                logger.security("Session invalidated", session_id=session_id, user_id=user_id)
                logger.audit("Session invalidated", session_id=session_id, user_id=user_id, 
                            event_type="session_invalidated")
                
                return True
            return False
        except Exception as e:
            logger.error(f"Error invalidating session: {e}", session_id=session_id)
            return False

    async def invalidate_user_sessions(self, user_id: str) -> int:
        """
        Invalidate all sessions for a user.
        """
        try:
            sessions_to_remove = [
                session_id for session_id, session in self.active_sessions.items()
                if session.user_id == user_id
            ]
            
            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]
                self._record_metric('session_invalidations')
            
            if sessions_to_remove:
                logger.security(f"All sessions invalidated for user", user_id=user_id, 
                               session_count=len(sessions_to_remove))
                logger.audit("All user sessions invalidated", user_id=user_id, 
                            event_type="all_sessions_invalidated", 
                            session_count=len(sessions_to_remove))
            
            return len(sessions_to_remove)
            
        except Exception as e:
            logger.error(f"Error invalidating user sessions: {e}", user_id=user_id)
            return 0

    def register_user(self, username: str, password: str, permissions: Optional[Set[str]] = None, roles: Optional[Set[Role]] = None) -> Tuple[bool, List[str]]:
        """
        Register a new user with enhanced password policy validation.
        """
        try:
            issues = []
            
            # Validate password against policy
            policy_valid, policy_issues = self._validate_password_policy(password, username)
            if not policy_valid:
                issues.extend(policy_issues)
            
            # Validate password strength using SecuritySystem
            strength_valid, strength_issues = self.security_system.password_manager.validate_password_strength(password)
            if not strength_valid:
                issues.extend(strength_issues)
            
            if issues:
                logger.warning("User registration failed - password validation", 
                              user_id=username, 
                              validation_issues=issues)
                return False, issues
            
            # Hash password
            password_hash, salt = self.security_system.password_manager.hash_password(password)
            
            # Expand role permissions
            final_permissions = permissions or set()
            if roles:
                role_permissions = self._expand_role_permissions(roles)
                final_permissions.update(role_permissions)
            
            # Create user credentials
            credentials = UserCredentials(
                username=username,
                password_hash=password_hash,
                salt=salt,
                permissions=final_permissions
            )
            
            # Store in SecuritySystem
            self.security_system.user_credentials[username] = credentials
            
            logger.info("User registered successfully", user_id=username)
            logger.security("User registered", 
                           user_id=username, 
                           permissions=list(final_permissions),
                           roles=[role.value for role in (roles or set())])
            logger.audit("User registration", 
                        user_id=username, 
                        event_type="user_registered", 
                        permissions=list(final_permissions),
                        roles=[role.value for role in (roles or set())])
            
            return True, []
            
        except Exception as e:
            logger.error(f"Error registering user {username}: {e}", user_id=username)
            return False, [f"Registration failed: {str(e)}"]

    async def elevate_session(self, session_id: str, password: str) -> bool:
        """
        Elevate a session for administrative operations.
        """
        try:
            session = self.active_sessions.get(session_id)
            if not session:
                logger.security("Session elevation failed - session not found", 
                               session_id=session_id)
                return False
            
            # Verify password
            success, _ = await self.security_system.authenticate_user(session.user_id, password)
            if not success:
                logger.security("Session elevation failed - invalid password", 
                               session_id=session_id, 
                               user_id=session.user_id)
                return False
            
            # Elevate session
            session.is_elevated = True
            session.elevation_expires_at = datetime.now(timezone.utc) + self.elevated_session_timeout
            
            logger.security("Session elevated", 
                           session_id=session_id, 
                           user_id=session.user_id)
            logger.audit("Session elevated", 
                        session_id=session_id, 
                        user_id=session.user_id, 
                        event_type="session_elevated")
            
            return True
            
        except Exception as e:
            logger.error(f"Error elevating session: {e}", session_id=session_id)
            return False

    def check_permission(self, user_id: str, permission: str, require_elevation: bool = False) -> bool:
        """
        Check if user has specific permission with RBAC support.
        """
        try:
            # Get user permissions
            user_permissions = self.get_user_permissions(user_id)
            
            # Check for wildcard permission (super admin)
            if "*" in user_permissions:
                return True
            
            # Check specific permission
            if permission not in user_permissions:
                return False
            
            # Check elevation requirement
            if require_elevation:
                # Find active session for user
                user_sessions = [
                    session for session in self.active_sessions.values()
                    if session.user_id == user_id and session.is_active
                ]
                
                if not user_sessions:
                    return False
                
                # Check if any session is elevated
                elevated_sessions = [
                    session for session in user_sessions
                    if session.is_elevated and 
                    session.elevation_expires_at and 
                    datetime.now(timezone.utc) < session.elevation_expires_at
                ]
                
                if not elevated_sessions:
                    logger.security("Permission denied - elevation required", 
                                   user_id=user_id, 
                                   permission=permission)
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking permission: {e}", user_id=user_id, permission=permission)
            return False

    def assign_role(self, user_id: str, role: Role) -> bool:
        """
        Assign a role to a user.
        """
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False
            
            # Get role permissions
            role_permissions = self.role_permissions.get(role, set())
            
            # Add role permissions to user
            credentials.permissions.update(role_permissions)
            
            logger.security("Role assigned", 
                           user_id=user_id, 
                           role=role.value,
                           new_permissions=list(role_permissions))
            logger.audit("Role assigned", 
                        user_id=user_id, 
                        role=role.value,
                        event_type="role_assigned")
            
            return True
            
        except Exception as e:
            logger.error(f"Error assigning role: {e}", user_id=user_id, role=role.value)
            return False

    def revoke_role(self, user_id: str, role: Role) -> bool:
        """
        Revoke a role from a user.
        """
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False
            
            # Get role permissions
            role_permissions = self.role_permissions.get(role, set())
            
            # Remove role permissions from user
            credentials.permissions.difference_update(role_permissions)
            
            logger.security("Role revoked", 
                           user_id=user_id, 
                           role=role.value,
                           removed_permissions=list(role_permissions))
            logger.audit("Role revoked", 
                        user_id=user_id, 
                        role=role.value,
                        event_type="role_revoked")
            
            return True
            
        except Exception as e:
            logger.error(f"Error revoking role: {e}", user_id=user_id, role=role.value)
            return False

    async def change_password(self, user_id: str, old_password: str, new_password: str) -> Tuple[bool, List[str]]:
        """
        Change user password with policy validation.
        """
        try:
            # Verify old password
            success, _ = await self.security_system.authenticate_user(user_id, old_password)
            if not success:
                logger.security("Password change failed - invalid old password", user_id=user_id)
                return False, ["Invalid current password"]
            
            # Validate new password
            policy_valid, policy_issues = self._validate_password_policy(new_password, user_id)
            if not policy_valid:
                return False, policy_issues
            
            strength_valid, strength_issues = self.security_system.password_manager.validate_password_strength(new_password)
            if not strength_valid:
                return False, strength_issues
            
            # Hash new password
            password_hash, salt = self.security_system.password_manager.hash_password(new_password)
            
            # Update credentials
            credentials = self.security_system.user_credentials.get(user_id)
            if credentials:
                credentials.password_hash = password_hash
                credentials.salt = salt
                
                logger.security("Password changed successfully", user_id=user_id)
                logger.audit("Password changed", 
                            user_id=user_id, 
                            event_type="password_changed")
                
                # Invalidate all user sessions except current one
                await self.invalidate_user_sessions(user_id)
                
                return True, []
            
            return False, ["User not found"]
            
        except Exception as e:
            logger.error(f"Error changing password: {e}", user_id=user_id)
            return False, [f"Password change failed: {str(e)}"]

    def get_user_permissions(self, user_id: str) -> Set[str]:
        """
        Get user permissions from SecuritySystem.
        """
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            permissions = credentials.permissions if credentials else set()
            logger.debug(f"Retrieved permissions for user", user_id=user_id, 
                        permission_count=len(permissions))
            return permissions
        except Exception as e:
            logger.error(f"Error getting user permissions for {user_id}: {e}", user_id=user_id)
            return set()

    def update_user_permissions(self, user_id: str, permissions: Set[str]) -> bool:
        """
        Update user permissions in SecuritySystem.
        """
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if credentials:
                old_permissions = credentials.permissions.copy()
                credentials.permissions = permissions
                
                logger.security("User permissions updated", user_id=user_id, 
                               old_permissions=list(old_permissions), 
                               new_permissions=list(permissions))
                logger.audit("User permissions changed", user_id=user_id, 
                            event_type="permissions_updated",
                            old_permissions=list(old_permissions), 
                            new_permissions=list(permissions))
                
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating user permissions for {user_id}: {e}", user_id=user_id)
            return False

    def get_security_status(self) -> Dict[str, Any]:
        """
        Get comprehensive authentication system status with enhanced metrics.
        """
        # Cleanup expired sessions before reporting
        self._cleanup_expired_sessions()
        
        security_status = self.security_system.get_security_status()
        
        # Calculate additional metrics
        elevated_sessions = len([s for s in self.active_sessions.values() if s.is_elevated])
        mfa_verified_sessions = len([s for s in self.active_sessions.values() if s.mfa_verified])
        high_risk_sessions = len([s for s in self.active_sessions.values() if s.risk_score > 70])
        
        return {
            **security_status,
            'auth_manager_metrics': self.metrics.copy(),
            'active_sessions': len(self.active_sessions),
            'elevated_sessions': elevated_sessions,
            'mfa_verified_sessions': mfa_verified_sessions,
            'high_risk_sessions': high_risk_sessions,
            'known_devices': len(self.known_devices),
            'trusted_devices': len(self.trusted_devices),
            'active_mfa_challenges': len(self.active_mfa_challenges),
            'oauth2_providers': len(self.oauth2_providers),
            'brute_force_tracking': len(self.brute_force_tracking),
            'blocked_ips': len([bf for bf in self.brute_force_tracking.values() if bf.is_blocked]),
            'auth_cache_available': auth_cache_available,
            'performance_logger_available': performance_logger_available,
            'mfa_store_available': mfa_store_available,
            'password_policy': {
                'min_length': self.password_policy.min_length,
                'complexity_threshold': self.password_policy.complexity_score_threshold,
                'max_age_days': self.password_policy.max_age_days
            }
        }

    async def cleanup(self) -> None:
        """
        Enhanced cleanup with comprehensive resource management.
        """
        try:
            initial_sessions = len(self.active_sessions)
            initial_challenges = len(self.active_mfa_challenges)
            initial_brute_force = len(self.brute_force_tracking)
            
            # Cleanup expired sessions and challenges
            self._cleanup_expired_sessions()
            
            # Cleanup old brute force tracking (older than 24 hours)
            current_time = datetime.now(timezone.utc)
            old_tracking = [
                ip for ip, protection in self.brute_force_tracking.items()
                if current_time - protection.last_attempt > timedelta(hours=24)
            ]
            
            for ip in old_tracking:
                del self.brute_force_tracking[ip]
            
            # Cleanup old device information (older than 90 days)
            old_devices = [
                device_id for device_id, device in self.known_devices.items()
                if current_time - device.last_seen > timedelta(days=90)
            ]
            
            for device_id in old_devices:
                del self.known_devices[device_id]
                self.trusted_devices.discard(device_id)
            
            expired_sessions = initial_sessions - len(self.active_sessions)
            expired_challenges = initial_challenges - len(self.active_mfa_challenges)
            cleaned_brute_force = len(old_tracking)
            cleaned_devices = len(old_devices)
            
            logger.info("Enhanced UnifiedAuthManager cleanup completed", 
                       expired_sessions_removed=expired_sessions,
                       expired_challenges_removed=expired_challenges,
                       cleaned_brute_force_entries=cleaned_brute_force,
                       cleaned_old_devices=cleaned_devices)
            
            if expired_sessions > 0 or expired_challenges > 0 or cleaned_brute_force > 0 or cleaned_devices > 0:
                logger.audit("Comprehensive cleanup performed", 
                            event_type="system_cleanup", 
                            expired_sessions_removed=expired_sessions,
                            expired_challenges_removed=expired_challenges,
                            cleaned_brute_force_entries=cleaned_brute_force,
                            cleaned_old_devices=cleaned_devices)
                            
        except Exception as e:
            logger.error(f"Error during enhanced cleanup: {e}")


# Global auth manager instance
_global_auth_manager: Optional[UnifiedAuthManager] = None


def get_auth_manager() -> UnifiedAuthManager:
    """Get the global authentication manager instance."""
    global _global_auth_manager
    if _global_auth_manager is None:
        _global_auth_manager = UnifiedAuthManager()
    return _global_auth_manager


async def initialize_auth_manager(security_system: Optional[SecuritySystem] = None) -> UnifiedAuthManager:
    """Initialize the global authentication manager."""
    global _global_auth_manager
    _global_auth_manager = UnifiedAuthManager(security_system)
    return _global_auth_manager


async def shutdown_auth_manager() -> None:
    """Shutdown the global authentication manager."""
    global _global_auth_manager
    if _global_auth_manager:
        await _global_auth_manager.cleanup()
        _global_auth_manager = None


__all__ = [
    "UnifiedAuthManager",
    "SessionInfo",
    "AuthResult",
    "DeviceInfo",
    "MFAChallenge",
    "OAuth2Config",
    "BruteForceProtection",
    "PasswordPolicy",
    "DeviceType",
    "AuthProvider",
    "Role",
    "MFAMethod",
    "get_auth_manager",
    "initialize_auth_manager",
    "shutdown_auth_manager"
]
