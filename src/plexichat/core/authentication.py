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
from plexichat.core.database.manager import database_manager

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

        # Initialize database manager
        self.db_manager = database_manager

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

        # Session management - now database-backed
        self.session_timeout = timedelta(hours=1)
        self.elevated_session_timeout = timedelta(minutes=15)

        # OAuth2 providers
        self.oauth2_providers: Dict[AuthProvider, OAuth2Config] = {}

        # Brute force protection - keep in memory for performance
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

        logger.info("Advanced UnifiedAuthManager initialized with database-backed storage")
        logger.audit("Authentication manager initialized",
                    component="auth_manager",
                    event_type="system_initialization",
                    features=["mfa", "oauth2", "rbac", "brute_force_protection", "device_tracking", "database_storage"])

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

    async def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions and MFA challenges from database."""
        current_time = datetime.now(timezone.utc)
        current_time_str = current_time.isoformat()

        try:
            async with self.db_manager.get_session() as session:
                # Clean up expired sessions
                expired_sessions_result = await session.fetchall(
                    "SELECT id, user_id FROM sessions WHERE expires_at < ? AND is_active = 1",
                    {"1": current_time_str}
                )

                if expired_sessions_result:
                    # Mark sessions as inactive
                    await session.execute(
                        "UPDATE sessions SET is_active = 0, updated_at = ? WHERE expires_at < ? AND is_active = 1",
                        {"1": current_time_str, "2": current_time_str}
                    )

                    for row in expired_sessions_result:
                        self._record_metric('session_invalidations')
                        logger.security("Session expired and marked inactive",
                                       session_id=row['id'],
                                       user_id=row['user_id'])
                        logger.audit("Session expired",
                                    session_id=row['id'],
                                    user_id=row['user_id'],
                                    event_type="session_expired")

                # Clean up expired MFA challenges
                expired_challenges_result = await session.fetchall(
                    "SELECT id, challenge_id, user_id FROM mfa_challenges WHERE expires_at < ?",
                    {"1": current_time_str}
                )

                if expired_challenges_result:
                    # Delete expired MFA challenges
                    await session.execute(
                        "DELETE FROM mfa_challenges WHERE expires_at < ?",
                        {"1": current_time_str}
                    )

                    for row in expired_challenges_result:
                        logger.security("MFA challenge expired and removed",
                                       challenge_id=row['challenge_id'],
                                       user_id=row['user_id'])

                await session.commit()

        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")

    async def _calculate_risk_score(self, ip_address: str, device_info: DeviceInfo, user_id: str) -> float:
        """Calculate risk score for authentication attempt."""
        risk_score = 0.0

        try:
            # Check if IP is from known location
            known_ips = await self._get_user_known_ips(user_id)
            if ip_address not in known_ips:
                risk_score += 30.0

            # Check if device is known and trusted
            device_known = await self._is_device_known(device_info.device_id)
            device_trusted = await self._is_device_trusted(device_info.device_id)

            if not device_known:
                risk_score += 25.0
            elif not device_trusted:
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

    async def _get_user_known_ips(self, user_id: str) -> Set[str]:
        """Get known IP addresses for a user from database."""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.fetchall(
                    "SELECT DISTINCT ip_address FROM sessions WHERE user_id = ? AND ip_address IS NOT NULL AND is_active = 1",
                    {"1": user_id}
                )
                return {row['ip_address'] for row in result}
        except Exception as e:
            logger.error(f"Error getting user known IPs: {e}")
            return set()

    async def _is_device_known(self, device_id: str) -> bool:
        """Check if device is known in database."""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.fetchone(
                    "SELECT id FROM devices WHERE device_id = ?",
                    {"1": device_id}
                )
                return result is not None
        except Exception as e:
            logger.error(f"Error checking if device is known: {e}")
            return False

    async def _is_device_trusted(self, device_id: str) -> bool:
        """Check if device is trusted in database."""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.fetchone(
                    "SELECT is_trusted FROM devices WHERE device_id = ?",
                    {"1": device_id}
                )
                return result is not None and result['is_trusted'] == 1
        except Exception as e:
            logger.error(f"Error checking if device is trusted: {e}")
            return False

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
            
            # Store challenge in database
            try:
                async with self.db_manager.get_session() as db_session:
                    await db_session.execute(
                        "INSERT INTO mfa_challenges (challenge_id, user_id, method, code, expires_at, attempts, max_attempts, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        {
                            "1": challenge.challenge_id,
                            "2": challenge.user_id,
                            "3": challenge.method.value,
                            "4": challenge.code,
                            "5": challenge.expires_at.isoformat(),
                            "6": challenge.attempts,
                            "7": challenge.max_attempts,
                            "8": int(challenge.is_verified)
                        }
                    )
                    await db_session.commit()

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
                logger.error(f"Error storing MFA challenge: {e}")
                return None
            
        except Exception as e:
            logger.error(f"Error creating MFA challenge: {e}", user_id=user_id)
            return None

    async def verify_mfa_challenge(self, challenge_id: str, user_code: str) -> bool:
        """Verify a multi-factor authentication challenge."""
        try:
            async with self.db_manager.get_session() as db_session:
                # Get challenge from database
                challenge_result = await db_session.fetchone(
                    "SELECT id, user_id, method, code, expires_at, attempts, max_attempts FROM mfa_challenges WHERE challenge_id = ? AND is_verified = 0",
                    {"1": challenge_id}
                )

                if not challenge_result:
                    logger.security("MFA verification failed - challenge not found",
                                   challenge_id=challenge_id)
                    return False

                # Check if challenge expired
                if datetime.now(timezone.utc) > datetime.fromisoformat(challenge_result['expires_at']):
                    await db_session.execute(
                        "DELETE FROM mfa_challenges WHERE id = ?",
                        {"1": challenge_result['id']}
                    )
                    await db_session.commit()

                    logger.security("MFA verification failed - challenge expired",
                                   challenge_id=challenge_id,
                                   user_id=challenge_result['user_id'])
                    return False

                # Check attempt limit
                attempts = challenge_result['attempts'] + 1
                if attempts > challenge_result['max_attempts']:
                    await db_session.execute(
                        "DELETE FROM mfa_challenges WHERE id = ?",
                        {"1": challenge_result['id']}
                    )
                    await db_session.commit()

                    logger.security("MFA verification failed - too many attempts",
                                   challenge_id=challenge_id,
                                   user_id=challenge_result['user_id'],
                                   attempts=attempts)
                    return False

                # Verify code
                method = MFAMethod(challenge_result['method'])
                stored_code = challenge_result['code']
                verified = False

                if method == MFAMethod.TOTP:
                    # Verify TOTP code
                    if self.mfa_store:
                        verified = await self.mfa_store.verify_totp(challenge_result['user_id'], user_code)
                elif method in [MFAMethod.EMAIL, MFAMethod.SMS]:
                    # Verify generated code
                    verified = hmac.compare_digest(stored_code or "", user_code)
                elif method == MFAMethod.BACKUP_CODES:
                    # Verify backup code
                    if self.mfa_store:
                        verified = await self.mfa_store.verify_backup_code(challenge_result['user_id'], user_code)

                if verified:
                    # Mark challenge as verified
                    await db_session.execute(
                        "UPDATE mfa_challenges SET is_verified = 1 WHERE id = ?",
                        {"1": challenge_result['id']}
                    )
                    await db_session.commit()

                    self._record_metric('mfa_verifications')

                    logger.security("MFA verification successful",
                                   challenge_id=challenge_id,
                                   user_id=challenge_result['user_id'],
                                   method=method.value)
                    logger.audit("MFA verification successful",
                                user_id=challenge_result['user_id'],
                                challenge_id=challenge_id,
                                event_type="mfa_verified",
                                method=method.value)

                    return True
                else:
                    # Update attempts
                    await db_session.execute(
                        "UPDATE mfa_challenges SET attempts = ? WHERE id = ?",
                        {"1": attempts, "2": challenge_result['id']}
                    )
                    await db_session.commit()

                    logger.security("MFA verification failed - invalid code",
                                   challenge_id=challenge_id,
                                   user_id=challenge_result['user_id'],
                                   attempts=attempts)
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
            
            # Create session in database
            session_id = self._generate_session_id()
            now = datetime.now(timezone.utc)
            now_str = now.isoformat()
            expires_at_str = (now + self.session_timeout).isoformat()

            roles = self._get_user_roles(user_id)
            permissions = self._expand_role_permissions(roles)
            permissions_json = json.dumps(list(permissions))
            roles_json = json.dumps([role.value for role in roles])

            try:
                async with self.db_manager.get_session() as db_session:
                    await db_session.execute(
                        "INSERT INTO sessions (id, user_id, created_at, last_accessed, expires_at, permissions, roles, auth_provider, mfa_verified, is_active, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        {
                            "1": session_id,
                            "2": user_id,
                            "3": now_str,
                            "4": now_str,
                            "5": expires_at_str,
                            "6": permissions_json,
                            "7": roles_json,
                            "8": provider.value,
                            "9": 1,  # mfa_verified
                            "10": 1,  # is_active
                            "11": 0.0  # risk_score
                        }
                    )
                    await db_session.commit()

                    self._record_metric('oauth2_authentications')
                    self._record_metric('session_creations')
            except Exception as e:
                logger.error(f"Error creating OAuth2 session: {e}")
                return AuthResult(
                    success=False,
                    error_message="Failed to create session",
                    error_code="SESSION_CREATION_FAILED"
                )
            
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

        # Update device trust status from database
        try:
            async with self.db_manager.get_session() as db_session:
                stored_device_result = await db_session.fetchone(
                    "SELECT is_trusted, first_seen, last_seen FROM devices WHERE device_id = ?",
                    {"1": device_info.device_id}
                )

                if stored_device_result:
                    device_info.is_trusted = bool(stored_device_result['is_trusted'])
                    device_info.first_seen = datetime.fromisoformat(stored_device_result['first_seen'])
                    device_info.last_seen = datetime.now(timezone.utc)

                    # Update last_seen in database
                    await db_session.execute(
                        "UPDATE devices SET last_seen = ? WHERE device_id = ?",
                        {"1": device_info.last_seen.isoformat(), "2": device_info.device_id}
                    )
                    await db_session.commit()
        except Exception as e:
            logger.debug(f"Error updating device info from database: {e}")

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
                # Create MFA challenge using database operations
                try:
                    async with self.db_manager.get_session() as db_session:
                        challenge_id = secrets.token_urlsafe(16)
                        challenge = MFAChallenge(
                            challenge_id=challenge_id,
                            user_id=username,
                            method=MFAMethod.TOTP
                        )

                        # Store challenge in database
                        await db_session.execute(
                            "INSERT INTO mfa_challenges (challenge_id, user_id, method, code, expires_at, attempts, max_attempts, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            {
                                "1": challenge.challenge_id,
                                "2": challenge.user_id,
                                "3": challenge.method.value,
                                "4": challenge.code,
                                "5": challenge.expires_at.isoformat(),
                                "6": challenge.attempts,
                                "7": challenge.max_attempts,
                                "8": int(challenge.is_verified)
                            }
                        )
                        await db_session.commit()

                        self._record_metric('mfa_challenges_issued')

                        logger.security("MFA challenge created",
                                       user_id=username,
                                       challenge_id=challenge_id,
                                       method=challenge.method.value)
                        logger.audit("MFA challenge issued",
                                    user_id=username,
                                    challenge_id=challenge_id,
                                    event_type="mfa_challenge_created",
                                    method=challenge.method.value)

                        logger.security("MFA required for authentication",
                                       user_id=username,
                                       risk_score=risk_score,
                                       challenge_id=challenge.challenge_id)

                        return AuthResult(
                            success=False,
                            user_id=username,
                            requires_mfa=True,
                            mfa_challenge=challenge,
                            error_message="Multi-factor authentication required",
                            error_code="MFA_REQUIRED",
                            risk_assessment={
                                'risk_score': risk_score,
                                'requires_mfa': True,
                                'device_trusted': device_info.is_trusted
                            }
                        )
                except Exception as e:
                    logger.error(f"Error creating MFA challenge: {e}")
                    return AuthResult(
                        success=False,
                        error_message="Failed to create MFA challenge",
                        error_code="MFA_CHALLENGE_FAILED"
                    )
            
            # Verify MFA if provided
            mfa_verified = False
            if mfa_code:
                # Find active MFA challenge for user in database
                try:
                    async with self.db_manager.get_session() as db_session:
                        current_time_str = datetime.now(timezone.utc).isoformat()

                        # Get active challenge for user
                        challenge_result = await db_session.fetchone(
                            "SELECT id, challenge_id, user_id, method, code, expires_at, attempts, max_attempts FROM mfa_challenges WHERE user_id = ? AND is_verified = 0 AND expires_at > ? ORDER BY expires_at DESC LIMIT 1",
                            {"1": username, "2": current_time_str}
                        )

                        if not challenge_result:
                            logger.security("No active MFA challenge found", user_id=username)
                            return AuthResult(
                                success=False,
                                error_message="No active MFA challenge",
                                error_code="NO_MFA_CHALLENGE"
                            )

                        challenge_id = challenge_result['challenge_id']
                        attempts = challenge_result['attempts'] + 1

                        # Check if challenge expired
                        if datetime.now(timezone.utc) > datetime.fromisoformat(challenge_result['expires_at']):
                            await db_session.execute(
                                "DELETE FROM mfa_challenges WHERE id = ?",
                                {"1": challenge_result['id']}
                            )
                            await db_session.commit()

                            logger.security("MFA verification failed - challenge expired",
                                           challenge_id=challenge_id,
                                           user_id=username)
                            return AuthResult(
                                success=False,
                                error_message="MFA challenge expired",
                                error_code="MFA_CHALLENGE_EXPIRED"
                            )

                        # Check attempt limit
                        if attempts > challenge_result['max_attempts']:
                            await db_session.execute(
                                "DELETE FROM mfa_challenges WHERE id = ?",
                                {"1": challenge_result['id']}
                            )
                            await db_session.commit()

                            logger.security("MFA verification failed - too many attempts",
                                           challenge_id=challenge_id,
                                           user_id=username,
                                           attempts=attempts)
                            return AuthResult(
                                success=False,
                                error_message="Too many MFA attempts",
                                error_code="MFA_TOO_MANY_ATTEMPTS"
                            )

                        # Verify code
                        method = MFAMethod(challenge_result['method'])
                        stored_code = challenge_result['code']

                        if method == MFAMethod.TOTP:
                            # Verify TOTP code
                            if self.mfa_store:
                                mfa_verified = await self.mfa_store.verify_totp(username, mfa_code)
                        elif method in [MFAMethod.EMAIL, MFAMethod.SMS]:
                            # Verify generated code
                            mfa_verified = hmac.compare_digest(stored_code or "", mfa_code)
                        elif method == MFAMethod.BACKUP_CODES:
                            # Verify backup code
                            if self.mfa_store:
                                mfa_verified = await self.mfa_store.verify_backup_code(username, mfa_code)

                        if mfa_verified:
                            # Mark challenge as verified and clean up
                            await db_session.execute(
                                "UPDATE mfa_challenges SET is_verified = 1 WHERE id = ?",
                                {"1": challenge_result['id']}
                            )
                            await db_session.commit()

                            self._record_metric('mfa_verifications')

                            logger.security("MFA verification successful",
                                           challenge_id=challenge_id,
                                           user_id=username,
                                           method=method.value)
                            logger.audit("MFA verification successful",
                                        user_id=username,
                                        challenge_id=challenge_id,
                                        event_type="mfa_verified",
                                        method=method.value)
                        else:
                            # Update attempts
                            await db_session.execute(
                                "UPDATE mfa_challenges SET attempts = ? WHERE id = ?",
                                {"1": attempts, "2": challenge_result['id']}
                            )
                            await db_session.commit()

                            logger.security("MFA verification failed - invalid code",
                                           challenge_id=challenge_id,
                                           user_id=username,
                                           attempts=attempts)
                            return AuthResult(
                                success=False,
                                error_message="Invalid MFA code",
                                error_code="INVALID_MFA_CODE"
                            )

                except Exception as e:
                    logger.error(f"Error verifying MFA challenge: {e}")
                    return AuthResult(
                        success=False,
                        error_message="MFA verification failed",
                        error_code="MFA_VERIFICATION_ERROR"
                    )
            
            # Update device information in database
            try:
                async with self.db_manager.get_session() as db_session:
                    current_time = datetime.now(timezone.utc)
                    current_time_str = current_time.isoformat()

                    # Check if device exists
                    existing_device_result = await db_session.fetchone(
                        "SELECT id FROM devices WHERE device_id = ?",
                        {"1": device_info.device_id}
                    )

                    if not existing_device_result:
                        # Register new device
                        await db_session.execute(
                            "INSERT INTO devices (device_id, device_type, os, browser, is_trusted, first_seen, last_seen, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            {
                                "1": device_info.device_id,
                                "2": device_info.device_type.value,
                                "3": device_info.os,
                                "4": device_info.browser,
                                "5": int(device_info.is_trusted),
                                "6": device_info.first_seen.isoformat(),
                                "7": current_time_str,
                                "8": username,
                                "9": ip_address,
                                "10": user_agent
                            }
                        )
                        self._record_metric('device_registrations')

                        logger.security("New device registered",
                                       user_id=username,
                                       device_id=device_info.device_id,
                                       device_type=device_info.device_type.value)
                    else:
                        # Update existing device
                        update_fields = ["last_seen = ?"]
                        params = {"1": current_time_str}

                        if device_trust and mfa_verified:
                            update_fields.append("is_trusted = ?")
                            params["2"] = 1

                        await db_session.execute(
                            f"UPDATE devices SET {', '.join(update_fields)} WHERE device_id = ?",
                            {**params, str(len(params) + 1): device_info.device_id}
                        )

                        if device_trust and mfa_verified:
                            logger.security("Device trust granted",
                                           user_id=username,
                                           device_id=device_info.device_id)

                    await db_session.commit()
            except Exception as e:
                logger.error(f"Error updating device information: {e}")
            
            # Create session in database
            session_id = self._generate_session_id()
            now = datetime.now(timezone.utc)
            now_str = now.isoformat()
            expires_at_str = (now + self.session_timeout).isoformat()

            permissions_json = json.dumps(list(all_permissions))
            roles_json = json.dumps([role.value for role in roles])
            device_info_json = json.dumps({
                'device_id': device_info.device_id,
                'device_type': device_info.device_type.value,
                'os': device_info.os,
                'browser': device_info.browser,
                'version': device_info.version,
                'is_trusted': device_info.is_trusted,
                'first_seen': device_info.first_seen.isoformat(),
                'last_seen': device_info.last_seen.isoformat()
            }) if device_info else None

            try:
                async with self.db_manager.get_session() as db_session:
                    await db_session.execute(
                        "INSERT INTO sessions (id, user_id, created_at, last_accessed, expires_at, permissions, roles, ip_address, user_agent, device_info, auth_provider, mfa_verified, is_active, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        {
                            "1": session_id,
                            "2": security_context.user_id or username,
                            "3": now_str,
                            "4": now_str,
                            "5": expires_at_str,
                            "6": permissions_json,
                            "7": roles_json,
                            "8": ip_address,
                            "9": user_agent,
                            "10": device_info_json,
                            "11": AuthProvider.LOCAL.value,
                            "12": int(mfa_verified or not requires_mfa),
                            "13": 1,  # is_active
                            "14": risk_score
                        }
                    )
                    await db_session.commit()

                    self._record_metric('session_creations')
                    self._record_metric('successful_authentications')
            except Exception as e:
                logger.error(f"Error creating session: {e}")
                return AuthResult(
                    success=False,
                    error_message="Failed to create session",
                    error_code="SESSION_CREATION_FAILED"
                )
            
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
        Validate session and update last accessed time using database.
        """
        try:
            async with self.db_manager.get_session() as db_session:
                # Query session from database
                session_result = await db_session.fetchone(
                    "SELECT id, user_id, created_at, last_accessed, expires_at, permissions, roles, ip_address, user_agent, device_info, auth_provider, mfa_verified, is_active, is_elevated, elevation_expires_at, location, risk_score FROM sessions WHERE id = ? AND is_active = 1",
                    {"1": session_id}
                )

                if not session_result:
                    logger.security("Session validation failed - session not found", session_id=session_id)
                    return False, None

                # Reconstruct SessionInfo from database data
                permissions = set(json.loads(session_result['permissions']) if session_result['permissions'] else [])
                roles = set(json.loads(session_result['roles']) if session_result['roles'] else [])
                device_info = json.loads(session_result['device_info']) if session_result['device_info'] else None

                if device_info:
                    device_info = DeviceInfo(
                        device_id=device_info['device_id'],
                        device_type=DeviceType(device_info['device_type']),
                        os=device_info.get('os'),
                        browser=device_info.get('browser'),
                        version=device_info.get('version'),
                        is_trusted=device_info.get('is_trusted', False),
                        first_seen=datetime.fromisoformat(device_info['first_seen']),
                        last_seen=datetime.fromisoformat(device_info['last_seen'])
                    )

                session = SessionInfo(
                    session_id=session_result['id'],
                    user_id=session_result['user_id'],
                    created_at=datetime.fromisoformat(session_result['created_at']),
                    last_accessed=datetime.fromisoformat(session_result['last_accessed']),
                    expires_at=datetime.fromisoformat(session_result['expires_at']),
                    permissions=permissions,
                    roles=set(Role(role) for role in roles),
                    ip_address=session_result['ip_address'],
                    user_agent=session_result['user_agent'],
                    device_info=device_info,
                    auth_provider=AuthProvider(session_result['auth_provider']),
                    mfa_verified=bool(session_result['mfa_verified']),
                    is_active=bool(session_result['is_active']),
                    is_elevated=bool(session_result['is_elevated']),
                    elevation_expires_at=datetime.fromisoformat(session_result['elevation_expires_at']) if session_result['elevation_expires_at'] else None,
                    location=session_result['location'],
                    risk_score=float(session_result['risk_score'] or 0.0)
                )

                # Check if session is expired
                if self._is_session_expired(session):
                    # Mark session as inactive in database
                    await db_session.execute(
                        "UPDATE sessions SET is_active = 0, updated_at = ? WHERE id = ?",
                        {"1": datetime.now(timezone.utc).isoformat(), "2": session_id}
                    )
                    await db_session.commit()

                    self._record_metric('session_invalidations')
                    logger.security("Session expired and invalidated",
                                   session_id=session_id, user_id=session.user_id)
                    logger.audit("Session expired",
                                session_id=session_id, user_id=session.user_id,
                                event_type="session_expired")
                    return False, None

                # Update last accessed time in database
                current_time = datetime.now(timezone.utc)
                current_time_str = current_time.isoformat()

                await db_session.execute(
                    "UPDATE sessions SET last_accessed = ?, updated_at = ? WHERE id = ?",
                    {"1": current_time_str, "2": current_time_str, "3": session_id}
                )
                await db_session.commit()

                # Update the session object with new last_accessed time
                session.last_accessed = current_time

                logger.debug("Session validated successfully", session_id=session_id, user_id=session.user_id)
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
        Invalidate a session using database operations.
        """
        try:
            async with self.db_manager.get_session() as db_session:
                # Get session info before invalidating for logging
                session_result = await db_session.fetchone(
                    "SELECT user_id FROM sessions WHERE id = ? AND is_active = 1",
                    {"1": session_id}
                )

                if not session_result:
                    logger.debug("Session not found or already inactive", session_id=session_id)
                    return False

                user_id = session_result['user_id']

                # Mark session as inactive in database
                await db_session.execute(
                    "UPDATE sessions SET is_active = 0, updated_at = ? WHERE id = ?",
                    {"1": datetime.now(timezone.utc).isoformat(), "2": session_id}
                )
                await db_session.commit()

                self._record_metric('session_invalidations')

                logger.security("Session invalidated", session_id=session_id, user_id=user_id)
                logger.audit("Session invalidated", session_id=session_id, user_id=user_id,
                            event_type="session_invalidated")

                return True

        except Exception as e:
            logger.error(f"Error invalidating session: {e}", session_id=session_id)
            return False

    async def invalidate_user_sessions(self, user_id: str) -> int:
        """
        Invalidate all sessions for a user using database operations.
        """
        try:
            async with self.db_manager.get_session() as db_session:
                # Get count of sessions to be invalidated for logging
                count_result = await db_session.fetchone(
                    "SELECT COUNT(*) as session_count FROM sessions WHERE user_id = ? AND is_active = 1",
                    {"1": user_id}
                )

                session_count = count_result['session_count'] if count_result else 0

                if session_count == 0:
                    return 0

                # Mark all user sessions as inactive
                await db_session.execute(
                    "UPDATE sessions SET is_active = 0, updated_at = ? WHERE user_id = ? AND is_active = 1",
                    {"1": datetime.now(timezone.utc).isoformat(), "2": user_id}
                )
                await db_session.commit()

                # Record metrics for each invalidated session
                for _ in range(session_count):
                    self._record_metric('session_invalidations')

                logger.security("All sessions invalidated for user", user_id=user_id,
                               session_count=session_count)
                logger.audit("All user sessions invalidated", user_id=user_id,
                            event_type="all_sessions_invalidated",
                            session_count=session_count)

                return session_count

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
        Elevate a session for administrative operations using database operations.
        """
        try:
            async with self.db_manager.get_session() as db_session:
                # Query session from database
                session_result = await db_session.fetchone(
                    "SELECT user_id, is_active, is_elevated, elevation_expires_at FROM sessions WHERE id = ? AND is_active = 1",
                    {"1": session_id}
                )

                if not session_result:
                    logger.security("Session elevation failed - session not found or inactive",
                                   session_id=session_id)
                    return False

                user_id = session_result['user_id']

                # Check if already elevated and still valid
                if session_result['is_elevated'] and session_result['elevation_expires_at']:
                    elevation_expires = datetime.fromisoformat(session_result['elevation_expires_at'])
                    if datetime.now(timezone.utc) < elevation_expires:
                        logger.debug("Session already elevated and valid", session_id=session_id, user_id=user_id)
                        return True

                # Verify password
                success, _ = await self.security_system.authenticate_user(user_id, password)
                if not success:
                    logger.security("Session elevation failed - invalid password",
                                   session_id=session_id,
                                   user_id=user_id)
                    return False

                # Elevate session in database
                current_time = datetime.now(timezone.utc)
                elevation_expires_at = current_time + self.elevated_session_timeout
                elevation_expires_str = elevation_expires_at.isoformat()
                updated_at_str = current_time.isoformat()

                await db_session.execute(
                    "UPDATE sessions SET is_elevated = 1, elevation_expires_at = ?, updated_at = ? WHERE id = ?",
                    {"1": elevation_expires_str, "2": updated_at_str, "3": session_id}
                )
                await db_session.commit()

                logger.security("Session elevated",
                               session_id=session_id,
                               user_id=user_id,
                               elevation_expires_at=elevation_expires_at)
                logger.audit("Session elevated",
                            session_id=session_id,
                            user_id=user_id,
                            event_type="session_elevated",
                            elevation_expires_at=elevation_expires_at)

                return True

        except Exception as e:
            logger.error(f"Error elevating session: {e}", session_id=session_id)
            return False

    async def check_permission(self, user_id: str, permission: str, require_elevation: bool = False) -> bool:
        """
        Check if user has specific permission with RBAC support using database operations.
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
                # Query database for active elevated sessions for user
                async with self.db_manager.get_session() as db_session:
                    current_time_str = datetime.now(timezone.utc).isoformat()

                    elevated_session_result = await db_session.fetchone(
                        "SELECT id FROM sessions WHERE user_id = ? AND is_active = 1 AND is_elevated = 1 AND elevation_expires_at > ?",
                        {"1": user_id, "2": current_time_str}
                    )

                    if not elevated_session_result:
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

    async def get_security_status(self) -> Dict[str, Any]:
        """
        Get comprehensive authentication system status with enhanced metrics using database operations.
        """
        try:
            # Cleanup expired sessions before reporting
            await self._cleanup_expired_sessions()

            security_status = self.security_system.get_security_status()

            # Query database for session metrics
            async with self.db_manager.get_session() as db_session:
                # Get active session counts
                active_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1",
                    {}
                )
                active_sessions = active_sessions_result['count'] if active_sessions_result else 0

                # Get elevated session counts
                elevated_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1 AND is_elevated = 1",
                    {}
                )
                elevated_sessions = elevated_sessions_result['count'] if elevated_sessions_result else 0

                # Get MFA verified session counts
                mfa_verified_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1 AND mfa_verified = 1",
                    {}
                )
                mfa_verified_sessions = mfa_verified_sessions_result['count'] if mfa_verified_sessions_result else 0

                # Get high risk session counts
                high_risk_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1 AND risk_score > 70",
                    {}
                )
                high_risk_sessions = high_risk_sessions_result['count'] if high_risk_sessions_result else 0

                # Get device counts
                known_devices_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM devices",
                    {}
                )
                known_devices = known_devices_result['count'] if known_devices_result else 0

                trusted_devices_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM devices WHERE is_trusted = 1",
                    {}
                )
                trusted_devices = trusted_devices_result['count'] if trusted_devices_result else 0

                # Get MFA challenge counts
                active_mfa_challenges_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM mfa_challenges WHERE expires_at > ?",
                    {"1": datetime.now(timezone.utc).isoformat()}
                )
                active_mfa_challenges = active_mfa_challenges_result['count'] if active_mfa_challenges_result else 0

            return {
                **security_status,
                'auth_manager_metrics': self.metrics.copy(),
                'active_sessions': active_sessions,
                'elevated_sessions': elevated_sessions,
                'mfa_verified_sessions': mfa_verified_sessions,
                'high_risk_sessions': high_risk_sessions,
                'known_devices': known_devices,
                'trusted_devices': trusted_devices,
                'active_mfa_challenges': active_mfa_challenges,
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

        except Exception as e:
            logger.error(f"Error getting security status: {e}")
            # Fallback to basic status
            security_status = self.security_system.get_security_status()
            return {
                **security_status,
                'auth_manager_metrics': self.metrics.copy(),
                'active_sessions': 0,
                'elevated_sessions': 0,
                'mfa_verified_sessions': 0,
                'high_risk_sessions': 0,
                'known_devices': 0,
                'trusted_devices': 0,
                'active_mfa_challenges': 0,
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
        Enhanced cleanup with comprehensive resource management using database operations.
        """
        try:
            current_time = datetime.now(timezone.utc)
            current_time_str = current_time.isoformat()
            initial_brute_force = len(self.brute_force_tracking)

            async with self.db_manager.get_session() as db_session:
                # Get initial counts for logging
                initial_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1",
                    {}
                )
                initial_sessions = initial_sessions_result['count'] if initial_sessions_result else 0

                initial_challenges_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM mfa_challenges",
                    {}
                )
                initial_challenges = initial_challenges_result['count'] if initial_challenges_result else 0

                # Cleanup expired sessions and challenges
                await self._cleanup_expired_sessions()

                # Cleanup old device information (older than 90 days)
                old_devices_cutoff = (current_time - timedelta(days=90)).isoformat()
                old_devices_result = await db_session.fetchall(
                    "SELECT device_id FROM devices WHERE last_seen < ?",
                    {"1": old_devices_cutoff}
                )

                if old_devices_result:
                    old_device_ids = [row['device_id'] for row in old_devices_result]

                    # Delete old devices
                    await db_session.execute(
                        "DELETE FROM devices WHERE last_seen < ?",
                        {"1": old_devices_cutoff}
                    )

                    cleaned_devices = len(old_device_ids)
                else:
                    cleaned_devices = 0

                await db_session.commit()

            # Cleanup old brute force tracking (older than 24 hours)
            old_tracking = [
                ip for ip, protection in self.brute_force_tracking.items()
                if current_time - protection.last_attempt > timedelta(hours=24)
            ]

            for ip in old_tracking:
                del self.brute_force_tracking[ip]

            # Get final counts for logging
            async with self.db_manager.get_session() as db_session:
                final_sessions_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM sessions WHERE is_active = 1",
                    {}
                )
                final_sessions = final_sessions_result['count'] if final_sessions_result else 0

                final_challenges_result = await db_session.fetchone(
                    "SELECT COUNT(*) as count FROM mfa_challenges",
                    {}
                )
                final_challenges = final_challenges_result['count'] if final_challenges_result else 0

            expired_sessions = initial_sessions - final_sessions
            expired_challenges = initial_challenges - final_challenges
            cleaned_brute_force = len(old_tracking)

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
