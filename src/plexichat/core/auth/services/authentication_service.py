"""
Core Authentication Service
Implements the main authentication logic with comprehensive security features.
"""

import asyncio
import secrets
import time
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass

from plexichat.core.logging import get_logger
from plexichat.core.authentication import (
    AuthResult,
    SessionInfo,
    DeviceInfo,
    MFAChallenge,
    AuthProvider,
    Role,
    MFAMethod,
    DeviceType
)
from plexichat.core.security import get_security_system
from plexichat.core.security.unified_security_module import UnifiedSecurityModule, SecurityContext
from plexichat.core.database.manager import database_manager

from .interfaces import IAuthenticationService
from ..config import get_auth_config


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

logger = get_logger(__name__)


class AuthenticationService(IAuthenticationService):
    """
    Core authentication service implementing comprehensive authentication logic.
    Handles user authentication, session management, MFA, and security features.
    """

    def __init__(self):
        self.config = get_auth_config()
        self.security_system = get_security_system()

        # Initialize unified security module
        from plexichat.core.security.unified_security_module import get_security_module
        self.unified_security = get_security_module()

        # Initialize database manager
        self.db_manager = database_manager

        # Session management - now database-backed
        self.session_cleanup_task: Optional[asyncio.Task] = None

        # OAuth2 providers
        self.oauth2_providers: Dict[AuthProvider, Any] = {}

        # Brute force protection - keep in memory for performance
        self.brute_force_tracking: Dict[str, Any] = {}

        # Note: Session cleanup task should be started explicitly via start_cleanup_task()
        # to avoid issues during testing and initialization

        logger.info("AuthenticationService initialized with database-backed storage")

    def _start_session_cleanup(self):
        """Start background task for cleaning up expired sessions."""
        if self.session_cleanup_task and not self.session_cleanup_task.done():
            return

        self.session_cleanup_task = asyncio.create_task(self._session_cleanup_worker())

    async def _session_cleanup_worker(self):
        """Background worker for cleaning up expired sessions."""
        while True:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                await self._cleanup_expired_sessions()
            except Exception as e:
                logger.error(f"Error in session cleanup worker: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    async def _cleanup_expired_sessions(self):
        """Clean up expired sessions and MFA challenges from database."""
        current_time = datetime.now(timezone.utc)
        current_time_str = current_time.isoformat()

        try:
            async with self.db_manager.get_session() as session:
                # Clean up expired sessions
                expired_sessions_result = await session.fetchall(
                    "SELECT id, user_id FROM sessions WHERE expires_at < ? AND is_active = 1",
                    (current_time_str,)
                )

                if expired_sessions_result:
                    # Mark sessions as inactive
                    await session.execute(
                        "UPDATE sessions SET is_active = 0, updated_at = ? WHERE expires_at < ? AND is_active = 1",
                        (current_time_str, current_time_str)
                    )

                    for row in expired_sessions_result:
                        logger.security("Session expired and marked inactive",
                                       session_id=row['id'],
                                       user_id=row['user_id'])

                # Clean up expired MFA challenges
                expired_challenges_result = await session.fetchall(
                    "SELECT id, challenge_id, user_id FROM mfa_challenges WHERE expires_at < ?",
                    (current_time_str,)
                )

                if expired_challenges_result:
                    # Delete expired MFA challenges
                    await session.execute(
                        "DELETE FROM mfa_challenges WHERE expires_at < ?",
                        (current_time_str,)
                    )

                    for row in expired_challenges_result:
                        logger.security("MFA challenge expired and removed",
                                       challenge_id=row['challenge_id'],
                                       user_id=row['user_id'])

                await session.commit()

                total_cleaned = len(expired_sessions_result) + len(expired_challenges_result)
                if total_cleaned > 0:
                    logger.info(f"Cleaned up {len(expired_sessions_result)} sessions and {len(expired_challenges_result)} MFA challenges")

        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")

    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _parse_user_agent(self, user_agent: Optional[str]) -> DeviceInfo:
        """Parse user agent to extract device information."""
        if not user_agent:
            return DeviceInfo(
                device_id=secrets.token_hex(8),
                device_type=DeviceType.UNKNOWN
            )

        device_id = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        # Simple user agent parsing
        user_agent_lower = user_agent.lower()

        if any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone']):
            device_type = DeviceType.MOBILE
        elif 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
            device_type = DeviceType.TABLET
        elif any(browser in user_agent_lower for browser in ['chrome', 'firefox', 'safari', 'edge']):
            device_type = DeviceType.DESKTOP
        else:
            device_type = DeviceType.UNKNOWN

        # Extract OS and browser info
        os_info = None
        browser_info = None

        if 'windows' in user_agent_lower:
            os_info = 'Windows'
        elif 'mac' in user_agent_lower:
            os_info = 'macOS'
        elif 'linux' in user_agent_lower:
            os_info = 'Linux'
        elif 'android' in user_agent_lower:
            os_info = 'Android'
        elif 'ios' in user_agent_lower:
            os_info = 'iOS'

        if 'chrome' in user_agent_lower:
            browser_info = 'Chrome'
        elif 'firefox' in user_agent_lower:
            browser_info = 'Firefox'
        elif 'safari' in user_agent_lower:
            browser_info = 'Safari'
        elif 'edge' in user_agent_lower:
            browser_info = 'Edge'

        return DeviceInfo(
            device_id=device_id,
            device_type=device_type,
            os=os_info,
            browser=browser_info
        )

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
                if bf_protection.get('failed_attempts', 0) > 0:
                    risk_score += min(bf_protection['failed_attempts'] * 5, 25.0)

            # Time-based risk
            current_hour = datetime.now(timezone.utc).hour
            if current_hour < 6 or current_hour > 22:
                risk_score += 10.0

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
                    (user_id,)
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
                    (device_id,)
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
                    (device_id,)
                )
                return result is not None and result['is_trusted'] == 1
        except Exception as e:
            logger.error(f"Error checking if device is trusted: {e}")
            return False

    async def _update_device_tracking(self, device_info: DeviceInfo, trust_device: bool) -> None:
        """Update device tracking in database."""
        try:
            current_time = datetime.now(timezone.utc)
            current_time_str = current_time.isoformat()

            async with self.db_manager.get_session() as session:
                # Check if device exists
                existing = await session.fetchone(
                    "SELECT id, is_trusted FROM devices WHERE device_id = ?",
                    (device_info.device_id,)
                )

                if existing:
                    # Update existing device
                    update_data = {
                        "last_seen": current_time_str,
                        "updated_at": current_time_str
                    }
                    if trust_device and not existing['is_trusted']:
                        update_data["is_trusted"] = "1"

                    await session.update("devices", update_data, {"device_id": device_info.device_id})
                else:
                    # Insert new device
                    device_data = {
                        "device_id": device_info.device_id,
                        "user_id": "",  # Will be updated when we have user context
                        "device_type": device_info.device_type.value,
                        "os": device_info.os,
                        "browser": device_info.browser,
                        "version": device_info.version,
                        "is_trusted": "1" if trust_device else "0",
                        "first_seen": current_time_str,
                        "last_seen": current_time_str,
                        "created_at": current_time_str,
                        "updated_at": current_time_str
                    }
                    await session.insert("devices", device_data)

                await session.commit()

        except Exception as e:
            logger.error(f"Error updating device tracking: {e}")

    async def _store_session(self, session: SessionInfo) -> None:
        """Store session in database."""
        try:
            async with self.db_manager.get_session() as session_db:
                session_data = {
                    "id": session.session_id,
                    "user_id": session.user_id,
                    "session_token": session.session_id,  # Use session_id as token for simplicity
                    "expires_at": session.expires_at.isoformat(),
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "is_active": 1,
                    "last_activity": session.last_accessed.isoformat(),
                    "created_at": session.created_at.isoformat(),
                    "updated_at": session.last_accessed.isoformat(),
                    "permissions": json.dumps(list(session.permissions)),
                    "roles": json.dumps([role.value for role in session.roles]),
                    "device_info": json.dumps({
                        "device_id": session.device_info.device_id if session.device_info else None,
                        "device_type": session.device_info.device_type.value if session.device_info else None,
                        "os": session.device_info.os if session.device_info else None,
                        "browser": session.device_info.browser if session.device_info else None
                    }) if session.device_info else "{}",
                    "auth_provider": session.auth_provider.value,
                    "mfa_verified": 1 if session.mfa_verified else 0,
                    "risk_score": session.risk_score
                }

                await session_db.insert("sessions", session_data)
                await session_db.commit()

                logger.debug(f"Session stored in database: {session.session_id}")

        except Exception as e:
            logger.error(f"Error storing session in database: {e}")
            raise

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            # Private/local IPs are generally safe
            if ip.is_private or ip.is_loopback:
                return False

            # In production, check against threat intelligence feeds
            return False

        except Exception:
            return True  # Invalid IP format is suspicious

    async def _check_brute_force_protection(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is blocked due to brute force attempts using unified security module."""
        try:
            # Create security context for rate limiting check
            from plexichat.core.security.unified_security_module import SecurityContext
            context = SecurityContext(
                ip_address=ip_address,
                endpoint="auth/login"
            )

            # Check rate limits using unified security module's validate_request method
            is_valid, error_message, security_event = self.unified_security.validate_request(None, context)

            if not is_valid and security_event and security_event.event_type.value == "rate_limit_exceeded":
                return False, error_message or "Rate limit exceeded"

            return True, None

        except Exception as e:
            logger.error(f"Error checking brute force protection: {e}")
            return True, None  # Allow on error

    async def _record_failed_attempt(self, ip_address: str):
        """Record a failed authentication attempt using unified security module."""
        try:
            # Create security context for rate limiting
            from plexichat.core.security.unified_security_module import SecurityContext
            context = SecurityContext(
                ip_address=ip_address,
                endpoint="auth/login"
            )

            # This will increment the rate limiting counters through validate_request
            await self.unified_security.validate_request(None, context)

            logger.security("Failed authentication attempt recorded",
                          ip_address=ip_address)

        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")

    def _get_user_roles(self, user_id: str) -> Set[Role]:
        """Get user roles from security system."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return {Role.GUEST}

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

        role_permissions = {
            Role.GUEST: set(),
            Role.USER: {"read", "write_own"},
            Role.MODERATOR: {"read", "write_own", "moderate", "delete_others"},
            Role.ADMIN: {"read", "write_own", "moderate", "delete_others", "admin", "user_management"},
            Role.SUPER_ADMIN: {"*"},
            Role.SYSTEM: {"*"}
        }

        for role in roles:
            role_perms = role_permissions.get(role, set())
            if "*" in role_perms:
                return {"*"}
            permissions.update(role_perms)

        return permissions

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        mfa_code: Optional[str] = None,
        device_trust: bool = False
    ) -> AuthResult:
        """Authenticate a user with comprehensive security checks."""
        start_time = time.time()

        # Parse device information
        device_info = self._parse_user_agent(user_agent)
        if ip_address:
            device_info.device_id = hashlib.sha256(f"{user_agent or ''}:{ip_address}".encode()).hexdigest()[:16]

        logger.security("Authentication attempt",
                      user_id=username,
                      ip_address=ip_address,
                      device_type=device_info.device_type.value,
                      device_id=device_info.device_id)

        try:
            # Check brute force protection
            allowed, block_message = await self._check_brute_force_protection(ip_address or "unknown")
            if not allowed:
                logger.security("Authentication blocked by brute force protection",
                              user_id=username,
                              ip_address=ip_address)

                return AuthResult(
                    success=False,
                    error_message=block_message or "Too many failed attempts",
                    error_code="BRUTE_FORCE_PROTECTION"
                )

            # Authenticate with security system
            success, security_context = await self.security_system.authenticate_user(username, password)

            if not success or not security_context:
                if ip_address:
                    await self._record_failed_attempt(ip_address)

                logger.security("Authentication failed - invalid credentials",
                              user_id=username,
                              ip_address=ip_address,
                              device_id=device_info.device_id)

                return AuthResult(
                    success=False,
                    error_message="Invalid username or password",
                    error_code="INVALID_CREDENTIALS"
                )

            # Calculate risk score
            risk_score = await self._calculate_risk_score(ip_address or "", device_info, username)

            # Get user roles and permissions
            roles = self._get_user_roles(username)
            permissions = self._expand_role_permissions(roles)

            # Combine with existing permissions
            all_permissions = security_context.permissions.union(permissions)

            # Update device trust status from database
            try:
                async with self.db_manager.get_session() as session_db:
                    stored_device_result = await session_db.fetchone(
                        "SELECT is_trusted, first_seen, last_seen FROM devices WHERE device_id = ?",
                        (device_info.device_id,)
                    )

                    if stored_device_result:
                        device_info.is_trusted = bool(stored_device_result['is_trusted'])
                        device_info.first_seen = datetime.fromisoformat(stored_device_result['first_seen'])
                        device_info.last_seen = datetime.now(timezone.utc)

                        # Update last_seen in database
                        await session_db.execute(
                            "UPDATE devices SET last_seen = ? WHERE device_id = ?",
                            (device_info.last_seen.isoformat(), device_info.device_id)
                        )
                        await session_db.commit()
            except Exception as e:
                logger.debug(f"Error updating device info from database: {e}")

            # Check if MFA is required
            requires_mfa = (
                risk_score > 50.0 or  # High risk
                not device_info.is_trusted or  # Unknown device
                "admin" in all_permissions or  # Admin access
                not device_trust  # User didn't request device trust
            )

            # Handle MFA
            if requires_mfa and not mfa_code:
                mfa_challenge = await self._create_mfa_challenge(username)
                if mfa_challenge:
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
            if mfa_code:
                mfa_verified = await self._verify_mfa_challenge(username, mfa_code)
                if not mfa_verified:
                    return AuthResult(
                        success=False,
                        error_message="Invalid MFA code",
                        error_code="INVALID_MFA_CODE"
                    )

            # Update device tracking in database
            await self._update_device_tracking(device_info, device_trust or mfa_code is not None)

            # Create session
            session_id = self._generate_session_id()
            now = datetime.now(timezone.utc)

            session = SessionInfo(
                session_id=session_id,
                user_id=security_context.user_id or username,
                created_at=now,
                last_accessed=now,
                expires_at=now + self.config.get_session_timeout(),
                permissions=all_permissions,
                roles=roles,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                auth_provider=AuthProvider.LOCAL,
                mfa_verified=mfa_code is not None or not requires_mfa,
                risk_score=risk_score
            )

            # Store session in database
            await self._store_session(session)

            # Create tokens
            access_token = self.security_system.token_manager.create_access_token(
                security_context.user_id or username,
                all_permissions
            )
            refresh_token = self.security_system.token_manager.create_refresh_token(
                security_context.user_id or username
            )

            # Clear brute force tracking on success
            if ip_address and ip_address in self.brute_force_tracking:
                del self.brute_force_tracking[ip_address]

            duration = time.time() - start_time

            logger.security("Authentication successful",
                          user_id=username,
                          session_id=session_id,
                          ip_address=ip_address,
                          device_id=device_info.device_id,
                          risk_score=risk_score,
                          mfa_verified=mfa_code is not None or not requires_mfa,
                          roles=[role.value for role in roles])

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
                    'mfa_verified': mfa_code is not None or not requires_mfa
                },
                auth_provider=AuthProvider.LOCAL
            )

        except Exception as e:
            if ip_address:
                await self._record_failed_attempt(ip_address)

            logger.error(f"Authentication error: {e}", user_id=username, ip_address=ip_address)
            duration = time.time() - start_time

            return AuthResult(
                success=False,
                error_message=f"Authentication failed: {str(e)}",
                error_code="AUTHENTICATION_ERROR"
            )

    async def authenticate_oauth2(
        self,
        provider: AuthProvider,
        authorization_code: str,
        state: str
    ) -> AuthResult:
        """Authenticate user via OAuth2."""
        try:
            config = self.oauth2_providers.get(provider)
            if not config:
                return AuthResult(
                    success=False,
                    error_message=f"OAuth2 provider {provider.value} not configured",
                    error_code="PROVIDER_NOT_CONFIGURED"
                )

            # Simulate OAuth2 flow (in production, make actual HTTP requests)
            oauth2_user_info = {
                'id': f"oauth2_{provider.value}_{secrets.token_hex(8)}",
                'email': f"user@{provider.value}.com",
                'name': "OAuth2 User"
            }

            user_id = oauth2_user_info['id']

            # Create or update user
            if user_id not in self.security_system.user_credentials:
                # Auto-register OAuth2 user
                from plexichat.core.security.security_manager import UserCredentials
                self.security_system.user_credentials[user_id] = UserCredentials(
                    username=user_id,
                    password_hash="",
                    salt="",
                    permissions={"read", "write_own"}
                )

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
                expires_at=now + self.config.get_session_timeout(),
                permissions=permissions,
                roles=roles,
                auth_provider=provider,
                mfa_verified=True  # OAuth2 is considered MFA
            )

            # Store session in database
            await self._store_session(session)

            # Create tokens
            access_token = self.security_system.token_manager.create_access_token(user_id, permissions)
            refresh_token = self.security_system.token_manager.create_refresh_token(user_id)

            logger.security("OAuth2 authentication successful",
                          user_id=user_id,
                          provider=provider.value,
                          session_id=session_id)

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

            from urllib.parse import urlencode
            url = f"{config.authorization_url}?{urlencode(params)}"

            logger.security("OAuth2 authorization URL generated",
                          provider=provider.value,
                          state=state)

            return url

        except Exception as e:
            logger.error(f"Error generating OAuth2 authorization URL: {e}")
            return None

    async def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate JWT token."""
        try:
            valid, payload = self.security_system.token_manager.verify_token(token)

            if valid and payload:
                return True, payload
            else:
                return False, None

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, None

    async def validate_session(self, session_id: str) -> Tuple[bool, Optional[SessionInfo]]:
        """Validate session by ID from database."""
        try:
            async with self.db_manager.get_session() as session_db:
                # Get session from database
                result = await session_db.fetchone(
                    "SELECT * FROM sessions WHERE id = ? AND is_active = 1",
                    (session_id,)
                )

                if not result:
                    return False, None

                # Check if session is expired
                expires_at = datetime.fromisoformat(result['expires_at'])
                current_time = datetime.now(timezone.utc)

                if current_time > expires_at:
                    # Mark session as inactive
                    await session_db.update("sessions", {"is_active": 0}, {"id": session_id})
                    await session_db.commit()
                    return False, None

                # Update last access time
                current_time_str = current_time.isoformat()
                await session_db.update("sessions",
                                      {"last_activity": current_time_str, "updated_at": current_time_str},
                                      {"id": session_id})

                # Reconstruct SessionInfo from database data
                permissions = set(json.loads(result['permissions'])) if result['permissions'] else set()
                roles_data = json.loads(result['roles']) if result['roles'] else []
                roles = {Role(role_str) for role_str in roles_data}

                device_info_data = json.loads(result['device_info']) if result['device_info'] else {}
                device_info = None
                if device_info_data:
                    device_info = DeviceInfo(
                        device_id=device_info_data.get('device_id', ''),
                        device_type=DeviceType(device_info_data.get('device_type', 'unknown')),
                        os=device_info_data.get('os'),
                        browser=device_info_data.get('browser')
                    )

                session = SessionInfo(
                    session_id=result['id'],
                    user_id=result['user_id'],
                    created_at=datetime.fromisoformat(result['created_at']),
                    last_accessed=current_time,
                    expires_at=expires_at,
                    permissions=permissions,
                    roles=roles,
                    ip_address=result['ip_address'],
                    user_agent=result['user_agent'],
                    device_info=device_info,
                    auth_provider=AuthProvider(result['auth_provider']),
                    mfa_verified=result['mfa_verified'] == 1,
                    risk_score=result['risk_score']
                )

                await session_db.commit()
                return True, session

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False, None

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key."""
        try:
            # Check user credentials for API key
            for username, credentials in self.security_system.user_credentials.items():
                if api_key in getattr(credentials, 'api_keys', []):
                    return {
                        'user_id': username,
                        'permissions': credentials.permissions,
                        'is_active': True
                    }

            return None

        except Exception as e:
            logger.error(f"API key validation error: {e}")
            return None

    async def _create_mfa_challenge(self, user_id: str) -> Optional[MFAChallenge]:
        """Create MFA challenge for user in database."""
        try:
            challenge_id = secrets.token_urlsafe(16)
            challenge = MFAChallenge(
                challenge_id=challenge_id,
                user_id=user_id,
                method=MFAMethod.TOTP,  # Default to TOTP
                code=secrets.token_hex(3).upper()  # 6-character code
            )

            # Store challenge in database
            async with self.db_manager.get_session() as session:
                challenge_data = {
                    "id": challenge_id,
                    "challenge_id": challenge_id,
                    "user_id": user_id,
                    "method": challenge.method.value,
                    "code": challenge.code,
                    "expires_at": challenge.expires_at.isoformat(),
                    "attempts": challenge.attempts,
                    "max_attempts": challenge.max_attempts,
                    "is_verified": 0,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }

                await session.insert("mfa_challenges", challenge_data)
                await session.commit()

            logger.security("MFA challenge created",
                           user_id=user_id,
                           challenge_id=challenge_id,
                           method=challenge.method.value)

            return challenge

        except Exception as e:
            logger.error(f"Error creating MFA challenge: {e}", user_id=user_id)
            return None

    async def _verify_mfa_challenge(self, user_id: str, code: str) -> bool:
        """Verify MFA challenge for user from database."""
        try:
            async with self.db_manager.get_session() as session:
                # Find active challenge for user
                result = await session.fetchone(
                    "SELECT * FROM mfa_challenges WHERE user_id = ? AND is_verified = 0 ORDER BY created_at DESC LIMIT 1",
                    (user_id,)
                )

                if not result:
                    return False

                # Check if challenge expired
                expires_at = datetime.fromisoformat(result['expires_at'])
                current_time = datetime.now(timezone.utc)

                if current_time > expires_at:
                    # Delete expired challenge
                    await session.execute("DELETE FROM mfa_challenges WHERE id = ?", (result['id'],))
                    await session.commit()
                    return False

                # Verify code
                if hmac.compare_digest(result['code'] or "", code.upper()):
                    # Mark as verified and delete
                    await session.execute("DELETE FROM mfa_challenges WHERE id = ?", (result['id'],))
                    await session.commit()

                    logger.security("MFA verification successful",
                                  user_id=user_id,
                                  challenge_id=result['challenge_id'])

                    return True
                else:
                    # Increment attempts
                    new_attempts = result['attempts'] + 1
                    if new_attempts >= result['max_attempts']:
                        # Delete challenge if max attempts reached
                        await session.execute("DELETE FROM mfa_challenges WHERE id = ?", (result['id'],))
                    else:
                        # Update attempts
                        await session.update("mfa_challenges", {"attempts": new_attempts}, {"id": result['id']})

                    await session.commit()
                    return False

        except Exception as e:
            logger.error(f"Error verifying MFA challenge: {e}", user_id=user_id)
            return False

    async def dispose(self):
        """Clean up resources."""
        if self.session_cleanup_task and not self.session_cleanup_task.done():
            self.session_cleanup_task.cancel()
            try:
                await self.session_cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("AuthenticationService disposed")


__all__ = ["AuthenticationService"]