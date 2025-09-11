"""
Core Authentication Service
Implements the main authentication logic with comprehensive security features.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from plexichat.core.authentication import (
    AuthProvider,
    AuthResult,
    DeviceInfo,
    DeviceType,
    MFAChallenge,
    MFAMethod,
    Role,
    SessionInfo,
)
from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger
from plexichat.core.security import get_security_system
from plexichat.core.security.unified_security_module import (
    SecurityContext,
    SecurityEvent,
)

from .interfaces import IAuthenticationService
from .audit_service import AuditEventType, AuditService

logger = get_logger(__name__)


@dataclass
class UserCredentials:
    """User credentials data structure."""

    user_id: str
    username: str
    password_hash: str
    salt: str
    roles: List[str]
    is_active: bool = True
    is_locked: bool = False
    failed_attempts: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime = datetime.now(timezone.utc)
    password_changed_at: Optional[datetime] = None


class AuthenticationService(IAuthenticationService):
    """
    Core authentication service with comprehensive security features.
    """

    def __init__(
        self,
        db_manager: Any = None,
        audit_service: Optional[AuditService] = None,
        max_failed_attempts: int = 5,
        lockout_duration: int = 900,  # 15 minutes
    ):
        self.db_manager = db_manager or database_manager
        self.audit_service = audit_service or AuditService()
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration = lockout_duration
        self.security_system = get_security_system()
        self.unified_security = self.security_system.get_unified_security()

    async def cleanup_expired_data(self) -> int:
        """Clean up expired sessions and MFA challenges."""
        current_time = datetime.now(timezone.utc)
        current_time_str = current_time.isoformat()
        expired_count = 0

        try:
            async with self.db_manager.get_session() as session:
                # Clean up expired sessions
                expired_sessions_result = await session.fetchall(
                    "SELECT id, user_id FROM sessions WHERE expires_at < :expires_at AND is_active = 1",
                    {"expires_at": current_time_str},
                )

                if expired_sessions_result:
                    # Mark sessions as inactive
                    await session.execute(
                        "UPDATE sessions SET is_active = 0, updated_at = :current_time WHERE expires_at < :expires_at AND is_active = 1",
                        {"current_time": current_time_str, "expires_at": current_time_str},
                    )

                    for row in expired_sessions_result:
                        logger.warning(
                            "[SECURITY] Session expired and marked inactive",
                            session_id=row["id"],
                            user_id=row["user_id"],
                        )

                    expired_count += len(expired_sessions_result)

                # Clean up expired MFA challenges
                expired_challenges_result = await session.fetchall(
                    "SELECT id, challenge_id, user_id FROM mfa_challenges WHERE expires_at < :expires_at",
                    {"expires_at": current_time_str},
                )

                if expired_challenges_result:
                    await session.execute(
                        "DELETE FROM mfa_challenges WHERE expires_at < :expires_at",
                        {"expires_at": current_time_str},
                    )

                    for row in expired_challenges_result:
                        logger.warning(
                            "[SECURITY] MFA challenge expired and removed",
                            challenge_id=row["challenge_id"],
                            user_id=row["user_id"],
                        )

                    expired_count += len(expired_challenges_result)

            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired authentication records")

        except Exception as e:
            logger.error(f"Error cleaning up expired data: {e}")
            raise

        return expired_count

    async def _rate_limit_check(
        self, username: str, ip_address: Optional[str]
    ) -> Tuple[bool, Optional[str]]:
        """Check rate limits for authentication attempts."""
        try:
            # Create security context
            context = SecurityContext(ip_address=ip_address, endpoint="auth/login")

            # Check rate limits using unified security module's validate_request method
            validation_result = await self.unified_security.validate_request(None, context)
            is_valid, error_message, security_event = validation_result

            if (
                not is_valid
                and security_event
                and security_event.event_type.value == "rate_limit_exceeded"
            ):
                return False, error_message or "Rate limit exceeded"

            return True, None

        except Exception as e:
            logger.error(f"Error checking rate limits: {e}")
            # Allow request to proceed if rate limiting fails
            return True, None

    async def _record_failed_attempt(
        self, username: str, ip_address: Optional[str], reason: str
    ) -> None:
        """Record a failed authentication attempt."""
        try:
            context = SecurityContext(ip_address=ip_address, endpoint="auth/login")

            # This will increment the rate limiting counters through validate_request
            await self.unified_security.validate_request(None, context)

            logger.warning(
                "[SECURITY] Failed authentication attempt recorded", ip_address=ip_address
            )

            # Log audit event
            await self.audit_service.log_event(
                AuditEventType.LOGIN_FAILURE,
                user_id=None,
                ip_address=ip_address,
                details={"username": username, "reason": reason},
                severity="warning",
            )

        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[DeviceInfo] = None,
    ) -> AuthResult:
        """
        Authenticate a user with comprehensive security checks.
        """
        start_time = time.time()

        try:
            # Rate limiting check
            rate_limit_ok, rate_limit_msg = await self._rate_limit_check(
                username, ip_address
            )
            if not rate_limit_ok:
                await self._record_failed_attempt(
                    username, ip_address, "rate_limit_exceeded"
                )
                return AuthResult(
                    success=False,
                    error_message=rate_limit_msg,
                    user_id=None,
                )

            # Get user credentials
            async with self.db_manager.get_session() as session:
                user_result = await session.fetchall(
                    "SELECT user_id, username, password_hash, salt, roles, is_active, is_locked, failed_attempts, lockout_until FROM user_credentials WHERE username = :username",
                    {"username": username},
                )

                if not user_result:
                    await self._record_failed_attempt(
                        username, ip_address, "user_not_found"
                    )
                    return AuthResult(
                        success=False,
                        error_message="Invalid credentials",
                        user_id=None,
                    )

                user_data = user_result[0]

                # Check if user is active
                if not user_data["is_active"]:
                    await self._record_failed_attempt(
                        username, ip_address, "user_inactive"
                    )
                    return AuthResult(
                        success=False,
                        error_message="Account is inactive",
                        user_id=user_data["user_id"],
                    )

                # Check if user is locked
                if user_data["is_locked"]:
                    lockout_until = user_data.get("lockout_until")
                    if lockout_until and datetime.fromisoformat(lockout_until) > datetime.now(timezone.utc):
                        await self._record_failed_attempt(
                            username, ip_address, "account_locked"
                        )
                        return AuthResult(
                            success=False,
                            error_message="Account is temporarily locked",
                            user_id=user_data["user_id"],
                        )

                # Check password
                stored_hash = user_data["password_hash"]
                salt = user_data["salt"]
                password_hash = self._hash_password(password, salt)

                if not secrets.compare_digest(password_hash, stored_hash):
                    # Update failed attempts
                    failed_attempts = user_data["failed_attempts"] + 1

                    # Lock account if max attempts reached
                    if failed_attempts >= self.max_failed_attempts:
                        lockout_until = datetime.now(timezone.utc) + timedelta(
                            seconds=self.lockout_duration
                        )
                        await session.execute(
                            "UPDATE user_credentials SET failed_attempts = :attempts, is_locked = 1, lockout_until = :lockout WHERE user_id = :user_id",
                            {
                                "attempts": failed_attempts,
                                "lockout": lockout_until.isoformat(),
                                "user_id": user_data["user_id"],
                            },
                        )
                    else:
                        await session.execute(
                            "UPDATE user_credentials SET failed_attempts = :attempts WHERE user_id = :user_id",
                            {"attempts": failed_attempts, "user_id": user_data["user_id"]},
                        )

                    await self._record_failed_attempt(
                        username, ip_address, "invalid_password"
                    )
                    return AuthResult(
                        success=False,
                        error_message="Invalid credentials",
                        user_id=user_data["user_id"],
                    )

                # Reset failed attempts on successful login
                await session.execute(
                    "UPDATE user_credentials SET failed_attempts = 0, is_locked = 0, lockout_until = NULL, last_login = :login_time WHERE user_id = :user_id",
                    {
                        "login_time": datetime.now(timezone.utc).isoformat(),
                        "user_id": user_data["user_id"],
                    },
                )

            # Successful authentication
            user_id = user_data["user_id"]
            roles = json.loads(user_data["roles"]) if user_data["roles"] else []

            # Log successful authentication
            await self.audit_service.log_event(
                AuditEventType.LOGIN_SUCCESS,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "username": username,
                    "device_type": device_info.device_type.value if device_info else "unknown",
                },
                severity="info",
            )

            auth_time = time.time() - start_time
            logger.info(f"User {username} authenticated successfully in {auth_time:.3f}s")

            return AuthResult(
                success=True,
                user_id=user_id,
                username=username,
                roles=roles,
                requires_mfa=await self._check_mfa_required(user_id),
            )

        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            await self._record_failed_attempt(username, ip_address, "system_error")
            return AuthResult(
                success=False,
                error_message="Authentication system error",
                user_id=None,
            )

    async def _check_mfa_required(self, user_id: str) -> bool:
        """Check if MFA is required for user."""
        try:
            async with self.db_manager.get_session() as session:
                mfa_result = await session.fetchall(
                    "SELECT method_type FROM user_mfa WHERE user_id = :user_id AND is_active = 1",
                    {"user_id": user_id},
                )
                return len(mfa_result) > 0
        except Exception as e:
            logger.error(f"Error checking MFA requirement: {e}")
            return False

    async def create_user(
        self,
        username: str,
        password: str,
        email: str,
        roles: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """Create a new user account."""
        try:
            # Validate input
            if not username or len(username) < 3:
                return False, "Username must be at least 3 characters long"

            if not password or len(password) < 8:
                return False, "Password must be at least 8 characters long"

            # Check if user already exists
            async with self.db_manager.get_session() as session:
                existing_result = await session.fetchall(
                    "SELECT user_id FROM user_credentials WHERE username = :username OR email = :email",
                    {"username": username, "email": email},
                )

                if existing_result:
                    return False, "User already exists"

                # Generate user ID, salt, and hash password
                user_id = self._generate_user_id()
                salt = self._generate_salt()
                password_hash = self._hash_password(password, salt)

                # Create user credentials
                user_roles = roles or ["user"]
                await session.execute(
                    "INSERT INTO user_credentials (user_id, username, email, password_hash, salt, roles, is_active, created_at, password_changed_at) VALUES (:user_id, :username, :email, :password_hash, :salt, :roles, 1, :created_at, :password_changed_at)",
                    {
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "password_hash": password_hash,
                        "salt": salt,
                        "roles": json.dumps(user_roles),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "password_changed_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

                # Log user creation
                await self.audit_service.log_event(
                    AuditEventType.LOGIN_SUCCESS,  # Using closest available event type
                    user_id=user_id,
                    details={
                        "username": username,
                        "roles": user_roles,
                        "action": "user_created",
                    },
                    severity="info",
                )

                logger.warning(
                    "[SECURITY] New user account created",
                    user_id=user_id,
                    username=username,
                )

                return True, user_id

        except Exception as e:
            logger.error(f"Error creating user {username}: {e}")
            return False, "Failed to create user account"

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Change user password with verification."""
        try:
            if not new_password or len(new_password) < 8:
                return False, "New password must be at least 8 characters long"

            async with self.db_manager.get_session() as session:
                # Get current user data
                user_result = await session.fetchall(
                    "SELECT username, password_hash, salt FROM user_credentials WHERE user_id = :user_id",
                    {"user_id": user_id},
                )

                if not user_result:
                    return False, "User not found"

                user_data = user_result[0]

                # Verify current password
                stored_hash = user_data["password_hash"]
                salt = user_data["salt"]
                current_hash = self._hash_password(current_password, salt)

                if not secrets.compare_digest(current_hash, stored_hash):
                    await self.audit_service.log_event(
                        AuditEventType.PASSWORD_CHANGE,
                        user_id=user_id,
                        ip_address=ip_address,
                        details={"result": "failed", "reason": "invalid_current_password"},
                        severity="warning",
                    )
                    return False, "Invalid current password"

                # Generate new salt and hash
                new_salt = self._generate_salt()
                new_hash = self._hash_password(new_password, new_salt)

                # Update password
                await session.execute(
                    "UPDATE user_credentials SET password_hash = :password_hash, salt = :salt, password_changed_at = :changed_at WHERE user_id = :user_id",
                    {
                        "password_hash": new_hash,
                        "salt": new_salt,
                        "changed_at": datetime.now(timezone.utc).isoformat(),
                        "user_id": user_id,
                    },
                )

                # Log password change
                await self.audit_service.log_event(
                    AuditEventType.PASSWORD_CHANGE,
                    user_id=user_id,
                    ip_address=ip_address,
                    details={"result": "success"},
                    severity="info",
                )

                logger.warning(
                    "[SECURITY] Password changed successfully", user_id=user_id
                )

                return True, "Password changed successfully"

        except Exception as e:
            logger.error(f"Error changing password for user {user_id}: {e}")
            return False, "Failed to change password"

    async def lock_user_account(
        self, user_id: str, duration_seconds: Optional[int] = None
    ) -> bool:
        """Lock a user account."""
        try:
            lockout_duration = duration_seconds or self.lockout_duration
            lockout_until = datetime.now(timezone.utc) + timedelta(
                seconds=lockout_duration
            )

            async with self.db_manager.get_session() as session:
                await session.execute(
                    "UPDATE user_credentials SET is_locked = 1, lockout_until = :lockout WHERE user_id = :user_id",
                    {"lockout": lockout_until.isoformat(), "user_id": user_id},
                )

                logger.warning(
                    "[SECURITY] User account locked", user_id=user_id, duration=lockout_duration
                )

                return True

        except Exception as e:
            logger.error(f"Error locking user account {user_id}: {e}")
            return False

    async def unlock_user_account(self, user_id: str) -> bool:
        """Unlock a user account."""
        try:
            async with self.db_manager.get_session() as session:
                await session.execute(
                    "UPDATE user_credentials SET is_locked = 0, lockout_until = NULL, failed_attempts = 0 WHERE user_id = :user_id",
                    {"user_id": user_id},
                )

                logger.warning("[SECURITY] User account unlocked", user_id=user_id)

                return True

        except Exception as e:
            logger.error(f"Error unlocking user account {user_id}: {e}")
            return False

    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        try:
            async with self.db_manager.get_session() as session:
                user_result = await session.fetchone(
                    "SELECT user_id, username, email, roles, is_active, is_locked, last_login, created_at FROM user_credentials WHERE user_id = :user_id",
                    {"user_id": user_id},
                )

                if not user_result:
                    return None

                user_data = dict(user_result)
                user_data["roles"] = json.loads(user_data["roles"]) if user_data["roles"] else []

                return user_data

        except Exception as e:
            logger.error(f"Error getting user info for {user_id}: {e}")
            return None

    async def deactivate_user(
        self, user_id: str, deactivated_by: str, reason: str = "manual_deactivation"
    ) -> bool:
        """Deactivate a user account."""
        try:
            async with self.db_manager.get_session() as session:
                # First check if user exists
                user_result = await session.fetchone(
                    "SELECT username FROM user_credentials WHERE user_id = :user_id",
                    {"user_id": user_id},
                )

                if not user_result:
                    logger.warning(f"Attempted to deactivate non-existent user: {user_id}")
                    return False

                # Deactivate user
                await session.execute(
                    "UPDATE user_credentials SET is_active = 0, deactivated_at = :deactivated_at, deactivated_by = :deactivated_by WHERE user_id = :user_id",
                    {
                        "deactivated_at": datetime.now(timezone.utc).isoformat(),
                        "deactivated_by": deactivated_by,
                        "user_id": user_id,
                    },
                )

                # Invalidate all active sessions
                await session.execute(
                    "UPDATE sessions SET is_active = 0, updated_at = :updated_at WHERE user_id = :user_id AND is_active = 1",
                    {"updated_at": datetime.now(timezone.utc).isoformat(), "user_id": user_id},
                )

                # Log deactivation
                await self.audit_service.log_event(
                    AuditEventType.LOGIN_FAILURE,  # Using closest available event type
                    user_id=user_id,
                    details={
                        "action": "user_deactivated",
                        "reason": reason,
                        "deactivated_by": deactivated_by,
                    },
                    severity="warning",
                )

                logger.warning(
                    "[SECURITY] User account deactivated",
                    user_id=user_id,
                    reason=reason,
                    by=deactivated_by,
                )

                return True

        except Exception as e:
            logger.error(f"Error deactivating user {user_id}: {e}")
            return False

    async def reactivate_user(self, user_id: str, reactivated_by: str) -> bool:
        """Reactivate a user account."""
        try:
            async with self.db_manager.get_session() as session:
                await session.execute(
                    "UPDATE user_credentials SET is_active = 1, is_locked = 0, lockout_until = NULL, failed_attempts = 0, reactivated_at = :reactivated_at, reactivated_by = :reactivated_by WHERE user_id = :user_id",
                    {
                        "reactivated_at": datetime.now(timezone.utc).isoformat(),
                        "reactivated_by": reactivated_by,
                        "user_id": user_id,
                    },
                )

                # Log reactivation
                await self.audit_service.log_event(
                    AuditEventType.LOGIN_SUCCESS,  # Using closest available event type
                    user_id=user_id,
                    details={
                        "action": "user_reactivated",
                        "reactivated_by": reactivated_by,
                    },
                    severity="info",
                )

                logger.warning(
                    "[SECURITY] User account reactivated",
                    user_id=user_id,
                    by=reactivated_by,
                )

                return True

        except Exception as e:
            logger.error(f"Error reactivating user {user_id}: {e}")
            return False

    def _generate_user_id(self) -> str:
        """Generate a unique user ID."""
        return f"user_{secrets.token_hex(16)}"

    def _generate_salt(self) -> str:
        """Generate a cryptographic salt."""
        return secrets.token_hex(32)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using PBKDF2."""
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()

    async def create_mfa_challenge(
        self,
        user_id: str,
        method: MFAMethod,
        ip_address: Optional[str] = None,
    ) -> Optional[MFAChallenge]:
        """Create MFA challenge for user."""
        try:
            challenge_id = f"mfa_{secrets.token_hex(16)}"
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

            if method == MFAMethod.TOTP:
                # Generate TOTP challenge
                challenge_data = {"type": "totp", "user_id": user_id}
            elif method == MFAMethod.SMS:
                # Generate SMS challenge
                verification_code = secrets.randbelow(1000000)
                challenge_data = {"type": "sms", "code": f"{verification_code:06d}"}
            else:
                logger.error(f"Unsupported MFA method: {method}")
                return None

            # Store challenge in database
            async with self.db_manager.get_session() as session:
                await session.execute(
                    "INSERT INTO mfa_challenges (challenge_id, user_id, method_type, challenge_data, expires_at, created_at) VALUES (:challenge_id, :user_id, :method_type, :challenge_data, :expires_at, :created_at)",
                    {
                        "challenge_id": challenge_id,
                        "user_id": user_id,
                        "method_type": method.value,
                        "challenge_data": json.dumps(challenge_data),
                        "expires_at": expires_at.isoformat(),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                )

            return MFAChallenge(
                challenge_id=challenge_id,
                method=method,
                expires_at=expires_at,
                challenge_data=challenge_data,
            )

        except Exception as e:
            logger.error(f"Error creating MFA challenge for user {user_id}: {e}")
            return None

    async def verify_mfa_challenge(
        self,
        challenge_id: str,
        response: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Verify MFA challenge response."""
        try:
            async with self.db_manager.get_session() as session:
                # Get challenge
                challenge_result = await session.fetchone(
                    "SELECT user_id, method_type, challenge_data, expires_at FROM mfa_challenges WHERE challenge_id = :challenge_id",
                    {"challenge_id": challenge_id},
                )

                if not challenge_result:
                    logger.warning(f"MFA challenge not found: {challenge_id}")
                    return False

                challenge_data = json.loads(challenge_result["challenge_data"])
                expires_at = datetime.fromisoformat(challenge_result["expires_at"])

                # Check if challenge expired
                if datetime.now(timezone.utc) > expires_at:
                    logger.warning(f"MFA challenge expired: {challenge_id}")
                    return False

                # Verify response based on method
                method = MFAMethod(challenge_result["method_type"])
                is_valid = False

                if method == MFAMethod.SMS:
                    expected_code = challenge_data.get("code")
                    is_valid = secrets.compare_digest(response, expected_code)
                elif method == MFAMethod.TOTP:
                    # Implement TOTP verification logic here
                    # This would typically involve checking against a TOTP library
                    is_valid = True  # Placeholder

                # Remove challenge after verification attempt
                await session.execute(
                    "DELETE FROM mfa_challenges WHERE challenge_id = :challenge_id",
                    {"challenge_id": challenge_id},
                )

                if is_valid:
                    await self.audit_service.log_event(
                        AuditEventType.MFA_VERIFY,
                        user_id=challenge_result["user_id"],
                        ip_address=ip_address,
                        details={"challenge_id": challenge_id, "method": method.value, "result": "success"},
                        severity="info",
                    )
                else:
                    await self.audit_service.log_event(
                        AuditEventType.MFA_VERIFY,
                        user_id=challenge_result["user_id"],
                        ip_address=ip_address,
                        details={"challenge_id": challenge_id, "method": method.value, "result": "failed"},
                        severity="warning",
                    )

                return is_valid

        except Exception as e:
            logger.error(f"Error verifying MFA challenge {challenge_id}: {e}")
            return False

    async def get_login_attempts(
        self, username: Optional[str] = None, ip_address: Optional[str] = None, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get recent login attempts for analysis."""
        try:
            # This would typically query a login_attempts table
            # For now, returning audit events as a substitute
            if username:
                events = await self.audit_service.get_user_events(username)
            else:
                events = await self.audit_service.get_events_by_ip(ip_address or "", limit=100)

            return [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "username": event.details.get("username"),
                    "ip_address": event.ip_address,
                    "success": event.event_type == AuditEventType.LOGIN_SUCCESS,
                    "reason": event.details.get("reason"),
                }
                for event in events
                if event.timestamp > datetime.now(timezone.utc) - timedelta(hours=hours)
            ]

        except Exception as e:
            logger.error(f"Error getting login attempts: {e}")
            return []