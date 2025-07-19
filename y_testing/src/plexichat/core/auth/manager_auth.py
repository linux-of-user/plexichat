"""
import time
PlexiChat Authentication Manager

Enhanced authentication management with comprehensive security and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Core auth imports
try:
    from .auth_core import auth_core
except ImportError:
    auth_core = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class AuthenticationManager:
    """Enhanced authentication manager using EXISTING systems."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.auth_core = auth_core

        # Session management
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)

    @async_track_performance("user_login") if async_track_performance else lambda f: f
    async def login(self, username: str, password: str, ip_address: str = "unknown") -> Optional[Dict[str, Any]]:
        """Authenticate user and create session."""
        try:
            # Check for account lockout
            if self._is_account_locked(username):
                logger.warning(f"Login attempt for locked account: {username}")
                return None

            # Authenticate user
            if self.auth_core:
                user = await self.auth_core.authenticate_user(username, password)
            else:
                user = None

            if user:
                # Clear failed attempts
                if username in self.failed_attempts:
                    del self.failed_attempts[username]

                # Create tokens
                access_token = self.auth_core.create_access_token({"sub": str(user["id"])})
                refresh_token = self.auth_core.create_refresh_token({"sub": str(user["id"])})

                # Create session
                session_data = {
                    "user_id": user["id"],
                    "username": user["username"],
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "created_at": datetime.now(),
                    "ip_address": ip_address,
                    "last_activity": datetime.now()
                }

                # Store session
                session_id = f"session_{user['id']}_{datetime.now().timestamp()}"
                self.active_sessions[session_id] = session_data

                # Log successful login
                await self._log_auth_event("login_success", user["id"], ip_address)

                # Performance tracking
                if self.performance_logger:
                    self.performance_logger.record_metric("successful_logins", 1, "count")

                return {
                    "session_id": session_id,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user["id"],
                        "username": user["username"],
                        "email": user["email"],
                        "is_admin": user["is_admin"]
                    }
                }
            else:
                # Record failed attempt
                self._record_failed_attempt(username)

                # Log failed login
                await self._log_auth_event("login_failed", None, ip_address, {"username": username})

                # Performance tracking
                if self.performance_logger:
                    self.performance_logger.record_metric("failed_logins", 1, "count")

                return None

        except Exception as e:
            logger.error(f"Error during login: {e}")
            return None

    @async_track_performance("user_logout") if async_track_performance else lambda f: f
    async def logout(self, session_id: str) -> bool:
        """Logout user and invalidate session."""
        try:
            if session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]

                # Log logout
                await self._log_auth_event("logout", session_data["user_id"], session_data["ip_address"])

                # Remove session
                del self.active_sessions[session_id]

                # Performance tracking
                if self.performance_logger:
                    self.performance_logger.record_metric("user_logouts", 1, "count")

                return True

            return False

        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False

    @async_track_performance("token_refresh") if async_track_performance else lambda f: f
    async def refresh_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token."""
        try:
            if self.auth_core:
                payload = self.auth_core.verify_token(refresh_token, "refresh")
                if payload:
                    user_id = payload.get("sub")
                    if user_id:
                        # Create new access token
                        new_access_token = self.auth_core.create_access_token({"sub": user_id})

                        # Performance tracking
                        if self.performance_logger:
                            self.performance_logger.record_metric("token_refreshes", 1, "count")

                        return {
                            "access_token": new_access_token,
                            "token_type": "bearer"
                        }

            return None

        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            return None

    async def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session and return user data."""
        try:
            if session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]

                # Check session expiry (24 hours)
                if datetime.now() - session_data["created_at"] > timedelta(hours=24):
                    del self.active_sessions[session_id]
                    return None

                # Update last activity
                session_data["last_activity"] = datetime.now()

                return session_data

            return None

        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None

    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username not in self.failed_attempts:
            return False

        attempts = self.failed_attempts[username]
        if len(attempts) < self.max_failed_attempts:
            return False

        # Check if lockout period has expired
        last_attempt = max(attempts)
        if datetime.now() - last_attempt > self.lockout_duration:
            # Clear failed attempts
            del self.failed_attempts[username]
            return False

        return True

    def _record_failed_attempt(self, username: str):
        """Record failed login attempt."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []

        self.failed_attempts[username].append(datetime.now())

        # Keep only recent attempts
        cutoff_time = datetime.now() - self.lockout_duration
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username]
            if attempt > cutoff_time
        ]

    async def _log_auth_event(self, event_type: str, user_id: Optional[int], ip_address: str, details: Optional[Dict[str, Any]] = None):
        """Log authentication event to database."""
        if self.db_manager:
            try:
                query = """
                    INSERT INTO auth_logs (event_type, user_id, ip_address, timestamp, details)
                    VALUES (?, ?, ?, ?, ?)
                """
                params = {
                    "event_type": event_type,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "timestamp": datetime.now(),
                    "details": str(details) if details else None
                }

                if self.performance_logger and timer:
                    with timer("auth_log_insert"):
                        await self.db_manager.execute_query(query, params)
                else:
                    await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error logging auth event: {e}")

    async def get_active_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get active sessions for user."""
        try:
            sessions = []
            for session_id, session_data in self.active_sessions.items():
                if session_data["user_id"] == user_id:
                    sessions.append({)
                        "session_id": session_id,
                        "created_at": session_data["created_at"],
                        "last_activity": session_data["last_activity"],
                        "ip_address": session_data["ip_address"]
                    })

            return sessions

        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []

    async def revoke_session(self, session_id: str, user_id: int) -> bool:
        """Revoke specific session for user."""
        try:
            if session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]
                if session_data["user_id"] == user_id:
                    del self.active_sessions[session_id]

                    # Log session revocation
                    await self._log_auth_event("session_revoked", user_id, session_data["ip_address"])

                    return True

            return False

        except Exception as e:
            logger.error(f"Error revoking session: {e}")
            return False

    async def revoke_all_sessions(self, user_id: int) -> int:
        """Revoke all sessions for user."""
        try:
            revoked_count = 0
            sessions_to_remove = []

            for session_id, session_data in self.active_sessions.items():
                if session_data["user_id"] == user_id:
                    sessions_to_remove.append(session_id)

            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]
                revoked_count += 1

            # Log mass session revocation
            if revoked_count > 0:
                await self._log_auth_event("all_sessions_revoked", user_id, "system")

            return revoked_count

        except Exception as e:
            logger.error(f"Error revoking all sessions: {e}")
            return 0

# Global authentication manager instance
auth_manager = AuthenticationManager()
