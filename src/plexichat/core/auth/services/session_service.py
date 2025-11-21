"""
Session Service
Manages user sessions with advanced security features.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from plexichat.core.auth.services.interfaces import ISessionService
from plexichat.core.authentication import DeviceInfo, SessionInfo
from plexichat.core.logging.unified_logger import get_logger

logger = get_logger(__name__)


@dataclass
class SessionStore:
    """In-memory session storage for development/testing."""

    sessions: dict[str, SessionInfo] = field(default_factory=dict)
    expired_sessions: set[str] = field(default_factory=set)

    def add_session(self, session: SessionInfo) -> None:
        """Add a session to storage."""
        self.sessions[session.session_id] = session

    def get_session(self, session_id: str) -> SessionInfo | None:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def remove_session(self, session_id: str) -> None:
        """Remove a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.expired_sessions.add(session_id)

    def get_active_sessions(self, user_id: str) -> list[SessionInfo]:
        """Get all active sessions for a user."""
        return [
            session
            for session in self.sessions.values()
            if session.user_id == user_id and not self._is_expired(session)
        ]

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count removed."""
        expired = []
        for session_id, session in self.sessions.items():
            if self._is_expired(session):
                expired.append(session_id)

        for session_id in expired:
            self.remove_session(session_id)

        return len(expired)

    def _is_expired(self, session: SessionInfo) -> bool:
        """Check if a session is expired."""
        return datetime.now(UTC) > session.expires_at


class SessionService(ISessionService):
    """Advanced session management service."""

    def __init__(self):
        super().__init__()
        self.session_store = SessionStore()
        self.cleanup_interval = 300  # 5 minutes
        self.max_concurrent_sessions = 5
        self._cleanup_task: asyncio.Task | None = None

    async def create_session(
        self,
        user_id: str,
        device_info: DeviceInfo,
        ip_address: str,
        permissions: set[str],
    ) -> SessionInfo:
        """Create a new session for the user."""
        session_id = self._generate_session_id()

        # Check concurrent session limit
        active_sessions = self.session_store.get_active_sessions(user_id)
        if len(active_sessions) >= self.max_concurrent_sessions:
            # Remove oldest session if limit exceeded
            oldest_session = min(active_sessions, key=lambda s: s.created_at)
            await self.invalidate_session(oldest_session.session_id)
            logger.warning(
                f"Removed oldest session for user {user_id} due to concurrent session limit"
            )

        session = SessionInfo(
            session_id=session_id,
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address,
            permissions=permissions,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=24),  # 24 hours
            is_active=True,
        )

        self.session_store.add_session(session)
        logger.info(f"Created session {session_id} for user {user_id}")

        return session

    async def validate_session(self, session_id: str) -> SessionInfo | None:
        """Validate and return session if active."""
        session = self.session_store.get_session(session_id)

        if not session or not session.is_active:
            return None

        if self._is_expired(session):
            await self.invalidate_session(session_id)
            return None

        # Update last activity
        session.last_activity = datetime.now(UTC)
        return session

    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session."""
        session = self.session_store.get_session(session_id)
        if session:
            session.is_active = False
            self.session_store.remove_session(session_id)
            logger.info(f"Invalidated session {session_id}")
            return True
        return False

    async def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user."""
        active_sessions = self.session_store.get_active_sessions(user_id)
        invalidated_count = 0

        for session in active_sessions:
            await self.invalidate_session(session.session_id)
            invalidated_count += 1

        logger.info(f"Invalidated {invalidated_count} sessions for user {user_id}")
        return invalidated_count

    async def get_user_sessions(self, user_id: str) -> list[SessionInfo]:
        """Get all active sessions for a user."""
        return self.session_store.get_active_sessions(user_id)

    async def extend_session(self, session_id: str, extension_hours: int = 24) -> bool:
        """Extend session expiration time."""
        session = self.session_store.get_session(session_id)
        if session and session.is_active and not self._is_expired(session):
            session.expires_at = datetime.now(UTC) + timedelta(hours=extension_hours)
            logger.info(f"Extended session {session_id} by {extension_hours} hours")
            return True
        return False

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions."""
        removed_count = self.session_store.cleanup_expired_sessions()
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} expired sessions")
        return removed_count

    async def start_cleanup_task(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _periodic_cleanup(self) -> None:
        """Periodic cleanup of expired sessions."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error during session cleanup: {e}")

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        import uuid

        return f"session_{uuid.uuid4().hex}"

    def _is_expired(self, session: SessionInfo) -> bool:
        """Check if a session is expired."""
        return datetime.now(UTC) > session.expires_at
