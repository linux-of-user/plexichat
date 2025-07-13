import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

"""
PlexiChat Session Manager

Comprehensive session management with security levels and device tracking.
"""

logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    """Session data structure."""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    security_level: str
    device_info: Dict[str, Any]
    ip_address: str
    user_agent: str
    risk_score: float
    is_active: bool = True


class SessionManager:
    """Session management system."""
    
    def __init__(self):
        self.sessions: Dict[str, SessionData] = {}
        self.config = {}
        self.initialized = False
    
    async def initialize(self, config: Dict[str, Any]):
        """Initialize session manager."""
        self.config = config
        self.initialized = True
        logger.info(" Session Manager initialized")
    
    async def create_session(self, user_id: str, device_info: Optional[Dict[str, Any]] = None,
                           security_level: str = "GOVERNMENT", risk_score: float = 0.0) -> str:
        """Create new session."""
        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        session_data = SessionData(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(minutes=30),
            security_level=security_level,
            device_info=device_info or {},
            ip_address=device_info.get("ip_address", "") if device_info else "",
            user_agent=device_info.get("user_agent", "") if device_info else "",
            risk_score=risk_score
        )
        
        self.sessions[session_id] = session_data
        return session_id
    
    async def validate_session(self, session_id: str) -> Dict[str, Any]:
        """Validate session."""
        session = self.sessions.get(session_id)
        if not session or not session.is_active:
            return {"valid": False, "error": "Session not found"}
        
        if session.expires_at <= datetime.now(timezone.utc):
            return {"valid": False, "error": "Session expired"}
        
        return {"valid": True, "session": session}
    
    async def invalidate_session(self, session_id: str):
        """Invalidate session."""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
    
    async def shutdown(self):
        """Shutdown session manager."""
        logger.info(" Session Manager shutdown complete")


# Global instance
session_manager = SessionManager()
