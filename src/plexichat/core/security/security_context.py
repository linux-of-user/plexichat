"""
Consolidated Security Context Module for PlexiChat
Provides the canonical SecurityContext class and related enums.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Set


class SecurityLevel(Enum):
    """Security access levels for endpoints."""
    PUBLIC = 0          # No authentication required
    BASIC = 1           # Basic authentication required
    AUTHENTICATED = 2   # Valid user session required
    ELEVATED = 3        # Enhanced privileges required
    ADMIN = 4           # Admin access required
    SYSTEM = 5          # System-level access required


@dataclass
class SecurityContext:
    """Security context for requests."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    endpoint: Optional[str] = None
    security_level: SecurityLevel = SecurityLevel.PUBLIC
    authenticated: bool = False
    permissions: Set[str] = field(default_factory=set)
    threat_score: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


__all__ = [
    "SecurityContext",
    "SecurityLevel"
]