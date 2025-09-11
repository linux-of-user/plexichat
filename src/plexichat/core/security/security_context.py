"""
Consolidated Security Context Module for PlexiChat
Provides the canonical SecurityContext class and related enums.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class SecurityLevel(Enum):
    """Security access levels for endpoints."""

    PUBLIC = 0  # No authentication required
    BASIC = 1  # Basic authentication required
    AUTHENTICATED = 2  # Valid user session required
    ELEVATED = 3  # Enhanced privileges required
    ADMIN = 4  # Admin access required
    SYSTEM = 5  # System-level access required


@dataclass
class SecurityContext:
    """Security context for requests."""

    user_id: str | None = None
    session_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    endpoint: str | None = None
    security_level: SecurityLevel = SecurityLevel.PUBLIC
    authenticated: bool = False
    permissions: set[str] = field(default_factory=set)
    threat_score: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


__all__ = ["SecurityContext", "SecurityLevel"]
