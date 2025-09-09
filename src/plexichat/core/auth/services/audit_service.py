"""
Audit Service
Provides comprehensive audit logging for authentication events.
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from plexichat.core.auth.services.interfaces import IAuditService
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Audit event types."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENROLL = "mfa_enroll"
    MFA_VERIFY = "mfa_verify"
    TOKEN_ISSUE = "token_issue"
    TOKEN_REVOKE = "token_revoke"
    SESSION_CREATE = "session_create"
    SESSION_DESTROY = "session_destroy"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE_DETECTED = "brute_force_detected"


@dataclass
class AuditEvent:
    """Audit event data."""

    event_id: str
    event_type: AuditEventType
    user_id: Optional[str]
    timestamp: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    source: str = "authentication"


class AuditService(IAuditService):
    """Comprehensive audit logging service."""

    def __init__(self):
        self.events: List[AuditEvent] = []
        self.max_events = 10000  # Keep last 10k events in memory
        self.retention_days = 90

    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> str:
        """Log an audit event."""
        event_id = self._generate_event_id()

        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
            severity=severity,
        )

        self.events.append(event)

        # Maintain max events limit
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]

        # Log to system logger as well
        log_message = f"AUDIT: {event_type.value} - User: {user_id or 'N/A'} - IP: {ip_address or 'N/A'}"
        if details:
            log_message += f" - Details: {json.dumps(details)}"

        if severity == "error":
            logger.error(log_message)
        elif severity == "warning":
            logger.warning(log_message)
        else:
            logger.info(log_message)

        return event_id

    async def get_user_events(
        self,
        user_id: str,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get audit events for a specific user."""
        user_events = [event for event in self.events if event.user_id == user_id]

        if event_type:
            user_events = [
                event for event in user_events if event.event_type == event_type
            ]

        # Return most recent events
        return sorted(user_events, key=lambda e: e.timestamp, reverse=True)[:limit]

    async def get_events_by_type(
        self, event_type: AuditEventType, limit: int = 100
    ) -> List[AuditEvent]:
        """Get audit events by type."""
        type_events = [event for event in self.events if event.event_type == event_type]

        return sorted(type_events, key=lambda e: e.timestamp, reverse=True)[:limit]

    async def get_events_by_ip(
        self, ip_address: str, limit: int = 100
    ) -> List[AuditEvent]:
        """Get audit events by IP address."""
        ip_events = [event for event in self.events if event.ip_address == ip_address]

        return sorted(ip_events, key=lambda e: e.timestamp, reverse=True)[:limit]

    async def get_suspicious_events(
        self, hours: int = 24, limit: int = 100
    ) -> List[AuditEvent]:
        """Get suspicious audit events within time window."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        suspicious_events = [
            event
            for event in self.events
            if event.timestamp > cutoff_time
            and (
                event.event_type
                in [
                    AuditEventType.LOGIN_FAILURE,
                    AuditEventType.BRUTE_FORCE_DETECTED,
                    AuditEventType.SUSPICIOUS_ACTIVITY,
                ]
                or event.severity in ["warning", "error"]
            )
        ]

        return sorted(suspicious_events, key=lambda e: e.timestamp, reverse=True)[
            :limit
        ]

    async def search_events(self, query: str, limit: int = 100) -> List[AuditEvent]:
        """Search audit events by query string."""
        query_lower = query.lower()

        matching_events = []
        for event in self.events:
            # Search in event details and user agent
            searchable_text = json.dumps(event.details).lower()
            if event.user_agent:
                searchable_text += " " + event.user_agent.lower()

            if query_lower in searchable_text:
                matching_events.append(event)

        return sorted(matching_events, key=lambda e: e.timestamp, reverse=True)[:limit]

    async def cleanup_old_events(self) -> int:
        """Clean up events older than retention period."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)

        old_events = [event for event in self.events if event.timestamp < cutoff_date]

        for event in old_events:
            self.events.remove(event)

        if old_events:
            logger.info(f"Cleaned up {len(old_events)} old audit events")

        return len(old_events)

    async def get_event_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get audit event statistics."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        recent_events = [
            event for event in self.events if event.timestamp > cutoff_time
        ]

        stats = {
            "total_events": len(recent_events),
            "by_type": {},
            "by_severity": {},
            "by_user": {},
            "time_range_hours": hours,
        }

        for event in recent_events:
            # Count by type
            event_type = event.event_type.value
            stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1

            # Count by severity
            stats["by_severity"][event.severity] = (
                stats["by_severity"].get(event.severity, 0) + 1
            )

            # Count by user
            if event.user_id:
                stats["by_user"][event.user_id] = (
                    stats["by_user"].get(event.user_id, 0) + 1
                )

        return stats

    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        import uuid

        return f"audit_{uuid.uuid4().hex}"
