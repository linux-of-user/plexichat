#!/usr/bin/env python3
"""
Authentication Audit Logger

Comprehensive audit logging for authentication events:
- Login attempts (successful/failed)
- Password changes
- MFA events
- Account lockouts
- Privilege escalations
- Session management
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pathlib import Path

from plexichat.core.logging.unified_logging_manager import get_logger
from plexichat.core.config import get_config

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    MFA_SETUP = "mfa_setup"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    MFA_BYPASS = "mfa_bypass"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PRIVILEGE_REVOCATION = "privilege_revocation"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_TERMINATED = "session_terminated"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"


class RiskLevel(Enum):
    """Risk levels for audit events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Authentication audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime = field(default_factory=datetime.now)
    user_id: Optional[str] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.LOW
    success: bool = True
    error_message: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "username": self.username,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "risk_level": self.risk_level.value,
            "success": self.success,
            "error_message": self.error_message,
            "additional_data": self.additional_data
        }


class AuthAuditLogger:
    """Authentication audit logger."""

    def __init__(self):
        self.audit_log_file = Path(LOGS_DIR) / "auth_audit.log"
        self.security_log_file = Path(LOGS_DIR) / "security_events.log"

        # Ensure log directories exist
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        self.security_log_file.parent.mkdir(parents=True, exist_ok=True)

        # In-memory storage for recent events (for analysis)
        self.recent_events: List[AuditEvent] = []
        self.max_recent_events = 1000

        # Failed login tracking
        self.failed_login_attempts: Dict[str, List[datetime]] = {}
        self.lockout_threshold = 5
        self.lockout_window_minutes = 15

    def log_event(self, event: AuditEvent):
        """Log an audit event."""
        # Add to recent events
        self.recent_events.append(event)
        if len(self.recent_events) > self.max_recent_events:
            self.recent_events.pop(0)

        # Write to audit log
        self._write_to_audit_log(event)

        # Write to security log if high risk
        if event.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            self._write_to_security_log(event)

        # Check for suspicious patterns
        self._analyze_for_suspicious_activity(event)

        # Log to application logger
        log_message = f"AUTH_AUDIT: {event.event_type.value} - User: {event.username or 'unknown'} - IP: {event.ip_address or 'unknown'}"
        if event.success:
            logger.info(log_message)
        else:
            logger.warning(f"{log_message} - Error: {event.error_message}")

    def log_login_success(self, user_id: str, username: str, ip_address: str,
                         user_agent: str = None, session_id: str = None):
        """Log successful login."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            risk_level=RiskLevel.LOW,
            success=True
        )

        # Clear failed login attempts for this user
        if username in self.failed_login_attempts:
            del self.failed_login_attempts[username]

        self.log_event(event)

    def log_login_failure(self, username: str, ip_address: str, reason: str,
                         user_agent: str = None):
        """Log failed login attempt."""
        # Track failed attempts
        if username not in self.failed_login_attempts:
            self.failed_login_attempts[username] = []

        self.failed_login_attempts[username].append(datetime.now())

        # Clean old attempts
        cutoff_time = datetime.now().timestamp() - (self.lockout_window_minutes * 60)
        self.failed_login_attempts[username] = [
            attempt for attempt in self.failed_login_attempts[username]
            if attempt.timestamp() > cutoff_time
        ]

        # Determine risk level
        attempt_count = len(self.failed_login_attempts[username])
        if attempt_count >= self.lockout_threshold:
            risk_level = RiskLevel.CRITICAL
        elif attempt_count >= 3:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.MEDIUM

        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.LOGIN_FAILURE,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            risk_level=risk_level,
            success=False,
            error_message=reason,
            additional_data={
                "failed_attempt_count": attempt_count,
                "lockout_threshold": self.lockout_threshold
            }
        )

        self.log_event(event)

        # Check if account should be locked
        if attempt_count >= self.lockout_threshold:
            self.log_account_locked(username, ip_address, "Too many failed login attempts")

    def log_mfa_event(self, user_id: str, username: str, mfa_method: str,
                     success: bool, ip_address: str = None, error_message: str = None):
        """Log MFA event."""
        event_type = AuditEventType.MFA_SUCCESS if success else AuditEventType.MFA_FAILURE
        risk_level = RiskLevel.LOW if success else RiskLevel.MEDIUM

        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=event_type,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            risk_level=risk_level,
            success=success,
            error_message=error_message,
            additional_data={"mfa_method": mfa_method}
        )

        self.log_event(event)

    def log_password_change(self, user_id: str, username: str, ip_address: str = None,
                           forced: bool = False):
        """Log password change."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.PASSWORD_CHANGE,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            risk_level=RiskLevel.LOW,
            success=True,
            additional_data={"forced_change": forced}
        )

        self.log_event(event)

    def log_account_locked(self, username: str, ip_address: str = None, reason: str = None):
        """Log account lockout."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.ACCOUNT_LOCKED,
            username=username,
            ip_address=ip_address,
            risk_level=RiskLevel.HIGH,
            success=True,
            additional_data={"lockout_reason": reason}
        )

        self.log_event(event)

    def log_privilege_escalation(self, user_id: str, username: str, old_role: str,
                               new_role: str, granted_by: str = None):
        """Log privilege escalation."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.PRIVILEGE_ESCALATION,
            user_id=user_id,
            username=username,
            risk_level=RiskLevel.HIGH,
            success=True,
            additional_data={
                "old_role": old_role,
                "new_role": new_role,
                "granted_by": granted_by
            }
        )

        self.log_event(event)

    def log_suspicious_activity(self, username: str = None, ip_address: str = None,
                              activity_type: str = None, details: Dict[str, Any] = None):
        """Log suspicious activity."""
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            username=username,
            ip_address=ip_address,
            risk_level=RiskLevel.HIGH,
            success=False,
            additional_data={
                "activity_type": activity_type,
                "details": details or {}
            }
        )

        self.log_event(event)

    def get_user_login_history(self, username: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get login history for a user."""
        user_events = []
        for event in reversed(self.recent_events):
            if (event.username == username and
                event.event_type in [AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE]):
                user_events.append(event.to_dict())
                if len(user_events) >= limit:
                    break

        return user_events

    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get security summary for the last N hours."""
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        recent_events = [
            event for event in self.recent_events
            if event.timestamp.timestamp() > cutoff_time
        ]

        summary = {
            "total_events": len(recent_events),
            "successful_logins": 0,
            "failed_logins": 0,
            "mfa_events": 0,
            "high_risk_events": 0,
            "unique_users": set(),
            "unique_ips": set(),
            "event_types": {}
        }

        for event in recent_events:
            if event.event_type == AuditEventType.LOGIN_SUCCESS:
                summary["successful_logins"] += 1
            elif event.event_type == AuditEventType.LOGIN_FAILURE:
                summary["failed_logins"] += 1
            elif event.event_type in [AuditEventType.MFA_SUCCESS, AuditEventType.MFA_FAILURE]:
                summary["mfa_events"] += 1

            if event.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                summary["high_risk_events"] += 1

            if event.username:
                summary["unique_users"].add(event.username)
            if event.ip_address:
                summary["unique_ips"].add(event.ip_address)

            event_type = event.event_type.value
            summary["event_types"][event_type] = summary["event_types"].get(event_type, 0) + 1

        # Convert sets to counts
        summary["unique_users"] = len(summary["unique_users"])
        summary["unique_ips"] = len(summary["unique_ips"])

        return summary

    def _write_to_audit_log(self, event: AuditEvent):
        """Write event to audit log file."""
        try:
            with open(self.audit_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to audit log: {e}")

    def _write_to_security_log(self, event: AuditEvent):
        """Write high-risk event to security log file."""
        try:
            with open(self.security_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to security log: {e}")

    def _analyze_for_suspicious_activity(self, event: AuditEvent):
        """Analyze event for suspicious patterns."""
        # Check for rapid failed login attempts from same IP
        if event.event_type == AuditEventType.LOGIN_FAILURE and event.ip_address:
            recent_failures = [
                e for e in self.recent_events[-50:]  # Check last 50 events
                if (e.event_type == AuditEventType.LOGIN_FAILURE and)
                    e.ip_address == event.ip_address and
                    (datetime.now() - e.timestamp).total_seconds() < 300)  # Last 5 minutes
            ]

            if len(recent_failures) >= 10:
                self.log_suspicious_activity()
                    ip_address=event.ip_address,
                    activity_type="rapid_failed_logins",
                    details={"failure_count": len(recent_failures), "time_window": "5_minutes"}
                )

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import secrets
        return f"audit_{secrets.token_urlsafe(16)}"


# Global audit logger instance
auth_audit_logger = AuthAuditLogger()


def get_auth_audit_logger() -> AuthAuditLogger:
    """Get the global auth audit logger instance."""
    return auth_audit_logger
