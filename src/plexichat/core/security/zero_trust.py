#!/usr/bin/env python3
"""
Zero Trust Security Model

Implements comprehensive zero-trust security including:
- Continuous verification
- Least privilege access
- Behavioral analysis
- Risk-based authentication
- Incident response
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


class TrustLevel(Enum):
    """Trust levels for zero-trust model."""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


class RiskLevel(Enum):
    """Risk assessment levels."""
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class IncidentSeverity(Enum):
    """Security incident severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UserContext:
    """User context for zero-trust evaluation."""
    user_id: str
    ip_address: str
    user_agent: str
    device_fingerprint: str
    location: Optional[Dict[str, str]] = None
    session_id: Optional[str] = None
    last_activity: datetime = field(default_factory=datetime.now)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_fingerprint": self.device_fingerprint,
            "location": self.location,
            "session_id": self.session_id,
            "last_activity": self.last_activity.isoformat(),
            "trust_level": self.trust_level.value,
            "risk_score": self.risk_score
        }


@dataclass
class SecurityIncident:
    """Security incident record."""
    incident_id: str
    incident_type: str
    severity: IncidentSeverity
    user_id: Optional[str]
    ip_address: Optional[str]
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    resolved: bool = False
    response_actions: List[str] = field(default_factory=list)


@dataclass
class BehaviorPattern:
    """User behavior pattern."""
    user_id: str
    pattern_type: str
    typical_hours: Set[int] = field(default_factory=set)
    typical_locations: Set[str] = field(default_factory=set)
    typical_devices: Set[str] = field(default_factory=set)
    typical_actions: Dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)


class BehavioralAnalyzer:
    """Analyzes user behavior patterns for anomaly detection."""

    def __init__(self):
        self.user_patterns: Dict[str, BehaviorPattern] = {}
        self.activity_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.max_history_days = 30

    def record_activity(self, user_id: str, activity_type: str, context: UserContext):
        """Record user activity for pattern analysis."""
        activity = {
            "type": activity_type,
            "timestamp": datetime.now(),
            "ip_address": context.ip_address,
            "device_fingerprint": context.device_fingerprint,
            "location": context.location,
            "hour": datetime.now().hour
        }

        self.activity_history[user_id].append(activity)

        # Clean old history
        cutoff_date = datetime.now() - timedelta(days=self.max_history_days)
        self.activity_history[user_id] = [
            a for a in self.activity_history[user_id]
            if a["timestamp"] > cutoff_date
        ]

        # Update behavior pattern
        self._update_behavior_pattern(user_id)

    def analyze_behavior(self, user_id: str, context: UserContext) -> Tuple[bool, float, List[str]]:
        """Analyze current behavior against established patterns."""
        pattern = self.user_patterns.get(user_id)
        if not pattern:
            return True, 0.0, ["No established pattern"]

        anomalies = []
        risk_score = 0.0

        current_hour = datetime.now().hour

        # Check time-based anomalies
        if current_hour not in pattern.typical_hours:
            anomalies.append(f"Unusual login time: {current_hour}:00")
            risk_score += 0.3

        # Check location anomalies
        if context.location:
            location_key = f"{context.location.get('country', 'unknown')}_{context.location.get('city', 'unknown')}"
            if location_key not in pattern.typical_locations:
                anomalies.append(f"Unusual location: {location_key}")
                risk_score += 0.4

        # Check device anomalies
        if context.device_fingerprint not in pattern.typical_devices:
            anomalies.append("New/unusual device")
            risk_score += 0.5

        # Check IP address patterns
        ip_prefix = ".".join(context.ip_address.split(".")[:3])
        known_ip_prefixes = {
            ".".join(activity["ip_address"].split(".")[:3])
            for activity in self.activity_history[user_id][-50:]  # Last 50 activities
        }

        if ip_prefix not in known_ip_prefixes:
            anomalies.append("New IP address range")
            risk_score += 0.3

        is_normal = risk_score < 0.5
        return is_normal, risk_score, anomalies

    def _update_behavior_pattern(self, user_id: str):
        """Update behavior pattern based on recent activity."""
        if user_id not in self.user_patterns:
            self.user_patterns[user_id] = BehaviorPattern(user_id=user_id, pattern_type="learned")

        pattern = self.user_patterns[user_id]
        recent_activities = self.activity_history[user_id][-100:]  # Last 100 activities

        # Update typical hours
        pattern.typical_hours = {
            activity["hour"] for activity in recent_activities
        }

        # Update typical locations
        pattern.typical_locations = {
            f"{activity['location'].get('country', 'unknown')}_{activity['location'].get('city', 'unknown')}"
            for activity in recent_activities
            if activity.get("location")
        }

        # Update typical devices
        pattern.typical_devices = {
            activity["device_fingerprint"] for activity in recent_activities
        }

        # Update typical actions
        action_counts = defaultdict(int)
        for activity in recent_activities:
            action_counts[activity["type"]] += 1
        pattern.typical_actions = dict(action_counts)

        pattern.last_updated = datetime.now()


class ZeroTrustEngine:
    """Zero Trust security engine."""

    def __init__(self):
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.user_contexts: Dict[str, UserContext] = {}
        self.security_incidents: List[SecurityIncident] = []
        self.trust_policies: Dict[str, Dict[str, Any]] = {}
        self.active_sessions: Dict[str, UserContext] = {}

        # Default trust policies
        self._initialize_default_policies()

    def _initialize_default_policies(self):
        """Initialize default zero-trust policies."""
        self.trust_policies = {
            "authentication": {
                "require_mfa_for_high_risk": True,
                "max_failed_attempts": 3,
                "session_timeout_minutes": 60,
                "require_device_verification": True
            },
            "authorization": {
                "default_access_level": "minimal",
                "require_justification_for_elevated_access": True,
                "max_privilege_duration_hours": 8
            },
            "monitoring": {
                "continuous_verification_interval_minutes": 15,
                "behavioral_analysis_enabled": True,
                "incident_auto_response": True
            }
        }

    async def evaluate_trust(
        self, user_id: str, context: UserContext, requested_action: str
    ) -> Tuple[TrustLevel, float, List[str]]:
        """Evaluate trust level for a user context and action."""
        try:
            # Record activity for behavioral analysis
            self.behavioral_analyzer.record_activity(user_id, requested_action, context)

            # Analyze behavior
            is_normal_behavior, behavior_risk, behavior_anomalies = \
                self.behavioral_analyzer.analyze_behavior(user_id, context)

            # Calculate base risk score
            risk_score = behavior_risk
            risk_factors = behavior_anomalies.copy()

            # Check session context
            if context.session_id in self.active_sessions:
                session_context = self.active_sessions[context.session_id]
                session_age = (datetime.now() - session_context.last_activity).total_seconds() / 60

                if session_age > self.trust_policies["authentication"]["session_timeout_minutes"]:
                    risk_score += 0.5
                    risk_factors.append("Session timeout exceeded")

            # Check IP reputation (simplified)
            if self._is_suspicious_ip(context.ip_address):
                risk_score += 0.6
                risk_factors.append("Suspicious IP address")

            # Check device trust
            if not self._is_trusted_device(context.device_fingerprint, user_id):
                risk_score += 0.3
                risk_factors.append("Untrusted device")

            # Determine trust level based on risk score
            if risk_score >= 0.8:
                trust_level = TrustLevel.UNTRUSTED
            elif risk_score >= 0.6:
                trust_level = TrustLevel.LOW
            elif risk_score >= 0.4:
                trust_level = TrustLevel.MEDIUM
            elif risk_score >= 0.2:
                trust_level = TrustLevel.HIGH
            else:
                trust_level = TrustLevel.VERIFIED

            # Update user context
            context.trust_level = trust_level
            context.risk_score = risk_score
            self.user_contexts[user_id] = context

            logger.info(f"Trust evaluation for {user_id}: {trust_level.name} (risk: {risk_score:.2f})")

            return trust_level, risk_score, risk_factors

        except Exception as e:
            logger.error(f"Trust evaluation failed: {e}")
            return TrustLevel.UNTRUSTED, 1.0, ["Evaluation error"]

    async def verify_access(
        self, user_id: str, resource: str, action: str, context: UserContext
    ) -> Tuple[bool, str]:
        """Verify access using zero-trust principles."""
        try:
            # Evaluate trust
            trust_level, risk_score, risk_factors = await self.evaluate_trust(
                user_id, context, f"{action}_{resource}"
            )

            # Apply least privilege principle
            required_trust = self._get_required_trust_level(resource, action)

            if trust_level.value < required_trust.value:
                reason = f"Insufficient trust level: {trust_level.name} < {required_trust.name}"

                # Create security incident for high-risk access attempts
                if risk_score > 0.7:
                    await self._create_security_incident(
                        "unauthorized_access_attempt",
                        IncidentSeverity.HIGH,
                        user_id,
                        context.ip_address,
                        f"High-risk access attempt to {resource}",
                        {
                            "resource": resource,
                            "action": action,
                            "trust_level": trust_level.name,
                            "risk_score": risk_score,
                            "risk_factors": risk_factors,
                        },
                    )

                return False, reason

            # Additional verification for high-risk actions
            if risk_score > 0.5 and self.trust_policies["authentication"]["require_mfa_for_high_risk"]:
                return False, "Additional verification required (MFA)"

            # Update session
            if context.session_id:
                self.active_sessions[context.session_id] = context

            return True, "Access granted"

        except Exception as e:
            logger.error(f"Access verification failed: {e}")
            return False, "Verification error"

    async def continuous_verification(self):
        """Perform continuous verification of active sessions."""
        try:
            current_time = datetime.now()
            verification_interval = timedelta(
                minutes=self.trust_policies["monitoring"]["continuous_verification_interval_minutes"]
            )

            for session_id, context in list(self.active_sessions.items()):
                # Check if verification is due
                if current_time - context.last_activity > verification_interval:
                    # Re-evaluate trust
                    trust_level, risk_score, risk_factors = await self.evaluate_trust(
                        context.user_id, context, "session_verification"
                    )

                    # Terminate high-risk sessions
                    if risk_score > 0.8:
                        await self._terminate_session(session_id, "High risk detected")

                        await self._create_security_incident(
                            "session_terminated_high_risk",
                            IncidentSeverity.MEDIUM,
                            context.user_id,
                            context.ip_address,
                            "Session terminated due to high risk",
                            {
                                "session_id": session_id,
                                "risk_score": risk_score,
                                "risk_factors": risk_factors,
                            },
                        )

                    # Update last verification time
                    context.last_activity = current_time

        except Exception as e:
            logger.error(f"Continuous verification failed: {e}")

    async def _create_security_incident(
        self,
        incident_type: str,
        severity: IncidentSeverity,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        description: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create a security incident."""
        incident = SecurityIncident(
            incident_id=f"inc_{int(time.time() * 1000)}",
            incident_type=incident_type,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            description=description,
            evidence=evidence or {}
        )

        self.security_incidents.append(incident)

        # Auto-response for critical incidents
        if severity == IncidentSeverity.CRITICAL and self.trust_policies["monitoring"]["incident_auto_response"]:
            await self._auto_respond_to_incident(incident)

        logger.warning(f"Security incident created: {incident.incident_id} - {description}")

    async def _auto_respond_to_incident(self, incident: SecurityIncident):
        """Automatically respond to security incidents."""
        try:
            if incident.user_id:
                # Terminate all sessions for the user
                user_sessions = [
                    session_id for session_id, context in self.active_sessions.items()
                    if context.user_id == incident.user_id
                ]

                for session_id in user_sessions:
                    await self._terminate_session(session_id, f"Auto-response to incident {incident.incident_id}")

                incident.response_actions.append(f"Terminated {len(user_sessions)} sessions")

            if incident.ip_address:
                # Block IP address (placeholder)
                incident.response_actions.append(f"Blocked IP address {incident.ip_address}")

            logger.info(f"Auto-response completed for incident {incident.incident_id}")

        except Exception as e:
            logger.error(f"Auto-response failed for incident {incident.incident_id}: {e}")

    async def _terminate_session(self, session_id: str, reason: str):
        """Terminate a user session."""
        if session_id in self.active_sessions:
            context = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            logger.info(f"Session {session_id} terminated: {reason}")

    def _get_required_trust_level(self, resource: str, action: str) -> TrustLevel:
        """Get required trust level for resource/action combination."""
        # Simplified trust level mapping
        if "admin" in resource.lower() or "delete" in action.lower():
            return TrustLevel.VERIFIED
        elif "sensitive" in resource.lower() or "modify" in action.lower():
            return TrustLevel.HIGH
        elif "write" in action.lower() or "create" in action.lower():
            return TrustLevel.MEDIUM
        else:
            return TrustLevel.LOW

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious (placeholder)."""
        # In production, this would check against threat intelligence feeds
        suspicious_ranges = ["192.168.1.100", "10.0.0.1"]  # Example
        return ip_address in suspicious_ranges

    def _is_trusted_device(self, device_fingerprint: str, user_id: str) -> bool:
        """Check if device is trusted for the user."""
        # Check if device has been used by this user before
        user_activities = self.behavioral_analyzer.activity_history.get(user_id, [])
        known_devices = {activity["device_fingerprint"] for activity in user_activities}
        return device_fingerprint in known_devices

    def get_security_dashboard(self) -> Dict[str, Any]:
        """Get security dashboard data."""
        recent_incidents = [
            incident for incident in self.security_incidents
            if (datetime.now() - incident.timestamp).days < 7
        ]

        return {
            "active_sessions": len(self.active_sessions),
            "recent_incidents": len(recent_incidents),
            "critical_incidents": len([i for i in recent_incidents if i.severity == IncidentSeverity.CRITICAL]),
            "high_risk_users": len([c for c in self.user_contexts.values() if c.risk_score > 0.7]),
            "trust_level_distribution": {
                level.name: len([c for c in self.user_contexts.values() if c.trust_level == level])
                for level in TrustLevel
            },
            "incident_types": {
                incident_type: len([i for i in recent_incidents if i.incident_type == incident_type])
                for incident_type in set(i.incident_type for i in recent_incidents)
            }
        }


# Global zero trust engine
zero_trust_engine = ZeroTrustEngine()


def get_zero_trust_engine() -> ZeroTrustEngine:
    """Get the global zero trust engine."""
    return zero_trust_engine
