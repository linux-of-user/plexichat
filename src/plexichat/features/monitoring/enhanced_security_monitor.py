"""
Enhanced Security Monitoring System
Provides real-time security monitoring, threat detection, and incident response.
"""

import time
import json
import logging
import asyncio
import hashlib
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(Enum):
    """Security event types."""
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_ACCESS = "system_access"
    API_ABUSE = "api_abuse"
    INJECTION_ATTEMPT = "injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTEMPT = "csrf_attempt"
    BRUTE_FORCE = "brute_force"
    ACCOUNT_LOCKOUT = "account_lockout"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    timestamp: datetime
    event_type: EventType
    threat_level: ThreatLevel
    source_ip: str
    user_id: Optional[str]
    user_agent: str
    endpoint: str
    method: str
    details: Dict[str, Any]
    risk_score: float
    action_taken: Optional[str] = None
    incident_id: Optional[str] = None


@dataclass
class ThreatPattern:
    """Threat pattern definition."""
    name: str
    description: str
    indicators: List[str]
    threshold: int
    time_window: int  # seconds
    threat_level: ThreatLevel
    auto_response: bool = False


@dataclass
class SecurityIncident:
    """Security incident record."""
    incident_id: str
    created_at: datetime
    threat_level: ThreatLevel
    event_type: EventType
    source_ip: str
    user_id: Optional[str]
    description: str
    events: List[SecurityEvent]
    status: str = "open"  # open, investigating, resolved, false_positive
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None


class EnhancedSecurityMonitor:
    """Enhanced security monitoring system with real-time threat detection."""

    def __init__(self):
        self.events: deque = deque(maxlen=10000)  # Keep last 10k events
        self.incidents: Dict[str, SecurityIncident] = {}
        self.threat_patterns: List[ThreatPattern] = []
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Dict[str, float] = {}  # IP -> risk score
        self.user_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Monitoring statistics
        self.stats = {
            "total_events": 0,
            "events_by_type": defaultdict(int),
            "events_by_threat_level": defaultdict(int),
            "incidents_created": 0,
            "ips_blocked": 0,
            "false_positives": 0,
            "last_updated": datetime.now()
        }
        
        # Real-time monitoring
        self.monitoring_active = True
        self.alert_callbacks: List[callable] = []
        
        # Initialize threat patterns
        self._initialize_threat_patterns()
        
        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._background_monitor, daemon=True)
        self.if monitor_thread and hasattr(monitor_thread, "start"): monitor_thread.start()

    def _initialize_threat_patterns(self):
        """Initialize built-in threat patterns."""
        self.threat_patterns = [
            ThreatPattern(
                name="Brute Force Login",
                description="Multiple failed login attempts from same IP",
                indicators=["login_failure"],
                threshold=5,
                time_window=300,  # 5 minutes
                threat_level=ThreatLevel.HIGH,
                auto_response=True
            ),
            ThreatPattern(
                name="SQL Injection Attempt",
                description="Potential SQL injection in request parameters",
                indicators=["injection_attempt"],
                threshold=1,
                time_window=60,
                threat_level=ThreatLevel.CRITICAL,
                auto_response=True
            ),
            ThreatPattern(
                name="XSS Attempt",
                description="Cross-site scripting attempt detected",
                indicators=["xss_attempt"],
                threshold=1,
                time_window=60,
                threat_level=ThreatLevel.HIGH,
                auto_response=True
            ),
            ThreatPattern(
                name="Rate Limit Abuse",
                description="Excessive rate limit violations",
                indicators=["rate_limit_exceeded"],
                threshold=10,
                time_window=600,  # 10 minutes
                threat_level=ThreatLevel.MEDIUM,
                auto_response=False
            ),
            ThreatPattern(
                name="Privilege Escalation",
                description="Attempt to access unauthorized resources",
                indicators=["permission_denied"],
                threshold=3,
                time_window=300,
                threat_level=ThreatLevel.HIGH,
                auto_response=True
            ),
            ThreatPattern(
                name="Suspicious API Usage",
                description="Unusual API access patterns",
                indicators=["api_abuse"],
                threshold=20,
                time_window=3600,  # 1 hour
                threat_level=ThreatLevel.MEDIUM,
                auto_response=False
            )
        ]

    async def log_event(self, event: SecurityEvent):
        """Log a security event and analyze for threats."""
        # Add to event queue
        self.events.append(event)
        
        # Update statistics
        self.stats["total_events"] += 1
        self.stats["events_by_type"][event.event_type.value] += 1
        self.stats["events_by_threat_level"][event.threat_level.value] += 1
        self.stats["last_updated"] = datetime.now()
        
        # Analyze for threat patterns
        await self._analyze_threat_patterns(event)
        
        # Update IP risk scores
        self._update_ip_risk_score(event)
        
        # Check for immediate threats
        if event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            await self._handle_high_threat_event(event)
        
        # Log to file/database
        self._log_to_storage(event)

    async def _analyze_threat_patterns(self, event: SecurityEvent):
        """Analyze event against known threat patterns."""
        current_time = event.timestamp
        
        for pattern in self.threat_patterns:
            if event.event_type.value in pattern.indicators:
                # Count matching events in time window
                matching_events = [
                    e for e in self.events
                    if (e.event_type.value in pattern.indicators and
                        e.source_ip == event.source_ip and
                        (current_time - e.timestamp).total_seconds() <= pattern.time_window)
                ]
                
                if len(matching_events) >= pattern.threshold:
                    await self._create_incident(pattern, event, matching_events)

    async def _create_incident(self, pattern: ThreatPattern, trigger_event: SecurityEvent, related_events: List[SecurityEvent]):
        """Create a security incident."""
        incident_id = self._generate_incident_id(trigger_event)
        
        incident = SecurityIncident(
            incident_id=incident_id,
            created_at=datetime.now(),
            threat_level=pattern.threat_level,
            event_type=trigger_event.event_type,
            source_ip=trigger_event.source_ip,
            user_id=trigger_event.user_id,
            description=f"{pattern.name}: {pattern.description}",
            events=related_events
        )
        
        self.incidents[incident_id] = incident
        self.stats["incidents_created"] += 1
        
        # Auto-response if configured
        if pattern.auto_response:
            await self._execute_auto_response(incident)
        
        # Send alerts
        await self._send_alert(incident)
        
        logger.warning(f"Security incident created: {incident_id} - {pattern.name}")

    async def _execute_auto_response(self, incident: SecurityIncident):
        """Execute automatic response to security incident."""
        if incident.threat_level == ThreatLevel.CRITICAL:
            # Block IP immediately
            self.blocked_ips.add(incident.source_ip)
            self.stats["ips_blocked"] += 1
            incident.action_taken = f"IP {incident.source_ip} blocked automatically"
            
            # Lock user account if applicable
            if incident.user_id:
                await self._lock_user_account(incident.user_id)
                incident.action_taken += f", User {incident.user_id} locked"
        
        elif incident.threat_level == ThreatLevel.HIGH:
            # Add to suspicious IPs
            self.suspicious_ips[incident.source_ip] = 0.8
            incident.action_taken = f"IP {incident.source_ip} marked as suspicious"
        
        logger.info(f"Auto-response executed for incident {incident.incident_id}: {incident.action_taken}")

    async def _handle_high_threat_event(self, event: SecurityEvent):
        """Handle high-threat events immediately."""
        if event.threat_level == ThreatLevel.CRITICAL:
            # Immediate blocking for critical threats
            self.blocked_ips.add(event.source_ip)
            self.stats["ips_blocked"] += 1
            
            # Create immediate incident
            incident_id = self._generate_incident_id(event)
            incident = SecurityIncident(
                incident_id=incident_id,
                created_at=datetime.now(),
                threat_level=event.threat_level,
                event_type=event.event_type,
                source_ip=event.source_ip,
                user_id=event.user_id,
                description=f"Critical threat detected: {event.details.get('description', 'Unknown')}",
                events=[event],
                action_taken=f"IP {event.source_ip} blocked immediately"
            )
            
            self.incidents[incident_id] = incident
            await self._send_alert(incident)

    def _update_ip_risk_score(self, event: SecurityEvent):
        """Update risk score for source IP."""
        ip = event.source_ip
        
        # Calculate risk score based on event
        risk_increase = {
            ThreatLevel.LOW: 0.1,
            ThreatLevel.MEDIUM: 0.3,
            ThreatLevel.HIGH: 0.6,
            ThreatLevel.CRITICAL: 1.0
        }.get(event.threat_level, 0.1)
        
        current_score = self.suspicious_ips.get(ip, 0.0)
        new_score = min(1.0, current_score + risk_increase)
        self.suspicious_ips[ip] = new_score
        
        # Auto-block if score is too high
        if new_score >= 0.9 and ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.stats["ips_blocked"] += 1
            logger.warning(f"IP {ip} auto-blocked due to high risk score: {new_score}")

    async def _send_alert(self, incident: SecurityIncident):
        """Send alert for security incident."""
        alert_data = {
            "incident_id": incident.incident_id,
            "threat_level": incident.threat_level.value,
            "description": incident.description,
            "source_ip": incident.source_ip,
            "user_id": incident.user_id,
            "timestamp": incident.created_at.isoformat(),
            "action_taken": incident.action_taken
        }
        
        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _background_monitor(self):
        """Background monitoring thread."""
        while self.monitoring_active:
            try:
                # Clean old events
                self._cleanup_old_events()
                
                # Decay IP risk scores
                self._decay_ip_risk_scores()
                
                # Check for patterns
                self._check_behavioral_patterns()
                
                time.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Background monitor error: {e}")
                time.sleep(60)

    def _cleanup_old_events(self):
        """Clean up old events and incidents."""
        cutoff_time = datetime.now() - timedelta(days=7)
        
        # Clean old incidents
        old_incidents = [
            incident_id for incident_id, incident in self.incidents.items()
            if incident.created_at < cutoff_time and incident.status == "resolved"
        ]
        
        for incident_id in old_incidents:
            del self.incidents[incident_id]

    def _decay_ip_risk_scores(self):
        """Decay IP risk scores over time."""
        decay_rate = 0.1  # 10% decay per hour
        current_time = time.time()
        
        for ip in list(self.suspicious_ips.keys()):
            # Decay score
            self.suspicious_ips[ip] *= (1 - decay_rate)
            
            # Remove if score is very low
            if self.suspicious_ips[ip] < 0.1:
                del self.suspicious_ips[ip]

    def _check_behavioral_patterns(self):
        """Check for behavioral anomalies."""
        # Implement behavioral analysis
        # This could include ML-based anomaly detection
        pass

    def _generate_incident_id(self, event: SecurityEvent) -> str:
        """Generate unique incident ID."""
        data = f"{event.timestamp.isoformat()}{event.source_ip}{event.event_type.value}"
        return f"INC-{hashlib.md5(data.encode()).hexdigest()[:8].upper()}"

    def _log_to_storage(self, event: SecurityEvent):
        """Log event to persistent storage."""
        # In production, this would write to database or log files
        log_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "threat_level": event.threat_level.value,
            "source_ip": event.source_ip,
            "user_id": event.user_id,
            "endpoint": event.endpoint,
            "method": event.method,
            "details": event.details,
            "risk_score": event.risk_score
        }
        
        logger.info(f"Security Event: {json.dumps(log_entry)}")

    async def _lock_user_account(self, user_id: str):
        """Lock user account for security."""
        # Implementation would depend on user management system
        logger.warning(f"User account locked for security: {user_id}")

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips

    def get_ip_risk_score(self, ip: str) -> float:
        """Get risk score for IP."""
        return self.suspicious_ips.get(ip, 0.0)

    def add_alert_callback(self, callback: callable):
        """Add alert callback function."""
        self.alert_callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return dict(self.stats)

    def get_recent_incidents(self, limit: int = 10) -> List[SecurityIncident]:
        """Get recent security incidents."""
        incidents = sorted(
            self.incidents.values(),
            key=lambda x: x.created_at,
            reverse=True
        )
        return incidents[:limit]

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Get specific incident by ID."""
        return self.incidents.get(incident_id)

    def resolve_incident(self, incident_id: str, resolution: str, resolved_by: str):
        """Resolve a security incident."""
        incident = self.incidents.get(incident_id)
        if incident:
            incident.status = "resolved"
            incident.resolution = resolution
            incident.resolved_at = datetime.now()
            incident.assigned_to = resolved_by
            logger.info(f"Incident {incident_id} resolved by {resolved_by}")

    def stop_monitoring(self):
        """Stop the monitoring system."""
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)


# Global monitor instance
_security_monitor = None


def get_security_monitor() -> EnhancedSecurityMonitor:
    """Get the global security monitor instance."""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = EnhancedSecurityMonitor()
    return _security_monitor


# Convenience functions for creating security events
def create_login_event(source_ip: str, user_id: str, success: bool, details: Dict[str, Any] = None) -> SecurityEvent:
    """Create a login event."""
    return SecurityEvent(
        timestamp=datetime.now(),
        event_type=EventType.LOGIN_SUCCESS if success else EventType.LOGIN_FAILURE,
        threat_level=ThreatLevel.LOW if success else ThreatLevel.MEDIUM,
        source_ip=source_ip,
        user_id=user_id,
        user_agent=details.get("user_agent", "") if details else "",
        endpoint="/auth/login",
        method="POST",
        details=details or {},
        risk_score=0.1 if success else 0.5
    )


def create_permission_denied_event(source_ip: str, user_id: str, endpoint: str, details: Dict[str, Any] = None) -> SecurityEvent:
    """Create a permission denied event."""
    return SecurityEvent(
        timestamp=datetime.now(),
        event_type=EventType.PERMISSION_DENIED,
        threat_level=ThreatLevel.MEDIUM,
        source_ip=source_ip,
        user_id=user_id,
        user_agent=details.get("user_agent", "") if details else "",
        endpoint=endpoint,
        method=details.get("method", "GET") if details else "GET",
        details=details or {},
        risk_score=0.6
    )


def create_injection_attempt_event(source_ip: str, endpoint: str, attack_type: str, details: Dict[str, Any] = None) -> SecurityEvent:
    """Create an injection attempt event."""
    return SecurityEvent(
        timestamp=datetime.now(),
        event_type=EventType.INJECTION_ATTEMPT,
        threat_level=ThreatLevel.CRITICAL,
        source_ip=source_ip,
        user_id=details.get("user_id") if details else None,
        user_agent=details.get("user_agent", "") if details else "",
        endpoint=endpoint,
        method=details.get("method", "GET") if details else "GET",
        details={**(details or {}), "attack_type": attack_type},
        risk_score=0.9
    )
