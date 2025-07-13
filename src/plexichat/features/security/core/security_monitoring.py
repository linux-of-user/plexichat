import json
import logging
import smtplib
import syslog
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

import aiohttp

"""
PlexiChat Security Monitoring System

Real-time security monitoring with alerting, incident response,
and comprehensive security event correlation.
"""

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of security events."""
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALWARE_DETECTED = "malware_detected"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    DATA_BREACH = "data_breach"
    DDOS_ATTACK = "ddos_attack"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    FILE_UPLOAD_THREAT = "file_upload_threat"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_COMPROMISE = "system_compromise"
    CONFIGURATION_CHANGE = "configuration_change"
    CERTIFICATE_EXPIRY = "certificate_expiry"


class Severity(Enum):
    """Event severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class AlertStatus(Enum):
    """Alert status."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_id: str
    event_type: EventType
    severity: Severity
    timestamp: datetime
    source_ip: Optional[str]
    user_id: Optional[str]
    description: str
    details: Dict[str, Any]
    affected_resources: List[str] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "user_id": self.user_id,
            "description": self.description,
            "details": self.details,
            "affected_resources": self.affected_resources,
            "indicators_of_compromise": self.indicators_of_compromise
        }


@dataclass
class SecurityAlert:
    """Security alert with response tracking."""
    alert_id: str
    event: SecurityEvent
    status: AlertStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    response_actions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    escalation_level: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "event": self.event.to_dict(),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "assigned_to": self.assigned_to,
            "response_actions": self.response_actions,
            "notes": self.notes,
            "escalation_level": self.escalation_level
        }


@dataclass
class MonitoringRule:
    """Security monitoring rule."""
    rule_id: str
    name: str
    description: str
    event_types: Set[EventType]
    conditions: Dict[str, Any]
    severity_threshold: Severity
    alert_threshold: int  # Number of events to trigger alert
    time_window: int  # Time window in seconds
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "event_types": [et.value for et in self.event_types],
            "conditions": self.conditions,
            "severity_threshold": self.severity_threshold.value,
            "alert_threshold": self.alert_threshold,
            "time_window": self.time_window,
            "enabled": self.enabled
        }


class SecurityMonitor:
    """Real-time security monitoring system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize security monitor."""
        self.config = config or {}
        
        # Event storage
        self.events: List[SecurityEvent] = []
        self.alerts: Dict[str, SecurityAlert] = {}
        
        # Monitoring rules
        self.rules: Dict[str, MonitoringRule] = {}
        
        # Event handlers
        self.event_handlers: Dict[EventType, List[Callable]] = {}
        
        # Alert channels
        self.alert_channels = {
            "email": self.config.get("email", {}),
            "webhook": self.config.get("webhook", {}),
            "syslog": self.config.get("syslog", {})
        }
        
        # Statistics
        self.stats = {
            "total_events": 0,
            "alerts_generated": 0,
            "alerts_resolved": 0,
            "false_positives": 0,
            "events_by_type": {},
            "events_by_severity": {}
        }
        
        # Setup default rules
        self._setup_default_rules()
        
        logger.info("Security Monitor initialized")
    
    def _setup_default_rules(self):
        """Setup default monitoring rules."""
        default_rules = [
            MonitoringRule(
                rule_id="brute_force_detection",
                name="Brute Force Attack Detection",
                description="Detect brute force authentication attempts",
                event_types={EventType.AUTHENTICATION_FAILURE},
                conditions={"source_ip": "same", "time_window": 300},
                severity_threshold=Severity.MEDIUM,
                alert_threshold=5,
                time_window=300
            ),
            MonitoringRule(
                rule_id="ddos_detection",
                name="DDoS Attack Detection",
                description="Detect distributed denial of service attacks",
                event_types={EventType.DDOS_ATTACK},
                conditions={"request_rate": ">100"},
                severity_threshold=Severity.HIGH,
                alert_threshold=1,
                time_window=60
            ),
            MonitoringRule(
                rule_id="malware_detection",
                name="Malware Detection",
                description="Detect malware uploads or execution",
                event_types={EventType.MALWARE_DETECTED},
                conditions={},
                severity_threshold=Severity.CRITICAL,
                alert_threshold=1,
                time_window=1
            ),
            MonitoringRule(
                rule_id="privilege_escalation",
                name="Privilege Escalation Detection",
                description="Detect unauthorized privilege escalation attempts",
                event_types={EventType.PRIVILEGE_ESCALATION},
                conditions={},
                severity_threshold=Severity.HIGH,
                alert_threshold=1,
                time_window=1
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.rule_id] = rule
    
    async def log_event(self, event: SecurityEvent):
        """Log a security event."""
        self.events.append(event)
        self.stats["total_events"] += 1
        
        # Update statistics
        event_type_key = event.event_type.value
        self.stats["events_by_type"][event_type_key] = self.stats["events_by_type"].get(event_type_key, 0) + 1
        
        severity_key = event.severity.value
        self.stats["events_by_severity"][severity_key] = self.stats["events_by_severity"].get(severity_key, 0) + 1
        
        # Check monitoring rules
        await self._check_monitoring_rules(event)
        
        # Call event handlers
        if event.event_type in self.event_handlers:
            for handler in self.event_handlers[event.event_type]:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")
        
        logger.info(f"Security event logged: {event.event_type.value} - {event.description}")
    
    async def _check_monitoring_rules(self, event: SecurityEvent):
        """Check if event triggers any monitoring rules."""
        current_time = event.timestamp
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if event.event_type not in rule.event_types:
                continue
            
            if event.severity.value < rule.severity_threshold.value:
                continue
            
            # Check time window
            window_start = current_time - timedelta(seconds=rule.time_window)
            relevant_events = [
                e for e in self.events
                if e.timestamp >= window_start and e.event_type in rule.event_types
            ]
            
            # Apply rule conditions
            if self._evaluate_rule_conditions(rule, relevant_events, event):
                if len(relevant_events) >= rule.alert_threshold:
                    await self._create_alert(rule, relevant_events)
    
    def _evaluate_rule_conditions(self, rule: MonitoringRule, events: List[SecurityEvent], current_event: SecurityEvent) -> bool:
        """Evaluate rule conditions against events."""
        conditions = rule.conditions
        
        if not conditions:
            return True
        
        # Check source IP condition
        if "source_ip" in conditions:
            if conditions["source_ip"] == "same":
                source_ips = set(e.source_ip for e in events if e.source_ip)
                if len(source_ips) > 1:
                    return False
        
        # Check request rate condition
        if "request_rate" in conditions:
            rate_condition = conditions["request_rate"]
            if rate_condition.startswith(">"):
                threshold = int(rate_condition[1:])
                if len(events) <= threshold:
                    return False
        
        return True
    
    async def _create_alert(self, rule: MonitoringRule, events: List[SecurityEvent]):
        """Create security alert from rule and events."""
        alert_id = f"alert_{int(time.time())}_{rule.rule_id}"
        
        # Use the most recent/severe event as the primary event
        primary_event = max(events, key=lambda e: (e.severity.value, e.timestamp.timestamp()))
        
        alert = SecurityAlert(
            alert_id=alert_id,
            event=primary_event,
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        self.alerts[alert_id] = alert
        self.stats["alerts_generated"] += 1
        
        # Send alert notifications
        await self._send_alert_notifications(alert)
        
        logger.warning(f"Security alert created: {alert_id} - {rule.name}")
    
    async def _send_alert_notifications(self, alert: SecurityAlert):
        """Send alert notifications through configured channels."""
        # Email notification
        if self.alert_channels["email"].get("enabled", False):
            await self._send_email_alert(alert)
        
        # Webhook notification
        if self.alert_channels["webhook"].get("enabled", False):
            await self._send_webhook_alert(alert)
        
        # Syslog notification
        if self.alert_channels["syslog"].get("enabled", False):
            await self._send_syslog_alert(alert)
    
    async def _send_email_alert(self, alert: SecurityAlert):
        """Send email alert notification."""
        try:
            email_config = self.alert_channels["email"]
            
            msg = MIMEMultipart()
            msg['From'] = email_config.get("from_address", "security@plexichat.local")
            msg['To'] = email_config.get("to_address", "admin@plexichat.local")
            msg['Subject'] = f"PlexiChat Security Alert: {alert.event.event_type.value}"
            
            body = f"""
Security Alert Generated

Alert ID: {alert.alert_id}
Event Type: {alert.event.event_type.value}
Severity: {alert.event.severity.name}
Timestamp: {alert.event.timestamp.isoformat()}
Source IP: {alert.event.source_ip or 'Unknown'}
User ID: {alert.event.user_id or 'Unknown'}

Description: {alert.event.description}

Details: {json.dumps(alert.event.details, indent=2)}

Please investigate this security event immediately.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config.get("smtp_server", "localhost"), email_config.get("smtp_port", 587))
            if email_config.get("use_tls", True):
                server.starttls()
            
            if email_config.get("username") and email_config.get("password"):
                server.login(email_config["username"], email_config["password"])
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent for {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    async def _send_webhook_alert(self, alert: SecurityAlert):
        """Send webhook alert notification."""
        try:
            webhook_config = self.alert_channels["webhook"]
            url = webhook_config.get("url")
            
            if not url:
                return
            
            payload = {
                "alert_id": alert.alert_id,
                "event_type": alert.event.event_type.value,
                "severity": alert.event.severity.name,
                "timestamp": alert.event.timestamp.isoformat(),
                "description": alert.event.description,
                "source_ip": alert.event.source_ip,
                "user_id": alert.event.user_id,
                "details": alert.event.details
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Webhook alert sent for {alert.alert_id}")
                    else:
                        logger.error(f"Webhook alert failed with status {response.status}")
                        
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
    
    async def _send_syslog_alert(self, alert: SecurityAlert):
        """Send syslog alert notification."""
        try:
            self.alert_channels["syslog"]
            
            # Map severity to syslog priority
            severity_map = {
                Severity.INFO: syslog.LOG_INFO,
                Severity.LOW: syslog.LOG_NOTICE,
                Severity.MEDIUM: syslog.LOG_WARNING,
                Severity.HIGH: syslog.LOG_ERR,
                Severity.CRITICAL: syslog.LOG_CRIT
            }
            
            priority = severity_map.get(alert.event.severity, syslog.LOG_WARNING)
            
            message = f"PlexiChat Security Alert [{alert.alert_id}]: {alert.event.event_type.value} - {alert.event.description}"
            
            syslog.openlog("plexichat-security", syslog.LOG_PID, syslog.LOG_DAEMON)
            syslog.syslog(priority, message)
            syslog.closelog()
            
            logger.info(f"Syslog alert sent for {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Failed to send syslog alert: {e}")
    
    def register_event_handler(self, event_type: EventType, handler: Callable):
        """Register event handler for specific event type."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
        logger.info(f"Event handler registered for {event_type.value}")
    
    def add_monitoring_rule(self, rule: MonitoringRule):
        """Add monitoring rule."""
        self.rules[rule.rule_id] = rule
        logger.info(f"Monitoring rule added: {rule.name}")
    
    def remove_monitoring_rule(self, rule_id: str) -> bool:
        """Remove monitoring rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Monitoring rule removed: {rule_id}")
            return True
        return False
    
    def get_monitoring_rules(self) -> List[Dict[str, Any]]:
        """Get all monitoring rules."""
        return [rule.to_dict() for rule in self.rules.values()]
    
    def update_alert_status(self, alert_id: str, status: AlertStatus, assigned_to: Optional[str] = None, notes: Optional[str] = None) -> bool:
        """Update alert status."""
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.status = status
        alert.updated_at = datetime.now(timezone.utc)
        
        if assigned_to:
            alert.assigned_to = assigned_to
        
        if notes:
            alert.notes.append(f"{datetime.now(timezone.utc).isoformat()}: {notes}")
        
        if status == AlertStatus.RESOLVED:
            self.stats["alerts_resolved"] += 1
        elif status == AlertStatus.FALSE_POSITIVE:
            self.stats["false_positives"] += 1
        
        logger.info(f"Alert {alert_id} status updated to {status.value}")
        return True
    
    def get_alerts(self, status: Optional[AlertStatus] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts with optional status filter."""
        alerts = list(self.alerts.values())
        
        if status:
            alerts = [alert for alert in alerts if alert.status == status]
        
        # Sort by creation time (newest first)
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        
        return [alert.to_dict() for alert in alerts[:limit]]
    
    def get_events(self, event_type: Optional[EventType] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get events with optional type filter."""
        events = self.events
        
        if event_type:
            events = [event for event in events if event.event_type == event_type]
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)
        
        return [event.to_dict() for event in events[:limit]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        open_alerts = len([alert for alert in self.alerts.values() if alert.status == AlertStatus.OPEN])
        
        return {
            **self.stats,
            "open_alerts": open_alerts,
            "total_alerts": len(self.alerts),
            "monitoring_rules": len(self.rules),
            "event_handlers": sum(len(handlers) for handlers in self.event_handlers.values())
        }
    
    def cleanup_old_events(self, max_age_hours: int = 168):  # 7 days default
        """Clean up old events."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        
        old_count = len(self.events)
        self.events = [event for event in self.events if event.timestamp >= cutoff_time]
        new_count = len(self.events)
        
        cleaned = old_count - new_count
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old security events")
        
        return cleaned


# Global instance
security_monitor = SecurityMonitor()
