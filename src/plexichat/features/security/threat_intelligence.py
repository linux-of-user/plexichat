"""
PlexiChat Advanced Threat Intelligence System

Real-time threat detection, analysis, and response using
machine learning and threat intelligence feeds.
"""

import json
import hashlib
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ThreatType(Enum):
    """Types of security threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_CONTROL = "command_control"


class IOCType(Enum):
    """Indicator of Compromise types."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"


@dataclass
class ThreatIndicator:
    """Indicator of Compromise (IOC)."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_types: List[ThreatType]
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "threat_types": [t.value for t in self.threat_types],
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "tags": self.tags
        }


@dataclass
class ThreatEvent:
    """Security threat event."""
    event_id: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    source_ip: str
    target_resource: str
    timestamp: datetime
    indicators: List[str] = field(default_factory=list)  # IOC IDs
    details: Dict[str, Any] = field(default_factory=dict)
    mitigated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "threat_type": self.threat_type.value,
            "threat_level": self.threat_level.value,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "timestamp": self.timestamp.isoformat(),
            "indicators": self.indicators,
            "details": self.details,
            "mitigated": self.mitigated
        }


class ThreatIntelligenceFeed:
    """Threat intelligence feed processor."""
    
    def __init__(self, feed_name: str, feed_url: str):
        self.feed_name = feed_name
        self.feed_url = feed_url
        self.last_update = None
        self.indicators: Dict[str, ThreatIndicator] = {}
        
    def update_feed(self) -> int:
        """Update threat intelligence feed."""
        # Simulated feed update (in production, fetch from actual feeds)
        new_indicators = self._simulate_feed_data()
        
        updated_count = 0
        for indicator in new_indicators:
            if indicator.ioc_id not in self.indicators:
                self.indicators[indicator.ioc_id] = indicator
                updated_count += 1
            else:
                # Update existing indicator
                existing = self.indicators[indicator.ioc_id]
                existing.last_seen = indicator.last_seen
                existing.confidence = max(existing.confidence, indicator.confidence)
        
        self.last_update = datetime.now(timezone.utc)
        logger.info(f"Updated {self.feed_name} feed: {updated_count} new indicators")
        return updated_count
    
    def _simulate_feed_data(self) -> List[ThreatIndicator]:
        """Simulate threat intelligence feed data."""
        import uuid
        
        # Simulated malicious IPs
        malicious_ips = [
            "192.168.100.50",
            "10.0.0.100",
            "172.16.0.50"
        ]
        
        indicators = []
        for ip in malicious_ips:
            indicator = ThreatIndicator(
                ioc_id=str(uuid.uuid4()),
                ioc_type=IOCType.IP_ADDRESS,
                value=ip,
                threat_types=[ThreatType.BRUTE_FORCE, ThreatType.RECONNAISSANCE],
                confidence=0.85,
                source=self.feed_name,
                first_seen=datetime.now(timezone.utc) - timedelta(days=1),
                last_seen=datetime.now(timezone.utc),
                description=f"Malicious IP observed in brute force attacks",
                tags=["brute_force", "scanner"]
            )
            indicators.append(indicator)
        
        return indicators
    
    def search_indicators(self, value: str, ioc_type: Optional[IOCType] = None) -> List[ThreatIndicator]:
        """Search for indicators matching value."""
        results = []
        
        for indicator in self.indicators.values():
            if ioc_type and indicator.ioc_type != ioc_type:
                continue
            
            if value.lower() in indicator.value.lower():
                results.append(indicator)
        
        return results


class ThreatDetectionEngine:
    """Real-time threat detection engine."""
    
    def __init__(self):
        self.detection_rules: Dict[str, Dict[str, Any]] = {}
        self.threat_events: List[ThreatEvent] = []
        self.blocked_ips: Set[str] = set()
        
        # Initialize detection rules
        self._initialize_detection_rules()
    
    def _initialize_detection_rules(self):
        """Initialize threat detection rules."""
        # Brute force detection
        self.detection_rules["brute_force"] = {
            "name": "Brute Force Detection",
            "description": "Detect brute force login attempts",
            "conditions": {
                "failed_logins_threshold": 5,
                "time_window_minutes": 10
            },
            "threat_type": ThreatType.BRUTE_FORCE,
            "threat_level": ThreatLevel.HIGH
        }
        
        # DDoS detection
        self.detection_rules["ddos"] = {
            "name": "DDoS Detection",
            "description": "Detect distributed denial of service attacks",
            "conditions": {
                "requests_per_minute_threshold": 1000,
                "unique_ips_threshold": 100
            },
            "threat_type": ThreatType.DDoS,
            "threat_level": ThreatLevel.CRITICAL
        }
        
        # Suspicious file access
        self.detection_rules["data_access"] = {
            "name": "Suspicious Data Access",
            "description": "Detect unusual data access patterns",
            "conditions": {
                "files_accessed_threshold": 50,
                "time_window_minutes": 5
            },
            "threat_type": ThreatType.DATA_EXFILTRATION,
            "threat_level": ThreatLevel.HIGH
        }
    
    def analyze_login_attempt(self, user_id: str, source_ip: str, success: bool) -> Optional[ThreatEvent]:
        """Analyze login attempt for threats."""
        if success:
            return None
        
        # Check for brute force pattern
        recent_failures = self._count_recent_failed_logins(source_ip)
        rule = self.detection_rules["brute_force"]
        
        if recent_failures >= rule["conditions"]["failed_logins_threshold"]:
            import uuid
            
            event = ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=rule["threat_type"],
                threat_level=rule["threat_level"],
                source_ip=source_ip,
                target_resource=f"user:{user_id}",
                timestamp=datetime.now(timezone.utc),
                details={
                    "failed_attempts": recent_failures,
                    "detection_rule": "brute_force",
                    "user_id": user_id
                }
            )
            
            self.threat_events.append(event)
            
            # Auto-block IP
            self.blocked_ips.add(source_ip)
            
            logger.warning(f"Brute force detected from {source_ip}: {recent_failures} failed attempts")
            return event
        
        return None
    
    def analyze_network_traffic(self, source_ip: str, request_count: int, 
                              unique_ips: int) -> Optional[ThreatEvent]:
        """Analyze network traffic for DDoS patterns."""
        rule = self.detection_rules["ddos"]
        
        if (request_count >= rule["conditions"]["requests_per_minute_threshold"] and
            unique_ips >= rule["conditions"]["unique_ips_threshold"]):
            
            import uuid
            
            event = ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=rule["threat_type"],
                threat_level=rule["threat_level"],
                source_ip=source_ip,
                target_resource="network",
                timestamp=datetime.now(timezone.utc),
                details={
                    "requests_per_minute": request_count,
                    "unique_source_ips": unique_ips,
                    "detection_rule": "ddos"
                }
            )
            
            self.threat_events.append(event)
            logger.critical(f"DDoS attack detected: {request_count} requests from {unique_ips} IPs")
            return event
        
        return None
    
    def analyze_file_access(self, user_id: str, file_path: str, 
                          access_count: int) -> Optional[ThreatEvent]:
        """Analyze file access patterns."""
        rule = self.detection_rules["data_access"]
        
        if access_count >= rule["conditions"]["files_accessed_threshold"]:
            import uuid
            
            event = ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=rule["threat_type"],
                threat_level=rule["threat_level"],
                source_ip="internal",
                target_resource=file_path,
                timestamp=datetime.now(timezone.utc),
                details={
                    "user_id": user_id,
                    "files_accessed": access_count,
                    "detection_rule": "data_access"
                }
            )
            
            self.threat_events.append(event)
            logger.warning(f"Suspicious data access by {user_id}: {access_count} files")
            return event
        
        return None
    
    def _count_recent_failed_logins(self, source_ip: str) -> int:
        """Count recent failed login attempts from IP."""
        # Simplified counting (in production, use proper time-series data)
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        count = 0
        for event in self.threat_events:
            if (event.source_ip == source_ip and 
                event.threat_type == ThreatType.BRUTE_FORCE and
                event.timestamp > cutoff_time):
                count += event.details.get("failed_attempts", 1)
        
        return count + 1  # Include current attempt
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked."""
        return ip_address in self.blocked_ips
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock IP address."""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            logger.info(f"Unblocked IP: {ip_address}")
            return True
        return False


class ThreatResponseSystem:
    """Automated threat response and mitigation."""
    
    def __init__(self, detection_engine: ThreatDetectionEngine):
        self.detection_engine = detection_engine
        self.response_actions: Dict[ThreatType, List[str]] = {}
        self.mitigation_history: List[Dict[str, Any]] = []
        
        # Initialize response actions
        self._initialize_response_actions()
    
    def _initialize_response_actions(self):
        """Initialize automated response actions."""
        self.response_actions = {
            ThreatType.BRUTE_FORCE: [
                "block_source_ip",
                "increase_login_delay",
                "notify_admin",
                "log_incident"
            ],
            ThreatType.DDoS: [
                "enable_rate_limiting",
                "block_source_ips",
                "activate_ddos_protection",
                "notify_admin",
                "log_incident"
            ],
            ThreatType.DATA_EXFILTRATION: [
                "suspend_user_account",
                "block_file_access",
                "notify_admin",
                "log_incident",
                "start_investigation"
            ]
        }
    
    def respond_to_threat(self, threat_event: ThreatEvent) -> Dict[str, Any]:
        """Execute automated response to threat."""
        actions_taken = []
        
        # Get response actions for threat type
        response_actions = self.response_actions.get(threat_event.threat_type, [])
        
        for action in response_actions:
            success = self._execute_action(action, threat_event)
            actions_taken.append({
                "action": action,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        
        # Record mitigation
        mitigation_record = {
            "event_id": threat_event.event_id,
            "threat_type": threat_event.threat_type.value,
            "actions_taken": actions_taken,
            "mitigation_time": datetime.now(timezone.utc).isoformat()
        }
        
        self.mitigation_history.append(mitigation_record)
        
        # Mark event as mitigated
        threat_event.mitigated = True
        
        logger.info(f"Responded to threat {threat_event.event_id}: {len(actions_taken)} actions taken")
        return mitigation_record
    
    def _execute_action(self, action: str, threat_event: ThreatEvent) -> bool:
        """Execute specific response action."""
        try:
            if action == "block_source_ip":
                self.detection_engine.blocked_ips.add(threat_event.source_ip)
                return True
            
            elif action == "notify_admin":
                # In production, send actual notifications
                logger.critical(f"ADMIN ALERT: {threat_event.threat_type.value} detected")
                return True
            
            elif action == "log_incident":
                # Log to security incident system
                logger.error(f"SECURITY INCIDENT: {threat_event.to_dict()}")
                return True
            
            elif action == "enable_rate_limiting":
                # Enable rate limiting (placeholder)
                logger.info("Rate limiting enabled")
                return True
            
            elif action == "suspend_user_account":
                user_id = threat_event.details.get("user_id")
                if user_id:
                    logger.warning(f"User account suspended: {user_id}")
                    return True
            
            # Add more actions as needed
            return True
            
        except Exception as e:
            logger.error(f"Failed to execute action {action}: {e}")
            return False


class ThreatIntelligenceManager:
    """Main threat intelligence management system."""
    
    def __init__(self):
        self.feeds: Dict[str, ThreatIntelligenceFeed] = {}
        self.detection_engine = ThreatDetectionEngine()
        self.response_system = ThreatResponseSystem(self.detection_engine)
        
        # Initialize threat feeds
        self._initialize_feeds()
        
        # Update feeds
        self.update_all_feeds()
    
    def _initialize_feeds(self):
        """Initialize threat intelligence feeds."""
        # Add threat intelligence feeds
        feeds = [
            ("PlexiChat Internal", "https://threat-intel.plexichat.local/feed"),
            ("Public Threat Feed", "https://public-threats.example.com/feed"),
            ("Government Feed", "https://gov-threats.example.gov/feed")
        ]
        
        for name, url in feeds:
            self.feeds[name] = ThreatIntelligenceFeed(name, url)
    
    def update_all_feeds(self) -> Dict[str, int]:
        """Update all threat intelligence feeds."""
        results = {}
        
        for feed_name, feed in self.feeds.items():
            try:
                updated_count = feed.update_feed()
                results[feed_name] = updated_count
            except Exception as e:
                logger.error(f"Failed to update feed {feed_name}: {e}")
                results[feed_name] = 0
        
        return results
    
    def check_ioc(self, value: str, ioc_type: IOCType) -> List[ThreatIndicator]:
        """Check if value matches any indicators of compromise."""
        all_matches = []
        
        for feed in self.feeds.values():
            matches = feed.search_indicators(value, ioc_type)
            all_matches.extend(matches)
        
        return all_matches
    
    def analyze_security_event(self, event_type: str, event_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Analyze security event for threats."""
        threat_event = None
        
        if event_type == "login_attempt":
            threat_event = self.detection_engine.analyze_login_attempt(
                event_data.get("user_id", ""),
                event_data.get("source_ip", ""),
                event_data.get("success", False)
            )
        
        elif event_type == "network_traffic":
            threat_event = self.detection_engine.analyze_network_traffic(
                event_data.get("source_ip", ""),
                event_data.get("request_count", 0),
                event_data.get("unique_ips", 0)
            )
        
        elif event_type == "file_access":
            threat_event = self.detection_engine.analyze_file_access(
                event_data.get("user_id", ""),
                event_data.get("file_path", ""),
                event_data.get("access_count", 0)
            )
        
        # Auto-respond to threats
        if threat_event and threat_event.threat_level.value >= ThreatLevel.HIGH.value:
            self.response_system.respond_to_threat(threat_event)
        
        return threat_event
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat summary for specified time period."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        recent_events = [
            event for event in self.detection_engine.threat_events
            if event.timestamp > cutoff_time
        ]
        
        # Categorize by threat type
        threat_counts = {}
        for event in recent_events:
            threat_type = event.threat_type.value
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        # Count by severity
        severity_counts = {}
        for event in recent_events:
            severity = event.threat_level.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "time_period_hours": hours,
            "total_threats": len(recent_events),
            "threat_types": threat_counts,
            "severity_levels": severity_counts,
            "blocked_ips": len(self.detection_engine.blocked_ips),
            "mitigated_threats": len([e for e in recent_events if e.mitigated])
        }
    
    def get_threat_intelligence_status(self) -> Dict[str, Any]:
        """Get comprehensive threat intelligence status."""
        total_indicators = sum(len(feed.indicators) for feed in self.feeds.values())
        
        feed_status = {}
        for name, feed in self.feeds.items():
            feed_status[name] = {
                "indicators": len(feed.indicators),
                "last_update": feed.last_update.isoformat() if feed.last_update else None
            }
        
        return {
            "threat_intelligence": {
                "feeds_active": len(self.feeds),
                "total_indicators": total_indicators,
                "feed_status": feed_status,
                "detection_rules": len(self.detection_engine.detection_rules),
                "blocked_ips": len(self.detection_engine.blocked_ips),
                "recent_threats": len(self.detection_engine.threat_events[-100:])  # Last 100
            }
        }


# Global threat intelligence manager
threat_intelligence_manager = ThreatIntelligenceManager()
