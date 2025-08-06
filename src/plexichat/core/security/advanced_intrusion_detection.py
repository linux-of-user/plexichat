"""
Advanced Intrusion Detection System

Comprehensive security monitoring with:
- Behavioral analysis and anomaly detection
- Real-time threat detection and response
- Machine learning-based pattern recognition
- Automated security incident response
- Advanced logging and forensics
- Threat intelligence integration
- Security compliance monitoring


import asyncio
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading
import ipaddress
import re
from pathlib import Path

from ..logging.unified_logging import get_logger
from ..logging.correlation_tracker import correlation_tracker, CorrelationType

logger = get_logger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
        LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AttackType(Enum):
    """Types of detected attacks."""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    DOS = "dos"
    DDOS = "ddos"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    PHISHING = "phishing"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    ANOMALOUS_ACCESS = "anomalous_access"


class ResponseAction(Enum):
    """Automated response actions."""
        LOG_ONLY = "log_only"
    ALERT = "alert"
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    BLOCK_USER = "block_user"
    QUARANTINE = "quarantine"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"


@dataclass
class SecurityEvent:
    """Security event information."""
    event_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    attack_type: AttackType
    source_ip: str
    user_id: Optional[str] = None
    
    # Event details
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    
    # Context
    user_agent: str = ""
    endpoint: str = ""
    method: str = ""
    payload: str = ""
    
    # Response
    response_actions: List[ResponseAction] = field(default_factory=list)
    blocked: bool = False
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    
    # Analysis
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    related_events: List[str] = field(default_factory=list)


@dataclass
class BehavioralProfile:
    """User behavioral profile for anomaly detection.
        user_id: str
    created_at: datetime = field(default_factory=datetime.now)
    
    # Access patterns
    typical_login_times: List[int] = field(default_factory=list)  # Hours of day
    typical_ip_addresses: Set[str] = field(default_factory=set)
    typical_user_agents: Set[str] = field(default_factory=set)
    typical_endpoints: Dict[str, int] = field(default_factory=dict)
    
    # Activity metrics
    average_session_duration: float = 0.0
    average_requests_per_session: float = 0.0
    typical_request_intervals: List[float] = field(default_factory=list)
    
    # Security metrics
    failed_login_attempts: int = 0
    successful_logins: int = 0
    security_violations: int = 0
    
    # Learning data
    total_sessions: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    learning_complete: bool = False


class ThreatIntelligence:
    """Threat intelligence system."""
        def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_user_agents: Set[str] = set()
        self.attack_signatures: Dict[str, List[str]] = {}
        self.threat_feeds: List[str] = []
        
        # Load initial threat data
        self._load_threat_data()
    
    def _load_threat_data(self):
        Load initial threat intelligence data."""
        # Known malicious IPs (example data)
        self.malicious_ips.update([
            '192.168.1.100',  # Example malicious IP
            '10.0.0.50',      # Example malicious IP
        ])
        
        # Malicious user agents
        self.malicious_user_agents.update([
            'sqlmap',
            'nikto',
            'nmap',
            'masscan',
            'zap',
            'burp',
            'w3af'
        ])
        
        # Attack signatures
        self.attack_signatures = {
            'sql_injection': [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"union.*select",
                r"select.*from",
                r"insert.*into",
                r"delete.*from",
                r"drop.*table"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e\\",
                r"etc/passwd",
                r"boot\.ini"
            ]
        }
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known to be malicious.
        return ip in self.malicious_ips
    
    def is_malicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is malicious."""
        user_agent_lower = user_agent.lower()
        return any(malicious in user_agent_lower for malicious in self.malicious_user_agents)
    
    def detect_attack_patterns(self, text: str) -> List[Tuple[str, float]]:
        Detect attack patterns in text."""
        detected_attacks = []
        
        for attack_type, patterns in self.attack_signatures.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    confidence = 0.8  # Base confidence
                    detected_attacks.append((attack_type, confidence))
                    break
        
        return detected_attacks


class AdvancedIntrusionDetection:
    """Advanced intrusion detection system."""
        def __init__(self):
        self.security_events: deque = deque(maxlen=10000)
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.threat_intelligence = ThreatIntelligence()
        
        # Rate limiting tracking
        self.ip_request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.user_request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Blocked entities
        self.blocked_ips: Dict[str, datetime] = {}
        self.blocked_users: Dict[str, datetime] = {}
        
        # Configuration
        self.config = {
            'max_requests_per_minute': 60,
            'max_failed_logins': 5,
            'learning_period_days': 7,
            'anomaly_threshold': 0.7,
            'auto_block_enabled': True,
            'block_duration_minutes': 60
        }
        
        # Monitoring
        self.monitoring_active = True
        self.response_callbacks: List[Callable] = []
        
        # Threading
        self._lock = threading.RLock()
        
        logger.info("Advanced intrusion detection system initialized")
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Analyze incoming request for security threats."""
        try:
            source_ip = request_data.get('source_ip', 'unknown')
            user_id = request_data.get('user_id')
            user_agent = request_data.get('user_agent', '')
            endpoint = request_data.get('endpoint', '')
            method = request_data.get('method', '')
            payload = request_data.get('payload', '')
            
            # Check if IP is blocked
            if self._is_ip_blocked(source_ip):
                return self._create_security_event(
                    ThreatLevel.HIGH,
                    AttackType.SUSPICIOUS_BEHAVIOR,
                    source_ip,
                    user_id,
                    "Request from blocked IP address",
                    request_data
                )
            
            # Check threat intelligence
            if self.threat_intelligence.is_malicious_ip(source_ip):
                return self._create_security_event(
                    ThreatLevel.HIGH,
                    AttackType.SUSPICIOUS_BEHAVIOR,
                    source_ip,
                    user_id,
                    "Request from known malicious IP",
                    request_data
                )
            
            if self.threat_intelligence.is_malicious_user_agent(user_agent):
                return self._create_security_event(
                    ThreatLevel.MEDIUM,
                    AttackType.SUSPICIOUS_BEHAVIOR,
                    source_ip,
                    user_id,
                    "Malicious user agent detected",
                    request_data
                )
            
            # Check for attack patterns
            full_request = f"{endpoint} {payload}"
            attack_patterns = self.threat_intelligence.detect_attack_patterns(full_request)
            
            if attack_patterns:
                attack_type, confidence = attack_patterns[0]  # Take highest confidence
                threat_level = ThreatLevel.HIGH if confidence > 0.8 else ThreatLevel.MEDIUM
                
                return self._create_security_event(
                    threat_level,
                    AttackType(attack_type),
                    source_ip,
                    user_id,
                    f"Attack pattern detected: {attack_type}",
                    request_data,
                    confidence_score=confidence
                )
            
            # Rate limiting check
            if self._check_rate_limiting(source_ip, user_id):
                return self._create_security_event(
                    ThreatLevel.MEDIUM,
                    AttackType.DOS,
                    source_ip,
                    user_id,
                    "Rate limit exceeded",
                    request_data
                )
            
            # Behavioral analysis
            if user_id:
                anomaly_score = await self._analyze_user_behavior(user_id, request_data)
                if anomaly_score > self.config['anomaly_threshold']:
                    return self._create_security_event(
                        ThreatLevel.MEDIUM,
                        AttackType.ANOMALOUS_ACCESS,
                        source_ip,
                        user_id,
                        f"Anomalous behavior detected (score: {anomaly_score:.2f})",
                        request_data,
                        confidence_score=anomaly_score
                    )
            
            # Update tracking
            self._update_request_tracking(source_ip, user_id)
            
            return None  # No threats detected
            
        except Exception as e:
            logger.error(f"Error analyzing request: {e}")
            return None
    
    def _create_security_event(self, threat_level: ThreatLevel, attack_type: AttackType,
                            source_ip: str, user_id: Optional[str], description: str,
                            raw_data: Dict[str, Any], confidence_score: float = 0.8) -> SecurityEvent:
        """Create a security event."""
        event_id = f"sec_{int(time.time() * 1000000)}"
        
        event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            threat_level=threat_level,
            attack_type=attack_type,
            source_ip=source_ip,
            user_id=user_id,
            description=description,
            raw_data=raw_data,
            confidence_score=confidence_score,
            user_agent=raw_data.get('user_agent', ''),
            endpoint=raw_data.get('endpoint', ''),
            method=raw_data.get('method', ''),
            payload=raw_data.get('payload', '')
        )
        
        # Determine response actions
        event.response_actions = self._determine_response_actions(event)
        
        # Execute response actions
        self._execute_response_actions(event)
        
        # Store event
        with self._lock:
            self.security_events.append(event)
        
        # Trigger callbacks
        for callback in self.response_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in security event callback: {e}")
        
        logger.warning(f"Security event: {event.description} from {source_ip}")
        
        return event
    
    def _determine_response_actions(self, event: SecurityEvent) -> List[ResponseAction]:
        """Determine appropriate response actions for a security event.
        actions = [ResponseAction.LOG_ONLY]
        
        if event.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append(ResponseAction.ALERT)
            
            if self.config['auto_block_enabled']:
                if event.attack_type in [AttackType.BRUTE_FORCE, AttackType.DOS, AttackType.DDOS]:
                    actions.append(ResponseAction.BLOCK_IP)
                elif event.attack_type in [AttackType.PRIVILEGE_ESCALATION, AttackType.DATA_EXFILTRATION]:
                    actions.append(ResponseAction.BLOCK_USER)
        
        if event.threat_level == ThreatLevel.EMERGENCY:
            actions.append(ResponseAction.EMERGENCY_SHUTDOWN)
        
        return actions
    
    def _execute_response_actions(self, event: SecurityEvent):
        """Execute response actions for a security event."""
        for action in event.response_actions:
            try:
                if action == ResponseAction.BLOCK_IP:
                    self._block_ip(event.source_ip)
                    event.blocked = True
                elif action == ResponseAction.BLOCK_USER and event.user_id:
                    self._block_user(event.user_id)
                    event.blocked = True
                elif action == ResponseAction.RATE_LIMIT:
                    # Rate limiting is handled in the analysis phase
                    pass
                elif action == ResponseAction.ALERT:
                    self._send_security_alert(event)
                elif action == ResponseAction.EMERGENCY_SHUTDOWN:
                    self._trigger_emergency_shutdown(event)
                    
            except Exception as e:
                logger.error(f"Error executing response action {action.value}: {e}")
    
    def _block_ip(self, ip: str):
        """Block an IP address."""
        block_until = datetime.now() + timedelta(minutes=self.config['block_duration_minutes'])
        self.blocked_ips[ip] = block_until
        logger.warning(f"Blocked IP {ip} until {block_until}")
    
    def _block_user(self, user_id: str):
        """Block a user."""
        block_until = datetime.now() + timedelta(minutes=self.config['block_duration_minutes'])
        self.blocked_users[user_id] = block_until
        logger.warning(f"Blocked user {user_id} until {block_until}")
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked.
        if ip in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def _check_rate_limiting(self, source_ip: str, user_id: Optional[str]) -> bool:
        """Check if rate limits are exceeded."""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Check IP rate limiting
        ip_requests = self.ip_request_counts[source_ip]
        recent_ip_requests = sum(1 for req_time in ip_requests if req_time > minute_ago)
        
        if recent_ip_requests > self.config['max_requests_per_minute']:
            return True
        
        # Check user rate limiting
        if user_id:
            user_requests = self.user_request_counts[user_id]
            recent_user_requests = sum(1 for req_time in user_requests if req_time > minute_ago)
            
            if recent_user_requests > self.config['max_requests_per_minute']:
                return True
        
        return False
    
    def _update_request_tracking(self, source_ip: str, user_id: Optional[str]):
        Update request tracking for rate limiting."""
        now = datetime.now()
        
        self.ip_request_counts[source_ip].append(now)
        
        if user_id:
            self.user_request_counts[user_id].append(now)
    
    async def _analyze_user_behavior(self, user_id: str, request_data: Dict[str, Any]) -> float:
        """Analyze user behavior for anomalies."""
        try:
            profile = self.behavioral_profiles.get(user_id)
            if not profile:
                # Create new profile
                profile = BehavioralProfile(user_id=user_id)
                self.behavioral_profiles[user_id] = profile
                return 0.0  # No anomaly for new users
            
            if not profile.learning_complete:
                # Still learning, update profile
                self._update_behavioral_profile(profile, request_data)
                return 0.0
            
            # Calculate anomaly score
            anomaly_score = 0.0
            
            # Check time-based anomalies
            current_hour = datetime.now().hour
            if profile.typical_login_times and current_hour not in profile.typical_login_times:
                anomaly_score += 0.3
            
            # Check IP-based anomalies
            source_ip = request_data.get('source_ip', '')
            if source_ip and source_ip not in profile.typical_ip_addresses:
                anomaly_score += 0.4
            
            # Check user agent anomalies
            user_agent = request_data.get('user_agent', '')
            if user_agent and user_agent not in profile.typical_user_agents:
                anomaly_score += 0.2
            
            # Check endpoint access patterns
            endpoint = request_data.get('endpoint', '')
            if endpoint and endpoint not in profile.typical_endpoints:
                anomaly_score += 0.1
            
            return min(anomaly_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error analyzing user behavior: {e}")
            return 0.0
    
    def _update_behavioral_profile(self, profile: BehavioralProfile, request_data: Dict[str, Any]):
        """Update user behavioral profile."""
        try:
            # Update access patterns
            current_hour = datetime.now().hour
            if current_hour not in profile.typical_login_times:
                profile.typical_login_times.append(current_hour)
            
            source_ip = request_data.get('source_ip', '')
            if source_ip:
                profile.typical_ip_addresses.add(source_ip)
            
            user_agent = request_data.get('user_agent', '')
            if user_agent:
                profile.typical_user_agents.add(user_agent)
            
            endpoint = request_data.get('endpoint', '')
            if endpoint:
                profile.typical_endpoints[endpoint] = profile.typical_endpoints.get(endpoint, 0) + 1
            
            profile.total_sessions += 1
            profile.last_updated = datetime.now()
            
            # Check if learning period is complete
            learning_period = timedelta(days=self.config['learning_period_days'])
            if datetime.now() - profile.created_at > learning_period:
                profile.learning_complete = True
                logger.info(f"Behavioral learning completed for user {profile.user_id}")
                
        except Exception as e:
            logger.error(f"Error updating behavioral profile: {e}")
    
    def _send_security_alert(self, event: SecurityEvent):
        """Send security alert."""
        alert_message = f"SECURITY ALERT: {event.description}"
        logger.critical(alert_message)
        # In a real implementation, this would send notifications via email, Slack, etc.
    
    def _trigger_emergency_shutdown(self, event: SecurityEvent):
        """Trigger emergency shutdown procedures."""
        logger.critical(f"EMERGENCY SHUTDOWN TRIGGERED: {event.description}")
        # In a real implementation, this would trigger emergency procedures
    
    def add_response_callback(self, callback: Callable[[SecurityEvent], None]):
        """Add callback for security events.
        self.response_callbacks.append(callback)
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security system summary."""
        recent_events = [e for e in self.security_events if e.timestamp > datetime.now() - timedelta(hours=24)]
        
        threat_counts = defaultdict(int)
        for event in recent_events:
            threat_counts[event.threat_level.value] += 1
        
        return {
            'total_events_24h': len(recent_events),
            'threat_level_counts': dict(threat_counts),
            'blocked_ips': len(self.blocked_ips),
            'blocked_users': len(self.blocked_users),
            'behavioral_profiles': len(self.behavioral_profiles),
            'monitoring_active': self.monitoring_active,
            'auto_block_enabled': self.config['auto_block_enabled']
        }}


# Global intrusion detection system
advanced_intrusion_detection = AdvancedIntrusionDetection()
