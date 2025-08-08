import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AttackType(Enum):
    """Types of security attacks."""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    DDoS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    ZERO_DAY = "zero_day"
    APT = "advanced_persistent_threat"
    INSIDER_THREAT = "insider_threat"
    SOCIAL_ENGINEERING = "social_engineering"
    CRYPTOGRAPHIC_ATTACK = "cryptographic_attack"
    SUPPLY_CHAIN = "supply_chain"
    IOT_ATTACK = "iot_attack"


class ResponseAction(Enum):
    """Automated response actions."""
    LOG_ONLY = "log_only"
    ALERT = "alert"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BLOCK = "temporary_block"
    PERMANENT_BLOCK = "permanent_block"
    QUARANTINE = "quarantine"
    ISOLATE_NETWORK = "isolate_network"
    ESCALATE = "escalate"
    SHUTDOWN_SERVICE = "shutdown_service"
    EMERGENCY_LOCKDOWN = "emergency_lockdown"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_id: str
    timestamp: datetime
    source_ip: str
    user_id: Optional[str]
    attack_type: AttackType
    threat_level: ThreatLevel
    description: str
    raw_data: Dict[str, Any]
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    payload: Optional[str] = None
    session_id: Optional[str] = None
    geolocation: Optional[Dict[str, str]] = None
    confidence_score: float = 0.0
    false_positive_probability: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralProfile:
    """User behavioral analysis profile."""
    user_id: str
    creation_time: datetime
    last_updated: datetime
    typical_login_times: List[int] = field(default_factory=list)  # Hours of day
    typical_locations: Set[str] = field(default_factory=set)  # IP ranges/countries
    typical_user_agents: Set[str] = field(default_factory=set)
    request_patterns: Dict[str, List[float]] = field(default_factory=dict)  # Path -> timing patterns
    failed_login_history: List[datetime] = field(default_factory=list)
    privilege_escalation_attempts: int = 0
    data_access_patterns: Dict[str, int] = field(default_factory=dict)
    anomaly_score: float = 0.0


@dataclass
class ThreatIntelligence:
    """Threat intelligence data."""
    malicious_ips: Set[str] = field(default_factory=set)
    malicious_domains: Set[str] = field(default_factory=set)
    malicious_user_agents: Set[str] = field(default_factory=set)
    attack_signatures: Dict[AttackType, List[str]] = field(default_factory=dict)
    compromised_credentials: Set[str] = field(default_factory=set)
    known_vulnerabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AdvancedIntrusionDetectionSystem:
    """Enterprise-grade Advanced Intrusion Detection System.
    
    Features:
    - Real-time threat detection and response
    - Machine learning-based behavioral analysis
    - Multi-layered security monitoring
    - Automated incident response
    - Threat intelligence integration
    - Zero-day attack detection
    - Advanced persistent threat (APT) detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.threat_intelligence = ThreatIntelligence()
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.security_events: deque = deque(maxlen=10000)
        self.blocked_ips: Dict[str, datetime] = {}
        self.blocked_users: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.honeypots: Dict[str, Dict[str, Any]] = {}
        self.ml_models: Dict[str, Any] = {}
        self.alert_callbacks: List[Callable[[SecurityEvent], None]] = []
        self.lock = threading.RLock()
        self.running = False
        self.background_tasks: List[asyncio.Task] = []
        
        # Attack pattern signatures
        self.attack_patterns = {
            AttackType.SQL_INJECTION: [
                r"(\bunion\b.*\bselect\b)|(\bselect\b.*\bunion\b)",
                r"(\bor\b\s+\d+\s*=\s*\d+)|(\band\b\s+\d+\s*=\s*\d+)",
                r"(\bdrop\b\s+\btable\b)|(\bdelete\b\s+\bfrom\b)",
                r"(\binsert\b\s+\binto\b)|(\bupdate\b.*\bset\b)",
                r"(\bexec\b\s*\()|(\bexecute\b\s*\()",
                r"(\bxp_cmdshell\b)|(\bsp_executesql\b)"
            ],
            AttackType.XSS: [
                r"<script[^>]*>.*?</script>",
                r"javascript\s*:",
                r"on\w+\s*=\s*[\"'][^\"']*[\"']",
                r"<iframe[^>]*>.*?</iframe>",
                r"<object[^>]*>.*?</object>",
                r"eval\s*\(",
                r"document\.(cookie|write|location)"
            ],
            AttackType.COMMAND_INJECTION: [
                r"(\||&|;|`|\$\(|\${)",
                r"(nc|netcat|wget|curl)\s+",
                r"(rm\s+-rf|del\s+/f)",
                r"(cat\s+/etc/passwd|type\s+c:\\windows)",
                r"(chmod\s+777|icacls\s+.*\s+/grant)",
                r"(python|perl|ruby|php)\s+-c"
            ],
            AttackType.PATH_TRAVERSAL: [
                r"\.\.[\\/]",
                r"[\\/]\.\.[\\/]",
                r"%2e%2e[\\/]",
                r"[\\/]%2e%2e[\\/]",
                r"(etc[\\/]passwd|windows[\\/]system32)",
                r"(boot\.ini|web\.config|\.htaccess)"
            ]
        }
        
        # Initialize ML models and threat intelligence
        self._initialize_threat_intelligence()
        self._initialize_ml_models()
        
    async def initialize(self):
        """Initialize the intrusion detection system."""
        try:
            self.running = True
            
            # Start background monitoring tasks
            self.background_tasks.extend([
                asyncio.create_task(self._threat_intelligence_updater()),
                asyncio.create_task(self._behavioral_analysis_engine()),
                asyncio.create_task(self._anomaly_detection_engine()),
                asyncio.create_task(self._cleanup_expired_blocks()),
                asyncio.create_task(self._honeypot_monitor()),
                asyncio.create_task(self._correlation_engine())
            ])
            
            logger.info("Advanced Intrusion Detection System initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AIDS: {e}")
            raise
    
    def _initialize_threat_intelligence(self):
        """Initialize threat intelligence data."""
        # Load known malicious IPs (example data)
        self.threat_intelligence.malicious_ips.update([
            "192.168.1.100",  # Example malicious IP
            "10.0.0.50",      # Example internal threat
        ])
        
        # Load malicious user agents
        self.threat_intelligence.malicious_user_agents.update([
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "gobuster",
            "dirb",
            "burpsuite",
            "metasploit"
        ])
        
        # Initialize attack signatures
        for attack_type in AttackType:
            if attack_type not in self.threat_intelligence.attack_signatures:
                self.threat_intelligence.attack_signatures[attack_type] = []
    
    def _initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection."""
        # Placeholder for ML model initialization
        # In production, would load trained models for:
        # - Behavioral analysis
        # - Anomaly detection
        # - Zero-day attack detection
        # - APT detection
        self.ml_models = {
            "behavioral_analyzer": None,
            "anomaly_detector": None,
            "zero_day_detector": None,
            "apt_detector": None
        }
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Analyze incoming request for security threats."""
        try:
            source_ip = request_data.get("source_ip", "unknown")
            user_id = request_data.get("user_id")
            user_agent = request_data.get("user_agent", "")
            request_path = request_data.get("path", "")
            payload = request_data.get("payload", "")
            session_id = request_data.get("session_id")
            
            # Check if IP is blocked
            if await self._is_ip_blocked(source_ip):
                return self._create_security_event(
                    source_ip, user_id, AttackType.RECONNAISSANCE,
                    ThreatLevel.HIGH, "Request from blocked IP",
                    request_data, user_agent, request_path, payload, session_id
                )
            
            # Check threat intelligence
            threat_event = await self._check_threat_intelligence(
                source_ip, user_agent, request_data
            )
            if threat_event:
                return threat_event
            
            # Pattern-based attack detection
            attack_event = await self._detect_attack_patterns(
                payload, request_path, user_agent, request_data
            )
            if attack_event:
                return attack_event
            
            # Behavioral analysis
            if user_id:
                behavioral_event = await self._analyze_user_behavior(
                    user_id, request_data
                )
                if behavioral_event:
                    return behavioral_event
            
            # Rate limiting analysis
            rate_limit_event = await self._check_rate_limits(source_ip, user_id)
            if rate_limit_event:
                return rate_limit_event
            
            # Advanced anomaly detection
            anomaly_event = await self._detect_anomalies(request_data)
            if anomaly_event:
                return anomaly_event
            
            return None
            
        except Exception as e:
            logger.error(f"Error analyzing request: {e}")
            return None

    async def _detect_attack_patterns(self, payload: str, request_path: str,
                                    user_agent: str, request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Detect attack patterns in request data."""
        combined_data = f"{payload} {request_path} {user_agent}".lower()

        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_data, re.IGNORECASE):
                    confidence = self._calculate_attack_confidence(pattern, combined_data)
                    threat_level = ThreatLevel.HIGH if confidence > 0.8 else ThreatLevel.MEDIUM

                    return self._create_security_event(
                        request_data.get("source_ip", "unknown"),
                        request_data.get("user_id"),
                        attack_type,
                        threat_level,
                        f"{attack_type.value} pattern detected: {pattern}",
                        request_data,
                        user_agent,
                        request_path,
                        payload,
                        confidence_score=confidence
                    )

        return None

    def _calculate_attack_confidence(self, pattern: str, data: str) -> float:
        """Calculate confidence score for attack detection."""
        # Simple confidence calculation based on pattern complexity and matches
        matches = len(re.findall(pattern, data, re.IGNORECASE))
        pattern_complexity = len(pattern) / 100.0  # Normalize pattern length
        return min(0.5 + (matches * 0.2) + pattern_complexity, 1.0)

    async def _analyze_user_behavior(self, user_id: str,
                                   request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Analyze user behavior for anomalies."""
        with self.lock:
            if user_id not in self.behavioral_profiles:
                self.behavioral_profiles[user_id] = BehavioralProfile(
                    user_id=user_id,
                    creation_time=datetime.now(timezone.utc),
                    last_updated=datetime.now(timezone.utc)
                )

            profile = self.behavioral_profiles[user_id]
            current_time = datetime.now(timezone.utc)
            source_ip = request_data.get("source_ip", "unknown")

            # Update profile
            profile.last_updated = current_time
            profile.typical_locations.add(source_ip)

            # Check for suspicious behavior
            anomaly_score = 0.0

            # Check login time anomaly
            current_hour = current_time.hour
            if profile.typical_login_times:
                if current_hour not in profile.typical_login_times:
                    anomaly_score += 0.3
            profile.typical_login_times.append(current_hour)

            # Check location anomaly
            if len(profile.typical_locations) > 1:
                # Simple geolocation check (in production, use proper geolocation)
                if source_ip not in profile.typical_locations:
                    anomaly_score += 0.4

            # Check for privilege escalation attempts
            if request_data.get("admin_access_attempt"):
                profile.privilege_escalation_attempts += 1
                anomaly_score += 0.5

            profile.anomaly_score = anomaly_score

            if anomaly_score > 0.7:
                return self._create_security_event(
                    source_ip, user_id, AttackType.INSIDER_THREAT,
                    ThreatLevel.HIGH, f"Behavioral anomaly detected (score: {anomaly_score:.2f})",
                    request_data, confidence_score=anomaly_score
                )

        return None

    async def _check_rate_limits(self, source_ip: str, user_id: Optional[str]) -> Optional[SecurityEvent]:
        """Check for rate limiting violations."""
        current_time = time.time()
        window_size = self.config.get("rate_limit_window", 60)  # 1 minute
        max_requests = self.config.get("max_requests_per_minute", 100)

        # Clean old entries
        cutoff_time = current_time - window_size

        # Check IP-based rate limiting
        ip_key = f"ip:{source_ip}"
        self.rate_limits[ip_key] = [
            req_time for req_time in self.rate_limits[ip_key]
            if req_time > cutoff_time
        ]

        if len(self.rate_limits[ip_key]) >= max_requests:
            return self._create_security_event(
                source_ip, user_id, AttackType.DDoS,
                ThreatLevel.HIGH, f"Rate limit exceeded for IP {source_ip}",
                {"source_ip": source_ip, "user_id": user_id}
            )

        self.rate_limits[ip_key].append(current_time)

        # Check user-based rate limiting if user is authenticated
        if user_id:
            user_key = f"user:{user_id}"
            self.rate_limits[user_key] = [
                req_time for req_time in self.rate_limits[user_key]
                if req_time > cutoff_time
            ]

            if len(self.rate_limits[user_key]) >= max_requests:
                return self._create_security_event(
                    source_ip, user_id, AttackType.BRUTE_FORCE,
                    ThreatLevel.MEDIUM, f"Rate limit exceeded for user {user_id}",
                    {"source_ip": source_ip, "user_id": user_id}
                )

            self.rate_limits[user_key].append(current_time)

        return None

    async def _detect_anomalies(self, request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Advanced anomaly detection using ML models."""
        # Placeholder for ML-based anomaly detection
        # In production, would use trained models to detect:
        # - Zero-day attacks
        # - Advanced persistent threats
        # - Novel attack patterns

        # Simple heuristic-based anomaly detection
        anomaly_indicators = []

        # Check for unusual request patterns
        payload = request_data.get("payload", "")
        if len(payload) > 10000:  # Unusually large payload
            anomaly_indicators.append("large_payload")

        # Check for binary data in text fields
        if payload and any(ord(char) > 127 for char in payload):
            anomaly_indicators.append("binary_data")

        # Check for unusual headers
        headers = request_data.get("headers", {})
        if len(headers) > 50:  # Too many headers
            anomaly_indicators.append("excessive_headers")

        if anomaly_indicators:
            return self._create_security_event(
                request_data.get("source_ip", "unknown"),
                request_data.get("user_id"),
                AttackType.ZERO_DAY,
                ThreatLevel.MEDIUM,
                f"Anomaly detected: {', '.join(anomaly_indicators)}",
                request_data
            )

        return None

    def _create_security_event(self, source_ip: str, user_id: Optional[str],
                             attack_type: AttackType, threat_level: ThreatLevel,
                             description: str, raw_data: Dict[str, Any],
                             user_agent: Optional[str] = None,
                             request_path: Optional[str] = None,
                             payload: Optional[str] = None,
                             session_id: Optional[str] = None,
                             confidence_score: float = 0.8) -> SecurityEvent:
        """Create a security event."""
        event_id = hashlib.sha256(
            f"{source_ip}{user_id}{attack_type.value}{time.time()}".encode()
        ).hexdigest()[:16]

        event = SecurityEvent(
            event_id=event_id,
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            user_id=user_id,
            attack_type=attack_type,
            threat_level=threat_level,
            description=description,
            raw_data=raw_data,
            user_agent=user_agent,
            request_path=request_path,
            payload=payload,
            session_id=session_id,
            confidence_score=confidence_score
        )

        # Store event
        with self.lock:
            self.security_events.append(event)

        # Trigger automated response
        asyncio.create_task(self._automated_response(event))

        # Notify alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

        return event

    async def _automated_response(self, event: SecurityEvent) -> ResponseAction:
        """Execute automated response based on threat level and type."""
        action = ResponseAction.LOG_ONLY

        # Determine response action based on threat level
        if event.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
            action = ResponseAction.PERMANENT_BLOCK
        elif event.threat_level == ThreatLevel.HIGH:
            if event.attack_type in [AttackType.SQL_INJECTION, AttackType.COMMAND_INJECTION]:
                action = ResponseAction.PERMANENT_BLOCK
            elif event.attack_type in [AttackType.BRUTE_FORCE, AttackType.DDoS]:
                action = ResponseAction.TEMPORARY_BLOCK
            else:
                action = ResponseAction.RATE_LIMIT
        elif event.threat_level == ThreatLevel.MEDIUM:
            action = ResponseAction.RATE_LIMIT

        # Execute response action
        await self._execute_response_action(action, event)

        logger.warning(f"Security event {event.event_id}: {event.description} - Action: {action.value}")

        return action

    async def _execute_response_action(self, action: ResponseAction, event: SecurityEvent):
        """Execute the specified response action."""
        if action == ResponseAction.TEMPORARY_BLOCK:
            await self._block_ip_temporarily(event.source_ip)
        elif action == ResponseAction.PERMANENT_BLOCK:
            await self._block_ip_permanently(event.source_ip)
        elif action == ResponseAction.QUARANTINE and event.user_id:
            await self._quarantine_user(event.user_id)
        elif action == ResponseAction.ESCALATE:
            await self._escalate_incident(event)
        elif action == ResponseAction.EMERGENCY_LOCKDOWN:
            await self._emergency_lockdown()

    async def _block_ip_temporarily(self, ip: str):
        """Temporarily block an IP address."""
        block_duration = timedelta(minutes=self.config.get("temp_block_minutes", 30))
        unblock_time = datetime.now(timezone.utc) + block_duration
        self.blocked_ips[ip] = unblock_time
        logger.info(f"Temporarily blocked IP {ip} until {unblock_time}")

    async def _block_ip_permanently(self, ip: str):
        """Permanently block an IP address."""
        # Set far future date for permanent block
        permanent_time = datetime.now(timezone.utc) + timedelta(days=365*10)
        self.blocked_ips[ip] = permanent_time
        logger.warning(f"Permanently blocked IP {ip}")

    async def _quarantine_user(self, user_id: str):
        """Quarantine a user account."""
        block_duration = timedelta(hours=self.config.get("quarantine_hours", 24))
        unblock_time = datetime.now(timezone.utc) + block_duration
        self.blocked_users[user_id] = unblock_time
        logger.warning(f"Quarantined user {user_id} until {unblock_time}")

    async def _escalate_incident(self, event: SecurityEvent):
        """Escalate security incident to administrators."""
        # In production, would integrate with SIEM, send alerts, etc.
        logger.critical(f"SECURITY INCIDENT ESCALATED: {event.description}")

    async def _emergency_lockdown(self):
        """Execute emergency lockdown procedures."""
        # In production, would disable services, isolate networks, etc.
        logger.critical("EMERGENCY LOCKDOWN ACTIVATED")

    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP address is currently blocked."""
        if ip in self.blocked_ips:
            unblock_time = self.blocked_ips[ip]
            if datetime.now(timezone.utc) < unblock_time:
                return True
            else:
                # Remove expired block
                del self.blocked_ips[ip]
        return False

    async def _is_user_blocked(self, user_id: str) -> bool:
        """Check if a user is currently blocked."""
        if user_id in self.blocked_users:
            unblock_time = self.blocked_users[user_id]
            if datetime.now(timezone.utc) < unblock_time:
                return True
            else:
                # Remove expired block
                del self.blocked_users[user_id]
        return False

    # Background monitoring tasks
    async def _threat_intelligence_updater(self):
        """Background task to update threat intelligence."""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self._update_threat_intelligence()
            except Exception as e:
                logger.error(f"Error updating threat intelligence: {e}")

    async def _update_threat_intelligence(self):
        """Update threat intelligence from external sources."""
        # In production, would fetch from threat intelligence feeds
        logger.info("Updating threat intelligence data")
        self.threat_intelligence.last_updated = datetime.now(timezone.utc)

    async def _behavioral_analysis_engine(self):
        """Background behavioral analysis engine."""
        while self.running:
            try:
                await asyncio.sleep(300)  # Analyze every 5 minutes
                await self._analyze_behavioral_patterns()
            except Exception as e:
                logger.error(f"Error in behavioral analysis: {e}")

    async def _analyze_behavioral_patterns(self):
        """Analyze user behavioral patterns for anomalies."""
        current_time = datetime.now(timezone.utc)

        with self.lock:
            for user_id, profile in self.behavioral_profiles.items():
                # Check for stale profiles
                if current_time - profile.last_updated > timedelta(days=30):
                    continue

                # Advanced behavioral analysis would go here
                # For now, just update anomaly scores
                if profile.privilege_escalation_attempts > 5:
                    logger.warning(f"User {user_id} has {profile.privilege_escalation_attempts} privilege escalation attempts")

    async def _anomaly_detection_engine(self):
        """Background anomaly detection engine."""
        while self.running:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._detect_system_anomalies()
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}")

    async def _detect_system_anomalies(self):
        """Detect system-wide anomalies."""
        # Analyze recent events for patterns
        recent_events = [
            event for event in self.security_events
            if datetime.now(timezone.utc) - event.timestamp < timedelta(minutes=10)
        ]

        if len(recent_events) > 50:  # High volume of security events
            logger.warning(f"High volume of security events: {len(recent_events)} in last 10 minutes")

    async def _cleanup_expired_blocks(self):
        """Clean up expired IP and user blocks."""
        while self.running:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                current_time = datetime.now(timezone.utc)

                # Clean expired IP blocks
                expired_ips = [
                    ip for ip, unblock_time in self.blocked_ips.items()
                    if current_time >= unblock_time
                ]
                for ip in expired_ips:
                    del self.blocked_ips[ip]
                    logger.info(f"Unblocked IP {ip}")

                # Clean expired user blocks
                expired_users = [
                    user_id for user_id, unblock_time in self.blocked_users.items()
                    if current_time >= unblock_time
                ]
                for user_id in expired_users:
                    del self.blocked_users[user_id]
                    logger.info(f"Unblocked user {user_id}")

            except Exception as e:
                logger.error(f"Error cleaning up expired blocks: {e}")

    async def _honeypot_monitor(self):
        """Monitor honeypot interactions."""
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                # Honeypot monitoring logic would go here
            except Exception as e:
                logger.error(f"Error in honeypot monitoring: {e}")

    async def _correlation_engine(self):
        """Correlate security events to detect complex attacks."""
        while self.running:
            try:
                await asyncio.sleep(120)  # Correlate every 2 minutes
                await self._correlate_security_events()
            except Exception as e:
                logger.error(f"Error in event correlation: {e}")

    async def _correlate_security_events(self):
        """Correlate security events to detect APTs and complex attacks."""
        # Look for patterns in recent events
        recent_events = [
            event for event in self.security_events
            if datetime.now(timezone.utc) - event.timestamp < timedelta(hours=1)
        ]

        # Group events by source IP
        ip_events = defaultdict(list)
        for event in recent_events:
            ip_events[event.source_ip].append(event)

        # Detect potential APT activity
        for ip, events in ip_events.items():
            if len(events) >= 5:  # Multiple events from same IP
                attack_types = set(event.attack_type for event in events)
                if len(attack_types) >= 3:  # Multiple attack types
                    logger.critical(f"Potential APT activity detected from {ip}: {attack_types}")

    # Public API methods
    def add_alert_callback(self, callback: Callable[[SecurityEvent], None]):
        """Add a callback function for security alerts."""
        self.alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: Callable[[SecurityEvent], None]):
        """Remove an alert callback function."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)

    def get_security_events(self, limit: int = 100,
                          threat_level: Optional[ThreatLevel] = None,
                          attack_type: Optional[AttackType] = None,
                          since: Optional[datetime] = None) -> List[SecurityEvent]:
        """Get security events with optional filtering."""
        events = list(self.security_events)

        # Apply filters
        if threat_level:
            events = [e for e in events if e.threat_level == threat_level]
        if attack_type:
            events = [e for e in events if e.attack_type == attack_type]
        if since:
            events = [e for e in events if e.timestamp >= since]

        # Sort by timestamp (newest first) and limit
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    def get_blocked_ips(self) -> Dict[str, datetime]:
        """Get currently blocked IP addresses."""
        return dict(self.blocked_ips)

    def get_blocked_users(self) -> Dict[str, datetime]:
        """Get currently blocked users."""
        return dict(self.blocked_users)

    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        current_time = datetime.now(timezone.utc)
        recent_events = [
            event for event in self.security_events
            if current_time - event.timestamp < timedelta(hours=24)
        ]

        stats = {
            "total_events": len(self.security_events),
            "events_last_24h": len(recent_events),
            "blocked_ips": len(self.blocked_ips),
            "blocked_users": len(self.blocked_users),
            "behavioral_profiles": len(self.behavioral_profiles),
            "threat_intelligence_last_updated": self.threat_intelligence.last_updated.isoformat(),
            "system_status": "running" if self.running else "stopped"
        }

        # Event breakdown by type
        event_types = defaultdict(int)
        threat_levels = defaultdict(int)
        for event in recent_events:
            event_types[event.attack_type.value] += 1
            threat_levels[event.threat_level.value] += 1

        stats["event_types_24h"] = dict(event_types)
        stats["threat_levels_24h"] = dict(threat_levels)

        return stats

    async def shutdown(self):
        """Shutdown the intrusion detection system."""
        self.running = False

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        await asyncio.gather(*self.background_tasks, return_exceptions=True)

        logger.info("Advanced Intrusion Detection System shutdown complete")


# Global instance
_aids_instance: Optional[AdvancedIntrusionDetectionSystem] = None


def get_intrusion_detection_system() -> AdvancedIntrusionDetectionSystem:
    """Get the global intrusion detection system instance."""
    global _aids_instance
    if _aids_instance is None:
        _aids_instance = AdvancedIntrusionDetectionSystem()
    return _aids_instance


async def initialize_intrusion_detection(config: Optional[Dict[str, Any]] = None) -> AdvancedIntrusionDetectionSystem:
    """Initialize and return the intrusion detection system."""
    aids = get_intrusion_detection_system()
    if config:
        aids.config.update(config)
    await aids.initialize()
    return aids
    
    async def _check_threat_intelligence(self, source_ip: str, user_agent: str, 
                                       request_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Check request against threat intelligence data."""
        # Check malicious IPs
        if source_ip in self.threat_intelligence.malicious_ips:
            return self._create_security_event(
                source_ip, request_data.get("user_id"), AttackType.RECONNAISSANCE,
                ThreatLevel.HIGH, f"Request from known malicious IP: {source_ip}",
                request_data, user_agent
            )
        
        # Check malicious user agents
        for malicious_ua in self.threat_intelligence.malicious_user_agents:
            if malicious_ua.lower() in user_agent.lower():
                return self._create_security_event(
                    source_ip, request_data.get("user_id"), AttackType.RECONNAISSANCE,
                    ThreatLevel.MEDIUM, f"Malicious user agent detected: {malicious_ua}",
                    request_data, user_agent
                )
        
        return None
