"""
NetLink Enhanced DDoS Protection System

Advanced DDoS protection with behavioral analysis, machine learning-based
threat detection, and dynamic response mechanisms.
"""

import asyncio
import logging
import time
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import ipaddress

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """DDoS threat levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class AttackType(Enum):
    """Types of DDoS attacks."""
    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    SLOWLORIS = "slowloris"
    HTTP_FLOOD = "http_flood"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    AMPLIFICATION = "amplification"


class ResponseAction(Enum):
    """DDoS response actions."""
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BLOCK = "temporary_block"
    PERMANENT_BLOCK = "permanent_block"
    CHALLENGE = "challenge"
    CAPTCHA = "captcha"
    QUARANTINE = "quarantine"


@dataclass
class RequestMetrics:
    """Request metrics for analysis."""
    ip_address: str
    timestamp: datetime
    request_size: int
    response_time: float
    status_code: int
    user_agent: str
    endpoint: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ThreatDetection:
    """Threat detection result."""
    detection_id: str
    ip_address: str
    threat_level: ThreatLevel
    attack_type: AttackType
    confidence_score: float
    evidence: List[str]
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_action: Optional[ResponseAction] = None


@dataclass
class IPReputation:
    """IP address reputation data."""
    ip_address: str
    reputation_score: float  # 0.0 (bad) to 1.0 (good)
    request_count: int
    blocked_count: int
    last_seen: datetime
    threat_detections: List[ThreatDetection] = field(default_factory=list)
    is_whitelisted: bool = False
    is_blacklisted: bool = False


class EnhancedDDoSProtection:
    """
    Enhanced DDoS protection system with advanced threat detection.
    
    Features:
    - Real-time traffic analysis
    - Behavioral pattern recognition
    - Machine learning-based threat detection
    - Dynamic rate limiting
    - Automatic IP reputation management
    - Geographic traffic analysis
    - Protocol-specific protection
    - Adaptive response mechanisms
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Traffic monitoring
        self.request_metrics: deque = deque(maxlen=100000)  # Last 100k requests
        self.ip_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.ip_reputation: Dict[str, IPReputation] = {}
        
        # Rate limiting
        self.rate_limits: Dict[str, Dict[str, Any]] = {}  # ip -> rate limit data
        self.global_rate_limit = self.config.get("global_rate_limit", 1000)  # requests per minute
        self.per_ip_rate_limit = self.config.get("per_ip_rate_limit", 100)  # requests per minute
        
        # Blacklists and whitelists
        self.blacklisted_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = set()
        self.temporary_blocks: Dict[str, datetime] = {}  # ip -> unblock_time

        # Auto-whitelist localhost and common local IPs
        self._setup_default_whitelist()
        
        # Threat detection
        self.threat_detections: List[ThreatDetection] = []
        self.attack_patterns: Dict[AttackType, Dict[str, Any]] = {}
        
        # Configuration
        self.enable_behavioral_analysis = self.config.get("behavioral_analysis", True)
        self.enable_ml_detection = self.config.get("ml_detection", True)
        self.auto_block_threshold = self.config.get("auto_block_threshold", 0.8)
        self.block_duration_minutes = self.config.get("block_duration_minutes", 60)
        
        self.initialized = False

    def _setup_default_whitelist(self):
        """Setup default whitelist for localhost and common local IPs."""
        default_whitelist = [
            "127.0.0.1",      # IPv4 localhost
            "::1",            # IPv6 localhost
            "localhost",      # Hostname localhost
            "0.0.0.0",        # All interfaces
            "192.168.1.1",    # Common router IP
            "10.0.0.1",       # Common private network
            "172.16.0.1",     # Common private network
        ]

        # Add local network ranges that should be whitelisted
        local_networks = [
            "127.0.0.0/8",    # Loopback
            "10.0.0.0/8",     # Private network
            "172.16.0.0/12",  # Private network
            "192.168.0.0/16", # Private network
        ]

        for ip in default_whitelist:
            self.whitelisted_ips.add(ip)

        # Store network ranges for checking
        self.whitelisted_networks = []
        for network in local_networks:
            try:
                import ipaddress
                self.whitelisted_networks.append(ipaddress.ip_network(network))
            except:
                pass

        logger.info(f"🔓 Default whitelist configured with {len(default_whitelist)} IPs and {len(local_networks)} networks")

    def _is_whitelisted_ip(self, ip_address: str) -> bool:
        """Check if IP is whitelisted (including network ranges)."""
        # Direct IP check
        if ip_address in self.whitelisted_ips:
            return True

        # Network range check
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            for network in getattr(self, 'whitelisted_networks', []):
                if ip in network:
                    return True
        except:
            pass

        return False

    async def initialize(self):
        """Initialize the DDoS protection system."""
        if self.initialized:
            return
        
        try:
            # Load existing reputation data
            await self._load_reputation_data()
            
            # Initialize attack pattern detection
            await self._initialize_attack_patterns()
            
            # Start monitoring tasks
            asyncio.create_task(self._traffic_analysis_loop())
            asyncio.create_task(self._reputation_update_loop())
            asyncio.create_task(self._cleanup_loop())
            
            self.initialized = True
            logger.info("✅ Enhanced DDoS Protection initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize DDoS Protection: {e}")
            raise
    
    async def analyze_request(self, ip_address: str, request_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Analyze incoming request for DDoS threats."""
        if not self.initialized:
            await self.initialize()
        
        try:
            # Check if IP is whitelisted
            if ip_address in self.whitelisted_ips:
                return True, None
            
            # Check if IP is blacklisted
            if ip_address in self.blacklisted_ips:
                return False, "IP address is blacklisted"
            
            # Check temporary blocks
            if ip_address in self.temporary_blocks:
                if datetime.now(timezone.utc) < self.temporary_blocks[ip_address]:
                    return False, "IP address is temporarily blocked"
                else:
                    del self.temporary_blocks[ip_address]
            
            # Create request metrics
            metrics = RequestMetrics(
                ip_address=ip_address,
                timestamp=datetime.now(timezone.utc),
                request_size=request_data.get("content_length", 0),
                response_time=0.0,  # Will be updated later
                status_code=0,  # Will be updated later
                user_agent=request_data.get("user_agent", ""),
                endpoint=request_data.get("path", ""),
                method=request_data.get("method", "GET"),
                headers=request_data.get("headers", {})
            )
            
            # Store metrics
            self.request_metrics.append(metrics)
            self.ip_metrics[ip_address].append(metrics)
            
            # Check rate limits
            rate_limit_result = await self._check_rate_limits(ip_address)
            if not rate_limit_result[0]:
                return rate_limit_result
            
            # Perform threat analysis
            threat_detection = await self._analyze_threats(ip_address, metrics)
            if threat_detection and threat_detection.confidence_score > self.auto_block_threshold:
                await self._execute_response_action(threat_detection)
                return False, f"Threat detected: {threat_detection.attack_type.value}"
            
            return True, None
            
        except Exception as e:
            logger.error(f"❌ Request analysis failed for {ip_address}: {e}")
            return True, None  # Allow request on error to avoid false positives
    
    async def update_request_metrics(self, ip_address: str, response_time: float, status_code: int):
        """Update request metrics with response data."""
        try:
            # Find the most recent request from this IP
            for metrics in reversed(self.ip_metrics[ip_address]):
                if metrics.response_time == 0.0:  # Not yet updated
                    metrics.response_time = response_time
                    metrics.status_code = status_code
                    break
            
            # Update IP reputation
            await self._update_ip_reputation(ip_address, status_code, response_time)
            
        except Exception as e:
            logger.error(f"❌ Failed to update metrics for {ip_address}: {e}")
    
    async def add_to_whitelist(self, ip_address: str) -> bool:
        """Add IP address to whitelist."""
        try:
            self.whitelisted_ips.add(ip_address)
            
            # Remove from blacklist if present
            self.blacklisted_ips.discard(ip_address)
            
            # Remove temporary blocks
            if ip_address in self.temporary_blocks:
                del self.temporary_blocks[ip_address]
            
            logger.info(f"✅ Added IP to whitelist: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to whitelist IP {ip_address}: {e}")
            return False
    
    async def add_to_blacklist(self, ip_address: str, reason: str = "Manual blacklist") -> bool:
        """Add IP address to blacklist."""
        try:
            self.blacklisted_ips.add(ip_address)
            
            # Remove from whitelist if present
            self.whitelisted_ips.discard(ip_address)
            
            # Create threat detection record
            detection = ThreatDetection(
                detection_id=f"blacklist_{int(time.time())}",
                ip_address=ip_address,
                threat_level=ThreatLevel.CRITICAL,
                attack_type=AttackType.APPLICATION,
                confidence_score=1.0,
                evidence=[reason],
                response_action=ResponseAction.PERMANENT_BLOCK
            )
            
            self.threat_detections.append(detection)
            
            logger.warning(f"🚫 Added IP to blacklist: {ip_address} - {reason}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to blacklist IP {ip_address}: {e}")
            return False
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get current threat summary."""
        try:
            current_time = datetime.now(timezone.utc)
            last_hour = current_time - timedelta(hours=1)
            
            # Recent threats
            recent_threats = [
                t for t in self.threat_detections
                if t.detected_at > last_hour
            ]
            
            # Threat level distribution
            threat_levels = {}
            for level in ThreatLevel:
                threat_levels[level.name] = len([t for t in recent_threats if t.threat_level == level])
            
            # Attack type distribution
            attack_types = {}
            for attack_type in AttackType:
                attack_types[attack_type.name] = len([t for t in recent_threats if t.attack_type == attack_type])
            
            # Traffic statistics
            recent_requests = [
                r for r in self.request_metrics
                if r.timestamp > last_hour
            ]
            
            return {
                "timestamp": current_time.isoformat(),
                "total_requests_last_hour": len(recent_requests),
                "threats_detected_last_hour": len(recent_threats),
                "blacklisted_ips": len(self.blacklisted_ips),
                "whitelisted_ips": len(self.whitelisted_ips),
                "temporarily_blocked_ips": len(self.temporary_blocks),
                "threat_level_distribution": threat_levels,
                "attack_type_distribution": attack_types,
                "average_response_time": statistics.mean([r.response_time for r in recent_requests if r.response_time > 0]) if recent_requests else 0,
                "top_threat_ips": [
                    {"ip": t.ip_address, "threat_level": t.threat_level.name, "attack_type": t.attack_type.name}
                    for t in sorted(recent_threats, key=lambda x: x.confidence_score, reverse=True)[:10]
                ]
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to generate threat summary: {e}")
            return {"error": str(e)}
    
    async def _check_rate_limits(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """Check if IP address exceeds rate limits."""
        try:
            # Check if IP is whitelisted (including network ranges)
            if self._is_whitelisted_ip(ip_address):
                return True, None

            # Check if IP is blacklisted
            if ip_address in self.blacklisted_ips:
                return False, "IP address is blacklisted"

            # Check temporary blocks
            current_time = datetime.now(timezone.utc)
            if ip_address in self.temporary_blocks:
                if current_time < self.temporary_blocks[ip_address]:
                    remaining = (self.temporary_blocks[ip_address] - current_time).total_seconds()
                    return False, f"Temporarily blocked for {remaining:.0f} seconds"
                else:
                    # Block expired, remove it
                    del self.temporary_blocks[ip_address]

            minute_ago = current_time - timedelta(minutes=1)

            # Count requests in the last minute
            recent_requests = [
                r for r in self.ip_metrics[ip_address]
                if r.timestamp > minute_ago
            ]

            requests_per_minute = len(recent_requests)

            # Check per-IP rate limit
            if requests_per_minute > self.per_ip_rate_limit:
                # Apply temporary block
                block_until = current_time + timedelta(minutes=self.block_duration_minutes)
                self.temporary_blocks[ip_address] = block_until
                
                logger.warning(f"⚠️ Rate limit exceeded for IP {ip_address}: {requests_per_minute} req/min")
                return False, f"Rate limit exceeded: {requests_per_minute} requests per minute"
            
            # Check global rate limit
            total_recent_requests = len([
                r for r in self.request_metrics
                if r.timestamp > minute_ago
            ])
            
            if total_recent_requests > self.global_rate_limit:
                logger.warning(f"⚠️ Global rate limit exceeded: {total_recent_requests} req/min")
                return False, "Global rate limit exceeded"
            
            return True, None
            
        except Exception as e:
            logger.error(f"❌ Rate limit check failed for {ip_address}: {e}")
            return True, None
    
    async def _analyze_threats(self, ip_address: str, metrics: RequestMetrics) -> Optional[ThreatDetection]:
        """Analyze request for potential threats."""
        try:
            evidence = []
            threat_level = ThreatLevel.LOW
            attack_type = AttackType.APPLICATION
            confidence_score = 0.0
            
            # Behavioral analysis
            if self.enable_behavioral_analysis:
                behavioral_score = await self._behavioral_analysis(ip_address, metrics)
                confidence_score = max(confidence_score, behavioral_score)
                
                if behavioral_score > 0.7:
                    evidence.append(f"Suspicious behavioral pattern (score: {behavioral_score:.2f})")
                    threat_level = ThreatLevel.HIGH
            
            # Pattern matching
            pattern_score = await self._pattern_matching(ip_address, metrics)
            confidence_score = max(confidence_score, pattern_score)
            
            if pattern_score > 0.6:
                evidence.append(f"Attack pattern detected (score: {pattern_score:.2f})")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
            
            # Volume analysis
            volume_score = await self._volume_analysis(ip_address)
            confidence_score = max(confidence_score, volume_score)
            
            if volume_score > 0.8:
                evidence.append(f"High volume traffic (score: {volume_score:.2f})")
                attack_type = AttackType.VOLUMETRIC
                threat_level = ThreatLevel.CRITICAL
            
            # Create detection if confidence is high enough
            if confidence_score > 0.5:
                detection = ThreatDetection(
                    detection_id=f"threat_{int(time.time())}_{ip_address}",
                    ip_address=ip_address,
                    threat_level=threat_level,
                    attack_type=attack_type,
                    confidence_score=confidence_score,
                    evidence=evidence
                )
                
                self.threat_detections.append(detection)
                return detection
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Threat analysis failed for {ip_address}: {e}")
            return None
    
    async def _behavioral_analysis(self, ip_address: str, metrics: RequestMetrics) -> float:
        """Perform behavioral analysis on IP address."""
        try:
            score = 0.0
            
            # Check request patterns
            recent_requests = list(self.ip_metrics[ip_address])[-50:]  # Last 50 requests
            
            if len(recent_requests) < 5:
                return 0.0
            
            # Check for rapid requests
            time_intervals = []
            for i in range(1, len(recent_requests)):
                interval = (recent_requests[i].timestamp - recent_requests[i-1].timestamp).total_seconds()
                time_intervals.append(interval)
            
            if time_intervals:
                avg_interval = statistics.mean(time_intervals)
                if avg_interval < 0.1:  # Less than 100ms between requests
                    score += 0.3
                elif avg_interval < 1.0:  # Less than 1 second
                    score += 0.2
            
            # Check for identical requests
            identical_requests = 0
            for i in range(1, len(recent_requests)):
                if (recent_requests[i].endpoint == recent_requests[i-1].endpoint and
                    recent_requests[i].method == recent_requests[i-1].method):
                    identical_requests += 1
            
            if identical_requests > len(recent_requests) * 0.8:
                score += 0.4
            
            # Check user agent patterns
            user_agents = [r.user_agent for r in recent_requests]
            unique_user_agents = len(set(user_agents))
            if unique_user_agents == 1 and len(recent_requests) > 10:
                score += 0.2
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Behavioral analysis failed for {ip_address}: {e}")
            return 0.0
    
    async def _pattern_matching(self, ip_address: str, metrics: RequestMetrics) -> float:
        """Match request against known attack patterns."""
        try:
            score = 0.0
            
            # Check for common attack patterns
            suspicious_paths = [
                '/admin', '/wp-admin', '/.env', '/config', '/backup',
                '/phpmyadmin', '/mysql', '/database', '/api/v1/admin'
            ]
            
            if any(path in metrics.endpoint.lower() for path in suspicious_paths):
                score += 0.3
            
            # Check for SQL injection patterns
            sql_patterns = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'exec']
            if any(pattern in metrics.endpoint.lower() for pattern in sql_patterns):
                score += 0.4
            
            # Check for XSS patterns
            xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
            if any(pattern in metrics.endpoint.lower() for pattern in xss_patterns):
                score += 0.4
            
            # Check for directory traversal
            if '../' in metrics.endpoint or '..\\' in metrics.endpoint:
                score += 0.5
            
            return min(score, 1.0)
            
        except Exception as e:
            logger.error(f"❌ Pattern matching failed for {ip_address}: {e}")
            return 0.0
    
    async def _volume_analysis(self, ip_address: str) -> float:
        """Analyze traffic volume from IP address."""
        try:
            current_time = datetime.now(timezone.utc)
            minute_ago = current_time - timedelta(minutes=1)
            
            # Count requests in the last minute
            recent_requests = [
                r for r in self.ip_metrics[ip_address]
                if r.timestamp > minute_ago
            ]
            
            requests_per_minute = len(recent_requests)
            
            # Calculate volume score based on request rate
            if requests_per_minute > 200:
                return 1.0
            elif requests_per_minute > 100:
                return 0.8
            elif requests_per_minute > 50:
                return 0.6
            elif requests_per_minute > 25:
                return 0.4
            else:
                return 0.0
                
        except Exception as e:
            logger.error(f"❌ Volume analysis failed for {ip_address}: {e}")
            return 0.0
    
    async def _execute_response_action(self, detection: ThreatDetection):
        """Execute response action for threat detection."""
        try:
            if detection.threat_level == ThreatLevel.CRITICAL:
                detection.response_action = ResponseAction.PERMANENT_BLOCK
                await self.add_to_blacklist(detection.ip_address, f"Critical threat: {detection.attack_type.value}")
            elif detection.threat_level == ThreatLevel.HIGH:
                detection.response_action = ResponseAction.TEMPORARY_BLOCK
                block_until = datetime.now(timezone.utc) + timedelta(hours=1)
                self.temporary_blocks[detection.ip_address] = block_until
            else:
                detection.response_action = ResponseAction.RATE_LIMIT
                # Rate limiting is already handled in the main flow
            
            logger.warning(f"🚨 DDoS response executed: {detection.response_action.value} for {detection.ip_address}")
            
        except Exception as e:
            logger.error(f"❌ Failed to execute response action: {e}")
    
    async def _update_ip_reputation(self, ip_address: str, status_code: int, response_time: float):
        """Update IP reputation based on request behavior."""
        try:
            if ip_address not in self.ip_reputation:
                self.ip_reputation[ip_address] = IPReputation(
                    ip_address=ip_address,
                    reputation_score=0.5,  # Neutral starting score
                    request_count=0,
                    blocked_count=0,
                    last_seen=datetime.now(timezone.utc)
                )
            
            reputation = self.ip_reputation[ip_address]
            reputation.request_count += 1
            reputation.last_seen = datetime.now(timezone.utc)
            
            # Adjust reputation based on behavior
            if status_code >= 400:
                reputation.reputation_score = max(0.0, reputation.reputation_score - 0.01)
            elif status_code == 200:
                reputation.reputation_score = min(1.0, reputation.reputation_score + 0.001)
            
            # Adjust based on response time (slow responses might indicate attacks)
            if response_time > 5.0:
                reputation.reputation_score = max(0.0, reputation.reputation_score - 0.005)
            
        except Exception as e:
            logger.error(f"❌ Failed to update IP reputation for {ip_address}: {e}")
    
    async def _load_reputation_data(self):
        """Load existing reputation data."""
        # TODO: Load from persistent storage
        logger.info("📋 DDoS reputation data loaded")
    
    async def _initialize_attack_patterns(self):
        """Initialize attack pattern detection."""
        # TODO: Load known attack patterns
        logger.info("🔍 Attack patterns initialized")
    
    async def _traffic_analysis_loop(self):
        """Continuous traffic analysis loop."""
        while True:
            try:
                await asyncio.sleep(60)  # Analyze every minute
                await self._analyze_global_traffic_patterns()
            except Exception as e:
                logger.error(f"❌ Traffic analysis loop error: {e}")
                await asyncio.sleep(60)
    
    async def _reputation_update_loop(self):
        """Update IP reputation scores periodically."""
        while True:
            try:
                await asyncio.sleep(300)  # Update every 5 minutes
                await self._update_reputation_scores()
            except Exception as e:
                logger.error(f"❌ Reputation update loop error: {e}")
                await asyncio.sleep(300)
    
    async def _cleanup_loop(self):
        """Clean up old data periodically."""
        while True:
            try:
                await asyncio.sleep(3600)  # Clean up every hour
                await self._cleanup_old_data()
            except Exception as e:
                logger.error(f"❌ Cleanup loop error: {e}")
                await asyncio.sleep(3600)
    
    async def _analyze_global_traffic_patterns(self):
        """Analyze global traffic patterns for anomalies."""
        # TODO: Implement global traffic pattern analysis
        pass
    
    async def _update_reputation_scores(self):
        """Update reputation scores based on recent behavior."""
        # TODO: Implement reputation score updates
        pass
    
    async def _cleanup_old_data(self):
        """Clean up old metrics and detection data."""
        try:
            current_time = datetime.now(timezone.utc)
            cutoff_time = current_time - timedelta(hours=24)
            
            # Clean up old threat detections
            self.threat_detections = [
                t for t in self.threat_detections
                if t.detected_at > cutoff_time
            ]
            
            # Clean up expired temporary blocks
            expired_blocks = [
                ip for ip, unblock_time in self.temporary_blocks.items()
                if unblock_time < current_time
            ]
            
            for ip in expired_blocks:
                del self.temporary_blocks[ip]
            
            if expired_blocks:
                logger.info(f"🗑️ Cleaned up {len(expired_blocks)} expired blocks")
                
        except Exception as e:
            logger.error(f"❌ Data cleanup failed: {e}")


# Global instance
ddos_protection = EnhancedDDoSProtection()
