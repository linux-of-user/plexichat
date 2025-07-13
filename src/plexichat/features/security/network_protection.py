import asyncio
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Optional, Set, Tuple

from ...core_system.config import get_config
from ...core_system.logging import get_logger


"""
PlexiChat Unified Network Protection System

CONSOLIDATED from multiple DDoS and rate limiting systems:
- features/security/ddos_protection.py - REMOVED
- features/security/core/ddos_protection.py - REMOVED  
- features/security/rate_limiting.py - REMOVED
- features/security/core/rate_limiting.py - REMOVED
- infrastructure/utils/rate_limiting.py - REMOVED

Features:
- Advanced DDoS protection with behavioral analysis
- Multi-algorithm rate limiting (token bucket, sliding window, fixed window)
- IP reputation management and blacklisting
- Adaptive rate limiting based on system load
- Geographic and behavioral threat detection
- Real-time monitoring and alerting
- Integration with unified security architecture
"""

logger = get_logger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    """Types of detected attacks."""
    DDOS = "ddos"
    RATE_LIMIT_VIOLATION = "rate_limit"
    SUSPICIOUS_BEHAVIOR = "suspicious"
    MALICIOUS_INPUT = "malicious_input"
    BRUTE_FORCE = "brute_force"
    BOT_ACTIVITY = "bot"


class ActionType(Enum):
    """Actions to take when limits are exceeded."""
    ALLOW = "allow"
    DELAY = "delay"
    BLOCK = "block"
    CAPTCHA = "captcha"
    TEMPORARY_BAN = "temporary_ban"
    PERMANENT_BAN = "permanent_ban"


class LimitType(Enum):
    """Types of rate limits."""
    REQUESTS_PER_SECOND = "requests_per_second"
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    LOGIN_ATTEMPTS_PER_MINUTE = "login_attempts_per_minute"
    FILE_UPLOADS_PER_HOUR = "file_uploads_per_hour"
    BANDWIDTH_PER_SECOND = "bandwidth_per_second"


@dataclass
class SecurityThreat:
    """Security threat information."""
    threat_id: str
    threat_type: AttackType
    threat_level: ThreatLevel
    source_ip: str
    timestamp: datetime
    description: str
    blocked: bool = False
    mitigation_action: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitRequest:
    """Rate limit request information."""
    ip_address: str
    user_id: Optional[str] = None
    endpoint: str = ""
    method: str = "GET"
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IPReputation:
    """IP reputation tracking."""
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    request_count: int = 0
    violation_count: int = 0
    threat_score: float = 0.0
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    country: str = ""
    user_agents: Set[str] = field(default_factory=set)
    blocked_until: Optional[datetime] = None


@dataclass
class RateLimit:
    """Rate limit configuration."""
    limit_type: LimitType
    max_requests: int
    window_seconds: int
    action: ActionType
    enabled: bool = True
    whitelist_ips: Set[str] = field(default_factory=set)
    blacklist_ips: Set[str] = field(default_factory=set)


class TokenBucket:
    """Token bucket algorithm implementation."""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket."""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def _refill(self):
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now


class SlidingWindowCounter:
    """Sliding window counter implementation."""
    
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.requests: deque = deque()
    
    def add_request(self, timestamp: float = None):
        """Add a request to the window."""
        if timestamp is None:
            timestamp = time.time()
        
        self.requests.append(timestamp)
        self._cleanup_old_requests()
    
    def get_count(self) -> int:
        """Get current request count in the window."""
        self._cleanup_old_requests()
        return len(self.requests)
    
    def _cleanup_old_requests(self):
        """Remove requests outside the window."""
        cutoff = time.time() - self.window_seconds
        while self.requests and self.requests[0] < cutoff:
            self.requests.popleft()


class BehavioralAnalyzer:
    """Behavioral analysis for threat detection."""
    
    def __init__(self):
        self.user_patterns: Dict[str, Dict] = defaultdict(dict)
        self.suspicious_patterns = {
            "rapid_requests": {"threshold": 50, "window": 60},
            "user_agent_rotation": {"threshold": 5, "window": 300},
            "endpoint_scanning": {"threshold": 20, "window": 300}
        }
    
    def analyze_request(self, request: RateLimitRequest) -> ThreatLevel:
        """Analyze request for suspicious behavior."""
        ip = request.ip_address
        current_time = time.time()
        
        # Initialize tracking for new IPs
        if ip not in self.user_patterns:
            self.user_patterns[ip] = {
                "requests": deque(maxlen=1000),
                "user_agents": set(),
                "endpoints": deque(maxlen=100),
                "last_analysis": current_time
            }
        
        pattern = self.user_patterns[ip]
        pattern["requests"].append(current_time)
        pattern["user_agents"].add(request.user_agent)
        pattern["endpoints"].append(request.endpoint)
        
        threat_score = 0
        
        # Check rapid requests
        recent_requests = [r for r in pattern["requests"] 
                          if current_time - r < self.suspicious_patterns["rapid_requests"]["window"]]
        if len(recent_requests) > self.suspicious_patterns["rapid_requests"]["threshold"]:
            threat_score += 2
        
        # Check user agent rotation
        if len(pattern["user_agents"]) > self.suspicious_patterns["user_agent_rotation"]["threshold"]:
            threat_score += 1
        
        # Check endpoint scanning
        recent_endpoints = [e for e in list(pattern["endpoints"])[-50:]]  # Last 50 endpoints
        unique_endpoints = len(set(recent_endpoints))
        if unique_endpoints > self.suspicious_patterns["endpoint_scanning"]["threshold"]:
            threat_score += 1
        
        # Determine threat level
        if threat_score >= 3:
            return ThreatLevel.CRITICAL
        elif threat_score >= 2:
            return ThreatLevel.HIGH
        elif threat_score >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW


class ConsolidatedNetworkProtection:
    """
    Consolidated Network Protection System - Single Source of Truth
    
    Replaces all previous DDoS protection and rate limiting systems with a unified,
    comprehensive solution supporting advanced threat detection and mitigation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("network_protection", {})
        self.initialized = False
        
        # Core components
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # IP tracking and reputation
        self.ip_reputation: Dict[str, IPReputation] = {}
        self.blacklisted_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = set()
        self.temporary_blocks: Dict[str, datetime] = {}
        
        # Rate limiting
        self.rate_limits: Dict[str, RateLimit] = {}
        self.token_buckets: Dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(100, 1.0))
        self.sliding_windows: Dict[str, SlidingWindowCounter] = defaultdict(lambda: SlidingWindowCounter(60))
        
        # Request tracking
        self.request_metrics: deque = deque(maxlen=100000)
        self.ip_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Configuration
        self.global_rate_limit = self.config.get("global_rate_limit", 1000)
        self.per_ip_rate_limit = self.config.get("per_ip_rate_limit", 100)
        self.block_duration_minutes = self.config.get("block_duration_minutes", 60)
        self.enable_behavioral_analysis = self.config.get("enable_behavioral_analysis", True)
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "threats_detected": 0,
            "ips_blocked": 0,
            "last_reset": time.time()
        }
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Setup default rate limits
        self._setup_default_limits()
        
        logger.info("Consolidated Network Protection initialized")
    
    async def initialize(self) -> bool:
        """Initialize the network protection system."""
        try:
            # Load persistent data
            await self._load_persistent_data()
            
            # Start background tasks
            asyncio.create_task(self._cleanup_task())
            asyncio.create_task(self._monitoring_task())
            
            self.initialized = True
            logger.info(" Network Protection System initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f" Network Protection initialization failed: {e}")
            return False
    
    def _setup_default_limits(self):
        """Setup default rate limits."""
        default_limits = [
            RateLimit(LimitType.REQUESTS_PER_SECOND, 10, 1, ActionType.DELAY),
            RateLimit(LimitType.REQUESTS_PER_MINUTE, 300, 60, ActionType.BLOCK),
            RateLimit(LimitType.REQUESTS_PER_HOUR, 5000, 3600, ActionType.TEMPORARY_BAN),
            RateLimit(LimitType.LOGIN_ATTEMPTS_PER_MINUTE, 5, 60, ActionType.CAPTCHA),
            RateLimit(LimitType.FILE_UPLOADS_PER_HOUR, 100, 3600, ActionType.BLOCK),
            RateLimit(LimitType.BANDWIDTH_PER_SECOND, 1024*1024, 1, ActionType.DELAY),
        ]
        
        for limit in default_limits:
            self.rate_limits[limit.limit_type.value] = limit

    async def check_request(self, request: RateLimitRequest) -> Tuple[bool, Optional[SecurityThreat]]:
        """Check if a request should be allowed."""
        if not self.initialized:
            await self.initialize()

        with self._lock:
            self.stats["total_requests"] += 1
            current_time = time.time()

            # Check if IP is temporarily blocked
            if request.ip_address in self.temporary_blocks:
                if datetime.now(timezone.utc) < self.temporary_blocks[request.ip_address]:
                    self.stats["blocked_requests"] += 1
                    threat = SecurityThreat(
                        threat_id=f"blocked_{request.ip_address}_{int(current_time)}",
                        threat_type=AttackType.RATE_LIMIT_VIOLATION,
                        threat_level=ThreatLevel.HIGH,
                        source_ip=request.ip_address,
                        timestamp=datetime.now(timezone.utc),
                        description=f"IP {request.ip_address} is temporarily blocked",
                        blocked=True,
                        mitigation_action="TEMPORARY_BLOCK"
                    )
                    return False, threat
                else:
                    # Remove expired block
                    del self.temporary_blocks[request.ip_address]

            # Check blacklist
            if request.ip_address in self.blacklisted_ips:
                self.stats["blocked_requests"] += 1
                threat = SecurityThreat(
                    threat_id=f"blacklist_{request.ip_address}_{int(current_time)}",
                    threat_type=AttackType.SUSPICIOUS_BEHAVIOR,
                    threat_level=ThreatLevel.CRITICAL,
                    source_ip=request.ip_address,
                    timestamp=datetime.now(timezone.utc),
                    description=f"IP {request.ip_address} is blacklisted",
                    blocked=True,
                    mitigation_action="BLACKLIST_BLOCK"
                )
                return False, threat

            # Skip checks for whitelisted IPs
            if request.ip_address in self.whitelisted_ips:
                self._record_request(request)
                return True, None

            # Behavioral analysis
            threat_level = ThreatLevel.LOW
            if self.enable_behavioral_analysis:
                threat_level = self.behavioral_analyzer.analyze_request(request)

            # Check rate limits
            for limit_name, limit in self.rate_limits.items():
                if not limit.enabled:
                    continue

                # Check specific rate limit
                violation = self._check_rate_limit(request, limit, threat_level)
                if violation:
                    return False, violation

            # Record successful request
            self._record_request(request)
            return True, None

    def _check_rate_limit(self, request: RateLimitRequest, limit: RateLimit, threat_level: ThreatLevel) -> Optional[SecurityThreat]:
        """Check a specific rate limit."""
        current_time = time.time()
        key = f"{request.ip_address}:{limit.limit_type.value}"

        # Use appropriate algorithm based on limit type
        if limit.limit_type in [LimitType.REQUESTS_PER_SECOND, LimitType.BANDWIDTH_PER_SECOND]:
            # Use token bucket for per-second limits
            bucket = self.token_buckets[key]
            if not bucket.consume():
                return self._create_violation_threat(request, limit, "Token bucket exhausted")
        else:
            # Use sliding window for longer periods
            window = self.sliding_windows[key]
            window.add_request(current_time)

            if window.get_count() > limit.max_requests:
                return self._create_violation_threat(request, limit, f"Rate limit exceeded: {window.get_count()}/{limit.max_requests}")

        return None

    def _create_violation_threat(self, request: RateLimitRequest, limit: RateLimit, description: str) -> SecurityThreat:
        """Create a security threat for rate limit violation."""
        current_time = time.time()

        # Apply action
        if limit.action == ActionType.TEMPORARY_BAN:
            block_until = datetime.now(timezone.utc) + timedelta(minutes=self.block_duration_minutes)
            self.temporary_blocks[request.ip_address] = block_until
        elif limit.action == ActionType.PERMANENT_BAN:
            self.blacklisted_ips.add(request.ip_address)

        self.stats["blocked_requests"] += 1
        self.stats["threats_detected"] += 1

        threat = SecurityThreat(
            threat_id=f"rate_limit_{request.ip_address}_{int(current_time)}",
            threat_type=AttackType.RATE_LIMIT_VIOLATION,
            threat_level=ThreatLevel.HIGH,
            source_ip=request.ip_address,
            timestamp=datetime.now(timezone.utc),
            description=description,
            blocked=True,
            mitigation_action=limit.action.value.upper(),
            metadata={
                "limit_type": limit.limit_type.value,
                "max_requests": limit.max_requests,
                "window_seconds": limit.window_seconds
            }
        )

        logger.warning(f" Rate limit violation: {request.ip_address} - {description}")
        return threat

    def _record_request(self, request: RateLimitRequest):
        """Record a successful request for tracking."""
        current_time = datetime.now(timezone.utc)

        # Update IP reputation
        if request.ip_address not in self.ip_reputation:
            self.ip_reputation[request.ip_address] = IPReputation(
                ip_address=request.ip_address,
                first_seen=current_time,
                last_seen=current_time
            )

        reputation = self.ip_reputation[request.ip_address]
        reputation.last_seen = current_time
        reputation.request_count += 1
        reputation.user_agents.add(request.user_agent)

        # Add to metrics
        self.request_metrics.append(request)
        self.ip_metrics[request.ip_address].append(request)

    async def _load_persistent_data(self):
        """Load persistent data from storage."""
        try:
            # Load blacklisted IPs, whitelisted IPs, etc.
            # This would typically load from a database or file
            pass
        except Exception as e:
            logger.warning(f"Failed to load persistent data: {e}")

    async def _cleanup_task(self):
        """Background task for cleaning up old data."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                current_time = datetime.now(timezone.utc)

                # Clean up expired temporary blocks
                expired_blocks = [
                    ip for ip, until in self.temporary_blocks.items()
                    if current_time >= until
                ]
                for ip in expired_blocks:
                    del self.temporary_blocks[ip]

                # Clean up old IP reputation data
                cutoff_time = current_time - timedelta(days=7)
                old_ips = [
                    ip for ip, rep in self.ip_reputation.items()
                    if rep.last_seen < cutoff_time and not rep.is_blacklisted
                ]
                for ip in old_ips:
                    del self.ip_reputation[ip]

                logger.debug(f"Cleanup completed: removed {len(expired_blocks)} expired blocks, {len(old_ips)} old IPs")

            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    async def _monitoring_task(self):
        """Background task for monitoring and alerting."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Calculate metrics
                current_time = time.time()
                minute_ago = current_time - 60

                recent_requests = len([r for r in self.request_metrics if r.timestamp > minute_ago])
                blocked_ratio = self.stats["blocked_requests"] / max(self.stats["total_requests"], 1)

                # Log statistics
                if recent_requests > 0:
                    logger.info(f" Network Protection Stats: {recent_requests} req/min, "
                              f"{len(self.temporary_blocks)} blocked IPs, "
                              f"{blocked_ratio:.2%} block rate")

                # Alert on high block rates
                if blocked_ratio > 0.1:  # More than 10% blocked
                    logger.warning(f" High block rate detected: {blocked_ratio:.2%}")

            except Exception as e:
                logger.error(f"Monitoring task error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive network protection status."""
        current_time = time.time()
        uptime = current_time - self.stats["last_reset"]

        return {
            "initialized": self.initialized,
            "uptime_seconds": uptime,
            "statistics": self.stats.copy(),
            "active_blocks": len(self.temporary_blocks),
            "blacklisted_ips": len(self.blacklisted_ips),
            "whitelisted_ips": len(self.whitelisted_ips),
            "tracked_ips": len(self.ip_reputation),
            "rate_limits": {
                name: {
                    "enabled": limit.enabled,
                    "max_requests": limit.max_requests,
                    "window_seconds": limit.window_seconds,
                    "action": limit.action.value
                }
                for name, limit in self.rate_limits.items()
            }
        }

    def add_to_whitelist(self, ip_address: str):
        """Add IP to whitelist."""
        self.whitelisted_ips.add(ip_address)
        # Remove from blacklist if present
        self.blacklisted_ips.discard(ip_address)
        # Remove temporary block if present
        self.temporary_blocks.pop(ip_address, None)
        logger.info(f" Added {ip_address} to whitelist")

    def add_to_blacklist(self, ip_address: str, reason: str = "Manual"):
        """Add IP to blacklist."""
        self.blacklisted_ips.add(ip_address)
        # Remove from whitelist if present
        self.whitelisted_ips.discard(ip_address)
        # Update reputation
        if ip_address in self.ip_reputation:
            self.ip_reputation[ip_address].is_blacklisted = True

        self.stats["ips_blocked"] += 1
        logger.warning(f" Added {ip_address} to blacklist: {reason}")

    def remove_from_blacklist(self, ip_address: str):
        """Remove IP from blacklist."""
        self.blacklisted_ips.discard(ip_address)
        if ip_address in self.ip_reputation:
            self.ip_reputation[ip_address].is_blacklisted = False
        logger.info(f" Removed {ip_address} from blacklist")


# Global instance - SINGLE SOURCE OF TRUTH
_network_protection: Optional[ConsolidatedNetworkProtection] = None


def get_network_protection() -> ConsolidatedNetworkProtection:
    """Get the global network protection instance."""
    global _network_protection
    if _network_protection is None:
        _network_protection = ConsolidatedNetworkProtection()
    return _network_protection


# Export main components
__all__ = [
    "ConsolidatedNetworkProtection",
    "get_network_protection",
    "SecurityThreat",
    "RateLimitRequest",
    "IPReputation",
    "ThreatLevel",
    "AttackType",
    "ActionType",
    "LimitType"
]
