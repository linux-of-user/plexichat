# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


"""
PlexiChat Rate Limiting System

Advanced rate limiting with sliding window, token bucket, and behavioral analysis.
Includes DDoS protection, IP-based limiting, and adaptive thresholds.
"""

logger = logging.getLogger(__name__)


logger = logging.getLogger(__name__)
class LimitType(Enum):
    """Types of rate limits."""
    REQUESTS_PER_SECOND = "requests_per_second"
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    BANDWIDTH_PER_SECOND = "bandwidth_per_second"
    CONCURRENT_CONNECTIONS = "concurrent_connections"
    FILE_UPLOADS_PER_HOUR = "file_uploads_per_hour"
    LOGIN_ATTEMPTS_PER_MINUTE = "login_attempts_per_minute"


class ActionType(Enum):
    """Actions to take when limit is exceeded."""
    BLOCK = "block"
    DELAY = "delay"
    CAPTCHA = "captcha"
    TEMPORARY_BAN = "temporary_ban"
    PERMANENT_BAN = "permanent_ban"
    ALERT_ONLY = "alert_only"


class ThreatLevel(Enum):
    """Threat levels for behavioral analysis."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class RateLimit:
    """Rate limit configuration."""
    limit_type: LimitType
    max_requests: int
    window_seconds: int
    action: ActionType
    burst_allowance: int = 0
    whitelist_ips: Set[str] = field(default_factory=set)
    blacklist_ips: Set[str] = field(default_factory=set)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "limit_type": self.limit_type.value,
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "action": self.action.value,
            "burst_allowance": self.burst_allowance,
            "whitelist_ips": list(self.whitelist_ips),
            "blacklist_ips": list(self.blacklist_ips),
            "enabled": self.enabled
        }


@dataclass
class RequestInfo:
    """Information about a request."""
    ip_address: str
    user_id: Optional[str]
    endpoint: str
    method: str
    user_agent: str
    timestamp: float
    size_bytes: int = 0

    def get_fingerlogger.info(self) -> str:
        """Get request fingerprint for behavioral analysis."""
        data = f"{self.ip_address}:{self.user_agent}:{self.endpoint}:{self.method}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class LimitStatus:
    """Status of rate limit check."""
    allowed: bool
    limit_type: LimitType
    current_count: int
    max_allowed: int
    reset_time: float
    action_taken: Optional[ActionType] = None
    retry_after: Optional[int] = None
    threat_level: ThreatLevel = ThreatLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "allowed": self.allowed,
            "limit_type": self.limit_type.value,
            "current_count": self.current_count,
            "max_allowed": self.max_allowed,
            "reset_time": self.reset_time,
            "action_taken": self.action_taken.value if self.action_taken else None,
            "retry_after": self.retry_after,
            "threat_level": self.threat_level.value
        }


class SlidingWindowCounter:
    """Sliding window rate limiter."""

    def __init__(self, window_seconds: int):
        """Initialize sliding window counter."""
        self.window_seconds = window_seconds
        self.requests: deque = deque()

    def add_request(self, timestamp: float):
        """Add a request to the window."""
        self.requests.append(timestamp)
        self._cleanup_old_requests(timestamp)

    def get_count(self, timestamp: float) -> int:
        """Get current request count in window."""
        self._cleanup_old_requests(timestamp)
        return len(self.requests)

    def _cleanup_old_requests(self, current_time: float):
        """Remove requests outside the window."""
        cutoff_time = current_time - self.window_seconds
        while self.requests and self.requests[0] < cutoff_time:
            self.requests.popleft()


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: int, refill_rate: float):
        """Initialize token bucket."""
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens."""
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


class BehavioralAnalyzer:
    """Behavioral analysis for threat detection."""

    def __init__(self):
        """Initialize behavioral analyzer."""
        self.request_patterns: Dict[str, List[RequestInfo]] = defaultdict(list)
        self.suspicious_patterns = {
            "rapid_requests": {"threshold": 100, "window": 60},
            "endpoint_scanning": {"threshold": 20, "window": 300},
            "user_agent_rotation": {"threshold": 5, "window": 300},
            "distributed_attack": {"threshold": 50, "window": 60}
        }

    def analyze_request(self, request: RequestInfo) -> ThreatLevel:
        """Analyze request for suspicious behavior."""
        fingerprint = request.get_fingerprint()
        self.request_patterns[fingerprint].append(request)

        # Clean old requests
        cutoff_time = request.timestamp - 3600  # Keep 1 hour of history
        self.request_patterns[fingerprint] = [
            req for req in self.request_patterns[fingerprint]
            if req.timestamp > cutoff_time
        ]

        threat_level = ThreatLevel.LOW

        # Check for rapid requests
        recent_requests = [
            req for req in self.request_patterns[fingerprint]
            if req.timestamp > request.timestamp - self.suspicious_patterns["rapid_requests"]["window"]
        ]

        if len(recent_requests) > self.suspicious_patterns["rapid_requests"]["threshold"]:
            threat_level = max(threat_level, ThreatLevel.HIGH)

        # Check for endpoint scanning
        unique_endpoints = set(req.endpoint for req in recent_requests)
        if len(unique_endpoints) > self.suspicious_patterns["endpoint_scanning"]["threshold"]:
            threat_level = max(threat_level, ThreatLevel.CRITICAL)

        # Check for user agent rotation
        unique_user_agents = set(req.user_agent for req in recent_requests)
        if len(unique_user_agents) > self.suspicious_patterns["user_agent_rotation"]["threshold"]:
            threat_level = max(threat_level, ThreatLevel.MEDIUM)

        return threat_level


class RateLimiter:
    """Advanced rate limiting system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize rate limiter."""
        self.config = config or {}

        # Rate limits
        self.limits: Dict[str, RateLimit] = {}

        # Counters and buckets
        self.sliding_windows: Dict[str, SlidingWindowCounter] = defaultdict(lambda: SlidingWindowCounter(60))
        self.token_buckets: Dict[str, TokenBucket] = defaultdict(lambda: TokenBucket(100, 1.0))

        # Behavioral analysis
        self.behavioral_analyzer = BehavioralAnalyzer()

        # Banned IPs and temporary bans
        self.banned_ips: Set[str] = set()
        self.temporary_bans: Dict[str, float] = {}  # IP -> ban_until_timestamp

        # Statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "delayed_requests": 0,
            "captcha_challenges": 0,
            "temporary_bans": 0,
            "permanent_bans": 0
        }

        # Default limits
        self._setup_default_limits()

        logger.info("Rate Limiter initialized")

    def _setup_default_limits(self):
        """Setup default rate limits."""
        default_limits = [
            RateLimit(LimitType.REQUESTS_PER_SECOND, 10, 1, ActionType.DELAY),
            RateLimit(LimitType.REQUESTS_PER_MINUTE, 300, 60, ActionType.BLOCK),
            RateLimit(LimitType.REQUESTS_PER_HOUR, 5000, 3600, ActionType.TEMPORARY_BAN),
            RateLimit(LimitType.LOGIN_ATTEMPTS_PER_MINUTE, 5, 60, ActionType.CAPTCHA),
            RateLimit(LimitType.FILE_UPLOADS_PER_HOUR, 100, 3600, ActionType.BLOCK),
            RateLimit(LimitType.BANDWIDTH_PER_SECOND, 1024*1024, 1, ActionType.DELAY),  # 1MB/s
        ]

        for limit in default_limits:
            self.limits[limit.limit_type.value] = limit

    async def check_rate_limit(self, request: RequestInfo) -> LimitStatus:
        """Check if request should be rate limited."""
        self.stats["total_requests"] += 1

        # Check if IP is permanently banned
        if request.ip_address in self.banned_ips:
            self.stats["blocked_requests"] += 1
            return LimitStatus(
                allowed=False,
                limit_type=LimitType.REQUESTS_PER_SECOND,
                current_count=0,
                max_allowed=0,
                reset_time=0,
                action_taken=ActionType.PERMANENT_BAN,
                threat_level=ThreatLevel.CRITICAL
            )

        # Check temporary bans
        if request.ip_address in self.temporary_bans:
            ban_until = self.temporary_bans[request.ip_address]
            if request.timestamp < ban_until:
                self.stats["blocked_requests"] += 1
                return LimitStatus()
                    allowed=False,
                    limit_type=LimitType.REQUESTS_PER_SECOND,
                    current_count=0,
                    max_allowed=0,
                    reset_time=ban_until,
                    action_taken=ActionType.TEMPORARY_BAN,
                    retry_after=int(ban_until - request.timestamp),
                    threat_level=ThreatLevel.HIGH
                )
            else:
                # Ban expired
                del self.temporary_bans[request.ip_address]

        # Behavioral analysis
        threat_level = self.behavioral_analyzer.analyze_request(request)

        # Check each rate limit
        for limit_name, limit in self.limits.items():
            if not limit.enabled:
                continue

            # Skip if IP is whitelisted
            if request.ip_address in limit.whitelist_ips:
                continue

            # Block if IP is blacklisted
            if request.ip_address in limit.blacklist_ips:
                self.stats["blocked_requests"] += 1
                return LimitStatus(
                    allowed=False,
                    limit_type=limit.limit_type,
                    current_count=0,
                    max_allowed=0,
                    reset_time=0,
                    action_taken=ActionType.BLOCK,
                    threat_level=ThreatLevel.HIGH
                )

            # Check specific limit
            status = await self._check_specific_limit(request, limit, threat_level)
            if not status.allowed:
                return status

        # All limits passed
        return LimitStatus()
            allowed=True,
            limit_type=LimitType.REQUESTS_PER_SECOND,
            current_count=0,
            max_allowed=0,
            reset_time=0,
            threat_level=threat_level
        )

    async def _check_specific_limit(self, request: RequestInfo, limit: RateLimit, threat_level: ThreatLevel) -> LimitStatus:
        """Check a specific rate limit."""
        key = f"{request.ip_address}:{limit.limit_type.value}"

        if limit.limit_type in [LimitType.REQUESTS_PER_SECOND, LimitType.REQUESTS_PER_MINUTE,
                               LimitType.REQUESTS_PER_HOUR, LimitType.REQUESTS_PER_DAY]:
            return await self._check_request_limit(request, limit, key, threat_level)
        elif limit.limit_type == LimitType.BANDWIDTH_PER_SECOND:
            return await self._check_bandwidth_limit(request, limit, key, threat_level)
        elif limit.limit_type == LimitType.LOGIN_ATTEMPTS_PER_MINUTE:
            return await self._check_login_limit(request, limit, key, threat_level)
        elif limit.limit_type == LimitType.FILE_UPLOADS_PER_HOUR:
            return await self._check_upload_limit(request, limit, key, threat_level)

        # Default to allowing
        return LimitStatus(
            allowed=True,
            limit_type=limit.limit_type,
            current_count=0,
            max_allowed=limit.max_requests,
            reset_time=request.timestamp + limit.window_seconds,
            threat_level=threat_level
        )

    async def _check_request_limit(self, request: RequestInfo, limit: RateLimit, key: str, threat_level: ThreatLevel) -> LimitStatus:
        """Check request-based rate limit."""
        window = self.sliding_windows[key]
        window.window_seconds = limit.window_seconds

        current_count = window.get_count(request.timestamp)
        max_allowed = limit.max_requests

        # Adjust limit based on threat level
        if threat_level == ThreatLevel.HIGH:
            max_allowed = max(1, max_allowed // 2)
        elif threat_level == ThreatLevel.CRITICAL:
            max_allowed = max(1, max_allowed // 4)

        if current_count >= max_allowed:
            action_taken = await self._take_action(request, limit, threat_level)

            return LimitStatus()
                allowed=False,
                limit_type=limit.limit_type,
                current_count=current_count,
                max_allowed=max_allowed,
                reset_time=request.timestamp + limit.window_seconds,
                action_taken=action_taken,
                retry_after=limit.window_seconds,
                threat_level=threat_level
            )

        # Add request to window
        window.add_request(request.timestamp)

        return LimitStatus()
            allowed=True,
            limit_type=limit.limit_type,
            current_count=current_count + 1,
            max_allowed=max_allowed,
            reset_time=request.timestamp + limit.window_seconds,
            threat_level=threat_level
        )

    async def _check_bandwidth_limit(self, request: RequestInfo, limit: RateLimit, key: str, threat_level: ThreatLevel) -> LimitStatus:
        """Check bandwidth rate limit."""
        bucket = self.token_buckets[key]
        bucket.capacity = limit.max_requests
        bucket.refill_rate = limit.max_requests / limit.window_seconds

        tokens_needed = max(1, request.size_bytes // 1024)  # 1 token per KB

        if not bucket.consume(tokens_needed):
            action_taken = await self._take_action(request, limit, threat_level)

            return LimitStatus()
                allowed=False,
                limit_type=limit.limit_type,
                current_count=int(bucket.capacity - bucket.tokens),
                max_allowed=bucket.capacity,
                reset_time=request.timestamp + limit.window_seconds,
                action_taken=action_taken,
                retry_after=int(tokens_needed / bucket.refill_rate),
                threat_level=threat_level
            )

        return LimitStatus()
            allowed=True,
            limit_type=limit.limit_type,
            current_count=int(bucket.capacity - bucket.tokens),
            max_allowed=bucket.capacity,
            reset_time=request.timestamp + limit.window_seconds,
            threat_level=threat_level
        )

    async def _check_login_limit(self, request: RequestInfo, limit: RateLimit, key: str, threat_level: ThreatLevel) -> LimitStatus:
        """Check login attempt rate limit."""
        # Only apply to login endpoints
        if "login" not in request.endpoint.lower() and "auth" not in request.endpoint.lower():
            return LimitStatus()
                allowed=True,
                limit_type=limit.limit_type,
                current_count=0,
                max_allowed=limit.max_requests,
                reset_time=request.timestamp + limit.window_seconds,
                threat_level=threat_level
            )

        return await self._check_request_limit(request, limit, key, threat_level)

    async def _check_upload_limit(self, request: RequestInfo, limit: RateLimit, key: str, threat_level: ThreatLevel) -> LimitStatus:
        """Check file upload rate limit."""
        # Only apply to upload endpoints
        if "upload" not in request.endpoint.lower() and request.method.upper() != "POST":
            return LimitStatus()
                allowed=True,
                limit_type=limit.limit_type,
                current_count=0,
                max_allowed=limit.max_requests,
                reset_time=request.timestamp + limit.window_seconds,
                threat_level=threat_level
            )

        return await self._check_request_limit(request, limit, key, threat_level)

    async def _take_action(self, request: RequestInfo, limit: RateLimit, threat_level: ThreatLevel) -> ActionType:
        """Take action when rate limit is exceeded."""
        action = limit.action

        # Escalate action based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            if action == ActionType.BLOCK:
                action = ActionType.TEMPORARY_BAN
            elif action == ActionType.DELAY:
                action = ActionType.BLOCK

        if action == ActionType.BLOCK:
            self.stats["blocked_requests"] += 1
        elif action == ActionType.DELAY:
            self.stats["delayed_requests"] += 1
        elif action == ActionType.CAPTCHA:
            self.stats["captcha_challenges"] += 1
        elif action == ActionType.TEMPORARY_BAN:
            self.stats["temporary_bans"] += 1
            ban_duration = 3600 * (threat_level.value)  # 1-4 hours based on threat level
            self.temporary_bans[request.ip_address] = request.timestamp + ban_duration
        elif action == ActionType.PERMANENT_BAN:
            self.stats["permanent_bans"] += 1
            self.banned_ips.add(request.ip_address)

        logger.warning(f"Rate limit action taken: {action.value} for IP {request.ip_address}")

        return action

    def add_rate_limit(self, limit: RateLimit) -> bool:
        """Add or update a rate limit."""
        try:
            self.limits[limit.limit_type.value] = limit
            logger.info(f"Rate limit added: {limit.limit_type.value}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rate limit: {e}")
            return False

    def remove_rate_limit(self, limit_type: LimitType) -> bool:
        """Remove a rate limit."""
        try:
            if limit_type.value in self.limits:
                del self.limits[limit_type.value]
                logger.info(f"Rate limit removed: {limit_type.value}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove rate limit: {e}")
            return False

    def get_rate_limits(self) -> List[Dict[str, Any]]:
        """Get all configured rate limits."""
        return [limit.to_dict() for limit in self.limits.values()]

    def whitelist_ip(self, ip_address: str, limit_types: Optional[List[LimitType]] = None):
        """Add IP to whitelist for specific or all limits."""
        if limit_types is None:
            limit_types = list(LimitType)

        for limit_type in limit_types:
            if limit_type.value in self.limits:
                self.limits[limit_type.value].whitelist_ips.add(ip_address)

        logger.info(f"IP {ip_address} whitelisted for {len(limit_types)} limit types")

    def blacklist_ip(self, ip_address: str, limit_types: Optional[List[LimitType]] = None):
        """Add IP to blacklist for specific or all limits."""
        if limit_types is None:
            limit_types = list(LimitType)

        for limit_type in limit_types:
            if limit_type.value in self.limits:
                self.limits[limit_type.value].blacklist_ips.add(ip_address)

        logger.info(f"IP {ip_address} blacklisted for {len(limit_types)} limit types")

    def ban_ip_permanently(self, ip_address: str):
        """Permanently ban an IP address."""
        self.banned_ips.add(ip_address)
        # Remove from temporary bans if present
        if ip_address in self.temporary_bans:
            del self.temporary_bans[ip_address]

        logger.warning(f"IP {ip_address} permanently banned")

    def ban_ip_temporarily(self, ip_address: str, duration_seconds: int):
        """Temporarily ban an IP address."""
        ban_until = time.time() + duration_seconds
        self.temporary_bans[ip_address] = ban_until

        logger.warning(f"IP {ip_address} temporarily banned for {duration_seconds} seconds")

    def unban_ip(self, ip_address: str):
        """Remove IP from all ban lists."""
        removed = False

        if ip_address in self.banned_ips:
            self.banned_ips.remove(ip_address)
            removed = True

        if ip_address in self.temporary_bans:
            del self.temporary_bans[ip_address]
            removed = True

        if removed:
            logger.info(f"IP {ip_address} unbanned")

        return removed

    def get_banned_ips(self) -> Dict[str, Any]:
        """Get all banned IPs."""
        current_time = time.time()
        active_temp_bans = {
            ip: ban_until for ip, ban_until in self.temporary_bans.items()
            if ban_until > current_time
        }

        return {
            "permanent_bans": list(self.banned_ips),
            "temporary_bans": active_temp_bans,
            "total_banned": len(self.banned_ips) + len(active_temp_bans)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        current_time = time.time()

        # Clean expired temporary bans
        expired_bans = [ip for ip, ban_until in self.temporary_bans.items() if ban_until <= current_time]
        for ip in expired_bans:
            del self.temporary_bans[ip]

        return {
            **self.stats,
            "active_temporary_bans": len(self.temporary_bans),
            "permanent_bans": len(self.banned_ips),
            "configured_limits": len(self.limits),
            "active_sliding_windows": len(self.sliding_windows),
            "active_token_buckets": len(self.token_buckets)
        }

    def reset_statistics(self):
        """Reset rate limiting statistics."""
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "delayed_requests": 0,
            "captcha_challenges": 0,
            "temporary_bans": 0,
            "permanent_bans": 0
        }
        logger.info("Rate limiting statistics reset")

    def cleanup_expired_data(self):
        """Clean up expired data structures."""
        current_time = time.time()

        # Clean expired temporary bans
        expired_bans = [ip for ip, ban_until in self.temporary_bans.items() if ban_until <= current_time]
        for ip in expired_bans:
            del self.temporary_bans[ip]

        # Clean old behavioral analysis data
        cutoff_time = current_time - 3600  # Keep 1 hour
        for fingerprint in list(self.behavioral_analyzer.request_patterns.keys()):
            self.behavioral_analyzer.request_patterns[fingerprint] = [
                req for req in self.behavioral_analyzer.request_patterns[fingerprint]
                if req.timestamp > cutoff_time
            ]

            # Remove empty patterns
            if not self.behavioral_analyzer.request_patterns[fingerprint]:
                del self.behavioral_analyzer.request_patterns[fingerprint]

        # Clean old sliding windows (keep only active ones)
        active_keys = set()
        for limit in self.limits.values():
            for ip in self.behavioral_analyzer.request_patterns.keys():
                active_keys.add(f"{ip}:{limit.limit_type.value}")

        inactive_windows = set(self.sliding_windows.keys()) - active_keys
        for key in inactive_windows:
            del self.sliding_windows[key]

        logger.info(f"Cleaned up {len(expired_bans)} expired bans, {len(inactive_windows)} inactive windows")

    def get_ip_status(self, ip_address: str) -> Dict[str, Any]:
        """Get detailed status for an IP address."""
        current_time = time.time()

        status = {
            "ip_address": ip_address,
            "permanently_banned": ip_address in self.banned_ips,
            "temporarily_banned": False,
            "ban_expires_at": None,
            "whitelisted_limits": [],
            "blacklisted_limits": [],
            "current_limits": {},
            "threat_level": ThreatLevel.LOW.value
        }

        # Check temporary ban
        if ip_address in self.temporary_bans:
            ban_until = self.temporary_bans[ip_address]
            if ban_until > current_time:
                status["temporarily_banned"] = True
                status["ban_expires_at"] = ban_until

        # Check whitelist/blacklist status
        for limit_name, limit in self.limits.items():
            if ip_address in limit.whitelist_ips:
                status["whitelisted_limits"].append(limit_name)
            if ip_address in limit.blacklist_ips:
                status["blacklisted_limits"].append(limit_name)

        # Get current limit status
        for limit_name, limit in self.limits.items():
            key = f"{ip_address}:{limit.limit_type.value}"
            if key in self.sliding_windows:
                window = self.sliding_windows[key]
                current_count = window.get_count(current_time)
                status["current_limits"][limit_name] = {
                    "current_count": current_count,
                    "max_allowed": limit.max_requests,
                    "window_seconds": limit.window_seconds,
                    "percentage_used": (current_count / limit.max_requests) * 100 if limit.max_requests > 0 else 0
                }

        # Get threat level from behavioral analysis
        for fingerprint, requests in self.behavioral_analyzer.request_patterns.items():
            if requests and requests[0].ip_address == ip_address:
                # Create a dummy request to get threat level
                dummy_request = RequestInfo()
                    ip_address=ip_address,
                    user_id=None,
                    endpoint="/",
                    method="GET",
                    user_agent="",
                    timestamp=current_time
                )
                threat_level = self.behavioral_analyzer.analyze_request(dummy_request)
                status["threat_level"] = threat_level.value
                break

        return status

    def export_configuration(self) -> Dict[str, Any]:
        """Export rate limiter configuration."""
        return {
            "limits": {name: limit.to_dict() for name, limit in self.limits.items()},
            "banned_ips": list(self.banned_ips),
            "temporary_bans": self.temporary_bans,
            "stats": self.stats
        }

    def import_configuration(self, config: Dict[str, Any]) -> bool:
        """Import rate limiter configuration."""
        try:
            # Import limits
            if "limits" in config:
                for limit_name, limit_data in config["limits"].items():
                    limit = RateLimit()
                        limit_type=LimitType(limit_data["limit_type"]),
                        max_requests=limit_data["max_requests"],
                        window_seconds=limit_data["window_seconds"],
                        action=ActionType(limit_data["action"]),
                        burst_allowance=limit_data.get("burst_allowance", 0),
                        whitelist_ips=set(limit_data.get("whitelist_ips", [])),
                        blacklist_ips=set(limit_data.get("blacklist_ips", [])),
                        enabled=limit_data.get("enabled", True)
                    )
                    self.limits[limit_name] = limit

            # Import banned IPs
            if "banned_ips" in config:
                self.banned_ips = set(config["banned_ips"])

            # Import temporary bans
            if "temporary_bans" in config:
                self.temporary_bans = config["temporary_bans"]

            # Import stats
            if "stats" in config:
                self.stats.update(config["stats"])

            logger.info("Rate limiter configuration imported successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False


# Global instance
rate_limiter = RateLimiter()
