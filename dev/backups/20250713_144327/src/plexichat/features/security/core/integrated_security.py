import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ..logging import get_logger

from datetime import datetime

from datetime import datetime

"""
PlexiChat Integrated Security System
Deep integration of security, rate limiting, and behavioral analysis across all endpoints.
"""

logger = get_logger(__name__)


class ThreatLevel(str, Enum):
    """Security threat levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAction(str, Enum):
    """Security actions to take."""
    ALLOW = "allow"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BLOCK = "temporary_block"
    PERMANENT_BLOCK = "permanent_block"
    REQUIRE_2FA = "require_2fa"
    LOG_ONLY = "log_only"


@dataclass
class SecurityEvent:
    """Security event data."""
    timestamp: datetime
    event_type: str
    source_ip: str
    user_id: Optional[int]
    endpoint: str
    threat_level: ThreatLevel
    details: Dict[str, Any] = field(default_factory=dict)
    action_taken: Optional[SecurityAction] = None


@dataclass
class UserBehaviorProfile:
    """User behavior analysis profile."""
    user_id: int
    typical_endpoints: List[str] = field(default_factory=list)
    typical_times: List[int] = field(default_factory=list)  # Hours of day
    typical_ips: List[str] = field(default_factory=list)
    request_patterns: Dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    anomaly_score: float = 0.0


class IntegratedSecurityManager:
    """Comprehensive security manager with deep endpoint integration."""

    def __init__(self):
        """Initialize the integrated security manager."""
        self.config = {
            "rate_limits": {
                "default": {"requests": 1000, "window": 3600},  # 1000/hour
                "auth": {"requests": 10, "window": 300},        # 10/5min
                "messages": {"requests": 100, "window": 60},    # 100/min
                "files": {"requests": 50, "window": 300},       # 50/5min
                "admin": {"requests": 200, "window": 3600},     # 200/hour
            },
            "security_rules": {
                "max_failed_logins": 5,
                "lockout_duration": 1800,  # 30 minutes
                "anomaly_threshold": 0.8,
                "auto_block_threshold": 0.9,
                "whitelist_localhost": True,
            },
            "behavioral_analysis": {
                "enabled": True,
                "learning_period_days": 7,
                "min_requests_for_profile": 50,
            }
        }

        # In-memory stores (in production, use Redis/database)
        self.rate_limit_store: Dict[str, Dict[str, Any]] = {}
        self.security_events: List[SecurityEvent] = []
        self.blocked_ips: Dict[str, datetime] = {}
        self.user_profiles: Dict[int, UserBehaviorProfile] = {}
        self.failed_logins: Dict[str, List[datetime]] = {}

        # Whitelisted IPs (localhost and private networks)
        self.whitelisted_ips = {
            "127.0.0.1", "::1", "localhost",
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        }

        logger.info("Integrated security manager initialized")

    def is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        if not self.config["security_rules"]["whitelist_localhost"]:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check exact matches
            if ip in self.whitelisted_ips:
                return True

            # Check network ranges
            for whitelist_entry in self.whitelisted_ips:
                if "/" in whitelist_entry:
                    network = ipaddress.ip_network(whitelist_entry, strict=False)
                    if ip_obj in network:
                        return True

            return False
        except Exception:
            return ip in ["127.0.0.1", "localhost"]

    async def check_rate_limit(
        self,
        key: str,
        endpoint_type: str = "default",
        user_id: Optional[int] = None
    ) -> bool:
        """Check if request is within rate limits."""
        # Skip rate limiting for whitelisted IPs
        if ":" in key:  # IP-based key
            ip = key.split(":")[0]
            if self.is_whitelisted_ip(ip):
                return True

        # Get rate limit config for endpoint type
        limits = self.config["rate_limits"].get(endpoint_type, self.config["rate_limits"]["default"])
        max_requests = limits["requests"]
        window_seconds = limits["window"]

        now = time.time()
        window_start = now - window_seconds

        # Initialize or clean old entries
        if key not in self.rate_limit_store:
            self.rate_limit_store[key] = {"requests": [], "blocked_until": None}

        store = self.rate_limit_store[key]

        # Check if currently blocked
        if store["blocked_until"] and now < store["blocked_until"]:
            return False

        # Clean old requests
        store["requests"] = [req_time for req_time in store["requests"] if req_time > window_start]

        # Check rate limit
        if len(store["requests"]) >= max_requests:
            # Block for the window duration
            store["blocked_until"] = now + window_seconds

            # Log rate limit violation
            await self._log_security_event(
                event_type="rate_limit_exceeded",
                source_ip=key.split(":")[0] if ":" in key else "unknown",
                user_id=user_id,
                endpoint=endpoint_type,
                threat_level=ThreatLevel.MEDIUM,
                details={"requests": len(store["requests"]), "limit": max_requests}
            )

            return False

        # Record this request
        store["requests"].append(now)
        return True

    async def analyze_request_behavior(
        self,
        user_id: int,
        endpoint: str,
        ip: str,
        request_data: Dict[str, Any]
    ) -> float:
        """Analyze request behavior and return anomaly score (0-1)."""
        if not self.config["behavioral_analysis"]["enabled"]:
            return 0.0

        # Get or create user profile
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id=user_id)

        profile = self.user_profiles[user_id]
        from datetime import datetime
current_hour = datetime.now()
datetime = datetime.now().hour

        # Calculate anomaly factors
        anomaly_factors = []

        # 1. Unusual endpoint access
        if endpoint not in profile.typical_endpoints:
            if len(profile.typical_endpoints) > 0:
                anomaly_factors.append(0.3)

        # 2. Unusual time of access
        if current_hour not in profile.typical_times:
            if len(profile.typical_times) > 0:
                anomaly_factors.append(0.2)

        # 3. New IP address
        if ip not in profile.typical_ips:
            if len(profile.typical_ips) > 0:
                anomaly_factors.append(0.4)

        # 4. Request pattern analysis
        request_signature = self._generate_request_signature(request_data)
        if request_signature not in profile.request_patterns:
            if len(profile.request_patterns) > 0:
                anomaly_factors.append(0.1)

        # Calculate overall anomaly score
        anomaly_score = min(sum(anomaly_factors), 1.0)

        # Update profile (learning)
        await self._update_user_profile(profile, endpoint, ip, current_hour, request_signature)

        return anomaly_score

    async def evaluate_security_action(
        self,
        ip: str,
        user_id: Optional[int],
        endpoint: str,
        anomaly_score: float,
        additional_context: Dict[str, Any] = None
    ) -> SecurityAction:
        """Evaluate what security action to take based on analysis."""
        # Skip security actions for whitelisted IPs
        if self.is_whitelisted_ip(ip):
            return SecurityAction.ALLOW

        # Check if IP is already blocked
        if ip in self.blocked_ips:
            if datetime.now(timezone.utc) < self.blocked_ips[ip]:
                return SecurityAction.PERMANENT_BLOCK
            else:
                del self.blocked_ips[ip]

        # Evaluate threat level
        threat_level = ThreatLevel.LOW

        if anomaly_score > self.config["security_rules"]["auto_block_threshold"]:
            threat_level = ThreatLevel.CRITICAL
        elif anomaly_score > self.config["security_rules"]["anomaly_threshold"]:
            threat_level = ThreatLevel.HIGH
        elif anomaly_score > 0.5:
            threat_level = ThreatLevel.MEDIUM

        # Determine action based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            # Block IP temporarily
            self.blocked_ips[ip] = datetime.now(timezone.utc) + timedelta(hours=24)
            return SecurityAction.TEMPORARY_BLOCK
        elif threat_level == ThreatLevel.HIGH:
            return SecurityAction.REQUIRE_2FA
        elif threat_level == ThreatLevel.MEDIUM:
            return SecurityAction.RATE_LIMIT
        else:
            return SecurityAction.ALLOW

    async def process_security_middleware(
        self,
        request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Main security middleware processing."""
        ip = request_data.get("client_ip", "unknown")
        user_id = request_data.get("user_id")
        endpoint = request_data.get("endpoint", "unknown")
        method = request_data.get("method", "GET")

        # Determine endpoint type for rate limiting
        endpoint_type = self._classify_endpoint(endpoint)

        # Check rate limits
        rate_limit_key = f"{ip}:{endpoint_type}"
        if user_id:
            rate_limit_key = f"user:{user_id}:{endpoint_type}"

        rate_limit_ok = await self.check_rate_limit(rate_limit_key, endpoint_type, user_id)

        if not rate_limit_ok:
            return {
                "allowed": False,
                "action": SecurityAction.RATE_LIMIT,
                "message": "Rate limit exceeded",
                "retry_after": 60
            }

        # Behavioral analysis (only for authenticated users)
        anomaly_score = 0.0
        if user_id:
            anomaly_score = await self.analyze_request_behavior(
                user_id, endpoint, ip, request_data
            )

        # Evaluate security action
        action = await self.evaluate_security_action(
            ip, user_id, endpoint, anomaly_score, request_data
        )

        # Log security event if significant
        if anomaly_score > 0.3 or action != SecurityAction.ALLOW:
            await self._log_security_event(
                event_type="request_analysis",
                source_ip=ip,
                user_id=user_id,
                endpoint=endpoint,
                threat_level=ThreatLevel.MEDIUM if anomaly_score > 0.5 else ThreatLevel.LOW,
                details={
                    "anomaly_score": anomaly_score,
                    "method": method,
                    "action": action.value
                },
                action_taken=action
            )

        return {
            "allowed": action in [SecurityAction.ALLOW, SecurityAction.LOG_ONLY],
            "action": action,
            "anomaly_score": anomaly_score,
            "requires_2fa": action == SecurityAction.REQUIRE_2FA,
            "message": self._get_action_message(action)
        }

    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify endpoint for rate limiting purposes."""
        if "/auth/" in endpoint:
            return "auth"
        elif "/messages/" in endpoint:
            return "messages"
        elif "/files/" in endpoint:
            return "files"
        elif "/admin/" in endpoint:
            return "admin"
        else:
            return "default"

    def _generate_request_signature(self, request_data: Dict[str, Any]) -> str:
        """Generate a signature for request pattern analysis."""
        # Create a simplified signature based on request characteristics
        signature_data = {
            "method": request_data.get("method", "GET"),
            "endpoint_pattern": self._normalize_endpoint(request_data.get("endpoint", "")),
            "has_body": bool(request_data.get("body")),
            "user_agent_type": self._classify_user_agent(request_data.get("user_agent", ""))
        }

        signature_str = json.dumps(signature_data, sort_keys=True)
        return hashlib.md5(signature_str.encode()).hexdigest()[:16]

    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for pattern matching."""
        # Replace IDs with placeholders
        normalized = re.sub(r'/\d+', '/{id}', endpoint)
        normalized = re.sub(r'/[a-f0-9-]{36}', '/{uuid}', normalized)
        return normalized

    def _classify_user_agent(self, user_agent: str) -> str:
        """Classify user agent type."""
        ua_lower = user_agent.lower()
        if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            return "mobile"
        elif "bot" in ua_lower or "crawler" in ua_lower:
            return "bot"
        else:
            return "desktop"

    async def _update_user_profile(
        self,
        profile: UserBehaviorProfile,
        endpoint: str,
        ip: str,
        hour: int,
        request_signature: str
    ):
        """Update user behavior profile with new data."""
        # Add to typical patterns (with limits)
        if endpoint not in profile.typical_endpoints:
            profile.typical_endpoints.append(endpoint)
            if len(profile.typical_endpoints) > 50:  # Limit size
                profile.typical_endpoints.pop(0)

        if hour not in profile.typical_times:
            profile.typical_times.append(hour)

        if ip not in profile.typical_ips:
            profile.typical_ips.append(ip)
            if len(profile.typical_ips) > 10:  # Limit to recent IPs
                profile.typical_ips.pop(0)

        # Update request patterns
        profile.request_patterns[request_signature] = profile.request_patterns.get(request_signature, 0) + 1

        # Limit pattern storage
        if len(profile.request_patterns) > 100:
            # Remove least common patterns
            sorted_patterns = sorted(profile.request_patterns.items(), key=lambda x: x[1])
            for pattern, _ in sorted_patterns[:20]:
                del profile.request_patterns[pattern]

        profile.last_updated = datetime.now(timezone.utc)

    async def _log_security_event(
        self,
        event_type: str,
        source_ip: str,
        user_id: Optional[int],
        endpoint: str,
        threat_level: ThreatLevel,
        details: Dict[str, Any],
        action_taken: Optional[SecurityAction] = None
    ):
        """Log a security event."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            source_ip=source_ip,
            user_id=user_id,
            endpoint=endpoint,
            threat_level=threat_level,
            details=details,
            action_taken=action_taken
        )

        self.security_events.append(event)

        # Limit event storage
        if len(self.security_events) > 10000:
            self.security_events = self.security_events[-5000:]

        # Log to file/database in production
        logger.info(f"Security event: {event_type} from {source_ip} - {threat_level.value}")

    def _get_action_message(self, action: SecurityAction) -> str:
        """Get user-friendly message for security action."""
        messages = {
            SecurityAction.ALLOW: "Request allowed",
            SecurityAction.RATE_LIMIT: "Rate limit exceeded. Please slow down.",
            SecurityAction.TEMPORARY_BLOCK: "Access temporarily blocked due to suspicious activity",
            SecurityAction.PERMANENT_BLOCK: "Access blocked",
            SecurityAction.REQUIRE_2FA: "Additional authentication required",
            SecurityAction.LOG_ONLY: "Request logged for monitoring"
        }
        return messages.get(action, "Security check completed")

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        now = datetime.now(timezone.utc)
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)

        recent_events = [e for e in self.security_events if e.timestamp > last_hour]
        daily_events = [e for e in self.security_events if e.timestamp > last_day]

        return {
            "total_events": len(self.security_events),
            "events_last_hour": len(recent_events),
            "events_last_day": len(daily_events),
            "blocked_ips": len(self.blocked_ips),
            "user_profiles": len(self.user_profiles),
            "threat_levels": {
                level.value: len([e for e in recent_events if e.threat_level == level])
                for level in ThreatLevel
            }
        }


# Global integrated security manager instance
integrated_security = IntegratedSecurityManager()
