# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


"""
PlexiChat Security Protection System

Consolidates security protection functionality from:
- src/plexichat/app/security/ (DDoS, rate limiting, input sanitization, etc.)
- src/plexichat/core/security/ (penetration testing, vulnerability scanning, etc.)

Provides comprehensive protection against various security threats.
"""

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Security threat levels."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    """Types of security attacks."""

    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    MALICIOUS_INPUT = "malicious_input"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


@dataclass
class SecurityThreat:
    """Security threat detection record."""

    threat_id: str
    threat_type: AttackType
    threat_level: ThreatLevel
    source_ip: str
    timestamp: datetime
    description: str
    blocked: bool = False
    mitigation_action: Optional[str] = None


class DDoSProtection:
    """
    Enhanced DDoS Protection System

    Consolidates DDoS protection from app/security/ddos_protection.py
    and core/security/ddos_protection.py
    """

    def __init__(self):
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips: Dict[str, datetime] = {}
        self.suspicious_patterns: Dict[str, int] = defaultdict(int)

        # Configuration
        self.max_requests_per_minute = 100
        self.max_requests_per_hour = 1000
        self.block_duration_minutes = 60
        self.suspicious_threshold = 10

        # Behavioral analysis
        self.user_agents: Dict[str, Set[str]] = defaultdict(set)
        self.request_patterns: Dict[str, List[str]] = defaultdict(list)

    async def check_request(
        self, ip_address: str, user_agent: str, endpoint: str
    ) -> Tuple[bool, Optional[SecurityThreat]]:
        """
        Check if request should be allowed or blocked.

        Returns:
            Tuple of (allowed, threat_info)
        """
        current_time = datetime.now(timezone.utc)

        # Check if IP is currently blocked
        if ip_address in self.blocked_ips:
            if current_time < self.blocked_ips[ip_address]:
                threat = SecurityThreat(
                    threat_id=f"ddos_{ip_address}_{int(time.time())}",
                    threat_type=AttackType.DDOS,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=ip_address,
                    timestamp=current_time,
                    description=f"IP {ip_address} is currently blocked for DDoS protection",
                    blocked=True,
                    mitigation_action="IP_BLOCKED",
                )
                return False, threat
            else:
                # Unblock expired IP
                del self.blocked_ips[ip_address]

        # Add request to tracking
        self.request_counts[ip_address].append(current_time)
        self.user_agents[ip_address].add(user_agent)
        self.request_patterns[ip_address].append(endpoint)

        # Check rate limits
        recent_requests = [
            req_time
            for req_time in self.request_counts[ip_address]
            if current_time - req_time < timedelta(minutes=1)
        ]

        if len(recent_requests) > self.max_requests_per_minute:
            # Block IP for DDoS
            self.blocked_ips[ip_address] = current_time + timedelta(
                minutes=self.block_duration_minutes
            )

            threat = SecurityThreat(
                threat_id=f"ddos_{ip_address}_{int(time.time())}",
                threat_type=AttackType.DDOS,
                threat_level=ThreatLevel.CRITICAL,
                source_ip=ip_address,
                timestamp=current_time,
                description=f"DDoS attack detected from {ip_address}: {len(recent_requests)} requests/minute",
                blocked=True,
                mitigation_action="IP_BLOCKED_DDOS",
            )

            logger.warning(
                f" DDoS attack blocked: {ip_address} - {len(recent_requests)} requests/minute"
            )
            return False, threat

        # Behavioral analysis
        if await self._analyze_suspicious_behavior(ip_address, user_agent, endpoint):
            self.suspicious_patterns[ip_address] += 1

            if self.suspicious_patterns[ip_address] >= self.suspicious_threshold:
                # Block suspicious IP
                self.blocked_ips[ip_address] = current_time + timedelta(
                    minutes=self.block_duration_minutes
                )

                threat = SecurityThreat(
                    threat_id=f"suspicious_{ip_address}_{int(time.time())}",
                    threat_type=AttackType.DDOS,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=ip_address,
                    timestamp=current_time,
                    description=f"Suspicious behavior detected from {ip_address}",
                    blocked=True,
                    mitigation_action="IP_BLOCKED_SUSPICIOUS",
                )

                logger.warning(f" Suspicious behavior blocked: {ip_address}")
                return False, threat

        return True, None

    async def _analyze_suspicious_behavior(
        self, ip_address: str, user_agent: str, endpoint: str
    ) -> bool:
        """Analyze request for suspicious patterns."""
        # Check for too many different user agents from same IP
        if len(self.user_agents[ip_address]) > 10:
            return True

        # Check for rapid endpoint scanning
        recent_patterns = self.request_patterns[ip_address][-50:]  # Last 50 requests
        unique_endpoints = set(recent_patterns)
        if len(unique_endpoints) > 20:  # Too many different endpoints
            return True

        # Check for suspicious user agent patterns
        suspicious_agents = ["bot", "crawler", "scanner", "hack", "exploit"]
        if any(pattern in user_agent.lower() for pattern in suspicious_agents):
            return True

        return False


class RateLimiter:
    """
    Advanced Rate Limiting System

    Consolidates rate limiting from app/security/rate_limiter.py
    """

    def __init__(self):
        self.request_counts: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=1000))
        )
        self.rate_limits = {
            "login": {"requests": 5, "window_minutes": 15},
            "api": {"requests": 100, "window_minutes": 1},
            "upload": {"requests": 10, "window_minutes": 60},
            "default": {"requests": 60, "window_minutes": 1},
        }

    async def is_allowed(
        self, identifier: str, action: str = "default"
    ) -> Tuple[bool, Optional[str]]:
        """Check if action is allowed for identifier."""
        current_time = datetime.now(timezone.utc)
        limit_config = self.rate_limits.get(action, self.rate_limits["default"])

        # Clean old requests
        window_start = current_time - timedelta(minutes=limit_config["window_minutes"])
        requests = self.request_counts[identifier][action]

        # Remove old requests
        while requests and requests[0] < window_start:
            requests.popleft()

        # Check if limit exceeded
        if len(requests) >= limit_config["requests"]:
            return (
                False,
                f"Rate limit exceeded for {action}: {len(requests)}/{limit_config['requests']} requests in {limit_config['window_minutes']} minutes",
            )

        # Record this request
        requests.append(current_time)
        return True, None


class InputSanitizer:
    """
    Input Sanitization and Validation System

    Consolidates input sanitization from app/security/input_sanitizer.py
    """

    def __init__(self):
        # SQL injection patterns
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\bUNION\s+SELECT\b)",
            r"(\b(EXEC|EXECUTE)\s*\()",
        ]

        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
        ]

        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
        ]

    async def sanitize_input(
        self, input_data: str, input_type: str = "general"
    ) -> Tuple[str, List[SecurityThreat]]:
        """
        Sanitize input and detect threats.

        Returns:
            Tuple of (sanitized_input, detected_threats)
        """
        threats = []
        sanitized = input_data

        # Check for SQL injection
        for pattern in self.sql_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                threat = SecurityThreat(
                    threat_id=f"sql_injection_{int(time.time())}",
                    threat_type=AttackType.SQL_INJECTION,
                    threat_level=ThreatLevel.CRITICAL,
                    source_ip="unknown",
                    timestamp=datetime.now(timezone.utc),
                    description=f"SQL injection attempt detected: {pattern}",
                    blocked=True,
                    mitigation_action="INPUT_SANITIZED",
                )
                threats.append(threat)
                # Remove dangerous SQL patterns
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # Check for XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                threat = SecurityThreat(
                    threat_id=f"xss_{int(time.time())}",
                    threat_type=AttackType.XSS,
                    threat_level=ThreatLevel.HIGH,
                    source_ip="unknown",
                    timestamp=datetime.now(timezone.utc),
                    description=f"XSS attempt detected: {pattern}",
                    blocked=True,
                    mitigation_action="INPUT_SANITIZED",
                )
                threats.append(threat)
                # Remove XSS patterns
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # Check for path traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                threat = SecurityThreat(
                    threat_id=f"path_traversal_{int(time.time())}",
                    threat_type=AttackType.MALICIOUS_INPUT,
                    threat_level=ThreatLevel.HIGH,
                    source_ip="unknown",
                    timestamp=datetime.now(timezone.utc),
                    description=f"Path traversal attempt detected: {pattern}",
                    blocked=True,
                    mitigation_action="INPUT_SANITIZED",
                )
                threats.append(threat)
                # Remove path traversal patterns
                sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        return sanitized, threats


# Placeholder classes for additional protection components
class PenetrationTester:
    """Automated penetration testing system."""


class VulnerabilityScanner:
    """Vulnerability scanning and assessment."""


class BehavioralAnalyzer:
    """Advanced behavioral analysis for threat detection."""


class MITMProtection:
    """Man-in-the-middle attack protection."""


# Create global instances
ddos_protection = DDoSProtection()
rate_limiter = RateLimiter()
input_sanitizer = InputSanitizer()
penetration_tester = PenetrationTester()
vulnerability_scanner = VulnerabilityScanner()
behavioral_analyzer = BehavioralAnalyzer()
mitm_protection = MITMProtection()
