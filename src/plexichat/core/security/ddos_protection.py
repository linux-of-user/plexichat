#!/usr/bin/env python3
"""
Advanced DDoS Protection System
Provides intelligent traffic analysis, automatic IP blocking, and real-time attack detection
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Import configuration and dependencies
try:
    from plexichat.core.config_manager import get_config_manager
    from plexichat.core.middleware.dynamic_rate_limiting_middleware import (
        DynamicRateLimitingMiddleware,
    )
except ImportError as e:
    print(f"Import error in DDoS protection: {e}")
    get_config_manager = None
    DynamicRateLimitingMiddleware = None

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of detected attacks."""

    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    SLOWLORIS = "slowloris"
    HTTP_FLOOD = "http_flood"
    BRUTE_FORCE = "brute_force"
    SCRAPING = "scraping"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


@dataclass
class IPMetrics:
    """Metrics for a specific IP address."""

    ip: str
    first_seen: float
    last_seen: float
    request_count: int = 0
    error_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    user_agents: Set[str] = field(default_factory=set)
    endpoints: Dict[str, int] = field(default_factory=dict)
    status_codes: Dict[int, int] = field(default_factory=dict)
    request_intervals: deque = field(default_factory=lambda: deque(maxlen=100))
    blocked_until: Optional[float] = None
    threat_score: float = 0.0
    detected_attacks: List[AttackType] = field(default_factory=list)


@dataclass
class AttackEvent:
    """Represents a detected attack event."""

    timestamp: float
    attack_type: AttackType
    threat_level: ThreatLevel
    source_ip: str
    description: str
    metrics: Dict[str, Any]
    action_taken: str


@dataclass
class DDoSStats:
    """Overall DDoS protection statistics."""

    total_requests: int = 0
    blocked_requests: int = 0
    blocked_ips: int = 0
    active_attacks: int = 0
    threat_level: ThreatLevel = ThreatLevel.LOW
    last_attack: Optional[float] = None


class TrafficAnalyzer:
    """Analyzes traffic patterns to detect attacks."""

    def __init__(self, config):
        self.config = config
        self.baseline_rps = 10.0  # Baseline requests per second
        self.baseline_error_rate = 0.05  # 5% baseline error rate

        # Pattern detection
        self.suspicious_patterns = [
            re.compile(r"\.\./", re.IGNORECASE),  # Directory traversal
            re.compile(r"<script", re.IGNORECASE),  # XSS attempts
            re.compile(r"union.*select", re.IGNORECASE),  # SQL injection
            re.compile(r"exec\(", re.IGNORECASE),  # Code execution
            re.compile(r"eval\(", re.IGNORECASE),  # Code evaluation
        ]

        # Bot detection patterns
        self.bot_patterns = [
            re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
            re.compile(r"curl|wget|python|java", re.IGNORECASE),
        ]

    def analyze_ip_behavior(
        self, ip_metrics: IPMetrics
    ) -> Tuple[float, List[AttackType]]:
        """Analyze IP behavior and return threat score and detected attacks."""
        threat_score = 0.0
        detected_attacks = []

        current_time = time.time()
        time_window = 300  # 5 minutes

        # Calculate request rate
        recent_requests = [
            t for t in ip_metrics.request_intervals if current_time - t < time_window
        ]
        request_rate = len(recent_requests) / time_window if recent_requests else 0

        # High request rate detection
        if request_rate > self.baseline_rps * 10:
            threat_score += 30
            detected_attacks.append(AttackType.VOLUMETRIC)
        elif request_rate > self.baseline_rps * 5:
            threat_score += 15
            detected_attacks.append(AttackType.HTTP_FLOOD)

        # Error rate analysis
        total_requests = sum(ip_metrics.status_codes.values())
        error_requests = sum(
            count for status, count in ip_metrics.status_codes.items() if status >= 400
        )
        error_rate = error_requests / total_requests if total_requests > 0 else 0

        if error_rate > 0.5:  # 50% error rate
            threat_score += 25
            detected_attacks.append(AttackType.BRUTE_FORCE)
        elif error_rate > 0.2:  # 20% error rate
            threat_score += 10

        # User agent analysis
        if len(ip_metrics.user_agents) == 1:
            ua = list(ip_metrics.user_agents)[0]
            if any(pattern.search(ua) for pattern in self.bot_patterns):
                threat_score += 15
                detected_attacks.append(AttackType.SCRAPING)
        elif len(ip_metrics.user_agents) > 10:  # Too many different UAs
            threat_score += 10
            detected_attacks.append(AttackType.SUSPICIOUS_PATTERN)

        # Endpoint diversity analysis
        unique_endpoints = len(ip_metrics.endpoints)
        if unique_endpoints > 50:  # Scanning behavior
            threat_score += 20
            detected_attacks.append(AttackType.SCRAPING)

        # Request pattern analysis
        if len(recent_requests) > 10:
            intervals = [
                recent_requests[i] - recent_requests[i - 1]
                for i in range(1, len(recent_requests))
            ]
            if intervals:
                avg_interval = statistics.mean(intervals)
                if avg_interval < 0.1:  # Very fast requests
                    threat_score += 15
                    detected_attacks.append(AttackType.HTTP_FLOOD)

        # Geographic and network analysis
        if self._is_suspicious_network(ip_metrics.ip):
            threat_score += 10

        return min(threat_score, 100.0), detected_attacks

    def _is_suspicious_network(self, ip: str) -> bool:
        """Check if IP belongs to suspicious networks."""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check for common VPN/proxy ranges (simplified)
            suspicious_ranges = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]

            return any(ip_obj in network for network in suspicious_ranges)
        except ValueError:
            return False

    def detect_slowloris(self, active_connections: Dict[str, float]) -> List[str]:
        """Detect Slowloris attacks based on connection patterns."""
        current_time = time.time()
        slowloris_ips = []

        # Group connections by IP
        ip_connections = defaultdict(list)
        for conn_id, start_time in active_connections.items():
            ip = conn_id.split(":")[0]  # Extract IP from connection ID
            ip_connections[ip].append(start_time)

        # Detect IPs with many long-lasting connections
        for ip, connections in ip_connections.items():
            long_connections = [
                t for t in connections if current_time - t > 30
            ]  # 30+ seconds
            if len(long_connections) > 10:  # Many slow connections
                slowloris_ips.append(ip)

        return slowloris_ips


class IPBlockManager:
    """Manages IP blocking and whitelisting."""

    def __init__(self, config):
        self.config = config
        self.blocked_ips: Dict[str, float] = {}  # IP -> unblock_time
        self.whitelist: Set[str] = set()
        self.permanent_blocks: Set[str] = set()
        self._lock = threading.RLock()

        # Load whitelist from config
        self._load_whitelist()

    def _load_whitelist(self):
        """Load IP whitelist from configuration."""
        # Add localhost and private networks to whitelist
        default_whitelist = [
            "127.0.0.1",
            "::1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]

        for ip_or_network in default_whitelist:
            self.whitelist.add(ip_or_network)

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if self.is_whitelisted(ip):
            return False

        with self._lock:
            if ip in self.permanent_blocks:
                return True

            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    # Block expired, remove it
                    del self.blocked_ips[ip]
                    return False

            return False

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_entry in self.whitelist:
                try:
                    if "/" in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry)
                        if ip_obj in network:
                            return True
                    elif ip == whitelist_entry:
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False

    def block_ip(self, ip: str, duration_seconds: int, reason: str = ""):
        """Block an IP address for specified duration."""
        if self.is_whitelisted(ip):
            logger.warning(f"Attempted to block whitelisted IP: {ip}")
            return

        with self._lock:
            unblock_time = time.time() + duration_seconds
            self.blocked_ips[ip] = unblock_time
            logger.warning(
                f"Blocked IP {ip} for {duration_seconds} seconds. Reason: {reason}"
            )

    def permanent_block(self, ip: str, reason: str = ""):
        """Permanently block an IP address."""
        if self.is_whitelisted(ip):
            logger.warning(f"Attempted to permanently block whitelisted IP: {ip}")
            return

        with self._lock:
            self.permanent_blocks.add(ip)
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
            logger.error(f"Permanently blocked IP {ip}. Reason: {reason}")

    def unblock_ip(self, ip: str):
        """Manually unblock an IP address."""
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
            if ip in self.permanent_blocks:
                self.permanent_blocks.remove(ip)
            logger.info(f"Unblocked IP {ip}")

    def get_blocked_ips(self) -> Dict[str, Dict[str, Any]]:
        """Get list of currently blocked IPs with details."""
        current_time = time.time()
        blocked_info = {}

        with self._lock:
            # Temporary blocks
            for ip, unblock_time in self.blocked_ips.items():
                if current_time < unblock_time:
                    blocked_info[ip] = {
                        "type": "temporary",
                        "expires_at": unblock_time,
                        "remaining_seconds": int(unblock_time - current_time),
                    }

            # Permanent blocks
            for ip in self.permanent_blocks:
                blocked_info[ip] = {
                    "type": "permanent",
                    "expires_at": None,
                    "remaining_seconds": None,
                }

        return blocked_info

    def cleanup_expired_blocks(self):
        """Remove expired IP blocks."""
        current_time = time.time()
        with self._lock:
            expired_ips = [
                ip
                for ip, unblock_time in self.blocked_ips.items()
                if current_time >= unblock_time
            ]
            for ip in expired_ips:
                del self.blocked_ips[ip]

            if expired_ips:
                logger.info(f"Cleaned up {len(expired_ips)} expired IP blocks")


class AlertManager:
    """Manages DDoS attack alerts and notifications."""

    def __init__(self, config):
        self.config = config
        self.alert_history: deque = deque(maxlen=1000)
        self.alert_callbacks: List[Callable] = []
        self.last_alert_time = 0
        self.alert_cooldown = 60  # 1 minute between similar alerts

    def add_alert_callback(self, callback: Callable):
        """Add a callback function for alerts."""
        self.alert_callbacks.append(callback)

    def send_alert(self, event: AttackEvent):
        """Send alert for attack event."""
        current_time = time.time()

        # Check cooldown
        if current_time - self.last_alert_time < self.alert_cooldown:
            return

        self.alert_history.append(event)
        self.last_alert_time = current_time

        # Log alert
        logger.error(
            f"DDoS Alert: {event.attack_type.value} attack from {event.source_ip} "
            f"(Threat: {event.threat_level.value}) - {event.description}"
        )

        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

    def get_recent_alerts(self, hours: int = 24) -> List[AttackEvent]:
        """Get recent alerts within specified hours."""
        cutoff_time = time.time() - (hours * 3600)
        return [event for event in self.alert_history if event.timestamp > cutoff_time]


class DDoSProtectionSystem:
    """Main DDoS protection system."""

    def __init__(
        self, dynamic_rate_limiter: Optional[DynamicRateLimitingMiddleware] = None
    ):
        # Load configuration
        if get_config_manager:
            config_manager = get_config_manager()
            self.config = config_manager._config.ddos
        else:
            # Fallback configuration
            from plexichat.core.config_manager import DDoSProtectionConfig

            self.config = DDoSProtectionConfig()

        self.enabled = self.config.enabled
        if not self.enabled:
            logger.info("DDoS protection is disabled")
            return

        # Initialize components
        self.traffic_analyzer = TrafficAnalyzer(self.config)
        self.ip_block_manager = IPBlockManager(self.config)
        self.alert_manager = AlertManager(self.config)
        self.dynamic_rate_limiter = dynamic_rate_limiter

        # Metrics storage
        self.ip_metrics: Dict[str, IPMetrics] = {}
        self.active_connections: Dict[str, float] = {}
        self.stats = DDoSStats()

        # Monitoring
        self._monitoring_task = None
        self._cleanup_task = None
        self._lock = threading.RLock()

        # Start background tasks
        self._start_monitoring()

        logger.info("DDoS protection system initialized")

    def _start_monitoring(self):
        """Start background monitoring tasks."""
        if not self.enabled:
            return

        async def monitor_threats():
            """Monitor for threats and update statistics."""
            while True:
                try:
                    await asyncio.sleep(30)  # Check every 30 seconds
                    await self._analyze_threats()
                except Exception as e:
                    logger.error(f"Error in threat monitoring: {e}")

        async def cleanup_data():
            """Clean up old data and expired blocks."""
            while True:
                try:
                    await asyncio.sleep(300)  # Clean up every 5 minutes
                    self._cleanup_old_data()
                    self.ip_block_manager.cleanup_expired_blocks()
                except Exception as e:
                    logger.error(f"Error in cleanup: {e}")

        # Start monitoring tasks
        if not self._monitoring_task or self._monitoring_task.done():
            self._monitoring_task = asyncio.create_task(monitor_threats())

        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(cleanup_data())

    async def _analyze_threats(self):
        """Analyze current threats and take action."""
        current_time = time.time()
        active_attacks = 0
        max_threat_level = ThreatLevel.LOW

        with self._lock:
            for ip, metrics in list(self.ip_metrics.items()):
                # Skip if IP is whitelisted
                if self.ip_block_manager.is_whitelisted(ip):
                    continue

                # Analyze IP behavior
                threat_score, detected_attacks = (
                    self.traffic_analyzer.analyze_ip_behavior(metrics)
                )
                metrics.threat_score = threat_score
                metrics.detected_attacks = detected_attacks

                # Determine threat level
                if threat_score >= 80:
                    threat_level = ThreatLevel.CRITICAL
                elif threat_score >= 60:
                    threat_level = ThreatLevel.HIGH
                elif threat_score >= 40:
                    threat_level = ThreatLevel.MEDIUM
                else:
                    threat_level = ThreatLevel.LOW

                # Take action based on threat level
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    active_attacks += 1
                    max_threat_level = max(
                        max_threat_level, threat_level, key=lambda x: x.value
                    )

                    # Block IP if not already blocked
                    if not self.ip_block_manager.is_blocked(ip):
                        duration = self._calculate_block_duration(
                            threat_level, threat_score
                        )
                        reason = f"Threat score: {threat_score:.1f}, Attacks: {[a.value for a in detected_attacks]}"
                        self.ip_block_manager.block_ip(ip, duration, reason)

                        # Send alert
                        for attack_type in detected_attacks:
                            event = AttackEvent(
                                timestamp=current_time,
                                attack_type=attack_type,
                                threat_level=threat_level,
                                source_ip=ip,
                                description=f"Detected {attack_type.value} attack with threat score {threat_score:.1f}",
                                metrics={
                                    "threat_score": threat_score,
                                    "request_count": metrics.request_count,
                                },
                                action_taken=f"Blocked for {duration} seconds",
                            )
                            self.alert_manager.send_alert(event)

        # Check for Slowloris attacks
        slowloris_ips = self.traffic_analyzer.detect_slowloris(self.active_connections)
        for ip in slowloris_ips:
            if not self.ip_block_manager.is_blocked(
                ip
            ) and not self.ip_block_manager.is_whitelisted(ip):
                self.ip_block_manager.block_ip(ip, 3600, "Slowloris attack detected")
                event = AttackEvent(
                    timestamp=current_time,
                    attack_type=AttackType.SLOWLORIS,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=ip,
                    description="Slowloris attack detected",
                    metrics={
                        "connection_count": len(
                            [c for c in self.active_connections if c.startswith(ip)]
                        )
                    },
                    action_taken="Blocked for 1 hour",
                )
                self.alert_manager.send_alert(event)
                active_attacks += 1

        # Update global statistics
        self.stats.active_attacks = active_attacks
        self.stats.threat_level = max_threat_level
        if active_attacks > 0:
            self.stats.last_attack = current_time

    def _calculate_block_duration(
        self, threat_level: ThreatLevel, threat_score: float
    ) -> int:
        """Calculate block duration based on threat level and score."""
        base_duration = self.config.ip_block_duration_seconds

        if threat_level == ThreatLevel.CRITICAL:
            return int(base_duration * 4)  # 4 hours for critical
        elif threat_level == ThreatLevel.HIGH:
            return int(base_duration * 2)  # 2 hours for high
        elif threat_level == ThreatLevel.MEDIUM:
            return base_duration  # 1 hour for medium
        else:
            return int(base_duration * 0.5)  # 30 minutes for low

    def _cleanup_old_data(self):
        """Clean up old metrics data."""
        current_time = time.time()
        cleanup_age = 3600  # 1 hour

        with self._lock:
            # Clean up old IP metrics
            old_ips = [
                ip
                for ip, metrics in self.ip_metrics.items()
                if current_time - metrics.last_seen > cleanup_age
            ]
            for ip in old_ips:
                del self.ip_metrics[ip]

            # Clean up old connections
            old_connections = [
                conn_id
                for conn_id, start_time in self.active_connections.items()
                if current_time - start_time > cleanup_age
            ]
            for conn_id in old_connections:
                del self.active_connections[conn_id]

            if old_ips or old_connections:
                logger.debug(
                    f"Cleaned up {len(old_ips)} old IP metrics and {len(old_connections)} old connections"
                )

    def process_request(self, request: Request) -> bool:
        """Process incoming request and return True if allowed, False if blocked."""
        if not self.enabled:
            return True

        # Extract client IP
        client_ip = self._get_client_ip(request)
        if not client_ip:
            return True

        # Check if IP is blocked
        if self.ip_block_manager.is_blocked(client_ip):
            self.stats.blocked_requests += 1
            logger.debug(f"Blocked request from {client_ip}")
            return False

        # Update metrics
        self._update_ip_metrics(client_ip, request)
        self.stats.total_requests += 1

        return True

    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Extract client IP from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fallback to client host
        if hasattr(request, "client") and request.client:
            return request.client.host

        return None

    def _update_ip_metrics(self, ip: str, request: Request):
        """Update metrics for an IP address."""
        current_time = time.time()

        with self._lock:
            if ip not in self.ip_metrics:
                self.ip_metrics[ip] = IPMetrics(
                    ip=ip, first_seen=current_time, last_seen=current_time
                )

            metrics = self.ip_metrics[ip]
            metrics.last_seen = current_time
            metrics.request_count += 1
            metrics.request_intervals.append(current_time)

            # Update user agent
            user_agent = request.headers.get("User-Agent", "Unknown")
            metrics.user_agents.add(user_agent)

            # Update endpoint
            endpoint = f"{request.method} {request.url.path}"
            metrics.endpoints[endpoint] = metrics.endpoints.get(endpoint, 0) + 1

            # Estimate request size
            content_length = request.headers.get("Content-Length")
            if content_length:
                try:
                    metrics.bytes_received += int(content_length)
                except ValueError:
                    pass

    def update_response_metrics(
        self, ip: str, status_code: int, response_size: int = 0
    ):
        """Update response metrics for an IP."""
        if not self.enabled or not ip:
            return

        with self._lock:
            if ip in self.ip_metrics:
                metrics = self.ip_metrics[ip]
                metrics.status_codes[status_code] = (
                    metrics.status_codes.get(status_code, 0) + 1
                )
                metrics.bytes_sent += response_size

                if status_code >= 400:
                    metrics.error_count += 1

    def register_connection(self, connection_id: str):
        """Register a new connection."""
        if self.enabled:
            self.active_connections[connection_id] = time.time()

    def unregister_connection(self, connection_id: str):
        """Unregister a connection."""
        if self.enabled and connection_id in self.active_connections:
            del self.active_connections[connection_id]

    def get_user_tier_limit(self, user_tier: str) -> int:
        """Get rate limit for user tier."""
        return self.config.user_tiers.get(user_tier, self.config.base_request_limit)

    def get_protection_status(self) -> Dict[str, Any]:
        """Get current protection status and statistics."""
        if not self.enabled:
            return {"enabled": False}

        blocked_ips = self.ip_block_manager.get_blocked_ips()
        recent_alerts = self.alert_manager.get_recent_alerts(1)  # Last hour

        # Calculate threat distribution
        threat_distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for metrics in self.ip_metrics.values():
            if metrics.threat_score >= 80:
                threat_distribution["critical"] += 1
            elif metrics.threat_score >= 60:
                threat_distribution["high"] += 1
            elif metrics.threat_score >= 40:
                threat_distribution["medium"] += 1
            else:
                threat_distribution["low"] += 1

        return {
            "enabled": True,
            "stats": {
                "total_requests": self.stats.total_requests,
                "blocked_requests": self.stats.blocked_requests,
                "blocked_ips": len(blocked_ips),
                "active_attacks": self.stats.active_attacks,
                "threat_level": self.stats.threat_level.value,
                "last_attack": self.stats.last_attack,
                "block_rate": (
                    self.stats.blocked_requests / max(self.stats.total_requests, 1)
                )
                * 100,
            },
            "blocked_ips": blocked_ips,
            "recent_alerts": len(recent_alerts),
            "threat_distribution": threat_distribution,
            "active_connections": len(self.active_connections),
            "monitored_ips": len(self.ip_metrics),
            "config": {
                "base_request_limit": self.config.base_request_limit,
                "burst_limit": self.config.burst_limit,
                "ip_block_threshold": self.config.ip_block_threshold,
                "user_tiers": self.config.user_tiers,
            },
        }


class DDoSProtectionMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for DDoS protection."""

    def __init__(self, app, ddos_system: Optional[DDoSProtectionSystem] = None):
        super().__init__(app)
        self.ddos_system = ddos_system or DDoSProtectionSystem()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method."""
        if not self.ddos_system.enabled:
            return await call_next(request)

        # Check if request is allowed
        if not self.ddos_system.process_request(request):
            raise HTTPException(
                status_code=429,
                detail="Too Many Requests - IP temporarily blocked due to suspicious activity",
            )

        # Generate connection ID and register
        client_ip = self.ddos_system._get_client_ip(request)
        connection_id = f"{client_ip}:{time.time()}"
        self.ddos_system.register_connection(connection_id)

        try:
            # Process request
            response = await call_next(request)

            # Update response metrics
            response_size = 0
            if hasattr(response, "headers") and "content-length" in response.headers:
                try:
                    response_size = int(response.headers["content-length"])
                except ValueError:
                    pass

            self.ddos_system.update_response_metrics(
                client_ip, response.status_code, response_size
            )

            # Add protection headers
            self._add_protection_headers(response)

            return response

        finally:
            # Unregister connection
            self.ddos_system.unregister_connection(connection_id)

    def _add_protection_headers(self, response: Response):
        """Add DDoS protection headers to response."""
        try:
            response.headers["X-DDoS-Protection"] = "active"
            response.headers["X-Threat-Level"] = (
                self.ddos_system.stats.threat_level.value
            )
            if self.ddos_system.stats.active_attacks > 0:
                response.headers["X-Active-Attacks"] = str(
                    self.ddos_system.stats.active_attacks
                )
        except Exception as e:
            logger.error(f"Error adding protection headers: {e}")


# Global DDoS protection instance
_ddos_protection: Optional[DDoSProtectionSystem] = None


def get_ddos_protection() -> DDoSProtectionSystem:
    """Get the global DDoS protection instance."""
    global _ddos_protection
    if _ddos_protection is None:
        _ddos_protection = DDoSProtectionSystem()
    return _ddos_protection


def add_ddos_protection_middleware(
    app, dynamic_rate_limiter: Optional[DynamicRateLimitingMiddleware] = None
):
    """Add DDoS protection middleware to FastAPI app."""
    ddos_system = DDoSProtectionSystem(dynamic_rate_limiter)
    app.add_middleware(DDoSProtectionMiddleware, ddos_system=ddos_system)
    logger.info("DDoS protection middleware added to FastAPI app")
    return ddos_system
