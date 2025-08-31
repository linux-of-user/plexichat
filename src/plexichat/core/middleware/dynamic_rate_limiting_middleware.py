#!/usr/bin/env python3
"""
Dynamic Rate Limiting Middleware
Automatically adjusts rate limits based on system load, performance metrics, and traffic patterns

Enhancements:
- SystemMetricsProvider singleton to share CPU/memory metrics between systems
- Adaptive rate limiting based on load
- User tier support (basic, premium, admin)
- Integration with SecuritySystem token verification for tier detection
- DDoS detection and progressive penalties (temporary blocks, CAPTCHA challenge)
- Metrics and logging for rate limiting decisions
- Basic support for WebSocket connection rate checks
"""

import asyncio
import time
import psutil
import logging
import threading
import secrets
from typing import Dict, Optional, Any, Callable, List, Deque, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.websockets import WebSocket

# Import configuration (best-effort)
try:
    from plexichat.core.rate_limit_config import get_rate_limiting_config, DynamicRateLimitConfig
except Exception:
    # Provide a minimal fallback config provider to allow middleware to operate in degraded mode
    class Dyn:
        enabled = True
        monitoring_interval = 10
        adjustment_interval = 5
        cpu_threshold_low = 0.10
        memory_threshold_low = 0.10
        low_load_multiplier = 1.5
        cpu_threshold_medium = 0.50
        memory_threshold_medium = 0.50
        medium_load_multiplier = 1.0
        cpu_threshold_high = 0.75
        memory_threshold_high = 0.75
        high_load_multiplier = 0.6
        critical_load_multiplier = 0.3
        request_window_seconds = 60
        ddos_detection_rps = 20  # requests per second considered suspicious per IP
        ddos_detection_rps_burst = 50  # burst threshold
        ddos_penalty_durations = [30, 300, 3600]  # progressive temp blocks in seconds
        tier_limits = {
            "basic": 60,    # requests per minute
            "premium": 300, # requests per minute
            "admin": 0      # 0 means unlimited
        }
        captcha_after_penalties = 2  # require captcha after X penalties

    class Cfg:
        dynamic_config = Dyn()

    def get_rate_limiting_config():
        return Cfg()

logger = logging.getLogger(__name__)
logging.getLogger("asyncio").setLevel(logging.WARNING)

@dataclass
class SystemMetrics:
    """System performance metrics."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_io_read: float
    disk_io_write: float
    network_io_sent: float
    network_io_recv: float
    active_connections: int
    response_time_avg: float
    error_rate: float

@dataclass
class TrafficMetrics:
    """Traffic and request metrics."""
    timestamp: float
    requests_per_second: float
    concurrent_requests: int
    queue_length: int
    bandwidth_usage: float
    endpoint_distribution: Dict[str, int] = field(default_factory=dict)
    status_code_distribution: Dict[int, int] = field(default_factory=dict)

@dataclass
class LoadLevel:
    """System load level definition."""
    name: str
    cpu_threshold: float
    memory_threshold: float
    response_time_threshold: float
    error_rate_threshold: float
    rate_limit_multiplier: float
    description: str

# SystemMetricsProvider singleton (thread-safe)
class SystemMetricsProvider:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._metrics_lock = threading.Lock()
        self._latest_metrics: Optional[SystemMetrics] = None
        # simple subscriber list for components that want updates
        self._subscribers: List[Callable[[SystemMetrics], None]] = []

    @classmethod
    def get_instance(cls) -> "SystemMetricsProvider":
        with cls._lock:
            if cls._instance is None:
                cls._instance = SystemMetricsProvider()
            return cls._instance

    def update_metrics(self, metrics: SystemMetrics) -> None:
        with self._metrics_lock:
            self._latest_metrics = metrics
            # notify subscribers in a best-effort non-blocking manner
            for sub in list(self._subscribers):
                try:
                    sub(metrics)
                except Exception:
                    logger.debug("Subscriber callback raised in SystemMetricsProvider", exc_info=True)

    def get_metrics(self) -> Optional[SystemMetrics]:
        with self._metrics_lock:
            return self._latest_metrics

    def subscribe(self, callback: Callable[[SystemMetrics], None]) -> None:
        with self._metrics_lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[SystemMetrics], None]) -> None:
        with self._metrics_lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)


# Attempt to get SecuritySystem for token verification and tier detection
try:
    from plexichat.core.security.security_manager import get_security_system
except Exception:
    # Provide a fallback stub with minimal behavior
    class Stub:
        def __init__(self):
            self.token_manager = None
            self.user_credentials = {}

        def token_verify(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
            return False, None

    def get_security_system():
        return Stub()

class DynamicRateLimitingMiddleware(BaseHTTPMiddleware):
    """Dynamic rate limiting middleware that adapts to system load and user tiers."""

    def __init__(self, app):
        super().__init__(app)

        # Configuration
        cfg = get_rate_limiting_config()
        self.config = cfg.dynamic_config if getattr(cfg, "dynamic_config", None) else cfg
        # If config indicates disabled, disable middleware
        self.enabled = getattr(self.config, "enabled", True)

        if not self.enabled:
            logger.info("Dynamic rate limiting middleware is disabled by configuration")
            return

        # Metrics storage
        self.system_metrics: Deque[SystemMetrics] = deque(maxlen=200)
        self.traffic_metrics: Deque[TrafficMetrics] = deque(maxlen=200)
        self.request_times: Deque[float] = deque(maxlen=10000)  # store timestamps
        self.error_counts: Deque[float] = deque(maxlen=10000)

        # Request tracking per IP and per user
        self.requests_by_ip: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=10000))
        self.requests_by_user: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=10000))

        # Penalty and block lists
        # blocked_ips: ip -> blocked_until timestamp
        self.blocked_ips: Dict[str, float] = {}
        # penalty_counts: ip -> number of penalties applied (for progressive escalation)
        self.penalty_counts: Dict[str, int] = defaultdict(int)
        # captcha_required: ip -> True/False
        self.captcha_required: Dict[str, bool] = {}

        # Stats
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "rate_limited": 0,
            "captcha_challenges": 0,
            "ddos_events": 0,
            "penalties_applied": 0
        }

        # Load level state
        self.current_load_level = "normal"
        self.current_multiplier = 1.0
        self.last_adjustment = time.time()
        self.concurrent_requests = 0
        self.request_queue_length = 0

        # Setup load levels
        self.load_levels = self._define_load_levels()

        # System metrics provider
        self.metrics_provider = SystemMetricsProvider.get_instance()

        # Security system for token verification
        try:
            self.security_system = get_security_system()
        except Exception:
            self.security_system = None

        # Start background tasks (monitoring & adjusting)
        self._monitoring_task: Optional[asyncio.Task] = None
        self._adjustment_task: Optional[asyncio.Task] = None
        self._start_monitoring()

        logger.info("Dynamic rate limiting middleware initialized")

    def _define_load_levels(self) -> Dict[str, LoadLevel]:
        """Define system load levels and their characteristics using config with fallbacks."""
        return {
            "low": LoadLevel(
                name="low",
                cpu_threshold=getattr(self.config, "cpu_threshold_low", 0.10),
                memory_threshold=getattr(self.config, "memory_threshold_low", 0.10),
                response_time_threshold=50.0,
                error_rate_threshold=0.01,
                rate_limit_multiplier=getattr(self.config, "low_load_multiplier", 1.5),
                description="Low system load - increased rate limits"
            ),
            "normal": LoadLevel(
                name="normal",
                cpu_threshold=getattr(self.config, "cpu_threshold_medium", 0.5),
                memory_threshold=getattr(self.config, "memory_threshold_medium", 0.5),
                response_time_threshold=200.0,
                error_rate_threshold=0.05,
                rate_limit_multiplier=getattr(self.config, "medium_load_multiplier", 1.0),
                description="Normal system load - standard rate limits"
            ),
            "high": LoadLevel(
                name="high",
                cpu_threshold=getattr(self.config, "cpu_threshold_high", 0.75),
                memory_threshold=getattr(self.config, "memory_threshold_high", 0.75),
                response_time_threshold=500.0,
                error_rate_threshold=0.10,
                rate_limit_multiplier=getattr(self.config, "high_load_multiplier", 0.6),
                description="High system load - reduced rate limits"
            ),
            "critical": LoadLevel(
                name="critical",
                cpu_threshold=1.0,
                memory_threshold=1.0,
                response_time_threshold=1000.0,
                error_rate_threshold=0.20,
                rate_limit_multiplier=getattr(self.config, "critical_load_multiplier", 0.3),
                description="Critical system load - severely reduced rate limits"
            )
        }

    def _start_monitoring(self):
        """Start background monitoring tasks for metrics collection and limit adjustment."""
        if not self.enabled:
            return

        async def monitor_system():
            while True:
                try:
                    await asyncio.sleep(getattr(self.config, "monitoring_interval", 10))
                    await self._collect_system_metrics()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in system monitoring loop", exc_info=True)
                    # continue and try again

        async def adjust_limits():
            while True:
                try:
                    await asyncio.sleep(getattr(self.config, "adjustment_interval", 5))
                    await self._adjust_rate_limits()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in rate limit adjustment loop", exc_info=True)

        loop = None
        try:
            loop = asyncio.get_event_loop()
        except Exception:
            pass

        if loop and loop.is_running():
            if not self._monitoring_task or self._monitoring_task.done():
                self._monitoring_task = asyncio.create_task(monitor_system())
            if not self._adjustment_task or self._adjustment_task.done():
                self._adjustment_task = asyncio.create_task(adjust_limits())
        else:
            # If event loop not running at construction time, schedule tasks lazily on first request
            logger.debug("Event loop is not running yet; monitoring tasks will start on first request")

    async def _collect_system_metrics(self):
        """Collect system metrics and publish them to the provider."""
        try:
            # CPU and memory (non-blocking call with short interval)
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # Disk and network (counters)
            disk_io = psutil.disk_io_counters()
            disk_read = disk_io.read_bytes if disk_io else 0
            disk_write = disk_io.write_bytes if disk_io else 0

            network_io = psutil.net_io_counters()
            network_sent = network_io.bytes_sent if network_io else 0
            network_recv = network_io.bytes_recv if network_io else 0

            try:
                connections = len(psutil.net_connections())
            except Exception:
                connections = 0

            response_time_avg = self._calculate_avg_response_time()
            error_rate = self._calculate_error_rate()

            metrics = SystemMetrics(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_io_read=disk_read,
                disk_io_write=disk_write,
                network_io_sent=network_sent,
                network_io_recv=network_recv,
                active_connections=connections,
                response_time_avg=response_time_avg,
                error_rate=error_rate
            )

            self.system_metrics.append(metrics)
            # Update provider for other systems (e.g., cluster manager)
            try:
                self.metrics_provider.update_metrics(metrics)
            except Exception:
                logger.debug("Failed to update SystemMetricsProvider", exc_info=True)

            # Collect traffic metrics snapshot
            await self._collect_traffic_metrics()

        except Exception as e:
            logger.error("Error collecting system metrics", exc_info=True)

    async def _collect_traffic_metrics(self):
        """Collect traffic-related metrics derived from request timestamps."""
        try:
            current_time = time.time()
            window = getattr(self.config, "request_window_seconds", 60)
            cutoff = current_time - window
            recent_requests = [t for t in self.request_times if t > cutoff]
            rps = len(recent_requests) / max(1.0, window)
            bandwidth = self._estimate_bandwidth_usage()
            traffic = TrafficMetrics(
                timestamp=current_time,
                requests_per_second=rps,
                concurrent_requests=self.concurrent_requests,
                queue_length=self.request_queue_length,
                bandwidth_usage=bandwidth
            )
            self.traffic_metrics.append(traffic)
        except Exception as e:
            logger.error("Error collecting traffic metrics", exc_info=True)

    async def _adjust_rate_limits(self):
        """Adjust rate limits based on system metrics and traffic patterns."""
        try:
            if not self.system_metrics:
                return
            latest = self.system_metrics[-1]
            new_level = self._determine_load_level(latest)
            if new_level != self.current_load_level:
                old = self.current_load_level
                self.current_load_level = new_level
                self.current_multiplier = self.load_levels[new_level].rate_limit_multiplier
                self.last_adjustment = time.time()
                logger.info("Load level changed: %s -> %s (multiplier: %.2f)",
                            old, new_level, self.current_multiplier)
                logger.info("Metrics: CPU=%.1f%% Memory=%.1f%% Resp=%.1fms Err=%.2f%%",
                            latest.cpu_percent, latest.memory_percent,
                            latest.response_time_avg, latest.error_rate * 100.0)
        except Exception:
            logger.exception("Error while adjusting rate limits")

    def _determine_load_level(self, metrics: SystemMetrics) -> str:
        """Decide current load level based on thresholds."""
        try:
            # Use percent vs threshold (thresholds expressed as 0-1 in config)
            if (metrics.cpu_percent / 100.0 > self.load_levels["high"].cpu_threshold or
                metrics.memory_percent / 100.0 > self.load_levels["high"].memory_threshold or
                metrics.response_time_avg > self.load_levels["critical"].response_time_threshold or
                metrics.error_rate > self.load_levels["critical"].error_rate_threshold):
                return "critical"

            if (metrics.cpu_percent / 100.0 > self.load_levels["normal"].cpu_threshold or
                metrics.memory_percent / 100.0 > self.load_levels["normal"].memory_threshold or
                metrics.response_time_avg > self.load_levels["high"].response_time_threshold or
                metrics.error_rate > self.load_levels["high"].error_rate_threshold):
                return "high"

            if (metrics.cpu_percent / 100.0 < self.load_levels["low"].cpu_threshold and
                metrics.memory_percent / 100.0 < self.load_levels["low"].memory_threshold and
                metrics.response_time_avg < self.load_levels["low"].response_time_threshold and
                metrics.error_rate < self.load_levels["low"].error_rate_threshold):
                return "low"

            return "normal"
        except Exception:
            logger.exception("Error determining load level")
            return "normal"

    def _calculate_avg_response_time(self) -> float:
        """Estimate average response time using recent request count (simplified)."""
        try:
            if not self.request_times:
                return 0.0
            recent_count = len([t for t in self.request_times if t > time.time() - 60])
            if recent_count > 200:
                return min(recent_count * 2.0, 2000.0)
            return max(10.0, recent_count * 0.5)
        except Exception:
            return 0.0

    def _calculate_error_rate(self) -> float:
        """Estimate error rate over recent window."""
        try:
            now = time.time()
            cutoff = now - 60
            recent_errors = len([t for t in self.error_counts if t > cutoff])
            recent_requests = len([t for t in self.request_times if t > cutoff])
            if recent_requests == 0:
                return 0.0
            return float(recent_errors) / float(recent_requests)
        except Exception:
            return 0.0

    def _estimate_bandwidth_usage(self) -> float:
        """Estimate bandwidth usage (bytes/sec) as heuristic."""
        try:
            recent = len([t for t in self.request_times if t > time.time() - 1])
            return recent * 1024.0
        except Exception:
            return 0.0

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method integrating adaptive rate limiting and DDoS protection."""
        # Ensure monitoring tasks are created if not already
        if self._monitoring_task is None or (self._monitoring_task and self._monitoring_task.done()):
            # Try to start monitoring tasks now that we are in an event loop
            try:
                self._start_monitoring()
            except Exception:
                pass

        if not self.enabled:
            return await call_next(request)

        start_time = time.time()
        self.stats["total_requests"] += 1
        self.concurrent_requests += 1
        client_ip = self._get_client_ip(request)
        user_id = await self._get_user_id_from_request(request)

        # Global identifier preference: user_id else ip
        identifier = user_id if user_id else client_ip

        # Check for blocked IP early
        if self._is_blocked(client_ip, identifier):
            self.stats["blocked_requests"] += 1
            retry_after = int(max(0, self.blocked_ips.get(client_ip, 0) - time.time()))
            return self._rate_limited_response("temporarily_blocked", retry_after=retry_after)

        # Enforce CAPTCHA if required and not provided
        if self.captcha_required.get(client_ip) and not self._validate_captcha_in_request(request):
            self.stats["captcha_challenges"] += 1
            # Generate a lightweight challenge token for the client to solve (placeholder)
            captcha_token = self._generate_captcha_token(client_ip)
            return self._rate_limited_response("captcha_required", retry_after=60, extra={"captcha_token": captcha_token})

        # Record request timestamp for identifier buckets
        self._record_request(identifier, start_time, client_ip=client_ip, user_id=user_id)

        # Determine allowed rate based on tier and system multiplier
        allowed, retry_after, action = await self._check_rate_limit(identifier, client_ip, user_id)
        if not allowed:
            self.stats["rate_limited"] += 1
            # Apply progressive penalty for offending IP
            self._apply_progressive_penalty(client_ip)
            return self._rate_limited_response(action or "rate_limited", retry_after=retry_after)

        # Proceed to next handler and measure response
        try:
            response = await call_next(request)
            end_time = time.time()

            # Log timing and status
            self.request_times.append(end_time)
            if response.status_code >= 400:
                self.error_counts.append(end_time)

            # Add dynamic headers to responses
            self._add_dynamic_headers(response)

            return response
        except Exception:
            # Count as error
            self.error_counts.append(time.time())
            raise
        finally:
            self.concurrent_requests = max(0, self.concurrent_requests - 1)

    # Public helper for WebSocket connection checks (call from WebSocket endpoint)
    async def check_websocket_connect(self, websocket: WebSocket) -> Tuple[bool, Optional[str]]:
        """
        Check whether a WebSocket connection should be allowed.
        Returns (allowed: bool, reason: Optional[str]).
        """
        try:
            scope = websocket.scope
            client = scope.get("client")
            client_ip = client[0] if client else "unknown"
            # Use IP-based checks for WebSocket connections
            if self._is_blocked(client_ip, client_ip):
                return False, "temporarily_blocked"
            # Record ws connect as request to avoid flooding
            now = time.time()
            self._record_request(client_ip, now, client_ip=client_ip, user_id=None)
            allowed, retry_after, action = await self._check_rate_limit(client_ip, client_ip, None)
            if not allowed:
                self._apply_progressive_penalty(client_ip)
                return False, action or "rate_limited"
            return True, None
        except Exception:
            logger.exception("Error checking websocket connect")
            return True, None

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers or connection info."""
        try:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
            real_ip = request.headers.get("x-real-ip")
            if real_ip:
                return real_ip
            if getattr(request, "client", None):
                client = request.client
                if client:
                    return client.host
        except Exception:
            logger.debug("Error extracting client IP", exc_info=True)
        return "unknown"

    async def _get_user_id_from_request(self, request: Request) -> Optional[str]:
        """
        Try to extract and verify an authorization token to derive user identity and tier.
        Uses SecuritySystem token manager if available.
        """
        try:
            header = request.headers.get("authorization", "")
            token = None
            if header and header.lower().startswith("bearer "):
                token = header[7:].strip()
            else:
                # Support query param or cookie token as fallback
                token = request.query_params.get("token") or request.cookies.get("access_token")

            if not token:
                return None

            # Attempt to use security system's token manager
            if hasattr(self.security_system, "token_manager") and self.security_system.token_manager:
                try:
                    verify = self.security_system.token_manager.verify_token(token)
                    # verify_token can return (bool, payload) or raise; handle both
                    if isinstance(verify, tuple) and len(verify) == 2:
                        ok, payload = verify
                        if ok and payload:
                            # tokens typically include 'user_id' or 'sub'
                            uid = payload.get("user_id") or payload.get("sub")
                            return uid
                    elif isinstance(verify, dict):
                        # Unexpected but try to get user_id
                        uid = verify.get("user_id") or verify.get("sub")
                        return uid
                except Exception:
                    logger.debug("SecuritySystem token verification failed", exc_info=True)
                    return None
            else:
                # No token manager available: best-effort parse JWT payload (unsafe, for tier detection only)
                try:
                    # Avoid importing jwt library; just do a naive parse for the user id in payload if token is JWT
                    parts = token.split(".")
                    if len(parts) >= 2:
                        import base64, json
                        padded = parts[1] + "=" * (-len(parts[1]) % 4)
                        payload_bytes = base64.urlsafe_b64decode(padded.encode("utf-8"))
                        payload = json.loads(payload_bytes.decode("utf-8"))
                        uid = payload.get("user_id") or payload.get("sub")
                        return uid
                except Exception:
                    return None
            return None
        except Exception:
            logger.exception("Error extracting user id from request")
            return None

    def _record_request(self, identifier: str, timestamp: float, client_ip: str, user_id: Optional[str] = None) -> None:
        """Record a request timestamp for identifier and IP/user buckets used for rate calculations."""
        try:
            self.request_times.append(timestamp)
            if user_id:
                self.requests_by_user[user_id].append(timestamp)
            else:
                # record by IP as fallback
                self.requests_by_ip[client_ip].append(timestamp)
            # Also keep per-ip bucket to detect bursts
            self.requests_by_ip[client_ip].append(timestamp)
        except Exception:
            logger.debug("Failed to record request timestamp", exc_info=True)

    async def _check_rate_limit(self, identifier: str, client_ip: str, user_id: Optional[str]) -> Tuple[bool, int, Optional[str]]:
        """
        Check whether the identifier is within allowed rate limits.
        Returns (allowed: bool, retry_after_seconds: int, action: Optional[str])
        """
        try:
            # Determine tier
            tier = await self._get_user_tier(user_id, client_ip)
            # Base limit in requests per minute
            tier_limits = getattr(self.config, "tier_limits", {"basic": 60, "premium": 300, "admin": 0})
            base_rpm = tier_limits.get(tier, tier_limits.get("basic", 60))
            # If admin unlimited
            if base_rpm == 0:
                return True, 0, None

            # Adjust by system multiplier (lower multiplier reduces allowed rate)
            multiplier = self.get_current_multiplier()
            effective_rpm = max(1, int(base_rpm * multiplier))
            window_seconds = int(getattr(self.config, "request_window_seconds", 60))
            cutoff = time.time() - window_seconds

            # Count requests in window for identifier
            bucket = self.requests_by_user[identifier] if user_id and identifier in self.requests_by_user else self.requests_by_ip.get(client_ip, deque())
            recent_count = len([t for t in bucket if t > cutoff])

            # Convert rpm to allowed in window
            allowed_in_window = int(effective_rpm * (window_seconds / 60.0))

            # DDoS detection: check per-IP requests per second bursts
            rps = self._calculate_rps(client_ip)
            ddos_threshold = getattr(self.config, "ddos_detection_rps", 20)
            ddos_burst = getattr(self.config, "ddos_detection_rps_burst", 50)
            if rps >= ddos_burst:
                # Immediate block
                logger.warning("DDoS burst detected from %s: rps=%s", client_ip, rps)
                self.stats["ddos_events"] += 1
                # apply an immediate severe penalty
                self._apply_immediate_block(client_ip, seconds=getattr(self.config, "ddos_block_seconds", 300))
                return False, int(getattr(self.config, "ddos_block_seconds", 300)), "ddos_block"

            if rps >= ddos_threshold:
                # Mark as suspicious and throttle aggressively
                logger.info("High request rate from %s: rps=%.1f, threshold=%.1f", client_ip, rps, ddos_threshold)
                self.stats["ddos_events"] += 1
                # escalate penalty count but still return rate_limited
                return False, 30, "ddos_rate_limited"

            # Normal rate enforcement
            if recent_count >= allowed_in_window:
                # Exceeded
                retry_after = int(window_seconds)
                logger.debug("Rate limit exceeded for %s (tier=%s): %d requests in window (allowed %d)",
                             identifier, tier, recent_count, allowed_in_window)
                return False, retry_after, "rate_limited"

            return True, 0, None
        except Exception:
            logger.exception("Error checking rate limit")
            # Fail open for resilience in edge cases
            return True, 0, None

    def _calculate_rps(self, client_ip: str) -> float:
        """Calculate approximate requests per second for the given IP over last short window."""
        try:
            now = time.time()
            short_window = 5.0
            bucket = self.requests_by_ip.get(client_ip, deque())
            recent = len([t for t in bucket if t > now - short_window])
            return float(recent) / max(1.0, short_window)
        except Exception:
            return 0.0

    async def _get_user_tier(self, user_id: Optional[str], client_ip: str) -> str:
        """Determine user tier based on security system or fallback heuristics."""
        try:
            if user_id:
                # If security system provides user metadata or permissions, prefer that (best-effort)
                try:
                    # If SecuritySystem provides a user lookup, use it
                    if hasattr(self.security_system, "user_credentials") and isinstance(self.security_system.user_credentials, dict):
                        creds = self.security_system.user_credentials.get(user_id)
                        if creds and hasattr(creds, "permissions"):
                            # Example: 'premium' permission
                            if "admin" in creds.permissions:
                                return "admin"
                            if "premium" in creds.permissions:
                                return "premium"
                            return "basic"
                except Exception:
                    pass
                # Attempt to inspect token payload for 'tier' claim
                try:
                    # This is best-effort and harmless if fails
                    header = None
                    # Not performing expensive operations here; calling _get_user_id_from_request would have parsed token earlier
                    # Default to basic if no stronger evidence
                    return "basic"
                except Exception:
                    return "basic"
            # Fallback: treat unknown users by IP as 'basic'
            return "basic"
        except Exception:
            return "basic"

    def _apply_immediate_block(self, client_ip: str, seconds: int = 300) -> None:
        """Apply an immediate temporary block to an IP address."""
        try:
            until = time.time() + seconds
            self.blocked_ips[client_ip] = until
            self.penalty_counts[client_ip] += 1
            self.stats["penalties_applied"] += 1
            logger.warning("Applied immediate block to %s for %d seconds", client_ip, seconds)
        except Exception:
            logger.exception("Failed to apply immediate block")

    def _apply_progressive_penalty(self, client_ip: str) -> None:
        """Apply progressive penalties escalating with repeated offenses."""
        try:
            # Increase penalty count
            self.penalty_counts[client_ip] += 1
            penalties = self.penalty_counts[client_ip]
            durations = getattr(self.config, "ddos_penalty_durations", [30, 300, 3600])
            # Select penalty duration based on number of penalties
            idx = min(len(durations) - 1, penalties - 1)
            duration = durations[idx] if durations else 60
            # If penalties exceed threshold for captcha requirement, set captcha
            captcha_threshold = getattr(self.config, "captcha_after_penalties", 2)
            if penalties >= captcha_threshold:
                self.captcha_required[client_ip] = True
                logger.info("CAPTCHA now required for %s after %d penalties", client_ip, penalties)
            # Apply temporary block
            until = time.time() + duration
            self.blocked_ips[client_ip] = until
            self.stats["penalties_applied"] += 1
            logger.info("Applied progressive penalty to %s: duration=%ds, penalties=%d", client_ip, duration, penalties)
        except Exception:
            logger.exception("Failed to apply progressive penalty")

    def _is_blocked(self, client_ip: str, identifier: str) -> bool:
        """Return True if the IP or identifier is currently blocked."""
        try:
            now = time.time()
            blocked_until = self.blocked_ips.get(client_ip)
            if blocked_until and blocked_until > now:
                return True
            # Clean up expired entries
            if blocked_until and blocked_until <= now:
                self.blocked_ips.pop(client_ip, None)
            return False
        except Exception:
            return False

    def _generate_captcha_token(self, client_ip: str) -> str:
        """Generate a placeholder CAPTCHA token (to be replaced by real CAPTCHA integration)."""
        token = secrets.token_urlsafe(24)
        # store ephemeral token mapping (in-memory); in production persist to store
        # For simplicity, reuse blocked_ips dict to store a short-lived mapping with expiry encoded in token mapping elsewhere if needed
        # Here just return token; validation will accept any token that matches this pattern for demonstration
        return token

    def _validate_captcha_in_request(self, request: Request) -> bool:
        """
        Validate provided captcha token. This is a placeholder implementation.
        In production, integrate with a CAPTCHA provider and verify tokens server-side.
        """
        try:
            # Accept token in header 'x-captcha-token' or query param 'captcha_token'
            token = request.headers.get("x-captcha-token") or request.query_params.get("captcha_token")
            if not token:
                return False
            # For placeholder, accept any non-empty token (real impl should verify)
            return True
        except Exception:
            return False

    def _rate_limited_response(self, action: str, retry_after: int = 60, extra: Optional[Dict[str, Any]] = None) -> Response:
        """Construct a JSON response representing a rate-limited outcome."""
        from starlette.responses import JSONResponse
        body = {
            "success": False,
            "reason": action,
            "retry_after": retry_after
        }
        if extra:
            body.update(extra)
        headers = {
            "Retry-After": str(retry_after),
            "X-RateLimit-Action": action
        }
        return JSONResponse(body, status_code=429, headers=headers)

    def _add_dynamic_headers(self, response: Response):
        """Add dynamic headers to the response to inform clients about limits and load."""
        try:
            response.headers["X-Dynamic-Rate-Limit-Level"] = self.current_load_level
            response.headers["X-Dynamic-Rate-Limit-Multiplier"] = f"{self.current_multiplier:.2f}"
            response.headers["X-Dynamic-Rate-Limit-Adjusted"] = str(int(self.last_adjustment))
            latest = self.system_metrics[-1] if self.system_metrics else None
            if latest:
                response.headers["X-System-Load-CPU"] = f"{latest.cpu_percent:.1f}"
                response.headers["X-System-Load-Memory"] = f"{latest.memory_percent:.1f}"
        except Exception:
            logger.debug("Failed to add dynamic headers", exc_info=True)

    def get_current_multiplier(self) -> float:
        """Get current rate limit multiplier (lower than 1 reduces allowed rate)."""
        return self.current_multiplier if self.enabled else 1.0

    def get_load_status(self) -> Dict[str, Any]:
        """Return diagnostic information about load and current metrics."""
        latest_system = self.system_metrics[-1] if self.system_metrics else None
        latest_traffic = self.traffic_metrics[-1] if self.traffic_metrics else None
        return {
            "enabled": self.enabled,
            "current_load_level": self.current_load_level,
            "current_multiplier": self.current_multiplier,
            "last_adjustment": self.last_adjustment,
            "system_metrics": {
                "cpu_percent": latest_system.cpu_percent if latest_system else 0,
                "memory_percent": latest_system.memory_percent if latest_system else 0,
                "response_time_avg": latest_system.response_time_avg if latest_system else 0,
                "error_rate": latest_system.error_rate if latest_system else 0,
            } if latest_system else {},
            "traffic_metrics": {
                "requests_per_second": latest_traffic.requests_per_second if latest_traffic else 0,
                "concurrent_requests": self.concurrent_requests,
                "bandwidth_usage": latest_traffic.bandwidth_usage if latest_traffic else 0,
            } if latest_traffic else {},
            "stats": self.stats
        }

# Utility function to add middleware to FastAPI app
def add_dynamic_rate_limiting_middleware(app):
    """Add dynamic rate limiting middleware to FastAPI app."""
    app.add_middleware(DynamicRateLimitingMiddleware)
    logger.info("Dynamic rate limiting middleware added to FastAPI app")
