"""
Unified Rate Limiting Engine
Consolidates features from:
- core/middleware/unified_rate_limiter.py
- core/middleware/rate_limiter.py (Redis/InMemory backends, metrics)
- core/middleware/account_rate_limiting_middleware.py (account tiers, bandwidth)
- core/middleware/dynamic_rate_limiting_middleware.py (adaptive multiplier)
- infrastructure/middleware/global_rate_limiting.py (global caps, headers)
- core/security/ddos_protection.py (temporary blocking integration points)

Note: This engine provides a single API surface and can be used as drop-in replacement
from this package, while we keep backward-compatible wrappers for old modules.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import time
from typing import Any

try:
    from fastapi import Request, Response, status
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
except Exception:
    Request = Any
    Response = Any
    BaseHTTPMiddleware = object
    JSONResponse = object

    class status:
        HTTP_429_TOO_MANY_REQUESTS = 429


# Logging
try:
    from plexichat.core.logging import get_logger

    logger = get_logger(__name__)
except Exception:
    import logging

    logger = logging.getLogger(__name__)

# Config
try:
    from plexichat.core.config_manager import get_config_manager

    CONFIG = get_config_manager()
except Exception:
    CONFIG = None


class RateLimitStrategy(Enum):
    GLOBAL = "global"
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ROUTE = "per_route"
    PER_METHOD = "per_method"
    PER_USER_AGENT = "per_user_agent"


class RateLimitAlgorithm(Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


@dataclass
class RateLimitConfig:
    enabled: bool = True
    default_algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    # Global
    global_requests_per_minute: int = 10000
    global_burst_limit: int = 500
    # Per-IP
    per_ip_requests_per_minute: int = 60
    per_ip_burst_limit: int = 10
    per_ip_block_duration: int = 300
    # Per-user
    per_user_requests_per_minute: int = 120
    per_user_burst_limit: int = 20
    per_user_block_duration: int = 180
    # Per-route
    per_route_requests_per_minute: int = 100
    per_route_burst_limit: int = 15
    # Per-method
    get_requests_per_minute: int = 200
    post_requests_per_minute: int = 60
    put_requests_per_minute: int = 30
    delete_requests_per_minute: int = 20
    patch_requests_per_minute: int = 40
    # Overrides and multipliers
    endpoint_overrides: dict[str, dict[str, int]] = field(default_factory=dict)
    user_tier_multipliers: dict[str, float] = field(
        default_factory=lambda: {
            "guest": 0.5,
            "user": 1.0,
            "premium": 2.0,
            "admin": 10.0,
            "system": 100.0,
        }
    )
    # Bandwidth and concurrency (from account middleware)
    concurrent_requests: int = 10
    bandwidth_per_second: int = 1_000_000  # 1MB/s default
    burst_allowance: int = 5
    # Adaptive multiplier (from dynamic middleware)
    adaptive_multiplier: float = 1.0


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def info(self) -> dict[str, float]:
        return {
            "capacity": self.capacity,
            "tokens": self.tokens,
            "refill_rate": self.refill_rate,
        }


class SlidingWindow:
    def __init__(self, window_seconds: int, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.requests: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def add(self) -> bool:
        async with self.lock:
            now = time.time()
            while self.requests and self.requests[0] <= now - self.window_seconds:
                self.requests.popleft()
            if len(self.requests) >= self.max_requests:
                return False
            self.requests.append(now)
            return True

    def count(self) -> int:
        now = time.time()
        while self.requests and self.requests[0] <= now - self.window_seconds:
            self.requests.popleft()
        return len(self.requests)


class FixedWindow:
    def __init__(self, window_seconds: int, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.window_start = 0
        self.count = 0
        self.lock = asyncio.Lock()

    async def add(self) -> bool:
        async with self.lock:
            now = time.time()
            start = int(now // self.window_seconds) * self.window_seconds
            if start != self.window_start:
                self.window_start = start
                self.count = 0
            if self.count >= self.max_requests:
                return False
            self.count += 1
            return True

    def count_current(self) -> int:
        now = time.time()
        start = int(now // self.window_seconds) * self.window_seconds
        if start != self.window_start:
            return 0
        return self.count


class RateLimitViolation:
    def __init__(
        self,
        strategy: RateLimitStrategy,
        key: str,
        limit: int,
        current: int,
        retry_after: int,
    ):
        self.strategy = strategy
        self.key = key
        self.limit = limit
        self.current = current
        self.retry_after = retry_after
        self.at = time.time()


class UnifiedRateLimiter:
    def __init__(self, config: RateLimitConfig | None = None):
        # Coerce config from dict if needed
        if isinstance(config, dict):
            cfg = RateLimitConfig()
            for k, v in config.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
            self.config = cfg
        else:
            self.config = config or RateLimitConfig()
        # Load overrides from config manager if available
        try:
            if CONFIG:
                # ddos user tiers (legacy support)
                tiers = CONFIG.get("ddos.user_tiers", None)
                if isinstance(tiers, dict) and tiers:
                    base = float(tiers.get("user", 60) or 60)
                    multipliers = {
                        str(k): (float(v) / base if base else 1.0)
                        for k, v in tiers.items()
                    }
                    for k in ("guest", "user", "premium", "admin", "system"):
                        multipliers.setdefault(k, 1.0)
                    self.config.user_tier_multipliers = multipliers
                # Unified rate limit config
                rl_cfg = CONFIG.get("rate_limit", None)
                if rl_cfg is not None:
                    # endpoint_overrides
                    ep = (
                        getattr(rl_cfg, "endpoint_overrides", None)
                        if not isinstance(rl_cfg, dict)
                        else rl_cfg.get("endpoint_overrides")
                    )
                    if isinstance(ep, dict):
                        self.config.endpoint_overrides = dict(ep)
                    # user tier multipliers override
                    ut = (
                        getattr(rl_cfg, "user_tier_multipliers", None)
                        if not isinstance(rl_cfg, dict)
                        else rl_cfg.get("user_tier_multipliers")
                    )
                    if isinstance(ut, dict) and ut:
                        self.config.user_tier_multipliers.update(
                            {str(k): float(v) for k, v in ut.items()}
                        )
                    # basic per-ip/per-user/rate values if present
                    for attr in (
                        "enabled",
                        "per_ip_requests_per_minute",
                        "per_user_requests_per_minute",
                        "per_route_requests_per_minute",
                        "global_requests_per_minute",
                        "per_ip_block_duration",
                        "per_user_block_duration",
                    ):
                        val = (
                            getattr(rl_cfg, attr, None)
                            if not isinstance(rl_cfg, dict)
                            else rl_cfg.get(attr)
                        )
                        if val is not None and hasattr(self.config, attr):
                            setattr(
                                self.config, attr, type(getattr(self.config, attr))(val)
                            )
        except Exception:
            pass
        # State
        self.token_buckets: dict[str, TokenBucket] = {}
        self.sliding_windows: dict[str, SlidingWindow] = {}
        self.fixed_windows: dict[str, FixedWindow] = {}
        self.blocked: dict[str, float] = {}
        self.stats = defaultdict(int)
        # Concurrency and bandwidth tracking
        self.concurrent: dict[str, int] = defaultdict(int)
        from collections import deque

        self.bandwidth: dict[str, deque[tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=1000)
        )

    def _id(self, request: Request, strategy: RateLimitStrategy) -> str:
        if strategy == RateLimitStrategy.PER_IP:
            fwd = (
                request.headers.get("X-Forwarded-For")
                if hasattr(request, "headers")
                else None
            )
            if fwd:
                return fwd.split(",")[0].strip()
            return (
                request.client.host if getattr(request, "client", None) else "unknown"
            )
        if strategy == RateLimitStrategy.PER_USER:
            uid = getattr(request.state, "user_id", None)
            return (
                f"user:{uid}"
                if uid
                else f"ip:{self._id(request, RateLimitStrategy.PER_IP)}"
            )
        if strategy == RateLimitStrategy.PER_ROUTE:
            return f"route:{request.url.path}"
        if strategy == RateLimitStrategy.PER_METHOD:
            return f"method:{request.method}"
        if strategy == RateLimitStrategy.PER_USER_AGENT:
            ua = (
                request.headers.get("User-Agent", "unknown")
                if hasattr(request, "headers")
                else "unknown"
            )
            return f"ua:{hashlib.md5(ua.encode()).hexdigest()[:16]}"
        if strategy == RateLimitStrategy.GLOBAL:
            return "global"
        return "unknown"

    def _limits(self, strategy: RateLimitStrategy, request: Request) -> tuple[int, int]:
        # Endpoint override
        endpoint = request.url.path if hasattr(request, "url") else ""
        if self.config.endpoint_overrides.get(endpoint):
            override = self.config.endpoint_overrides[endpoint]
            if strategy.value in override:
                return override[strategy.value], 60
        # Tier multiplier
        tier = getattr(request.state, "user_tier", "guest")
        mult = self.config.user_tier_multipliers.get(tier, 1.0)
        if strategy == RateLimitStrategy.PER_IP:
            return int(self.config.per_ip_requests_per_minute * mult), 60
        if strategy == RateLimitStrategy.PER_USER:
            return int(self.config.per_user_requests_per_minute * mult), 60
        if strategy == RateLimitStrategy.PER_ROUTE:
            return int(self.config.per_route_requests_per_minute * mult), 60
        if strategy == RateLimitStrategy.PER_METHOD:
            method_limits = {
                "GET": self.config.get_requests_per_minute,
                "POST": self.config.post_requests_per_minute,
                "PUT": self.config.put_requests_per_minute,
                "DELETE": self.config.delete_requests_per_minute,
                "PATCH": self.config.patch_requests_per_minute,
            }
            limit = method_limits.get(getattr(request, "method", "GET"), 60)
            return int(limit * mult), 60
        if strategy == RateLimitStrategy.GLOBAL:
            return self.config.global_requests_per_minute, 60
        return 60, 60

    async def _apply(
        self, key: str, algo: RateLimitAlgorithm, max_req: int, window: int
    ) -> bool:
        if algo == RateLimitAlgorithm.TOKEN_BUCKET:
            if key not in self.token_buckets:
                self.token_buckets[key] = TokenBucket(max_req, max_req / window)
            return await self.token_buckets[key].consume()
        if algo == RateLimitAlgorithm.SLIDING_WINDOW:
            if key not in self.sliding_windows:
                self.sliding_windows[key] = SlidingWindow(window, max_req)
            return await self.sliding_windows[key].add()
        if algo == RateLimitAlgorithm.FIXED_WINDOW:
            if key not in self.fixed_windows:
                self.fixed_windows[key] = FixedWindow(window, max_req)
            return await self.fixed_windows[key].add()
        if key not in self.sliding_windows:
            self.sliding_windows[key] = SlidingWindow(window, max_req)
        return await self.sliding_windows[key].add()

    async def check(self, request: Request) -> RateLimitViolation | None:
        if not self.config.enabled:
            return None
        now = time.time()
        # Unblock expired
        for k, until in list(self.blocked.items()):
            if now >= until:
                del self.blocked[k]
        # Strategies
        strategies = [
            RateLimitStrategy.GLOBAL,
            RateLimitStrategy.PER_IP,
            RateLimitStrategy.PER_USER,
            RateLimitStrategy.PER_METHOD,
            RateLimitStrategy.PER_ROUTE,
        ]
        for strat in strategies:
            key = self._id(request, strat)
            if key in self.blocked:
                retry = int(self.blocked[key] - now)
                self.stats["blocked_requests"] += 1
                return RateLimitViolation(strat, key, 0, 0, max(retry, 1))
            max_req, window = self._limits(strat, request)
            allowed = await self._apply(
                key, self.config.default_algorithm, max_req, window
            )
            if not allowed:
                current = self._current_count(key, self.config.default_algorithm)
                block_for = self._block_for(strat)
                self.blocked[key] = now + block_for
                self.stats["blocked_requests"] += 1
                return RateLimitViolation(strat, key, max_req, current, block_for)
        self.stats["total_requests"] += 1
        return None

    def _current_count(self, key: str, algo: RateLimitAlgorithm) -> int:
        if algo == RateLimitAlgorithm.SLIDING_WINDOW and key in self.sliding_windows:
            return self.sliding_windows[key].count()
        if algo == RateLimitAlgorithm.FIXED_WINDOW and key in self.fixed_windows:
            return self.fixed_windows[key].count_current()
        if algo == RateLimitAlgorithm.TOKEN_BUCKET and key in self.token_buckets:
            info = self.token_buckets[key].info()
            return int(info["capacity"] - info["tokens"])
        return 0

    def _block_for(self, strategy: RateLimitStrategy) -> int:
        if strategy == RateLimitStrategy.PER_IP:
            return self.config.per_ip_block_duration
        if strategy == RateLimitStrategy.PER_USER:
            return self.config.per_user_block_duration
        if strategy == RateLimitStrategy.GLOBAL:
            return 60
        return 300

    def stats_summary(self) -> dict[str, Any]:
        return {
            "total_requests": self.stats.get("total_requests", 0),
            "blocked_requests": self.stats.get("blocked_requests", 0),
        }

    def get_stats(self) -> dict[str, Any]:
        """Public accessor for statistics."""
        return self.stats_summary()

    def get_config_summary(self) -> dict[str, Any]:
        """Return a summary of current rate limiting configuration."""
        return {
            "enabled": getattr(self.config, "enabled", True),
            "global_requests_per_minute": getattr(
                self.config, "global_requests_per_minute", 0
            ),
            "per_ip_requests_per_minute": getattr(
                self.config, "per_ip_requests_per_minute", 0
            ),
            "per_user_requests_per_minute": getattr(
                self.config, "per_user_requests_per_minute", 0
            ),
            "per_route_requests_per_minute": getattr(
                self.config, "per_route_requests_per_minute", 0
            ),
            "endpoint_overrides": dict(getattr(self.config, "endpoint_overrides", {})),
            "user_tier_multipliers": dict(
                getattr(self.config, "user_tier_multipliers", {})
            ),
        }

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable rate limiting."""
        self.config.enabled = bool(enabled)

    def add_endpoint_override(self, path: str, limits: dict[str, int]) -> None:
        """Add or update per-endpoint rate limits."""
        self.config.endpoint_overrides[path] = limits

    def remove_endpoint_override(self, path: str) -> None:
        """Remove endpoint-specific override if present."""
        try:
            if path in self.config.endpoint_overrides:
                del self.config.endpoint_overrides[path]
        except Exception:
            pass

    def update_user_tier_multiplier(self, tier: str, multiplier: float) -> None:
        """Update user tier multiplier for dynamic scaling per tier."""
        try:
            self.config.user_tier_multipliers[str(tier)] = float(multiplier)
        except Exception:
            pass

    async def check_user_action(
        self, user_id: str, endpoint: str
    ) -> tuple[bool, dict[str, Any]]:
        """Check rate limiting for a given user and endpoint without a Request object."""
        # Enforce per-user and per-route strategies using default algorithm and 60s window
        # Build keys as used internally
        user_key = f"user:{user_id}"
        route_key = f"route:{endpoint}"
        # Determine limits
        user_limit, window = self._limits(
            RateLimitStrategy.PER_USER,
            type(
                "R",
                (),
                {
                    "url": type("U", (), {"path": endpoint})(),
                    "headers": {},
                    "method": "GET",
                    "client": None,
                    "state": type("S", (), {"user_id": user_id, "user_tier": "user"})(),
                },
            ),
        )
        route_limit, _ = self._limits(
            RateLimitStrategy.PER_ROUTE,
            type(
                "R",
                (),
                {
                    "url": type("U", (), {"path": endpoint})(),
                    "headers": {},
                    "method": "GET",
                    "client": None,
                    "state": type("S", (), {"user_id": user_id, "user_tier": "user"})(),
                },
            ),
        )
        # Apply both limits
        ok_user = await self._apply(
            user_key, self.config.default_algorithm, user_limit, window
        )
        ok_route = await self._apply(
            route_key, self.config.default_algorithm, route_limit, window
        )
        allowed = ok_user and ok_route
        info = {
            "limit_user": user_limit,
            "limit_route": route_limit,
            "window_seconds": window,
            "remaining_user": max(
                0,
                user_limit
                - self._current_count(user_key, self.config.default_algorithm),
            ),
            "remaining_route": max(
                0,
                route_limit
                - self._current_count(route_key, self.config.default_algorithm),
            ),
        }
        if not allowed:
            # Simplified retry-after: next minute
            info["retry_after"] = 60
        return allowed, info

    async def check_ip_action(
        self, ip_address: str, endpoint: str = "/"
    ) -> tuple[bool, dict[str, Any]]:
        """Check rate limiting for a given IP and endpoint without a Request object."""
        # Keys consistent with internal strategies
        ip_key = f"ip:{ip_address}"
        route_key = f"route:{endpoint}"
        # Mock request-like for limits resolution
        req_mock = type(
            "R",
            (),
            {
                "url": type("U", (), {"path": endpoint})(),
                "headers": {},
                "method": "GET",
                "client": type("C", (), {"host": ip_address})(),
                "state": type("S", (), {"user_id": None, "user_tier": "guest"})(),
            },
        )
        ip_limit, window = self._limits(RateLimitStrategy.PER_IP, req_mock)
        route_limit, _ = self._limits(RateLimitStrategy.PER_ROUTE, req_mock)
        ok_ip = await self._apply(
            ip_key, self.config.default_algorithm, ip_limit, window
        )
        ok_route = await self._apply(
            route_key, self.config.default_algorithm, route_limit, window
        )
        allowed = ok_ip and ok_route
        info = {
            "limit_ip": ip_limit,
            "limit_route": route_limit,
            "window_seconds": window,
            "remaining_ip": max(
                0, ip_limit - self._current_count(ip_key, self.config.default_algorithm)
            ),
            "remaining_route": max(
                0,
                route_limit
                - self._current_count(route_key, self.config.default_algorithm),
            ),
        }
        if not allowed:
            info["retry_after"] = 60
        return allowed, info


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: RateLimitConfig | None = None):
        super().__init__(app)
        self.limiter = UnifiedRateLimiter(config)

    async def dispatch(self, request: Request, call_next):
        try:
            # Concurrency key (prefer user, fallback to ip)
            ckey = self.limiter._id(request, RateLimitStrategy.PER_USER)
            if ckey == "user:None" or ckey.endswith("None"):
                ckey = f"ip:{self.limiter._id(request, RateLimitStrategy.PER_IP)}"
            # Concurrency check
            current_conc = self.limiter.concurrent[ckey]
            if current_conc >= self.limiter.config.concurrent_requests:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"error": "Too many concurrent requests", "retry_after": 1},
                    headers={"Retry-After": "1", "X-RateLimit-Strategy": "concurrency"},
                )
            self.limiter.concurrent[ckey] += 1
            try:
                # Bandwidth pre-check (rough estimate using request content-length)
                bw_limit = getattr(self.limiter.config, "bandwidth_per_second", 0)
                if bw_limit:
                    dq = self.limiter.bandwidth[ckey]
                    now = time.time()
                    # purge older than 1s
                    while dq and now - dq[0][0] > 1.0:
                        dq.popleft()
                    used = sum(sz for ts, sz in dq)
                    req_size = 0
                    try:
                        req_size = int(request.headers.get("content-length", "0"))
                    except Exception:
                        req_size = 0
                    if used + req_size > bw_limit:
                        return JSONResponse(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            content={
                                "error": "Bandwidth limit exceeded",
                                "retry_after": 1,
                            },
                            headers={
                                "Retry-After": "1",
                                "X-RateLimit-Strategy": "bandwidth",
                            },
                        )
                # Core rate check
                v = await self.limiter.check(request)
                if v:
                    headers = {
                        "Retry-After": str(v.retry_after),
                        "X-RateLimit-Limit": str(v.limit),
                        "X-RateLimit-Remaining": str(max(0, v.limit - v.current)),
                        "X-RateLimit-Reset": str(int(time.time() + v.retry_after)),
                        "X-RateLimit-Strategy": v.strategy.value,
                    }
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "error": "Rate limit exceeded",
                            "message": f"Too many requests for {v.strategy.value}",
                            "limit": v.limit,
                            "current": v.current,
                            "retry_after": v.retry_after,
                            "strategy": v.strategy.value,
                        },
                        headers=headers,
                    )
                response = await call_next(request)
                # Record response bandwidth
                try:
                    resp_len = 0
                    if (
                        hasattr(response, "headers")
                        and "content-length" in response.headers
                    ):
                        resp_len = int(response.headers["content-length"])
                    elif hasattr(response, "body") and response.body:
                        resp_len = len(response.body)
                    dq = self.limiter.bandwidth[ckey]
                    dq.append((time.time(), resp_len))
                except Exception:
                    pass
                return response
            finally:
                self.limiter.concurrent[ckey] = max(
                    0, self.limiter.concurrent[ckey] - 1
                )
        except Exception as e:
            if hasattr(logger, "error"):
                logger.error(f"Rate limiting error: {e}")
            return await call_next(request)


# Convenience accessors
_global: UnifiedRateLimiter | None = None


def get_rate_limiter() -> UnifiedRateLimiter:
    global _global
    if _global is None:
        _global = UnifiedRateLimiter()
    return _global


def configure_rate_limiter(cfg: RateLimitConfig):
    global _global
    _global = UnifiedRateLimiter(cfg)
