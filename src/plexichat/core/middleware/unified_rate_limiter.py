#!/usr/bin/env python3
"""
Unified Rate Limiting System for PlexiChat

Implements comprehensive rate limiting strategies:
- Per IP address
- Per user (authenticated)
- Per route/endpoint
- Per method
- Per user agent (optional)
- Global rate limiting

Supports multiple algorithms:
- Token bucket
- Sliding window
- Fixed window
- Leaky bucket
"""

import asyncio
import time
import json
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

# Web framework imports
try:
    from fastapi import Request
except ImportError:
    try:
        from starlette.requests import Request
    except ImportError:
        # Fallback for when Request is not available
        Request = Any

# Import logging safely
try:
    from ..logging.unified_logger import get_logger, LogCategory
    logger = get_logger("rate_limiter")
except ImportError:
    import logging
    logger = logging.getLogger("rate_limiter")

class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ROUTE = "per_route"
    PER_METHOD = "per_method"
    PER_USER_AGENT = "per_user_agent"
    GLOBAL = "global"

class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"

@dataclass
class RateLimitRule:
    """Rate limit rule configuration."""
    strategy: RateLimitStrategy
    algorithm: RateLimitAlgorithm
    max_requests: int
    window_seconds: int
    burst_limit: Optional[int] = None
    block_duration_seconds: int = 300  # 5 minutes default
    enabled: bool = True
    priority: int = 100  # Lower number = higher priority

@dataclass
class RateLimitConfig:
    """Comprehensive rate limiting configuration."""
    # Global settings
    enabled: bool = True
    default_algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    
    # Per-IP limits
    per_ip_requests_per_minute: int = 60
    per_ip_burst_limit: int = 10
    per_ip_block_duration: int = 300
    
    # Per-user limits (authenticated users)
    per_user_requests_per_minute: int = 120
    per_user_burst_limit: int = 20
    per_user_block_duration: int = 180
    
    # Per-route limits (can be overridden per endpoint)
    per_route_requests_per_minute: int = 100
    per_route_burst_limit: int = 15
    
    # Per-method limits
    get_requests_per_minute: int = 200
    post_requests_per_minute: int = 60
    put_requests_per_minute: int = 30
    delete_requests_per_minute: int = 20
    patch_requests_per_minute: int = 40
    
    # Global limits (across all clients)
    global_requests_per_minute: int = 10000
    global_burst_limit: int = 500
    
    # Special endpoint overrides
    endpoint_overrides: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # User tier multipliers
    user_tier_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "guest": 0.5,
        "user": 1.0,
        "premium": 2.0,
        "admin": 10.0,
        "system": 100.0
    })

class TokenBucket:
    """Token bucket implementation for rate limiting.
        def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.time()
        self.lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket."""
        async with self.lock:
            current_time = time.time()
            
            # Refill tokens based on elapsed time
            elapsed = current_time - self.last_refill
            tokens_to_add = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = current_time
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_info(self) -> Dict[str, float]:
        Get current bucket information."""
        return {
            "capacity": self.capacity,
            "tokens": self.tokens,
            "refill_rate": self.refill_rate
        }

class SlidingWindow:
    """Sliding window implementation for rate limiting.
        def __init__(self, window_seconds: int, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.requests = deque()
        self.lock = asyncio.Lock()
    
    async def add_request(self) -> bool:
        """Add a request and check if within limits."""
        async with self.lock:
            current_time = time.time()
            
            # Remove old requests outside the window
            while self.requests and self.requests[0] <= current_time - self.window_seconds:
                self.requests.popleft()
            
            # Check if we're within limits
            if len(self.requests) >= self.max_requests:
                return False
            
            # Add current request
            self.requests.append(current_time)
            return True
    
    def get_count(self) -> int:
        Get current request count in window."""
        current_time = time.time()
        # Clean old requests
        while self.requests and self.requests[0] <= current_time - self.window_seconds:
            self.requests.popleft()
        return len(self.requests)

class FixedWindow:
    """Fixed window implementation for rate limiting.
        def __init__(self, window_seconds: int, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.current_window_start = 0
        self.current_count = 0
        self.lock = asyncio.Lock()
    
    async def add_request(self) -> bool:
        """Add a request and check if within limits."""
        async with self.lock:
            current_time = time.time()
            window_start = int(current_time // self.window_seconds) * self.window_seconds
            
            # Reset if new window
            if window_start != self.current_window_start:
                self.current_window_start = window_start
                self.current_count = 0
            
            # Check if within limits
            if self.current_count >= self.max_requests:
                return False
            
            self.current_count += 1
            return True
    
    def get_count(self) -> int:
        Get current request count in window."""
        current_time = time.time()
        window_start = int(current_time // self.window_seconds) * self.window_seconds
        
        if window_start != self.current_window_start:
            return 0
        return self.current_count

class RateLimitViolation:
    """Rate limit violation information.
        def __init__(self, strategy: RateLimitStrategy, key: str, 
                limit: int, current: int, retry_after: int):
        self.strategy = strategy
        self.key = key
        self.limit = limit
        self.current = current
        self.retry_after = retry_after
        self.timestamp = time.time()

class UnifiedRateLimiter:
    """Unified rate limiting system with multiple strategies and algorithms."""
        def __init__(self, config: RateLimitConfig):
        self.config = config
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.sliding_windows: Dict[str, SlidingWindow] = {}
        self.fixed_windows: Dict[str, FixedWindow] = {}
        self.blocked_keys: Dict[str, float] = {}  # key -> unblock_time
        self.violations: List[RateLimitViolation] = []
        self.global_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "violations_by_strategy": defaultdict(int),
            "violations_by_key": defaultdict(int)
        }
        
        if hasattr(logger, 'info'):
            logger.info("Unified Rate Limiter initialized", LogCategory.STARTUP)
        else:
            print("[INFO] Unified Rate Limiter initialized")
    
    def _get_client_identifier(self, request: Request, strategy: RateLimitStrategy) -> str:
        """Get client identifier based on strategy."""
        if strategy == RateLimitStrategy.PER_IP:
            # Get real IP, considering proxies
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                return forwarded_for.split(",")[0].strip()
            return request.client.host if request.client else "unknown"
        
        elif strategy == RateLimitStrategy.PER_USER:
            # Get user ID from authentication
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                return f"user:{user_id}"
            # Fall back to IP for unauthenticated users
            return f"ip:{self._get_client_identifier(request, RateLimitStrategy.PER_IP)}"
        
        elif strategy == RateLimitStrategy.PER_ROUTE:
            return f"route:{request.url.path}"
        
        elif strategy == RateLimitStrategy.PER_METHOD:
            return f"method:{request.method}"
        
        elif strategy == RateLimitStrategy.PER_USER_AGENT:
            user_agent = request.headers.get("User-Agent", "unknown")
            # Hash user agent to avoid long keys
            return f"ua:{hashlib.md5(user_agent.encode()).hexdigest()[:16]}"
        
        elif strategy == RateLimitStrategy.GLOBAL:
            return "global"
        
        return "unknown"

    def _get_rate_limit_for_strategy(self, strategy: RateLimitStrategy,
                                request: Request) -> Tuple[int, int]:
        """Get rate limit and window for a strategy."""
        # Check for endpoint-specific overrides
        endpoint = request.url.path
        if endpoint in self.config.endpoint_overrides:
            override = self.config.endpoint_overrides[endpoint]
            if strategy.value in override:
                return override[strategy.value], 60  # Default 1 minute window

        # Get user tier multiplier
        user_tier = getattr(request.state, "user_tier", "guest")
        multiplier = self.config.user_tier_multipliers.get(user_tier, 1.0)

        if strategy == RateLimitStrategy.PER_IP:
            return int(self.config.per_ip_requests_per_minute * multiplier), 60
        elif strategy == RateLimitStrategy.PER_USER:
            return int(self.config.per_user_requests_per_minute * multiplier), 60
        elif strategy == RateLimitStrategy.PER_ROUTE:
            return int(self.config.per_route_requests_per_minute * multiplier), 60
        elif strategy == RateLimitStrategy.PER_METHOD:
            method_limits = {
                "GET": self.config.get_requests_per_minute,
                "POST": self.config.post_requests_per_minute,
                "PUT": self.config.put_requests_per_minute,
                "DELETE": self.config.delete_requests_per_minute,
                "PATCH": self.config.patch_requests_per_minute
            }
            limit = method_limits.get(request.method, 60)
            return int(limit * multiplier), 60
        elif strategy == RateLimitStrategy.GLOBAL:
            return self.config.global_requests_per_minute, 60

        return 60, 60  # Default fallback

    async def _check_rate_limit_with_algorithm(self, key: str, algorithm: RateLimitAlgorithm,
                                            max_requests: int, window_seconds: int) -> bool:
        """Check rate limit using specified algorithm.
        if algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            if key not in self.token_buckets:
                refill_rate = max_requests / window_seconds
                self.token_buckets[key] = TokenBucket(max_requests, refill_rate)
            return await self.token_buckets[key].consume()

        elif algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            if key not in self.sliding_windows:
                self.sliding_windows[key] = SlidingWindow(window_seconds, max_requests)
            return await self.sliding_windows[key].add_request()

        elif algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            if key not in self.fixed_windows:
                self.fixed_windows[key] = FixedWindow(window_seconds, max_requests)
            return await self.fixed_windows[key].add_request()

        # Default to sliding window
        if key not in self.sliding_windows:
            self.sliding_windows[key] = SlidingWindow(window_seconds, max_requests)
        return await self.sliding_windows[key].add_request()

    async def check_rate_limits(self, request: Request) -> Optional[RateLimitViolation]:
        """Check all applicable rate limits for a request."""
        if not self.config.enabled:
            return None

        async with self.global_lock:
            self.stats["total_requests"] += 1

            # Check if any key is currently blocked
            current_time = time.time()
            blocked_keys_to_remove = []
            for key, unblock_time in self.blocked_keys.items():
                if current_time >= unblock_time:
                    blocked_keys_to_remove.append(key)

            for key in blocked_keys_to_remove:
                del self.blocked_keys[key]

            # Define strategies to check (in order of priority)
            strategies_to_check = [
                RateLimitStrategy.GLOBAL,
                RateLimitStrategy.PER_IP,
                RateLimitStrategy.PER_USER,
                RateLimitStrategy.PER_METHOD,
                RateLimitStrategy.PER_ROUTE
            ]

            for strategy in strategies_to_check:
                key = self._get_client_identifier(request, strategy)

                # Check if this key is currently blocked
                if key in self.blocked_keys:
                    retry_after = int(self.blocked_keys[key] - current_time)
                    violation = RateLimitViolation(
                        strategy=strategy,
                        key=key,
                        limit=0,
                        current=0,
                        retry_after=max(retry_after, 1)
                    )
                    self.stats["blocked_requests"] += 1
                    self.stats["violations_by_strategy"][strategy.value] += 1
                    return violation

                # Get rate limit for this strategy
                max_requests, window_seconds = self._get_rate_limit_for_strategy(strategy, request)

                # Check rate limit
                allowed = await self._check_rate_limit_with_algorithm(
                    key, self.config.default_algorithm, max_requests, window_seconds
                )

                if not allowed:
                    # Get current count for violation info
                    current_count = self._get_current_count(key, self.config.default_algorithm)

                    # Block the key temporarily
                    block_duration = self._get_block_duration(strategy)
                    self.blocked_keys[key] = current_time + block_duration

                    violation = RateLimitViolation(
                        strategy=strategy,
                        key=key,
                        limit=max_requests,
                        current=current_count,
                        retry_after=block_duration
                    )

                    self.violations.append(violation)
                    self.stats["blocked_requests"] += 1
                    self.stats["violations_by_strategy"][strategy.value] += 1
                    self.stats["violations_by_key"][key] += 1

                    if hasattr(logger, 'log_rate_limit_violation'):
                        logger.log_rate_limit_violation(key, strategy.value, max_requests, current_count)
                    elif hasattr(logger, 'warning'):
                        logger.warning(f"Rate limit violation: {strategy.value} for {key} "
                                    f"({current_count}/{max_requests})", LogCategory.RATE_LIMIT)
                    else:
                        print(f"[WARNING] Rate limit violation: {strategy.value} for {key} ({current_count}/{max_requests})")

                    return violation

            return None

    def _get_current_count(self, key: str, algorithm: RateLimitAlgorithm) -> int:
        """Get current request count for a key."""
        if algorithm == RateLimitAlgorithm.SLIDING_WINDOW and key in self.sliding_windows:
            return self.sliding_windows[key].get_count()
        elif algorithm == RateLimitAlgorithm.FIXED_WINDOW and key in self.fixed_windows:
            return self.fixed_windows[key].get_count()
        elif algorithm == RateLimitAlgorithm.TOKEN_BUCKET and key in self.token_buckets:
            bucket_info = self.token_buckets[key].get_info()
            return int(bucket_info["capacity"] - bucket_info["tokens"])
        return 0

    def _get_block_duration(self, strategy: RateLimitStrategy) -> int:
        """Get block duration for a strategy.
        if strategy == RateLimitStrategy.PER_IP:
            return self.config.per_ip_block_duration
        elif strategy == RateLimitStrategy.PER_USER:
            return self.config.per_user_block_duration
        elif strategy == RateLimitStrategy.GLOBAL:
            return 60  # Short block for global limits
        return 300  # Default 5 minutes

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        return {
            "total_requests": self.stats["total_requests"],
            "blocked_requests": self.stats["blocked_requests"],
            "block_rate": (self.stats["blocked_requests"] / max(self.stats["total_requests"], 1)) * 100,
            "violations_by_strategy": dict(self.stats["violations_by_strategy"]),
            "violations_by_key": dict(self.stats["violations_by_key"]),
            "active_blocks": len(self.blocked_keys),
            "active_buckets": len(self.token_buckets),
            "active_windows": len(self.sliding_windows) + len(self.fixed_windows)
        }

    async def cleanup_old_data(self):
        """Clean up old rate limiting data."""
        current_time = time.time()

        # Remove old violations (keep last 1000)
        if len(self.violations) > 1000:
            self.violations = self.violations[-1000:]

        # Clean up expired blocks
        expired_blocks = [key for key, unblock_time in self.blocked_keys.items()
                        if current_time >= unblock_time]
        for key in expired_blocks:
            del self.blocked_keys[key]

        if hasattr(logger, 'debug'):
            logger.debug(f"Cleaned up {len(expired_blocks)} expired blocks", LogCategory.RATE_LIMIT)
        else:
            print(f"[DEBUG] Cleaned up {len(expired_blocks)} expired blocks")

class RateLimitMiddleware:
    """FastAPI middleware for unified rate limiting.
        def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.rate_limiter = UnifiedRateLimiter(self.config)
        self.cleanup_task = None
        self._start_cleanup_task()

    def _start_cleanup_task(self):
        """Start background cleanup task."""
        async def cleanup_loop():
            while True:
                try:
                    await asyncio.sleep(300)  # Clean up every 5 minutes
                    await self.rate_limiter.cleanup_old_data()
                except Exception as e:
                    if hasattr(logger, 'error'):
                        logger.error(f"Rate limiter cleanup error: {e}", LogCategory.RATE_LIMIT)
                    else:
                        print(f"[ERROR] Rate limiter cleanup error: {e}")

        self.cleanup_task = asyncio.create_task(cleanup_loop())

    async def __call__(self, request: Request, call_next):
        """Process request through rate limiting."""
        try:
            # Check rate limits
            violation = await self.rate_limiter.check_rate_limits(request)

            if violation:
                # Create rate limit response
                response_data = {
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests for {violation.strategy.value}",
                    "limit": violation.limit,
                    "current": violation.current,
                    "retry_after": violation.retry_after,
                    "strategy": violation.strategy.value
                }

                headers = {
                    "Retry-After": str(violation.retry_after),
                    "X-RateLimit-Limit": str(violation.limit),
                    "X-RateLimit-Remaining": str(max(0, violation.limit - violation.current)),
                    "X-RateLimit-Reset": str(int(time.time() + violation.retry_after)),
                    "X-RateLimit-Strategy": violation.strategy.value
                }

                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content=response_data,
                    headers=headers
                )

            # Process request
            response = await call_next(request)

            # Add rate limit headers to successful responses
            if hasattr(request.state, "user_id"):
                user_key = f"user:{request.state.user_id}"
            else:
                user_key = f"ip:{self.rate_limiter._get_client_identifier(request, RateLimitStrategy.PER_IP)}"

            # Get current limits for headers
            max_requests, _ = self.rate_limiter._get_rate_limit_for_strategy(
                RateLimitStrategy.PER_USER if hasattr(request.state, "user_id") else RateLimitStrategy.PER_IP,
                request
            )
            current_count = self.rate_limiter._get_current_count(user_key, self.config.default_algorithm)

            response.headers["X-RateLimit-Limit"] = str(max_requests)
            response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - current_count))
            response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))  # Next minute

            return response

        except Exception as e:
            if hasattr(logger, 'error'):
                logger.error(f"Rate limiting middleware error: {e}", LogCategory.RATE_LIMIT)
            else:
                print(f"[ERROR] Rate limiting middleware error: {e}")
            # Continue processing on error to avoid breaking the application
            return await call_next(request)

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics.
        return self.rate_limiter.get_stats()

    async def shutdown(self):
        """Shutdown the middleware and cleanup tasks."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

# Decorator for additional route-specific rate limiting
def rate_limit(strategy: RateLimitStrategy = RateLimitStrategy.PER_USER,
            max_requests: int = 60,
            window_seconds: int = 60,
            algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW):
    Decorator for additional route-specific rate limiting."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # This would be implemented to work with the middleware
            # For now, just pass through
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Global rate limiter instance
_global_rate_limiter: Optional[UnifiedRateLimiter] = None

def get_rate_limiter() -> UnifiedRateLimiter:
    """Get the global rate limiter instance.
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = UnifiedRateLimiter(RateLimitConfig())
    return _global_rate_limiter

def configure_rate_limiter(config: RateLimitConfig):
    """Configure the global rate limiter."""
    global _global_rate_limiter
    _global_rate_limiter = UnifiedRateLimiter(config)
