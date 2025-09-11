"""
PlexiChat Rate Limiting Middleware
==================================

Comprehensive rate limiting system to protect against abuse and DoS attacks.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Callable, Awaitable

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitConfig:
    """Configuration for rate limiting."""

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_limit: int = 10,
        window_size: int = 60,  # seconds
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_limit = burst_limit
        self.window_size = window_size


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""

    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, float] = {}

    def _clean_old_requests(self, client_id: str, current_time: float):
        """Remove old requests outside the window."""
        if client_id not in self.requests:
            return

        cutoff_time = current_time - self.config.window_size
        while self.requests[client_id] and self.requests[client_id][0] < cutoff_time:
            self.requests[client_id].popleft()

    def is_rate_limited(self, client_id: str) -> bool:
        """Check if client is rate limited."""
        current_time = time.time()

        # Check if IP is blocked
        if client_id in self.blocked_ips:
            if current_time < self.blocked_ips[client_id]:
                return True
            else:
                del self.blocked_ips[client_id]

        # Clean old requests
        self._clean_old_requests(client_id, current_time)

        # Check burst limit
        if len(self.requests[client_id]) >= self.config.burst_limit:
            # Block for 5 minutes
            self.blocked_ips[client_id] = current_time + 300
            logger.warning(f"IP {client_id} blocked for burst limit violation")
            return True

        # Check per-minute limit
        if len(self.requests[client_id]) >= self.config.requests_per_minute:
            return True

        return False

    def add_request(self, client_id: str):
        """Add a request for the client."""
        current_time = time.time()
        self.requests[client_id].append(current_time)

    def get_rate_limit_info(self, client_id: str) -> Dict[str, int]:
        """Get rate limit information for client."""
        current_time = time.time()
        self._clean_old_requests(client_id, current_time)

        requests_in_window = len(self.requests[client_id])
        remaining = max(0, self.config.requests_per_minute - requests_in_window)
        reset_time = int(current_time + self.config.window_size)

        return {
            "limit": self.config.requests_per_minute,
            "remaining": remaining,
            "reset": reset_time,
            "window": self.config.window_size,
        }


class TokenBucketRateLimiter:
    """Token bucket rate limiter for more flexible rate limiting."""

    def __init__(self, capacity: int = 60, refill_rate: float = 1.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens: Dict[str, float] = defaultdict(float)
        self.last_refill: Dict[str, float] = defaultdict(float)

    def _refill_tokens(self, client_id: str, current_time: float):
        """Refill tokens based on elapsed time."""
        if client_id not in self.last_refill:
            self.last_refill[client_id] = current_time
            self.tokens[client_id] = self.capacity
            return

        elapsed = current_time - self.last_refill[client_id]
        tokens_to_add = elapsed * self.refill_rate

        self.tokens[client_id] = min(
            self.capacity, self.tokens[client_id] + tokens_to_add
        )
        self.last_refill[client_id] = current_time

    def consume_token(self, client_id: str) -> bool:
        """Consume a token for the client."""
        current_time = time.time()
        self._refill_tokens(client_id, current_time)

        if self.tokens[client_id] >= 1:
            self.tokens[client_id] -= 1
            return True

        return False

    def get_token_info(self, client_id: str) -> Dict[str, float]:
        """Get token information for client."""
        current_time = time.time()
        self._refill_tokens(client_id, current_time)

        return {
            "capacity": self.capacity,
            "remaining": self.tokens[client_id],
            "refill_rate": self.refill_rate,
        }


class RateLimitMiddleware:
    """FastAPI middleware for rate limiting."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.sliding_limiter = SlidingWindowRateLimiter(self.config)
        self.token_limiter = TokenBucketRateLimiter()

    async def __call__(self, scope, receive, send):
        """Rate limiting middleware handler."""
        if scope["type"] != "http":
            # Skip non-HTTP requests
            from starlette.applications import Starlette

            app = Starlette()
            await app(scope, receive, send)
            return

        # Get client identifier from scope
        client_ip = scope.get("client", ["unknown", None])[0]
        headers = dict(scope.get("headers", []))
        user_agent = headers.get(b"user-agent", b"").decode("utf-8", errors="ignore")
        client_id = f"{client_ip}:{user_agent[:50]}"  # Limit user agent length

        # Check rate limits
        if self.sliding_limiter.is_rate_limited(client_id):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            response = JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"},
            )
            await response(scope, receive, send)
            return

        if not self.token_limiter.consume_token(client_id):
            logger.warning(f"Token bucket limit exceeded for IP: {client_ip}")
            response = JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "retry_after": 30,
                },
                headers={"Retry-After": "30"},
            )
            await response(scope, receive, send)
            return

        # Log the request
        self.sliding_limiter.add_request(client_id)

        # Continue to next middleware/app
        from starlette.applications import Starlette

        app = Starlette()
        await app(scope, receive, send)


# Global rate limiter instance
rate_limiter = RateLimitMiddleware()


# Convenience function for manual rate limiting
async def check_rate_limit(client_id: str) -> bool:
    """Check if client is rate limited."""
    return not rate_limiter.sliding_limiter.is_rate_limited(client_id)


# Export the middleware
__all__ = ["RateLimitMiddleware", "rate_limiter", "check_rate_limit"]
