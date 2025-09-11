"""
Unified Rate Limiting Module
Consolidated, feature-complete rate limiting for PlexiChat.
This package unifies previous implementations:
- unified_rate_limiter
- rate_limiter (Redis/InMemory)
- account_rate_limiting_middleware
- dynamic_rate_limiting_middleware
- infrastructure global rate limiting

All consumers should import from this package going forward.
"""

from .engine import (
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitMiddleware,
    RateLimitStrategy,
    UnifiedRateLimiter,
    configure_rate_limiter,
    get_rate_limiter,
)

__all__ = [
    "RateLimitAlgorithm",
    "RateLimitConfig",
    "RateLimitMiddleware",
    "RateLimitStrategy",
    "UnifiedRateLimiter",
    "configure_rate_limiter",
    "get_rate_limiter",
]
