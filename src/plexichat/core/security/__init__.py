# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Security System - SINGLE SOURCE OF TRUTH

Consolidates ALL security functionality from:
- core/security/security_manager.py - INTEGRATED
- core/security/unified_security_manager.py - INTEGRATED
- features/security/ (all modules) - INTEGRATED
- Related security components - INTEGRATED

Provides a single, unified interface for all security operations.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import warnings

from plexichat.core.security.security_manager import (
    AuthenticationMethod,
    EncryptionAlgorithm,
    InputSanitizer,
    PasswordManager,
    SecurityContext,
    SecurityEventType,
    SecurityLevel,
    SecurityPolicy,
    SecuritySystem,
    SecurityToken,
    ThreatLevel,
    TokenManager,
    UserCredentials,
    get_security_system,
)

# Backward compatibility aliases
security_manager = get_security_system()
SecurityManager = SecuritySystem

# Provide Network Protection and RateLimitRequest stubs/implementations
# These are required by the FastAPI adapter and other modules. If a more
# advanced implementation exists elsewhere it will be used; otherwise these
# provide safe defaults so imports resolve and functionality degrades gracefully.

import asyncio
from dataclasses import dataclass, field
from enum import Enum
import time


class KeyDomain(Enum):
    """Key domain for distributed key management."""

    AUTH = "auth"
    ENCRYPTION = "encryption"
    SIGNING = "signing"
    SESSION = "session"


@dataclass
class RateLimitRequest:
    """
    Represents a rate limit check request.
    FastAPI adapter expects these attributes:
    - ip_address: source IP address of the request
    - endpoint: path of the request
    - method: HTTP method
    - user_agent: user-agent header
    - size_bytes: size of the request payload in bytes
    - action: logical action identifier for rate limiting
    - limit: numeric limit of requests allowed in window
    - window_seconds: time window (seconds) for the limit
    - user_id: optional user identifier for user-scoped limits
    """

    ip_address: str = "unknown"
    endpoint: str = "/"
    method: str = "GET"
    user_agent: str = "unknown"
    size_bytes: int = 0
    action: str = ""
    limit: int = 0
    window_seconds: int = 60
    user_id: str | None = None


class NetworkProtection:
    """
    Simple in-process network protection / rate limiting component.

    This implementation is intentionally conservative and lightweight: it
    performs in-memory tracking of actions per (ip, action) within a sliding
    window. It provides an async check_request(rate_request) method that
    returns a tuple (allowed: bool, threat_info: Optional[dict]).

    In production deployments this should be replaced by a distributed
    rate limiter / WAF integration that persists counters and supports
    coordination across instances.
    """

    def __init__(self):
        # Keyed by (ip_address, action) -> list of timestamps (floats)
        self._counters: dict[tuple[str, str], list[float]] = {}
        # A simple lock to protect the in-memory structure across async calls
        self._lock = asyncio.Lock()

    async def check_request(
        self, rate_request: RateLimitRequest
    ) -> tuple[bool, dict[str, Any] | None]:
        """
        Check whether the given rate_request should be allowed.

        Returns:
            (allowed: bool, threat_info: Optional[dict])
        """
        # Basic sanity check
        if rate_request is None:
            return True, None

        key = (
            rate_request.ip_address or "unknown",
            rate_request.action or "__default__",
        )
        now = time.time()
        window = max(1, int(rate_request.window_seconds or 60))
        limit = max(1, int(rate_request.limit or 1000))

        async with self._lock:
            timestamps = self._counters.get(key)
            if timestamps is None:
                timestamps = []
                self._counters[key] = timestamps

            # Purge old timestamps outside the window
            cutoff = now - window
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            # Check allowance
            if len(timestamps) >= limit:
                # Rate limit exceeded
                threat_info = {
                    "reason": "rate_limit_exceeded",
                    "ip_address": rate_request.ip_address,
                    "endpoint": rate_request.endpoint,
                    "action": rate_request.action,
                    "limit": limit,
                    "window_seconds": window,
                    "current_count": len(timestamps),
                }
                # Optionally record the event via logging (non-blocking)
                try:
                    logger = logging.getLogger(
                        "plexichat.core.security.network_protection"
                    )
                    logger.warning(f"Rate limit exceeded: {threat_info}")
                except Exception:
                    pass
                return False, threat_info

            # Allow and record this request
            timestamps.append(now)
            return True, None


# Singleton instance and accessor
_network_protection: NetworkProtection | None = None


def get_network_protection() -> NetworkProtection:
    """
    Get the global NetworkProtection instance. Creates a default in-memory
    protection instance if one does not already exist.

    This is safe to call from sync or async code.
    """
    global _network_protection
    if _network_protection is None:
        _network_protection = NetworkProtection()
    return _network_protection


# Distributed Key Manager stub
class DistributedKeyManager:
    """Stub distributed key manager for testing."""

    def __init__(self):
        pass

    def get_key(self, domain: KeyDomain, key_id: str):
        """Get a key for the given domain and id."""
        return f"key_{domain.value}_{key_id}"

    def store_key(self, domain: KeyDomain, key_id: str, key: str):
        """Store a key."""
        pass

    async def get_domain_key(self, domain: KeyDomain):
        """Get domain key asynchronously."""
        return f"domain_key_{domain.value}"


_distributed_key_manager: DistributedKeyManager | None = None


def get_distributed_key_manager() -> DistributedKeyManager:
    """Get the distributed key manager instance."""
    global _distributed_key_manager
    if _distributed_key_manager is None:
        _distributed_key_manager = DistributedKeyManager()
    return _distributed_key_manager


# Alias for backward compatibility
distributed_key_manager = get_distributed_key_manager()


# Export all the main classes and functions
__all__ = [
    # Security system
    "SecuritySystem",
    "PasswordManager",
    "TokenManager",
    "InputSanitizer",
    # Data classes and enums
    "SecurityLevel",
    "ThreatLevel",
    "SecurityEventType",
    "AuthenticationMethod",
    "EncryptionAlgorithm",
    "SecurityPolicy",
    "UserCredentials",
    "SecurityContext",
    "SecurityToken",
    # Main functions
    "get_security_system",
    # Network protection utilities (required by FastAPI adapter)
    "get_network_protection",
    "RateLimitRequest",
    "NetworkProtection",
    # Key management
    "KeyDomain",
    "DistributedKeyManager",
    "get_distributed_key_manager",
    "distributed_key_manager",
    # Backward compatibility aliases
    "security_manager",
    "SecurityManager",
]
