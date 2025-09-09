#!/usr/bin/env python3
"""
Integrated Protection System for PlexiChat

Combines DDoS protection, rate limiting, and dynamic scaling based on system load.
Provides fair and comprehensive protection with account type support.
"""

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

# FastAPI availability check
fastapi_available = False
try:
    import fastapi

    fastapi_available = True
except ImportError:
    pass

# Import psutil safely
try:
    import psutil

    psutil_available = True
except ImportError:
    psutil_available = False

# Import logging safely
try:
    import logging

    logger = logging.getLogger("integrated_protection")
except ImportError:
    import logging

    logger = logging.getLogger("integrated_protection")


class SystemLoadLevel(Enum):
    """System load levels for dynamic scaling."""

    LOW = "low"  # < 30% load
    NORMAL = "normal"  # 30-70% load
    HIGH = "high"  # 70-90% load
    CRITICAL = "critical"  # > 90% load


class AccountType(Enum):
    """Account types for rate limiting."""

    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    ADMIN = "admin"


class RateLimitStrategy(Enum):
    """Rate limiting strategies."""

    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"


@dataclass
class SystemMetrics:
    """Current system metrics."""

    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_io: float = 0.0
    active_connections: int = 0
    requests_per_second: float = 0.0
    load_level: SystemLoadLevel = SystemLoadLevel.NORMAL
    timestamp: float = field(default_factory=time.time)


@dataclass
class DynamicLimits:
    """Dynamic rate limits based on system load and account type."""

    base_limit: int
    current_limit: int
    load_multiplier: float
    account_multiplier: float
    burst_allowance: int
    fairness_factor: float = 1.0


@dataclass
class AccountTypeRateLimit:
    """Rate limits for different account types."""

    requests_per_minute: int
    burst_limit: int
    concurrent_connections: int
    priority_weight: float


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    enabled: bool = True
    per_ip_requests_per_minute: int = 60
    per_user_requests_per_minute: int = 100
    burst_limit: int = 10
    window_size_seconds: int = 60
    cleanup_interval_seconds: int = 300
    ban_duration_seconds: int = 3600
    ban_threshold: int = 10


class IntegratedProtectionSystem:
    """
    Integrated Protection System combining DDoS protection, rate limiting,
    and dynamic scaling based on system load and account types.
    """

    def __init__(self, rate_limit_config: Optional[RateLimitConfig] = None):
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        self.ddos_service = None  # Will be initialized if available

        # System monitoring
        self.system_metrics = SystemMetrics()
        self.metrics_history: deque = deque(maxlen=100)

        # Rate limiting storage
        self.ip_requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.user_requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.ip_violations: Dict[str, int] = defaultdict(int)
        self.banned_ips: Dict[str, float] = {}

        # Account type limits
        self.account_limits: Dict[AccountType, AccountTypeRateLimit] = {
            AccountType.FREE: AccountTypeRateLimit(30, 5, 5, 0.5),
            AccountType.BASIC: AccountTypeRateLimit(60, 10, 10, 1.0),
            AccountType.PREMIUM: AccountTypeRateLimit(120, 20, 20, 1.5),
            AccountType.ENTERPRISE: AccountTypeRateLimit(300, 50, 50, 2.0),
            AccountType.ADMIN: AccountTypeRateLimit(1000, 100, 100, 3.0),
        }

        # Dynamic scaling
        self.load_multipliers: Dict[SystemLoadLevel, float] = {
            SystemLoadLevel.LOW: 1.2,
            SystemLoadLevel.NORMAL: 1.0,
            SystemLoadLevel.HIGH: 0.7,
            SystemLoadLevel.CRITICAL: 0.3,
        }

        # Fairness weights
        self.fairness_weights: Dict[AccountType, float] = {
            AccountType.FREE: 0.5,
            AccountType.BASIC: 1.0,
            AccountType.PREMIUM: 1.5,
            AccountType.ENTERPRISE: 2.0,
            AccountType.ADMIN: 3.0,
        }

        # Background monitoring
        self.monitoring_task: Optional[asyncio.Task] = None
        self.is_running = False

        logger.info("Integrated Protection System initialized")

    async def start_monitoring(self) -> None:
        """Start background monitoring tasks."""
        if not self.is_running:
            self.is_running = True
            self.monitoring_task = asyncio.create_task(self._monitor_system())
            logger.info("Started background monitoring")

    async def stop_monitoring(self) -> None:
        """Stop background monitoring tasks."""
        if self.is_running:
            self.is_running = False
            if self.monitoring_task:
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    pass
            logger.info("Stopped background monitoring")

    async def _monitor_system(self) -> None:
        """Background task to monitor system metrics."""
        while self.is_running:
            try:
                await self._update_system_metrics()
                await self._cleanup_old_requests()
                await asyncio.sleep(10)  # Update every 10 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in system monitoring: {e}")
                await asyncio.sleep(30)  # Wait longer on error

    async def _update_system_metrics(self) -> None:
        """Update current system metrics."""
        if psutil_available:
            try:
                import psutil

                self.system_metrics.cpu_usage = psutil.cpu_percent(interval=1)
                self.system_metrics.memory_usage = psutil.virtual_memory().percent
                self.system_metrics.disk_usage = psutil.disk_usage("/").percent

                # Determine load level
                avg_load = (
                    self.system_metrics.cpu_usage + self.system_metrics.memory_usage
                ) / 2
                if avg_load < 30:
                    self.system_metrics.load_level = SystemLoadLevel.LOW
                elif avg_load < 70:
                    self.system_metrics.load_level = SystemLoadLevel.NORMAL
                elif avg_load < 90:
                    self.system_metrics.load_level = SystemLoadLevel.HIGH
                else:
                    self.system_metrics.load_level = SystemLoadLevel.CRITICAL

                self.system_metrics.timestamp = time.time()
                self.metrics_history.append(self.system_metrics)

            except Exception as e:
                logger.error(f"Error updating system metrics: {e}")

    async def _cleanup_old_requests(self) -> None:
        """Clean up old request records and expired bans."""
        current_time = time.time()
        cutoff_time = current_time - self.rate_limit_config.window_size_seconds

        # Clean IP requests
        for ip, requests in list(self.ip_requests.items()):
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            if not requests:
                del self.ip_requests[ip]

        # Clean user requests
        for user, requests in list(self.user_requests.items()):
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            if not requests:
                del self.user_requests[user]

        # Clean up expired bans
        for ip, unban_time in list(self.banned_ips.items()):
            if current_time > unban_time:
                del self.banned_ips[ip]
                self.ip_violations[ip] = 0
                logger.info(f"IP {ip} unbanned.")

    def _get_account_type(self, request: Any) -> Tuple[AccountType, Optional[str]]:
        """Determine account type and user ID from request."""
        try:
            if hasattr(request, "state") and hasattr(request.state, "user"):
                user = getattr(request.state, "user", None)
                if user and hasattr(user, "account_type") and hasattr(user, "id"):
                    return AccountType(user.account_type), str(user.id)
        except (AttributeError, ValueError):
            pass
        return AccountType.FREE, None

    def _calculate_dynamic_limits(self, account_type: AccountType) -> DynamicLimits:
        """Calculate dynamic limits based on system load and account type."""
        base_limits = self.account_limits[account_type]
        load_multiplier = self.load_multipliers[self.system_metrics.load_level]
        account_multiplier = self.fairness_weights[account_type]

        current_limit = int(
            base_limits.requests_per_minute * load_multiplier * account_multiplier
        )
        burst_allowance = int(base_limits.burst_limit * load_multiplier)

        return DynamicLimits(
            base_limit=base_limits.requests_per_minute,
            current_limit=max(1, current_limit),  # Ensure at least 1 request
            load_multiplier=load_multiplier,
            account_multiplier=account_multiplier,
            burst_allowance=max(1, burst_allowance),
            fairness_factor=self.fairness_weights[account_type],
        )

    async def check_rate_limit(self, request: Any) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check if request should be rate limited.

        Returns:
            Tuple of (allowed, reason, details)
        """
        if not self.rate_limit_config.enabled:
            return True, "rate_limiting_disabled", {}

        current_time = time.time()
        client_ip = getattr(request.client, "host", "127.0.0.1")

        if client_ip in self.banned_ips:
            if current_time < self.banned_ips[client_ip]:
                return False, "ip_banned", {"unban_time": self.banned_ips[client_ip]}
            else:
                del self.banned_ips[client_ip]
                self.ip_violations[client_ip] = 0

        account_type, user_id = self._get_account_type(request)

        # Calculate dynamic limits
        limits = self._calculate_dynamic_limits(account_type)

        # IP-based rate limiting
        ip_requests = self.ip_requests[client_ip]
        ip_requests.append(current_time)

        cutoff_time = current_time - self.rate_limit_config.window_size_seconds
        recent_ip_requests = sum(
            1 for req_time in ip_requests if req_time >= cutoff_time
        )

        if recent_ip_requests > limits.current_limit:
            self.ip_violations[client_ip] += 1
            if self.ip_violations[client_ip] >= self.rate_limit_config.ban_threshold:
                unban_time = current_time + self.rate_limit_config.ban_duration_seconds
                self.banned_ips[client_ip] = unban_time
                logger.warning(
                    f"IP {client_ip} banned for {self.rate_limit_config.ban_duration_seconds} seconds."
                )
            return False, "rate_limit_exceeded", {"type": "ip"}

        # User-based rate limiting
        if user_id:
            user_requests = self.user_requests[user_id]
            user_requests.append(current_time)
            recent_user_requests = sum(
                1 for req_time in user_requests if req_time >= cutoff_time
            )
            if (
                recent_user_requests
                > self.rate_limit_config.per_user_requests_per_minute
            ):
                return False, "rate_limit_exceeded", {"type": "user"}

        return True, "allowed", {}

    async def process_request(self, request: Any) -> Tuple[bool, Optional[Any]]:
        """
        Process incoming request through protection system.

        Returns:
            Tuple of (allowed, response_if_blocked)
        """
        try:
            # Check rate limiting
            allowed, reason, details = await self.check_rate_limit(request)

            if not allowed:
                if FASTAPI_AVAILABLE:
                    from fastapi.responses import JSONResponse

                    response = JSONResponse(
                        content={
                            "error": "Rate limit exceeded",
                            "reason": reason,
                            "details": details,
                            "retry_after": self.rate_limit_config.window_size_seconds,
                        },
                        status_code=429,
                    )
                else:
                    # Fallback response
                    response = {
                        "error": "Rate limit exceeded",
                        "reason": reason,
                        "details": details,
                        "retry_after": self.rate_limit_config.window_size_seconds,
                        "status_code": 429,
                    }
                return False, response

            return True, None

        except Exception as e:
            logger.error(f"Error in protection system: {e}")
            # On error, allow request to proceed
            return True, None

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive protection system status."""
        return {
            "system_metrics": {
                "cpu_usage": self.system_metrics.cpu_usage,
                "memory_usage": self.system_metrics.memory_usage,
                "load_level": self.system_metrics.load_level.value,
                "active_connections": self.system_metrics.active_connections,
                "requests_per_second": self.system_metrics.requests_per_second,
            },
            "rate_limiting": {
                "enabled": self.rate_limit_config.enabled,
                "active_ips": len(self.ip_requests),
                "active_users": len(self.user_requests),
            },
            "monitoring": {
                "is_running": self.is_running,
                "metrics_history_size": len(self.metrics_history),
            },
        }

    async def shutdown(self) -> None:
        """Shutdown the protection system."""
        await self.stop_monitoring()
        logger.info("Integrated Protection System shut down")


# Global protection system instance
_global_protection_system: Optional[IntegratedProtectionSystem] = None


def get_protection_system() -> IntegratedProtectionSystem:
    """Get the global protection system instance."""
    global _global_protection_system
    if _global_protection_system is None:
        _global_protection_system = IntegratedProtectionSystem()
    return _global_protection_system


async def initialize_protection_system(
    config: Optional[RateLimitConfig] = None,
) -> IntegratedProtectionSystem:
    """Initialize and start the protection system."""
    global _global_protection_system
    _global_protection_system = IntegratedProtectionSystem(config)
    await _global_protection_system.start_monitoring()
    return _global_protection_system


async def shutdown_protection_system() -> None:
    """Shutdown the global protection system."""
    global _global_protection_system
    if _global_protection_system:
        await _global_protection_system.shutdown()
        _global_protection_system = None


__all__ = [
    "IntegratedProtectionSystem",
    "SystemLoadLevel",
    "AccountType",
    "RateLimitStrategy",
    "SystemMetrics",
    "DynamicLimits",
    "AccountTypeRateLimit",
    "RateLimitConfig",
    "get_protection_system",
    "initialize_protection_system",
    "shutdown_protection_system",
]
