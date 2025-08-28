#!/usr/bin/env python3
"""
Unified Rate Limiting System for PlexiChat
Provides dynamic rate limiting with system resource monitoring, user tier integration,
DDoS protection integration, and distributed Redis backend support.
"""

import asyncio
import hashlib
import json
import logging
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics
from collections import defaultdict, deque

# System monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

# Redis support
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    try:
        import redis
        REDIS_AVAILABLE = True
    except ImportError:
        REDIS_AVAILABLE = False
        redis = None

# FastAPI
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

# PlexiChat imports
try:
    from plexichat.src.plexichat.core.config_manager import get_config_manager
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    get_config_manager = None

try:
    from plexichat.core.security.ddos_protection import get_ddos_protection
    DDOS_AVAILABLE = True
except ImportError:
    DDOS_AVAILABLE = False
    get_ddos_protection = None

try:
    from plexichat.src.plexichat.core.security.security_manager import get_unified_security_system
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    get_unified_security_system = None

logger = logging.getLogger(__name__)


class UserTier(Enum):
    """User tier levels for rate limiting."""
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    PREMIUM = "premium"
    ADMIN = "admin"
    SYSTEM = "system"


class RateLimitType(Enum):
    """Types of rate limits."""
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"


@dataclass
class RateLimitConfig:
    """Rate limit configuration for different user tiers."""
    requests_per_minute: int
    burst_limit: int
    window_size_seconds: int = 60
    enabled: bool = True


@dataclass
class SystemResourceThresholds:
    """System resource thresholds for dynamic rate limiting."""
    cpu_threshold: float = 80.0
    memory_threshold: float = 80.0
    disk_threshold: float = 90.0
    network_threshold: float = 80.0
    load_threshold: float = 5.0


@dataclass
class RateLimitMetrics:
    """Rate limiting metrics for monitoring."""
    total_requests: int = 0
    allowed_requests: int = 0
    blocked_requests: int = 0
    current_rps: float = 0.0
    peak_rps: float = 0.0
    active_limits: int = 0
    system_load_factor: float = 1.0
    ddos_threat_level: str = "low"


@dataclass
class RateLimitEntry:
    """Individual rate limit entry."""
    key: str
    count: int
    window_start: float
    last_request: float
    tier: UserTier
    blocked_until: Optional[float] = None


class SystemMonitor:
    """System resource monitoring for dynamic rate limiting."""
    
    def __init__(self, thresholds: SystemResourceThresholds):
        self.thresholds = thresholds
        self.enabled = PSUTIL_AVAILABLE
        self.current_metrics = {}
        self.history = deque(maxlen=60)  # Keep 1 minute of history
        self._lock = threading.RLock()
        
        if not self.enabled:
            logger.warning("psutil not available - system monitoring disabled")
    
    def get_system_load_factor(self) -> float:
        """Get system load factor (1.0 = normal, >1.0 = high load)."""
        if not self.enabled:
            return 1.0
        
        try:
            # Get current system metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Calculate load factors
            cpu_factor = max(1.0, cpu_percent / self.thresholds.cpu_threshold)
            memory_factor = max(1.0, memory.percent / self.thresholds.memory_threshold)
            disk_factor = max(1.0, disk.percent / self.thresholds.disk_threshold)
            
            # Get load average if available (Unix systems)
            load_factor = 1.0
            try:
                load_avg = psutil.getloadavg()[0]  # 1-minute load average
                cpu_count = psutil.cpu_count()
                if cpu_count:
                    load_factor = max(1.0, load_avg / (cpu_count * self.thresholds.load_threshold))
            except (AttributeError, OSError):
                pass  # getloadavg not available on Windows
            
            # Take the maximum factor (most constrained resource)
            overall_factor = max(cpu_factor, memory_factor, disk_factor, load_factor)
            
            # Store metrics
            with self._lock:
                self.current_metrics = {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent,
                    'load_factor': load_factor,
                    'overall_factor': overall_factor,
                    'timestamp': time.time()
                }
                self.history.append(self.current_metrics.copy())
            
            return overall_factor
            
        except Exception as e:
            logger.error(f"Error getting system load factor: {e}")
            return 1.0
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        with self._lock:
            return self.current_metrics.copy()
    
    def get_history(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Get system metrics history."""
        cutoff_time = time.time() - (minutes * 60)
        with self._lock:
            return [m for m in self.history if m.get('timestamp', 0) > cutoff_time]


class RedisRateLimitBackend:
    """Redis backend for distributed rate limiting."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self.redis_client = None
        self.enabled = REDIS_AVAILABLE
        self.key_prefix = "plexichat:ratelimit:"
        
        if not self.enabled:
            logger.warning("Redis not available - using in-memory rate limiting")
    
    async def initialize(self):
        """Initialize Redis connection."""
        if not self.enabled:
            return
        
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            await self.redis_client.ping()
            logger.info("Redis rate limiting backend initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Redis backend: {e}")
            self.enabled = False
    
    async def increment(self, key: str, window_seconds: int) -> Tuple[int, float]:
        """Increment counter and return (count, window_start)."""
        if not self.enabled or not self.redis_client:
            raise RuntimeError("Redis backend not available")
        
        redis_key = f"{self.key_prefix}{key}"
        current_time = time.time()
        window_start = int(current_time // window_seconds) * window_seconds
        window_key = f"{redis_key}:{window_start}"
        
        pipe = self.redis_client.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, window_seconds * 2)  # Keep for 2 windows
        results = await pipe.execute()
        
        return results[0], window_start
    
    async def get_count(self, key: str, window_seconds: int) -> Tuple[int, float]:
        """Get current count for key."""
        if not self.enabled or not self.redis_client:
            raise RuntimeError("Redis backend not available")
        
        redis_key = f"{self.key_prefix}{key}"
        current_time = time.time()
        window_start = int(current_time // window_seconds) * window_seconds
        window_key = f"{redis_key}:{window_start}"
        
        count = await self.redis_client.get(window_key)
        return int(count) if count else 0, window_start
    
    async def cleanup(self):
        """Cleanup Redis connection."""
        if self.redis_client:
            await self.redis_client.close()


class InMemoryRateLimitBackend:
    """In-memory backend for single-node rate limiting."""
    
    def __init__(self):
        self.data: Dict[str, RateLimitEntry] = {}
        self._lock = threading.RLock()
        self._cleanup_task = None
        self._start_cleanup()
    
    def _start_cleanup(self):
        """Start background cleanup task."""
        async def cleanup_expired():
            while True:
                try:
                    await asyncio.sleep(60)  # Cleanup every minute
                    self._cleanup_expired_entries()
                except Exception as e:
                    logger.error(f"Error in rate limit cleanup: {e}")
        
        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(cleanup_expired())
    
    def _cleanup_expired_entries(self):
        """Remove expired rate limit entries."""
        current_time = time.time()
        with self._lock:
            expired_keys = [
                key for key, entry in self.data.items()
                if current_time - entry.window_start > 120  # 2 minutes old
            ]
            for key in expired_keys:
                del self.data[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired rate limit entries")
    
    async def increment(self, key: str, window_seconds: int) -> Tuple[int, float]:
        """Increment counter and return (count, window_start)."""
        current_time = time.time()
        window_start = int(current_time // window_seconds) * window_seconds
        
        with self._lock:
            if key not in self.data:
                self.data[key] = RateLimitEntry(
                    key=key,
                    count=0,
                    window_start=window_start,
                    last_request=current_time,
                    tier=UserTier.ANONYMOUS
                )
            
            entry = self.data[key]
            
            # Reset counter if new window
            if entry.window_start < window_start:
                entry.count = 0
                entry.window_start = window_start
            
            entry.count += 1
            entry.last_request = current_time
            
            return entry.count, window_start
    
    async def get_count(self, key: str, window_seconds: int) -> Tuple[int, float]:
        """Get current count for key."""
        current_time = time.time()
        window_start = int(current_time // window_seconds) * window_seconds
        
        with self._lock:
            if key not in self.data:
                return 0, window_start
            
            entry = self.data[key]
            
            # Reset if new window
            if entry.window_start < window_start:
                entry.count = 0
                entry.window_start = window_start
            
            return entry.count, window_start


class UnifiedRateLimiter:
    """Unified rate limiting system with dynamic scaling and DDoS integration."""
    
    def __init__(self, redis_url: Optional[str] = None):
        # Load configuration
        self.config = self._load_config()
        
        # Initialize backends
        self.redis_backend = RedisRateLimitBackend(redis_url) if redis_url else None
        self.memory_backend = InMemoryRateLimitBackend()
        
        # System monitoring
        self.system_monitor = SystemMonitor(self.config.get('resource_thresholds', SystemResourceThresholds()))
        
        # Rate limit configurations by tier
        self.tier_configs = self._initialize_tier_configs()
        
        # Metrics
        self.metrics = RateLimitMetrics()
        self.request_history = deque(maxlen=1000)
        
        # Integration components
        self.ddos_protection = None
        self.security_system = None
        
        # Background tasks
        self._metrics_task = None
        self._start_background_tasks()
        
        logger.info("Unified Rate Limiter initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from config manager."""
        default_config = {
            'enabled': True,
            'redis_enabled': True,
            'system_monitoring_enabled': True,
            'ddos_integration_enabled': True,
            'resource_thresholds': SystemResourceThresholds(),
            'tier_configs': {
                UserTier.ANONYMOUS: RateLimitConfig(10, 20),
                UserTier.AUTHENTICATED: RateLimitConfig(60, 120),
                UserTier.PREMIUM: RateLimitConfig(600, 1200),
                UserTier.ADMIN: RateLimitConfig(120, 240),
                UserTier.SYSTEM: RateLimitConfig(10000, 20000)
            }
        }
        
        if CONFIG_AVAILABLE and get_config_manager:
            try:
                config_manager = get_config_manager()
                rate_limit_config = getattr(config_manager._config, 'rate_limiting', {})
                default_config.update(rate_limit_config)
            except Exception as e:
                logger.warning(f"Failed to load rate limiting config: {e}")
        
        return default_config
    
    def _initialize_tier_configs(self) -> Dict[UserTier, RateLimitConfig]:
        """Initialize rate limit configurations for each user tier."""
        return self.config.get('tier_configs', {
            UserTier.ANONYMOUS: RateLimitConfig(10, 20),
            UserTier.AUTHENTICATED: RateLimitConfig(60, 120),
            UserTier.PREMIUM: RateLimitConfig(600, 1200),
            UserTier.ADMIN: RateLimitConfig(120, 240),
            UserTier.SYSTEM: RateLimitConfig(10000, 20000)
        })
    
    def _start_background_tasks(self):
        """Start background monitoring tasks."""
        async def update_metrics():
            """Update rate limiting metrics."""
            while True:
                try:
                    await asyncio.sleep(10)  # Update every 10 seconds
                    await self._update_metrics()
                except Exception as e:
                    logger.error(f"Error updating rate limit metrics: {e}")
        
        if not self._metrics_task or self._metrics_task.done():
            self._metrics_task = asyncio.create_task(update_metrics())
    
    async def initialize(self):
        """Initialize the rate limiter."""
        # Initialize Redis backend if available
        if self.redis_backend:
            await self.redis_backend.initialize()
        
        # Initialize integrations
        if DDOS_AVAILABLE and get_ddos_protection:
            try:
                self.ddos_protection = get_ddos_protection()
            except Exception as e:
                logger.warning(f"Failed to initialize DDoS integration: {e}")
        
        if SECURITY_AVAILABLE and get_unified_security_system:
            try:
                self.security_system = get_unified_security_system()
            except Exception as e:
                logger.warning(f"Failed to initialize security system integration: {e}")
    
    async def _update_metrics(self):
        """Update rate limiting metrics."""
        current_time = time.time()
        
        # Calculate current RPS
        recent_requests = [t for t in self.request_history if current_time - t < 60]
        self.metrics.current_rps = len(recent_requests) / 60.0
        self.metrics.peak_rps = max(self.metrics.peak_rps, self.metrics.current_rps)
        
        # Update system load factor
        self.metrics.system_load_factor = self.system_monitor.get_system_load_factor()
        
        # Update DDoS threat level
        if self.ddos_protection:
            try:
                status = self.ddos_protection.get_protection_status()
                self.metrics.ddos_threat_level = status.get('stats', {}).get('threat_level', 'low')
            except Exception as e:
                logger.error(f"Error getting DDoS status: {e}")
    
    def _get_user_tier(self, request: Request) -> UserTier:
        """Determine user tier from request."""
        # Try to get user info from security system
        if self.security_system:
            try:
                # Check for authentication token
                auth_header = request.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    is_valid, payload = self.security_system.token_manager.verify_token(token)
                    if is_valid and payload:
                        permissions = set(payload.get('permissions', []))
                        if 'admin' in permissions:
                            return UserTier.ADMIN
                        elif 'premium' in permissions:
                            return UserTier.PREMIUM
                        else:
                            return UserTier.AUTHENTICATED
            except Exception as e:
                logger.debug(f"Error determining user tier: {e}")
        
        # Check for API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return UserTier.AUTHENTICATED
        
        return UserTier.ANONYMOUS
    
    def _get_rate_limit_key(self, request: Request, limit_type: RateLimitType) -> str:
        """Generate rate limit key for request."""
        if limit_type == RateLimitType.PER_IP:
            client_ip = self._get_client_ip(request)
            return f"ip:{client_ip}"
        elif limit_type == RateLimitType.PER_USER:
            user_id = self._get_user_id(request)
            return f"user:{user_id}"
        elif limit_type == RateLimitType.PER_ENDPOINT:
            endpoint = f"{request.method}:{request.url.path}"
            return f"endpoint:{endpoint}"
        elif limit_type == RateLimitType.GLOBAL:
            return "global"
        else:
            return f"unknown:{hash(str(request))}"
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fallback to client host
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return 'unknown'
    
    def _get_user_id(self, request: Request) -> str:
        """Extract user ID from request."""
        if self.security_system:
            try:
                auth_header = request.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    is_valid, payload = self.security_system.token_manager.verify_token(token)
                    if is_valid and payload:
                        return payload.get('user_id', 'anonymous')
            except Exception:
                pass
        
        return self._get_client_ip(request)
    
    def _calculate_dynamic_limit(self, base_config: RateLimitConfig) -> RateLimitConfig:
        """Calculate dynamic rate limit based on system load and threat level."""
        # Start with base configuration
        dynamic_config = RateLimitConfig(
            requests_per_minute=base_config.requests_per_minute,
            burst_limit=base_config.burst_limit,
            window_size_seconds=base_config.window_size_seconds,
            enabled=base_config.enabled
        )
        
        # Apply system load factor
        load_factor = self.metrics.system_load_factor
        if load_factor > 1.0:
            # Reduce limits when system is under load
            reduction_factor = min(0.1, 1.0 / load_factor)  # Minimum 10% of original
            dynamic_config.requests_per_minute = int(base_config.requests_per_minute * reduction_factor)
            dynamic_config.burst_limit = int(base_config.burst_limit * reduction_factor)
        
        # Apply DDoS threat level adjustments
        threat_level = self.metrics.ddos_threat_level
        if threat_level in ['high', 'critical']:
            # Further reduce limits during attacks
            threat_reduction = 0.5 if threat_level == 'high' else 0.2
            dynamic_config.requests_per_minute = int(dynamic_config.requests_per_minute * threat_reduction)
            dynamic_config.burst_limit = int(dynamic_config.burst_limit * threat_reduction)
        
        # Ensure minimum limits
        dynamic_config.requests_per_minute = max(1, dynamic_config.requests_per_minute)
        dynamic_config.burst_limit = max(1, dynamic_config.burst_limit)
        
        return dynamic_config
    
    async def check_rate_limit(self, request: Request) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limits."""
        if not self.config.get('enabled', True):
            return True, {}
        
        # Record request
        current_time = time.time()
        self.request_history.append(current_time)
        self.metrics.total_requests += 1
        
        # Determine user tier and get configuration
        user_tier = self._get_user_tier(request)
        base_config = self.tier_configs.get(user_tier, self.tier_configs[UserTier.ANONYMOUS])
        
        # Calculate dynamic limits
        dynamic_config = self._calculate_dynamic_limit(base_config)
        
        # Check rate limits for different types
        limit_checks = [
            (RateLimitType.PER_IP, self._get_rate_limit_key(request, RateLimitType.PER_IP)),
            (RateLimitType.PER_USER, self._get_rate_limit_key(request, RateLimitType.PER_USER))
        ]
        
        for limit_type, key in limit_checks:
            allowed, info = await self._check_single_limit(key, dynamic_config)
            if not allowed:
                self.metrics.blocked_requests += 1
                return False, {
                    'limit_type': limit_type.value,
                    'user_tier': user_tier.value,
                    'limit': dynamic_config.requests_per_minute,
                    'window_seconds': dynamic_config.window_size_seconds,
                    'system_load_factor': self.metrics.system_load_factor,
                    'ddos_threat_level': self.metrics.ddos_threat_level,
                    **info
                }
        
        self.metrics.allowed_requests += 1
        return True, {
            'user_tier': user_tier.value,
            'limit': dynamic_config.requests_per_minute,
            'system_load_factor': self.metrics.system_load_factor
        }
    
    async def _check_single_limit(self, key: str, config: RateLimitConfig) -> Tuple[bool, Dict[str, Any]]:
        """Check a single rate limit."""
        try:
            # Try Redis backend first
            if self.redis_backend and self.redis_backend.enabled:
                count, window_start = await self.redis_backend.increment(key, config.window_size_seconds)
            else:
                count, window_start = await self.memory_backend.increment(key, config.window_size_seconds)
            
            # Check if limit exceeded
            allowed = count <= config.requests_per_minute
            
            # Calculate reset time
            reset_time = window_start + config.window_size_seconds
            
            return allowed, {
                'current_count': count,
                'limit': config.requests_per_minute,
                'window_start': window_start,
                'reset_time': reset_time,
                'remaining': max(0, config.requests_per_minute - count)
            }
            
        except Exception as e:
            logger.error(f"Error checking rate limit for {key}: {e}")
            # Fail open - allow request if rate limiting fails
            return True, {'error': str(e)}
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get rate limiting metrics."""
        system_metrics = self.system_monitor.get_metrics()
        
        return {
            'rate_limiting': {
                'total_requests': self.metrics.total_requests,
                'allowed_requests': self.metrics.allowed_requests,
                'blocked_requests': self.metrics.blocked_requests,
                'current_rps': self.metrics.current_rps,
                'peak_rps': self.metrics.peak_rps,
                'block_rate': (self.metrics.blocked_requests / max(self.metrics.total_requests, 1)) * 100,
                'system_load_factor': self.metrics.system_load_factor,
                'ddos_threat_level': self.metrics.ddos_threat_level
            },
            'system_resources': system_metrics,
            'tier_configs': {
                tier.value: {
                    'base_limit': config.requests_per_minute,
                    'dynamic_limit': self._calculate_dynamic_limit(config).requests_per_minute
                }
                for tier, config in self.tier_configs.items()
            },
            'backends': {
                'redis_enabled': self.redis_backend and self.redis_backend.enabled,
                'memory_enabled': True,
                'psutil_available': PSUTIL_AVAILABLE
            }
        }
    
    async def cleanup(self):
        """Cleanup rate limiter resources."""
        if self.redis_backend:
            await self.redis_backend.cleanup()
        
        if self._metrics_task and not self._metrics_task.done():
            self._metrics_task.cancel()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for unified rate limiting."""
    
    def __init__(self, app, rate_limiter: Optional[UnifiedRateLimiter] = None, redis_url: Optional[str] = None):
        super().__init__(app)
        self.rate_limiter = rate_limiter or UnifiedRateLimiter(redis_url)
        self._initialized = False
    
    async def _ensure_initialized(self):
        """Ensure rate limiter is initialized."""
        if not self._initialized:
            await self.rate_limiter.initialize()
            self._initialized = True
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method."""
        await self._ensure_initialized()
        
        # Check rate limits
        allowed, info = await self.rate_limiter.check_rate_limit(request)
        
        if not allowed:
            # Add rate limit headers
            headers = {
                'X-RateLimit-Limit': str(info.get('limit', 0)),
                'X-RateLimit-Remaining': str(info.get('remaining', 0)),
                'X-RateLimit-Reset': str(int(info.get('reset_time', 0))),
                'X-RateLimit-Type': info.get('limit_type', 'unknown'),
                'X-RateLimit-Tier': info.get('user_tier', 'anonymous'),
                'Retry-After': str(info.get('window_seconds', 60))
            }
            
            raise HTTPException(
                status_code=429,
                detail={
                    'error': 'Rate limit exceeded',
                    'message': f"Too many requests for {info.get('user_tier', 'anonymous')} tier",
                    'limit': info.get('limit'),
                    'reset_time': info.get('reset_time'),
                    'system_load_factor': info.get('system_load_factor', 1.0),
                    'ddos_threat_level': info.get('ddos_threat_level', 'low')
                },
                headers=headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to successful responses
        if 'limit' in info:
            response.headers['X-RateLimit-Limit'] = str(info['limit'])
            response.headers['X-RateLimit-Tier'] = info.get('user_tier', 'anonymous')
            response.headers['X-RateLimit-System-Load'] = str(info.get('system_load_factor', 1.0))
        
        return response


# Global rate limiter instance
_global_rate_limiter: Optional[UnifiedRateLimiter] = None


def get_rate_limiter(redis_url: Optional[str] = None) -> UnifiedRateLimiter:
    """Get the global rate limiter instance."""
    global _global_rate_limiter
    if _global_rate_limiter is None:
        _global_rate_limiter = UnifiedRateLimiter(redis_url)
    return _global_rate_limiter


def add_rate_limit_middleware(app, redis_url: Optional[str] = None):
    """Add rate limiting middleware to FastAPI app."""
    rate_limiter = get_rate_limiter(redis_url)
    app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)
    logger.info("Rate limiting middleware added to FastAPI app")
    return rate_limiter


async def initialize_rate_limiter(redis_url: Optional[str] = None) -> UnifiedRateLimiter:
    """Initialize the global rate limiter."""
    rate_limiter = get_rate_limiter(redis_url)
    await rate_limiter.initialize()
    return rate_limiter


async def shutdown_rate_limiter():
    """Shutdown the global rate limiter."""
    global _global_rate_limiter
    if _global_rate_limiter:
        await _global_rate_limiter.cleanup()
        _global_rate_limiter = None


__all__ = [
    "UnifiedRateLimiter",
    "RateLimitMiddleware",
    "UserTier",
    "RateLimitType",
    "RateLimitConfig",
    "SystemResourceThresholds",
    "RateLimitMetrics",
    "get_rate_limiter",
    "add_rate_limit_middleware",
    "initialize_rate_limiter",
    "shutdown_rate_limiter"
]