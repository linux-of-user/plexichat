"""
Rate Limiting System for PlexiChat
Advanced rate limiting with per-user, per-IP, and dynamic global limits.

Features:
- Token bucket algorithm for smooth rate limiting
- Per-user limits for different operations (login, message send, file upload)
- Per-IP limits with higher thresholds for shared infrastructure
- Dynamic global rate limiting based on system load
- Configurable limits via YAML configuration
- Real-time metrics and monitoring
"""

import asyncio
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(default=0.0)
    last_refill: float = field(default_factory=time.time)

    def consume(self, tokens: float = 1.0) -> bool:
        """Consume tokens from the bucket. Returns True if successful."""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def get_tokens_available(self) -> float:
        """Get number of tokens currently available."""
        self._refill()
        return self.tokens

    def time_to_next_token(self) -> float:
        """Get time in seconds until next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate


@dataclass
class RateLimitMetrics:
    """Metrics for rate limiting."""
    requests_total: int = 0
    requests_allowed: int = 0
    requests_blocked: int = 0
    current_system_load: float = 0.0
    active_buckets: int = 0
    last_cleanup: float = field(default_factory=time.time)


class RateLimitingSystem:
    """
    Advanced rate limiting system with multiple layers.

    Features:
    - Per-user rate limiting with token buckets
    - Per-IP rate limiting with higher limits
    - Dynamic global rate limiting based on system load
    - Automatic cleanup of expired buckets
    - Real-time metrics and monitoring
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)

        if not self.enabled:
            logger.info("Rate limiting is disabled")
            return

        # Rate limit configurations
        self.per_user_limits = config.get('per_user_limits', {
            'login': 5,
            'message_send': 100,
            'file_upload': 20
        })

        self.per_ip_limits = config.get('per_ip_limits', {
            'login': 20,
            'message_send': 500,
            'file_upload': 100
        })

        # Dynamic global rate limiting
        self.dynamic_config = config.get('dynamic_global', {
            'enabled': True,
            'system_load_threshold': 0.8,
            'scaling_factor': 0.5
        })

        # Token buckets storage
        self.user_buckets: Dict[str, Dict[str, TokenBucket]] = defaultdict(dict)
        self.ip_buckets: Dict[str, Dict[str, TokenBucket]] = defaultdict(dict)
        self.global_buckets: Dict[str, TokenBucket] = {}

        # Metrics
        self.metrics = RateLimitMetrics()

        # Cleanup settings
        self.bucket_ttl = 3600  # 1 hour
        self.cleanup_interval = 300  # 5 minutes

        # Threading lock for thread safety
        self._lock = threading.RLock()

        # Background tasks (will be started later)
        self._cleanup_task: Optional[asyncio.Task] = None

    def start_background_tasks(self):
        """Start background tasks when event loop is available."""
        if self.enabled and not self._cleanup_task:
            self._start_cleanup_task()

        # Initialize global buckets
        self._initialize_global_buckets()

        logger.info("Rate limiting system initialized")

    def _initialize_global_buckets(self):
        """Initialize global rate limiting buckets."""
        for operation, limit in self.per_user_limits.items():
            # Global buckets use higher limits
            global_limit = limit * 10  # 10x the per-user limit
            self.global_buckets[operation] = TokenBucket(
                capacity=global_limit,
                refill_rate=global_limit / 60.0  # Refill over 1 minute
            )

    def _start_cleanup_task(self):
        """Start the background cleanup task."""
        if not self.enabled:
            return

        async def cleanup_worker():
            """Background worker for cleaning up expired buckets."""
            while True:
                try:
                    await asyncio.sleep(self.cleanup_interval)
                    self._cleanup_expired_buckets()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in rate limit cleanup: {e}")

        self._cleanup_task = asyncio.create_task(cleanup_worker())

    def _cleanup_expired_buckets(self):
        """Clean up expired rate limiting buckets."""
        if not self.enabled:
            return

        current_time = time.time()
        cleanup_threshold = current_time - self.bucket_ttl

        with self._lock:
            # Clean up user buckets
            expired_users = []
            for user_id, buckets in self.user_buckets.items():
                # Remove buckets that haven't been used recently
                active_buckets = {}
                for op, bucket in buckets.items():
                    if bucket.last_refill > cleanup_threshold:
                        active_buckets[op] = bucket
                    else:
                        logger.debug(f"Cleaned up expired bucket for user {user_id}, operation {op}")

                if active_buckets:
                    self.user_buckets[user_id] = active_buckets
                else:
                    expired_users.append(user_id)

            for user_id in expired_users:
                del self.user_buckets[user_id]

            # Clean up IP buckets
            expired_ips = []
            for ip, buckets in self.ip_buckets.items():
                active_buckets = {}
                for op, bucket in buckets.items():
                    if bucket.last_refill > cleanup_threshold:
                        active_buckets[op] = bucket

                if active_buckets:
                    self.ip_buckets[ip] = active_buckets
                else:
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self.ip_buckets[ip]

            # Update metrics
            self.metrics.active_buckets = len(self.user_buckets) + len(self.ip_buckets)
            self.metrics.last_cleanup = current_time

            if expired_users or expired_ips:
                logger.info(f"Cleaned up {len(expired_users)} user buckets and {len(expired_ips)} IP buckets")

    def _get_or_create_bucket(self, buckets_dict: Dict, key: str, operation: str, limit: int) -> TokenBucket:
        """Get or create a token bucket."""
        if key not in buckets_dict:
            buckets_dict[key] = {}

        if operation not in buckets_dict[key]:
            buckets_dict[key][operation] = TokenBucket(
                capacity=limit,
                refill_rate=limit / 60.0  # Refill over 1 minute
            )

        return buckets_dict[key][operation]

    def _get_dynamic_limit(self, base_limit: int, operation: str) -> int:
        """Get dynamic limit based on system load."""
        if not self.dynamic_config['enabled']:
            return base_limit

        try:
            # Get current system load
            system_load = psutil.cpu_percent() / 100.0
            self.metrics.current_system_load = system_load

            # If system load is high, scale down limits
            if system_load > self.dynamic_config['system_load_threshold']:
                scaling_factor = self.dynamic_config['scaling_factor']
                new_limit = int(base_limit * scaling_factor)
                logger.debug(f"System load {system_load:.2%}, scaled {operation} limit from {base_limit} to {new_limit}")
                return max(1, new_limit)  # Minimum limit of 1

        except Exception as e:
            logger.error(f"Error getting system load: {e}")

        return base_limit

    async def check_rate_limits(self, context: Any) -> Dict[str, Any]:
        """
        Check all applicable rate limits for a request.

        Args:
            context: SecurityContext with user_id, ip_address, and endpoint info

        Returns:
            Dict with 'allowed', 'message', and 'limit_type' keys
        """
        if not self.enabled:
            return {'allowed': True, 'message': None, 'limit_type': None}

        self.metrics.requests_total += 1

        with self._lock:
            try:
                # Extract context information
                user_id = getattr(context, 'user_id', None)
                ip_address = getattr(context, 'ip_address', None)
                endpoint = getattr(context, 'endpoint', None)

                # Determine operation type from endpoint
                operation = self._classify_operation(endpoint)

                # Check per-user limits
                if user_id:
                    user_limit = self.per_user_limits.get(operation, 60)
                    dynamic_user_limit = self._get_dynamic_limit(user_limit, f"user_{operation}")

                    user_bucket = self._get_or_create_bucket(
                        self.user_buckets, user_id, operation, dynamic_user_limit
                    )

                    if not user_bucket.consume():
                        self.metrics.requests_blocked += 1
                        tokens_available = user_bucket.get_tokens_available()
                        time_to_next = user_bucket.time_to_next_token()

                        return {
                            'allowed': False,
                            'message': f"User rate limit exceeded for {operation}. "
                                     f"Available tokens: {tokens_available:.1f}, "
                                     f"Next token in: {time_to_next:.1f}s",
                            'limit_type': 'per_user'
                        }

                # Check per-IP limits
                if ip_address:
                    ip_limit = self.per_ip_limits.get(operation, 300)
                    dynamic_ip_limit = self._get_dynamic_limit(ip_limit, f"ip_{operation}")

                    ip_bucket = self._get_or_create_bucket(
                        self.ip_buckets, ip_address, operation, dynamic_ip_limit
                    )

                    if not ip_bucket.consume():
                        self.metrics.requests_blocked += 1
                        tokens_available = ip_bucket.get_tokens_available()
                        time_to_next = ip_bucket.time_to_next_token()

                        return {
                            'allowed': False,
                            'message': f"IP rate limit exceeded for {operation}. "
                                     f"Available tokens: {tokens_available:.1f}, "
                                     f"Next token in: {time_to_next:.1f}s",
                            'limit_type': 'per_ip'
                        }

                # Check global limits
                if operation in self.global_buckets:
                    global_bucket = self.global_buckets[operation]
                    if not global_bucket.consume():
                        self.metrics.requests_blocked += 1
                        tokens_available = global_bucket.get_tokens_available()
                        time_to_next = global_bucket.time_to_next_token()

                        return {
                            'allowed': False,
                            'message': f"Global rate limit exceeded for {operation}. "
                                     f"Available tokens: {tokens_available:.1f}, "
                                     f"Next token in: {time_to_next:.1f}s",
                            'limit_type': 'global'
                        }

                # All checks passed
                self.metrics.requests_allowed += 1
                return {'allowed': True, 'message': None, 'limit_type': None}

            except Exception as e:
                logger.error(f"Error in rate limit check: {e}")
                # Allow request on error to avoid blocking legitimate users
                return {'allowed': True, 'message': None, 'limit_type': None}

    def _classify_operation(self, endpoint: Optional[str]) -> str:
        """Classify the operation type from the endpoint."""
        if not endpoint:
            return 'unknown'

        endpoint_lower = endpoint.lower()

        # Classify based on endpoint patterns
        if any(pattern in endpoint_lower for pattern in ['login', 'auth', 'authenticate']):
            return 'login'
        elif any(pattern in endpoint_lower for pattern in ['message', 'send', 'chat']):
            return 'message_send'
        elif any(pattern in endpoint_lower for pattern in ['upload', 'file']):
            return 'file_upload'
        else:
            return 'other'

    def get_rate_limit_status(self, user_id: Optional[str] = None, ip_address: Optional[str] = None) -> Dict[str, Any]:
        """Get current rate limiting status."""
        if not self.enabled:
            return {'enabled': False}

        status = {
            'enabled': True,
            'metrics': {
                'requests_total': self.metrics.requests_total,
                'requests_allowed': self.metrics.requests_allowed,
                'requests_blocked': self.metrics.requests_blocked,
                'block_rate': (self.metrics.requests_blocked / max(self.metrics.requests_total, 1)) * 100,
                'current_system_load': self.metrics.current_system_load,
                'active_buckets': self.metrics.active_buckets,
                'last_cleanup': self.metrics.last_cleanup
            },
            'config': {
                'per_user_limits': self.per_user_limits,
                'per_ip_limits': self.per_ip_limits,
                'dynamic_global': self.dynamic_config
            }
        }

        # Add user-specific status
        if user_id and user_id in self.user_buckets:
            user_status = {}
            for operation, bucket in self.user_buckets[user_id].items():
                user_status[operation] = {
                    'tokens_available': bucket.get_tokens_available(),
                    'capacity': bucket.capacity,
                    'time_to_next_token': bucket.time_to_next_token()
                }
            status['user_status'] = user_status

        # Add IP-specific status
        if ip_address and ip_address in self.ip_buckets:
            ip_status = {}
            for operation, bucket in self.ip_buckets[ip_address].items():
                ip_status[operation] = {
                    'tokens_available': bucket.get_tokens_available(),
                    'capacity': bucket.capacity,
                    'time_to_next_token': bucket.time_to_next_token()
                }
            status['ip_status'] = ip_status

        # Add global status
        global_status = {}
        for operation, bucket in self.global_buckets.items():
            global_status[operation] = {
                'tokens_available': bucket.get_tokens_available(),
                'capacity': bucket.capacity,
                'time_to_next_token': bucket.time_to_next_token()
            }
        status['global_status'] = global_status

        return status

    def reset_user_limits(self, user_id: str):
        """Reset rate limits for a specific user."""
        if not self.enabled:
            return

        with self._lock:
            if user_id in self.user_buckets:
                for bucket in self.user_buckets[user_id].values():
                    bucket.tokens = bucket.capacity
                    bucket.last_refill = time.time()
                logger.info(f"Reset rate limits for user {user_id}")

    def reset_ip_limits(self, ip_address: str):
        """Reset rate limits for a specific IP."""
        if not self.enabled:
            return

        with self._lock:
            if ip_address in self.ip_buckets:
                for bucket in self.ip_buckets[ip_address].values():
                    bucket.tokens = bucket.capacity
                    bucket.last_refill = time.time()
                logger.info(f"Reset rate limits for IP {ip_address}")

    def update_config(self, new_config: Dict[str, Any]):
        """Update rate limiting configuration."""
        if not self.enabled:
            return

        with self._lock:
            self.config.update(new_config)
            self.per_user_limits = self.config.get('per_user_limits', self.per_user_limits)
            self.per_ip_limits = self.config.get('per_ip_limits', self.per_ip_limits)
            self.dynamic_config = self.config.get('dynamic_global', self.dynamic_config)

            # Reinitialize global buckets with new limits
            self._initialize_global_buckets()

            logger.info("Rate limiting configuration updated")

    async def shutdown(self):
        """Shutdown the rate limiting system."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("Rate limiting system shut down")


__all__ = ["RateLimitingSystem", "TokenBucket", "RateLimitMetrics"]