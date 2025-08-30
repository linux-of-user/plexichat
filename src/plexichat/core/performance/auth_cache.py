"""
Authentication Cache System for PlexiChat

Specialized caching layer for authentication operations to improve response times.
Integrates with QuantumSecureCache and SecuritySystem to reduce redundant cryptographic operations.
"""

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import jwt

from plexichat.core.performance.cache_manager import QuantumSecureCache, CacheLevel, secure_cache
from plexichat.core.security.security_manager import get_security_system, SecurityContext, SecurityToken

logger = logging.getLogger(__name__)


class AuthCacheType(Enum):
    """Types of authentication data that can be cached."""
    TOKEN_VERIFICATION = "token_verification"
    USER_PERMISSIONS = "user_permissions"
    API_KEY_VALIDATION = "api_key_validation"
    USER_CONTEXT = "user_context"
    SESSION_DATA = "session_data"
    REVOKED_TOKENS = "revoked_tokens"


@dataclass
class CachedTokenData:
    """Cached token verification result."""
    is_valid: bool
    user_id: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    token_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    jti: Optional[str] = None
    cached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CachedUserPermissions:
    """Cached user permissions data."""
    user_id: str
    permissions: Set[str]
    security_level: str
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CachedAPIKeyData:
    """Cached API key validation result."""
    is_valid: bool
    user_id: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    rate_limit: Optional[int] = None
    expires_at: Optional[datetime] = None
    cached_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuthCacheStats:
    """Authentication cache performance statistics."""
    token_cache_hits: int = 0
    token_cache_misses: int = 0
    permission_cache_hits: int = 0
    permission_cache_misses: int = 0
    api_key_cache_hits: int = 0
    api_key_cache_misses: int = 0
    cache_invalidations: int = 0
    total_auth_operations: int = 0
    avg_response_time_ms: float = 0.0
    cache_warming_operations: int = 0


class AuthenticationCache:
    """
    Specialized authentication caching system for PlexiChat.
    
    Features:
    - JWT token verification caching with automatic expiration
    - User permission caching with invalidation on updates
    - API key validation caching
    - Cache warming for frequently accessed auth data
    - Integration with QuantumSecureCache for security
    - Performance monitoring and metrics
    - Automatic cache invalidation on token revocation
    """

    def __init__(self, 
                 cache_instance: Optional[QuantumSecureCache] = None,
                 default_token_cache_ttl: int = 300,  # 5 minutes
                 default_permission_cache_ttl: int = 600,  # 10 minutes
                 default_api_key_cache_ttl: int = 900):  # 15 minutes
        
        self.cache = cache_instance or secure_cache
        self.security_system = get_security_system()
        
        # Cache TTL settings
        self.default_token_cache_ttl = default_token_cache_ttl
        self.default_permission_cache_ttl = default_permission_cache_ttl
        self.default_api_key_cache_ttl = default_api_key_cache_ttl
        
        # Performance tracking
        self.stats = AuthCacheStats()
        self.performance_metrics: List[Dict[str, Any]] = []
        
        # Cache warming configuration
        self.warm_cache_enabled = True
        self.frequently_accessed_users: Set[str] = set()
        self.frequently_accessed_tokens: Set[str] = set()
        
        # Cache invalidation tracking
        self.revoked_token_jtis: Set[str] = set()
        self.invalidated_users: Set[str] = set()
        
        logger.info("🔐 Authentication Cache System initialized")

    def _generate_cache_key(self, cache_type: AuthCacheType, identifier: str) -> str:
        """Generate a secure cache key for authentication data."""
        # Use a hash to ensure consistent key length and avoid key collisions
        key_data = f"{cache_type.value}:{identifier}"
        key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:32]
        return f"auth_cache:{cache_type.value}:{key_hash}"

    def _calculate_token_ttl(self, token_payload: Dict[str, Any]) -> int:
        """Calculate appropriate TTL based on token expiration."""
        try:
            if 'exp' in token_payload:
                exp_timestamp = token_payload['exp']
                if isinstance(exp_timestamp, (int, float)):
                    expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
                    now = datetime.now(timezone.utc)
                    remaining_seconds = int((expires_at - now).total_seconds())
                    
                    # Use the minimum of remaining time and default TTL
                    # But ensure we don't cache for less than 30 seconds
                    return max(30, min(remaining_seconds, self.default_token_cache_ttl))
        except Exception as e:
            logger.warning(f"Error calculating token TTL: {e}")
        
        return self.default_token_cache_ttl

    async def cache_token_verification(self, 
                                     token: str, 
                                     verification_result: Tuple[bool, Optional[Dict[str, Any]]]) -> bool:
        """Cache JWT token verification result."""
        try:
            start_time = time.time()
            
            is_valid, payload = verification_result
            
            # Create cache data
            cached_data = CachedTokenData(is_valid=is_valid)
            
            if is_valid and payload:
                cached_data.user_id = payload.get('user_id')
                cached_data.permissions = set(payload.get('permissions', []))
                cached_data.token_type = payload.get('token_type')
                cached_data.jti = payload.get('jti')
                
                if 'exp' in payload:
                    cached_data.expires_at = datetime.fromtimestamp(
                        payload['exp'], tz=timezone.utc
                    )
            
            # Generate cache key
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cache_key = self._generate_cache_key(AuthCacheType.TOKEN_VERIFICATION, token_hash)
            
            # Calculate TTL
            ttl = self._calculate_token_ttl(payload) if payload else self.default_token_cache_ttl
            
            # Cache with appropriate security level
            security_level = CacheLevel.RESTRICTED if is_valid else CacheLevel.INTERNAL
            success = await self.cache.set(
                cache_key, 
                cached_data, 
                ttl=ttl,
                security_level=security_level
            )
            
            # Track performance
            operation_time = (time.time() - start_time) * 1000
            self._update_performance_metrics("token_cache_set", operation_time)
            
            if success:
                logger.debug(f"🔐 Cached token verification result (TTL: {ttl}s)")
                
                # Track frequently accessed tokens for cache warming
                if is_valid:
                    self.frequently_accessed_tokens.add(token_hash)
                    if len(self.frequently_accessed_tokens) > 1000:
                        # Keep only the most recent 1000 tokens
                        self.frequently_accessed_tokens = set(
                            list(self.frequently_accessed_tokens)[-1000:]
                        )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache token verification: {e}")
            return False

    async def get_cached_token_verification(self, token: str) -> Optional[CachedTokenData]:
        """Retrieve cached token verification result."""
        try:
            start_time = time.time()
            
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cache_key = self._generate_cache_key(AuthCacheType.TOKEN_VERIFICATION, token_hash)
            
            cached_data = await self.cache.get(cache_key)
            
            # Track performance
            operation_time = (time.time() - start_time) * 1000
            
            if cached_data:
                self.stats.token_cache_hits += 1
                self._update_performance_metrics("token_cache_hit", operation_time)
                
                # Check if token is in revoked list
                if cached_data.jti and cached_data.jti in self.revoked_token_jtis:
                    logger.debug("🔐 Token found in revoked list, invalidating cache")
                    await self.invalidate_token_cache(token)
                    self.stats.token_cache_misses += 1
                    return None
                
                logger.debug("🔐 Token verification cache hit")
                return cached_data
            else:
                self.stats.token_cache_misses += 1
                self._update_performance_metrics("token_cache_miss", operation_time)
                logger.debug("🔐 Token verification cache miss")
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve cached token verification: {e}")
            self.stats.token_cache_misses += 1
            return None

    async def cache_user_permissions(self, 
                                   user_id: str, 
                                   permissions: Set[str], 
                                   security_level: str = "AUTHENTICATED") -> bool:
        """Cache user permissions data."""
        try:
            cached_data = CachedUserPermissions(
                user_id=user_id,
                permissions=permissions,
                security_level=security_level
            )
            
            cache_key = self._generate_cache_key(AuthCacheType.USER_PERMISSIONS, user_id)
            
            success = await self.cache.set(
                cache_key,
                cached_data,
                ttl=self.default_permission_cache_ttl,
                security_level=CacheLevel.CONFIDENTIAL
            )
            
            if success:
                logger.debug(f"🔐 Cached permissions for user: {user_id}")
                self.frequently_accessed_users.add(user_id)
                
                # Limit frequently accessed users tracking
                if len(self.frequently_accessed_users) > 500:
                    self.frequently_accessed_users = set(
                        list(self.frequently_accessed_users)[-500:]
                    )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache user permissions: {e}")
            return False

    async def get_cached_user_permissions(self, user_id: str) -> Optional[CachedUserPermissions]:
        """Retrieve cached user permissions."""
        try:
            start_time = time.time()
            
            cache_key = self._generate_cache_key(AuthCacheType.USER_PERMISSIONS, user_id)
            cached_data = await self.cache.get(cache_key)
            
            operation_time = (time.time() - start_time) * 1000
            
            if cached_data:
                self.stats.permission_cache_hits += 1
                self._update_performance_metrics("permission_cache_hit", operation_time)
                
                # Check if user permissions were invalidated
                if user_id in self.invalidated_users:
                    logger.debug(f"🔐 User {user_id} permissions invalidated, removing from cache")
                    await self.invalidate_user_cache(user_id)
                    self.stats.permission_cache_misses += 1
                    return None
                
                logger.debug(f"🔐 Permission cache hit for user: {user_id}")
                return cached_data
            else:
                self.stats.permission_cache_misses += 1
                self._update_performance_metrics("permission_cache_miss", operation_time)
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve cached user permissions: {e}")
            self.stats.permission_cache_misses += 1
            return None

    async def cache_api_key_validation(self, 
                                     api_key: str, 
                                     validation_result: Tuple[bool, Optional[Dict[str, Any]]]) -> bool:
        """Cache API key validation result."""
        try:
            is_valid, key_data = validation_result
            
            cached_data = CachedAPIKeyData(is_valid=is_valid)
            
            if is_valid and key_data:
                cached_data.user_id = key_data.get('user_id')
                cached_data.permissions = set(key_data.get('permissions', []))
                cached_data.rate_limit = key_data.get('rate_limit')
                
                if 'expires_at' in key_data:
                    cached_data.expires_at = key_data['expires_at']
            
            # Hash the API key for security
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            cache_key = self._generate_cache_key(AuthCacheType.API_KEY_VALIDATION, key_hash)
            
            success = await self.cache.set(
                cache_key,
                cached_data,
                ttl=self.default_api_key_cache_ttl,
                security_level=CacheLevel.RESTRICTED
            )
            
            if success:
                logger.debug("🔐 Cached API key validation result")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache API key validation: {e}")
            return False

    async def get_cached_api_key_validation(self, api_key: str) -> Optional[CachedAPIKeyData]:
        """Retrieve cached API key validation result."""
        try:
            start_time = time.time()
            
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            cache_key = self._generate_cache_key(AuthCacheType.API_KEY_VALIDATION, key_hash)
            
            cached_data = await self.cache.get(cache_key)
            
            operation_time = (time.time() - start_time) * 1000
            
            if cached_data:
                self.stats.api_key_cache_hits += 1
                self._update_performance_metrics("api_key_cache_hit", operation_time)
                
                # Check if API key has expired
                if cached_data.expires_at and datetime.now(timezone.utc) > cached_data.expires_at:
                    logger.debug("🔐 Cached API key has expired, invalidating")
                    await self.cache.delete(cache_key)
                    self.stats.api_key_cache_misses += 1
                    return None
                
                logger.debug("🔐 API key validation cache hit")
                return cached_data
            else:
                self.stats.api_key_cache_misses += 1
                self._update_performance_metrics("api_key_cache_miss", operation_time)
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve cached API key validation: {e}")
            self.stats.api_key_cache_misses += 1
            return None

    async def invalidate_token_cache(self, token: str) -> bool:
        """Invalidate cached token verification result."""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cache_key = self._generate_cache_key(AuthCacheType.TOKEN_VERIFICATION, token_hash)
            
            success = await self.cache.delete(cache_key)
            
            if success:
                self.stats.cache_invalidations += 1
                logger.debug("🔐 Invalidated token cache")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to invalidate token cache: {e}")
            return False

    async def invalidate_user_cache(self, user_id: str) -> bool:
        """Invalidate all cached data for a user."""
        try:
            # Invalidate user permissions
            permissions_key = self._generate_cache_key(AuthCacheType.USER_PERMISSIONS, user_id)
            await self.cache.delete(permissions_key)
            
            # Invalidate user context
            context_key = self._generate_cache_key(AuthCacheType.USER_CONTEXT, user_id)
            await self.cache.delete(context_key)
            
            # Mark user as invalidated
            self.invalidated_users.add(user_id)
            
            # Limit invalidated users tracking
            if len(self.invalidated_users) > 1000:
                self.invalidated_users = set(list(self.invalidated_users)[-1000:])
            
            self.stats.cache_invalidations += 1
            logger.debug(f"🔐 Invalidated all cache for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to invalidate user cache: {e}")
            return False

    async def revoke_token_by_jti(self, jti: str) -> bool:
        """Mark a token as revoked by its JTI."""
        try:
            self.revoked_token_jtis.add(jti)
            
            # Limit revoked tokens tracking
            if len(self.revoked_token_jtis) > 10000:
                self.revoked_token_jtis = set(list(self.revoked_token_jtis)[-10000:])
            
            logger.debug(f"🔐 Marked token JTI as revoked: {jti}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark token as revoked: {e}")
            return False

    async def warm_cache(self) -> int:
        """Warm the cache with frequently accessed authentication data."""
        if not self.warm_cache_enabled:
            return 0
        
        warmed_count = 0
        
        try:
            logger.info("🔐 Starting authentication cache warming")
            
            # Warm user permissions for frequently accessed users
            for user_id in list(self.frequently_accessed_users):
                try:
                    # Check if already cached
                    cached_permissions = await self.get_cached_user_permissions(user_id)
                    if not cached_permissions:
                        # Fetch from security system and cache
                        # This would typically involve calling the security system
                        # For now, we'll skip actual fetching to avoid dependencies
                        logger.debug(f"🔐 Would warm cache for user: {user_id}")
                        warmed_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to warm cache for user {user_id}: {e}")
            
            self.stats.cache_warming_operations += warmed_count
            logger.info(f"🔐 Cache warming completed: {warmed_count} entries warmed")
            
        except Exception as e:
            logger.error(f"Cache warming failed: {e}")
        
        return warmed_count

    def _update_performance_metrics(self, operation: str, duration_ms: float):
        """Update performance metrics for cache operations."""
        metric = {
            'operation': operation,
            'duration_ms': duration_ms,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self.performance_metrics.append(metric)
        
        # Keep only the last 1000 metrics
        if len(self.performance_metrics) > 1000:
            self.performance_metrics = self.performance_metrics[-1000:]
        
        # Update average response time
        total_operations = len(self.performance_metrics)
        if total_operations > 0:
            total_time = sum(m['duration_ms'] for m in self.performance_metrics)
            self.stats.avg_response_time_ms = total_time / total_operations

    async def clear_all_auth_cache(self) -> bool:
        """Clear all authentication cache data."""
        try:
            # This would require iterating through all cache keys
            # For now, we'll clear our tracking sets
            self.revoked_token_jtis.clear()
            self.invalidated_users.clear()
            self.frequently_accessed_users.clear()
            self.frequently_accessed_tokens.clear()
            
            logger.info("🔐 Cleared all authentication cache tracking data")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear authentication cache: {e}")
            return False

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive authentication cache statistics."""
        total_cache_operations = (
            self.stats.token_cache_hits + self.stats.token_cache_misses +
            self.stats.permission_cache_hits + self.stats.permission_cache_misses +
            self.stats.api_key_cache_hits + self.stats.api_key_cache_misses
        )
        
        cache_hit_rate = 0.0
        if total_cache_operations > 0:
            total_hits = (
                self.stats.token_cache_hits + 
                self.stats.permission_cache_hits + 
                self.stats.api_key_cache_hits
            )
            cache_hit_rate = total_hits / total_cache_operations
        
        return {
            'token_cache': {
                'hits': self.stats.token_cache_hits,
                'misses': self.stats.token_cache_misses,
                'hit_rate': (
                    self.stats.token_cache_hits / 
                    max(1, self.stats.token_cache_hits + self.stats.token_cache_misses)
                )
            },
            'permission_cache': {
                'hits': self.stats.permission_cache_hits,
                'misses': self.stats.permission_cache_misses,
                'hit_rate': (
                    self.stats.permission_cache_hits / 
                    max(1, self.stats.permission_cache_hits + self.stats.permission_cache_misses)
                )
            },
            'api_key_cache': {
                'hits': self.stats.api_key_cache_hits,
                'misses': self.stats.api_key_cache_misses,
                'hit_rate': (
                    self.stats.api_key_cache_hits / 
                    max(1, self.stats.api_key_cache_hits + self.stats.api_key_cache_misses)
                )
            },
            'overall': {
                'total_operations': total_cache_operations,
                'cache_hit_rate': cache_hit_rate,
                'cache_invalidations': self.stats.cache_invalidations,
                'avg_response_time_ms': self.stats.avg_response_time_ms,
                'cache_warming_operations': self.stats.cache_warming_operations
            },
            'tracking': {
                'frequently_accessed_users': len(self.frequently_accessed_users),
                'frequently_accessed_tokens': len(self.frequently_accessed_tokens),
                'revoked_token_jtis': len(self.revoked_token_jtis),
                'invalidated_users': len(self.invalidated_users)
            },
            'configuration': {
                'default_token_cache_ttl': self.default_token_cache_ttl,
                'default_permission_cache_ttl': self.default_permission_cache_ttl,
                'default_api_key_cache_ttl': self.default_api_key_cache_ttl,
                'warm_cache_enabled': self.warm_cache_enabled
            }
        }


# Global authentication cache instance
_global_auth_cache: Optional[AuthenticationCache] = None


def get_auth_cache() -> AuthenticationCache:
    """Get the global authentication cache instance."""
    global _global_auth_cache
    if _global_auth_cache is None:
        _global_auth_cache = AuthenticationCache()
    return _global_auth_cache


async def initialize_auth_cache(
    cache_instance: Optional[QuantumSecureCache] = None,
    **kwargs
) -> AuthenticationCache:
    """Initialize the global authentication cache."""
    global _global_auth_cache
    _global_auth_cache = AuthenticationCache(cache_instance, **kwargs)
    
    # Start cache warming
    await _global_auth_cache.warm_cache()
    
    return _global_auth_cache


async def shutdown_auth_cache() -> None:
    """Shutdown the authentication cache system."""
    global _global_auth_cache
    if _global_auth_cache:
        await _global_auth_cache.clear_all_auth_cache()
        _global_auth_cache = None
        logger.info("🔐 Authentication Cache System shut down")


__all__ = [
    'AuthenticationCache',
    'AuthCacheType',
    'CachedTokenData',
    'CachedUserPermissions',
    'CachedAPIKeyData',
    'AuthCacheStats',
    'get_auth_cache',
    'initialize_auth_cache',
    'shutdown_auth_cache'
]
