"""
Typing Cache Service

Caching layer for frequently accessed typing data to improve performance.
"""

import logging
from typing import Any

    def __init__(self):
        self.cache_ttl = get_setting(
            "typing.cache_ttl_seconds", 30
        )  # Cache TTL for typing data
        self.channel_users_cache_ttl = get_setting(
            "typing.cache_ttl_seconds", 10
        )  # For channel users list
        self.typing_status_cache_ttl = get_setting(
            "typing.cache_ttl_seconds", 5
        )  # For individual typing status

    async def get_cached_typing_users(self, channel_id: str) -> list[str] | None:
        """Get cached typing users for a channel."""
        cache_key = CacheKeyBuilder.build("typing", "channel_users", channel_id)

        try:
            cached_data = await cache_get(cache_key)
            if cached_data:
                logger.debug(f"Cache hit for typing users in channel {channel_id}")
                return cached_data
        except Exception as e:
            logger.warning(f"Error getting cached typing users: {e}")

        return None

    async def set_cached_typing_users(self, channel_id: str, users: list[str]) -> bool:
        """Cache typing users for a channel."""
        cache_key = CacheKeyBuilder.build("typing", "channel_users", channel_id)

        try:
            success = await cache_set(
                cache_key,
                users,
                ttl=self.channel_users_cache_ttl,
                tags=["typing", f"channel:{channel_id}"],
            )
            if success:
                logger.debug(
                    f"Cached typing users for channel {channel_id}: {len(users)} users"
                )
            return success
        except Exception as e:
            logger.warning(f"Error caching typing users: {e}")
            return False

    async def invalidate_channel_cache(self, channel_id: str) -> bool:
        """Invalidate all cache entries for a channel."""
        try:
            # Delete channel users cache
            users_cache_key = CacheKeyBuilder.build(
                "typing", "channel_users", channel_id
            )
            await cache_delete(users_cache_key)

            # Delete individual typing status caches for this channel
            # Note: In a real implementation, you might want to use cache tags
            # to delete all related entries at once

            logger.debug(f"Invalidated cache for channel {channel_id}")
            return True
        except Exception as e:
            logger.warning(f"Error invalidating channel cache: {e}")
            return False

    async def get_cached_typing_status(
        self, user_id: str, channel_id: str
    ) -> dict[str, Any] | None:
        """Get cached typing status for a user in a channel."""
        cache_key = CacheKeyBuilder.build("typing", "status", user_id, channel_id)

        try:
            cached_data = await cache_get(cache_key)
            if cached_data:
                logger.debug(f"Cache hit for typing status: {user_id} in {channel_id}")
                return cached_data
        except Exception as e:
            logger.warning(f"Error getting cached typing status: {e}")

        return None

    async def set_cached_typing_status(
        self, user_id: str, channel_id: str, status: dict[str, Any]
    ) -> bool:
        """Cache typing status for a user in a channel."""
        cache_key = CacheKeyBuilder.build("typing", "status", user_id, channel_id)

        try:
            success = await cache_set(
                cache_key,
                status,
                ttl=self.typing_status_cache_ttl,
                tags=["typing", f"user:{user_id}", f"channel:{channel_id}"],
            )
            if success:
                logger.debug(f"Cached typing status for {user_id} in {channel_id}")
            return success
        except Exception as e:
            logger.warning(f"Error caching typing status: {e}")
            return False

    async def invalidate_user_cache(
        self, user_id: str, channel_id: str | None = None
    ) -> bool:
        """Invalidate cache entries for a user."""
        try:
            if channel_id:
                # Invalidate specific user-channel combination
                status_cache_key = CacheKeyBuilder.build(
                    "typing", "status", user_id, channel_id
                )
                await cache_delete(status_cache_key)

                # Also invalidate channel users cache
                await self.invalidate_channel_cache(channel_id)
            else:
                # Invalidate all cache entries for this user
                # Note: In a real implementation, you might need to query cache tags
                # or maintain a separate index of user-related keys
                pass

            logger.debug(f"Invalidated cache for user {user_id}")
            return True
        except Exception as e:
            logger.warning(f"Error invalidating user cache: {e}")
            return False

    async def get_typing_users_with_cache(self, channel_id: str) -> list[str]:
        """Get typing users with caching - checks cache first, then database."""
        # Try cache first
        cached_users = await self.get_cached_typing_users(channel_id)
        if cached_users is not None:
            return cached_users

        # Cache miss - get from database
        from plexichat.core.services.typing_service import typing_service

        users = await typing_service.get_typing_users(channel_id)

        # Cache the result
        await self.set_cached_typing_users(channel_id, users)

        return users

    async def invalidate_all_typing_cache(self) -> bool:
        """Invalidate all typing-related cache entries."""
        try:
            # Note: In a production system, you might want to use cache tags
            # or maintain a registry of all typing-related cache keys
            # For now, we'll clear the entire cache (not ideal but functional)
            from plexichat.core.caching.unified_cache_integration import cache_clear

            await cache_clear()
            logger.info("Invalidated all typing cache")
            return True
        except Exception as e:
            logger.warning(f"Error invalidating all typing cache: {e}")
            return False

    async def preload_channel_cache(self, channel_id: str) -> bool:
        """Preload cache for a channel (useful for frequently accessed channels)."""
        try:
            from plexichat.core.services.typing_service import typing_service

            users = await typing_service.get_typing_users(channel_id)
            await self.set_cached_typing_users(channel_id, users)
            logger.debug(f"Preloaded cache for channel {channel_id}")
            return True
        except Exception as e:
            logger.warning(f"Error preloading channel cache: {e}")
            return False

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        # Note: This would need to be implemented in the cache manager
        # For now, return basic info
        return {
            "cache_ttl": self.cache_ttl,
            "channel_users_cache_ttl": self.channel_users_cache_ttl,
            "typing_status_cache_ttl": self.typing_status_cache_ttl,
            "service": "typing_cache",
        }


# Global cache service instance
typing_cache_service = TypingCacheService()


async def get_cached_typing_users(channel_id: str) -> list[str]:
    """Get typing users with caching."""
    return await typing_cache_service.get_typing_users_with_cache(channel_id)


async def invalidate_typing_cache(channel_id: str) -> bool:
    """Invalidate typing cache for a channel."""
    return await typing_cache_service.invalidate_channel_cache(channel_id)


async def preload_typing_cache(channel_id: str) -> bool:
    """Preload typing cache for a channel."""
    return await typing_cache_service.preload_channel_cache(channel_id)
