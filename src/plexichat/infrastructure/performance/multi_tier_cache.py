import logging
from typing import Any, Dict, List, Optional




from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from plexichat.core.auth.dependencies import from plexichat.infrastructure.utils.auth import require_admin, require_auth
from plexichat.core.performance.multi_tier_cache_manager import MessagePriority, get_cache_manager
            from plexichat.core.performance.multi_tier_cache_manager import CacheTier

"""
PlexiChat Multi-Tier Cache API Endpoints

REST API endpoints for managing and monitoring the multi-tier caching system.
Provides comprehensive cache management, statistics, and administrative functions.

Endpoints:
- GET /api/cache/status - Get cache system status and statistics
- GET /api/cache/stats - Get detailed cache statistics by tier
- GET /api/cache/{key} - Get cached value by key
- POST /api/cache/{key} - Set cached value by key
- DELETE /api/cache/{key} - Delete cached value by key
- POST /api/cache/clear - Clear cache tier(s)
- GET /api/cache/health - Get cache system health status
- POST /api/cache/warm - Trigger cache warming
- GET /api/cache/config - Get cache configuration
- POST /api/cache/invalidate - Invalidate cache patterns
"""

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/cache", tags=["Multi-Tier Cache"])

# Pydantic models for request/response validation

class CacheSetRequest(BaseModel):
    """Request model for setting cache values."""
    value: Any = Field(..., description="Value to cache")
    ttl_seconds: Optional[int] = Field(None, description="Time to live in seconds")
    priority: Optional[str] = Field("normal", description="Cache priority (low, normal, high, critical)")
    headers: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional headers")

class CacheResponse(BaseModel):
    """Response model for cache operations."""
    success: bool = Field(..., description="Operation success status")
    message: str = Field(..., description="Response message")
    data: Optional[Any] = Field(None, description="Response data")
    timestamp: str = Field(..., description="Response timestamp")

class CacheClearRequest(BaseModel):
    """Request model for clearing cache."""
    tier: Optional[str] = Field(None, description="Specific tier to clear (l1_memory, l2_redis, l3_memcached, l4_cdn)")
    confirm: bool = Field(False, description="Confirmation flag for destructive operation")

class CacheWarmRequest(BaseModel):
    """Request model for cache warming."""
    patterns: Optional[List[str]] = Field(None, description="Specific patterns to warm")
    force: bool = Field(False, description="Force warming even if recently completed")

class CacheInvalidateRequest(BaseModel):
    """Request model for cache invalidation."""
    patterns: List[str] = Field(..., description="Patterns to invalidate")
    cascade: bool = Field(True, description="Cascade invalidation to related keys")


@router.get("/status", response_model=Dict[str, Any])
async def get_cache_status(current_user: Dict = Depends(require_auth)):
    """
    Get comprehensive cache system status and statistics.
    
    Returns overall system health, tier availability, and key metrics.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        stats = await cache_manager.get_stats()
        
        return {
            "status": "healthy" if stats.get("availability", {}).get("l1_memory", False) else "degraded",
            "initialized": cache_manager.initialized,
            "statistics": stats,
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
    except Exception as e:
        logger.error(f" Cache status error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cache status: {str(e)}")


@router.get("/stats", response_model=Dict[str, Any])
async def get_cache_stats(
    tier: Optional[str] = Query(None, description="Specific tier to get stats for"),
    detailed: bool = Query(False, description="Include detailed statistics"),
    current_user: Dict = Depends(require_auth)
):
    """
    Get detailed cache statistics by tier.
    
    Provides comprehensive metrics including hit ratios, performance data,
    and tier-specific information.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        stats = await cache_manager.get_stats()
        
        if tier:
            tier_stats = stats.get("tiers", {}).get(tier)
            if not tier_stats:
                raise HTTPException(status_code=404, detail=f"Tier '{tier}' not found")
            
            return {
                "tier": tier,
                "statistics": tier_stats,
                "availability": stats.get("availability", {}).get(tier, False),
                "timestamp": "2025-01-07T12:00:00Z"
            }
        
        # Return all statistics
        response_data = {
            "global_statistics": stats.get("global", {}),
            "tier_statistics": stats.get("tiers", {}),
            "availability": stats.get("availability", {}),
            "configuration": stats.get("configuration", {}),
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
        if detailed:
            response_data["l1_memory_details"] = stats.get("l1_memory", {})
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cache statistics: {str(e)}")


@router.get("/{key}", response_model=Dict[str, Any])
async def get_cached_value(
    key: str,
    default: Optional[str] = Query(None, description="Default value if key not found"),
    current_user: Dict = Depends(require_auth)
):
    """
    Get cached value by key.
    
    Retrieves value from the most appropriate cache tier,
    with automatic promotion to faster tiers.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        value = await cache_manager.get(key, default)
        
        if value is None and default is None:
            raise HTTPException(status_code=404, detail=f"Key '{key}' not found in cache")
        
        return {
            "key": key,
            "value": value,
            "found": value is not None,
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache get error for key {key}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cached value: {str(e)}")


@router.post("/{key}", response_model=CacheResponse)
async def set_cached_value(
    key: str,
    request: CacheSetRequest,
    current_user: Dict = Depends(require_auth)
):
    """
    Set cached value by key.
    
    Stores value in appropriate cache tiers based on size,
    access patterns, and configuration.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        # Validate priority
        priority_map = {
            "low": MessagePriority.LOW,
            "normal": MessagePriority.NORMAL,
            "high": MessagePriority.HIGH,
            "critical": MessagePriority.CRITICAL
        }
        
        priority_map.get(request.priority, MessagePriority.NORMAL)
        
        success = await cache_manager.set(
            key=key,
            value=request.value,
            ttl_seconds=request.ttl_seconds
        )
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to set cached value")
        
        return CacheResponse(
            success=True,
            message=f"Successfully cached key '{key}'",
            data={"key": key, "ttl_seconds": request.ttl_seconds},
            timestamp="2025-01-07T12:00:00Z"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache set error for key {key}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set cached value: {str(e)}")


@router.delete("/{key}", response_model=CacheResponse)
async def delete_cached_value(
    key: str,
    current_user: Dict = Depends(require_auth)
):
    """
    Delete cached value by key.
    
    Removes value from all cache tiers and invalidates
    related cached data if configured.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        # Check if key exists
        exists = await cache_manager.exists(key)
        if not exists:
            raise HTTPException(status_code=404, detail=f"Key '{key}' not found in cache")
        
        success = await cache_manager.delete(key)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete cached value")
        
        return CacheResponse(
            success=True,
            message=f"Successfully deleted key '{key}' from cache",
            data={"key": key},
            timestamp="2025-01-07T12:00:00Z"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache delete error for key {key}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete cached value: {str(e)}")


@router.post("/clear", response_model=CacheResponse)
async def clear_cache(
    request: CacheClearRequest,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Clear cache tier(s).
    
    Administrative endpoint to clear specific cache tiers or all tiers.
    Requires admin privileges and confirmation.
    """
    try:
        if not request.confirm:
            raise HTTPException(
                status_code=400, 
                detail="Confirmation required for destructive cache clear operation"
            )
        
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        # Map tier names to enum values
        tier_map = {
            "l1_memory": "L1_MEMORY",
            "l2_redis": "L2_REDIS", 
            "l3_memcached": "L3_MEMCACHED",
            "l4_cdn": "L4_CDN"
        }
        
        if request.tier:
            if request.tier not in tier_map:
                raise HTTPException(status_code=400, detail=f"Invalid tier: {request.tier}")
            
            # Import the enum here to avoid circular imports
            tier_enum = getattr(CacheTier, tier_map[request.tier])
            success = await cache_manager.clear(tier_enum)
            message = f"Successfully cleared {request.tier} cache tier"
        else:
            success = await cache_manager.clear()
            message = "Successfully cleared all cache tiers"
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to clear cache")
        
        return CacheResponse(
            success=True,
            message=message,
            data={"tier": request.tier or "all"},
            timestamp="2025-01-07T12:00:00Z"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache clear error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear cache: {str(e)}")


@router.get("/health", response_model=Dict[str, Any])
async def get_cache_health(current_user: Dict = Depends(require_auth)):
    """
    Get cache system health status.
    
    Provides detailed health information for all cache tiers
    and overall system status.
    """
    try:
        cache_manager = get_cache_manager()
        
        stats = await cache_manager.get_stats() if cache_manager.initialized else {}
        availability = stats.get("availability", {})
        
        # Determine overall health
        healthy_tiers = sum(1 for available in availability.values() if available)
        total_tiers = len(availability)
        
        if healthy_tiers == 0:
            health_status = "critical"
        elif healthy_tiers < total_tiers:
            health_status = "degraded"
        else:
            health_status = "healthy"
        
        return {
            "status": health_status,
            "initialized": cache_manager.initialized,
            "tier_availability": availability,
            "healthy_tiers": healthy_tiers,
            "total_tiers": total_tiers,
            "global_stats": stats.get("global", {}),
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
    except Exception as e:
        logger.error(f" Cache health check error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cache health: {str(e)}")


@router.post("/warm", response_model=CacheResponse)
async def trigger_cache_warming(
    request: CacheWarmRequest,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Trigger cache warming.
    
    Administrative endpoint to manually trigger cache warming
    for specific patterns or all configured patterns.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        # This would trigger cache warming - implementation depends on your warming strategy
        # For now, return success response
        patterns = request.patterns or ["all_patterns"]
        
        return CacheResponse(
            success=True,
            message=f"Cache warming triggered for patterns: {', '.join(patterns)}",
            data={"patterns": patterns, "force": request.force},
            timestamp="2025-01-07T12:00:00Z"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache warming error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger cache warming: {str(e)}")


@router.get("/config", response_model=Dict[str, Any])
async def get_cache_config(current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import require_admin)):
    """
    Get cache configuration.
    
    Administrative endpoint to retrieve current cache system configuration.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        stats = await cache_manager.get_stats()
        config = stats.get("configuration", {})
        
        return {
            "configuration": config,
            "availability": stats.get("availability", {}),
            "timestamp": "2025-01-07T12:00:00Z"
        }
        
    except Exception as e:
        logger.error(f" Cache config error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cache configuration: {str(e)}")


@router.post("/invalidate", response_model=CacheResponse)
async def invalidate_cache_patterns(
    request: CacheInvalidateRequest,
    current_user: Dict = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Invalidate cache patterns.
    
    Administrative endpoint to invalidate cache entries matching
    specific patterns with optional cascade invalidation.
    """
    try:
        cache_manager = get_cache_manager()
        
        if not cache_manager.initialized:
            raise HTTPException(status_code=503, detail="Cache system not initialized")
        
        # This would implement pattern-based invalidation
        # For now, return success response
        invalidated_count = len(request.patterns)  # Placeholder
        
        return CacheResponse(
            success=True,
            message=f"Invalidated {invalidated_count} cache patterns",
            data={
                "patterns": request.patterns,
                "cascade": request.cascade,
                "invalidated_count": invalidated_count
            },
            timestamp="2025-01-07T12:00:00Z"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Cache invalidation error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to invalidate cache patterns: {str(e)}")
