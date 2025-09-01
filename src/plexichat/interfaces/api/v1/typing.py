"""
Typing API Endpoints

REST API endpoints for typing indicators.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

from plexichat.core.services.typing_service import typing_service
from plexichat.core.config import get_config, get_config_manager
from plexichat.core.services.typing_cleanup_service import typing_cleanup_service
from plexichat.core.services.optimized_websocket_service import optimized_websocket_service
from plexichat.core.services.typing_cache_service import typing_cache_service

# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}

router = APIRouter(prefix="/typing", tags=["Typing"])

class TypingStartRequest(BaseModel):
    """Request model for starting typing."""
    channel_id: str

class TypingStopRequest(BaseModel):
    """Request model for stopping typing."""
    channel_id: str

class TypingStatusResponse(BaseModel):
    """Response model for typing status."""
    channel_id: str
    typing_users: List[str]
    count: int

@router.post("/start")
async def start_typing(request: TypingStartRequest, current_user: dict = Depends(get_current_user)):
    """Start typing indicator in a channel."""
    try:
        user_id = current_user["id"]
        success = await typing_service.start_typing(user_id, request.channel_id)

        if not success:
            raise HTTPException(status_code=400, detail="Failed to start typing")

        return {"message": "Typing started", "user_id": user_id, "channel_id": request.channel_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/stop")
async def stop_typing(request: TypingStopRequest, current_user: dict = Depends(get_current_user)):
    """Stop typing indicator in a channel."""
    try:
        user_id = current_user["id"]
        success = await typing_service.stop_typing(user_id, request.channel_id)

        if not success:
            raise HTTPException(status_code=400, detail="Failed to stop typing")

        return {"message": "Typing stopped", "user_id": user_id, "channel_id": request.channel_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/status/{channel_id}")
async def get_typing_status(channel_id: str, current_user: dict = Depends(get_current_user)):
    """Get typing status for a channel."""
    try:
        # Check if user has access to channel (simplified check)
        # In a real implementation, this would verify channel membership/permissions

        typing_users = await typing_service.get_typing_users(channel_id)

        return TypingStatusResponse(
            channel_id=channel_id,
            typing_users=typing_users,
            count=len(typing_users)
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/cleanup")
async def cleanup_expired_typing_states(current_user: dict = Depends(get_current_user)):
    """Clean up expired typing states (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        cleaned_count = await typing_service.cleanup_expired_states()

        return {"message": f"Cleaned up {cleaned_count} expired typing states"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# Admin Configuration Endpoints

class TypingConfigUpdate(BaseModel):
    """Request model for updating typing configuration."""
    enabled: bool = None
    timeout_seconds: int = None
    cleanup_interval_seconds: int = None
    max_concurrent_typing_users: int = None
    debounce_delay_seconds: float = None
    cache_ttl_seconds: int = None
    broadcast_batch_size: int = None
    broadcast_interval_seconds: float = None
    enable_persistence: bool = None
    max_typing_history_days: int = None
    enable_metrics: bool = None
    enable_debug_logging: bool = None


class TypingConfigResponse(BaseModel):
    """Response model for typing configuration."""
    enabled: bool
    timeout_seconds: int
    cleanup_interval_seconds: int
    max_concurrent_typing_users: int
    debounce_delay_seconds: float
    cache_ttl_seconds: int
    broadcast_batch_size: int
    broadcast_interval_seconds: float
    enable_persistence: bool
    max_typing_history_days: int
    enable_metrics: bool
    enable_debug_logging: bool


@router.get("/admin/config", response_model=TypingConfigResponse)
async def get_typing_config(current_user: dict = Depends(get_current_user)):
    """Get current typing configuration (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        config = {
            "enabled": get_config("typing.enabled", True),
            "timeout_seconds": get_config("typing.timeout_seconds", 3),
            "cleanup_interval_seconds": get_config("typing.cleanup_interval_seconds", 30),
            "max_concurrent_typing_users": get_config("typing.max_concurrent_typing_users", 100),
            "debounce_delay_seconds": get_config("typing.debounce_delay_seconds", 0.5),
            "cache_ttl_seconds": get_config("typing.cache_ttl_seconds", 60),
            "broadcast_batch_size": get_config("typing.broadcast_batch_size", 10),
            "broadcast_interval_seconds": get_config("typing.broadcast_interval_seconds", 0.1),
            "enable_persistence": get_config("typing.enable_persistence", True),
            "max_typing_history_days": get_config("typing.max_typing_history_days", 7),
            "enable_metrics": get_config("typing.enable_metrics", True),
            "enable_debug_logging": get_config("typing.enable_debug_logging", False)
        }

        return TypingConfigResponse(**config)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.put("/admin/config", response_model=TypingConfigResponse)
async def update_typing_config(
    config_update: TypingConfigUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update typing configuration (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        config_manager = get_config_manager()

        # Update configuration values
        updates = config_update.dict(exclude_unset=True)
        for key, value in updates.items():
            config_key = f"typing.{key}"
            config_manager.set(config_key, value)

        # Save configuration
        config_manager.save()

        # Return updated configuration
        return await get_typing_config(current_user)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/admin/metrics")
async def get_typing_metrics(current_user: dict = Depends(get_current_user)):
    """Get typing service metrics (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        # Collect metrics from all typing services
        metrics = {
            "websocket_service": optimized_websocket_service.get_metrics(),
            "cache_service": typing_cache_service.get_cache_stats(),
            "cleanup_service": await typing_cleanup_service.get_status(),
            "typing_service": {
                "timeout": typing_service.typing_timeout,
                "debounce_delay": typing_service.debounce_delay,
                "max_concurrent_users": typing_service.max_concurrent_users,
                "debug_logging": typing_service.enable_debug_logging
            }
        }

        return metrics

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/admin/cache/invalidate")
async def invalidate_typing_cache(current_user: dict = Depends(get_current_user)):
    """Invalidate all typing cache (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        success = await typing_cache_service.invalidate_all_typing_cache()

        if success:
            return {"message": "Typing cache invalidated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to invalidate typing cache")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/admin/cleanup/force")
async def force_typing_cleanup(current_user: dict = Depends(get_current_user)):
    """Force immediate typing cleanup (admin endpoint)."""
    try:
        # In a real implementation, check if user is admin
        if current_user.get("is_admin") != True:
            raise HTTPException(status_code=403, detail="Admin access required")

        result = await typing_cleanup_service.force_cleanup()
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")