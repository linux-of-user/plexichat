"""
Typing API Endpoints

REST API endpoints for typing indicators.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List

from plexichat.core.services.typing_service import typing_service

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