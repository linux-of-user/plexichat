"""
User Status API Router

Provides REST API endpoints for user status management.
"""

import logging
from typing import Dict, List, Any, Optional

try:
    from fastapi import APIRouter, HTTPException, Depends, Query
    from pydantic import BaseModel, Field
except ImportError:
    APIRouter = None
    HTTPException = Exception
    Depends = None
    Query = None
    BaseModel = object
    Field = lambda **kwargs: None

from plexichat.core.services.user_status_service import user_status_service
from plexichat.interfaces.api.main_api import get_current_user

logger = logging.getLogger(__name__)

# Create router
if APIRouter:
    router = APIRouter(prefix="/status", tags=["status"])
else:
    router = None

# Pydantic models for request/response
class StatusUpdateRequest(BaseModel):
    """Request model for status updates."""
    status: str = Field(..., description="User status", examples=["online", "away", "busy", "offline"])
    custom_status: Optional[str] = Field(None, description="Custom status message", max_length=100)

class StatusResponse(BaseModel):
    """Response model for status information."""
    user_id: str
    status: str
    custom_status: Optional[str]
    status_updated_at: Optional[str]

class OnlineUsersResponse(BaseModel):
    """Response model for online users list."""
    users: List[Dict[str, Any]]
    count: int

# API Endpoints
if router:

    @router.get("/me", response_model=StatusResponse)
    async def get_my_status(current_user: Dict[str, Any] = Depends(get_current_user)):
        """Get current user's status."""
        try:
            user_id = str(current_user["id"])
            status = await user_status_service.get_user_status(user_id)

            if not status:
                # Return default status if not found
                return StatusResponse(
                    user_id=user_id,
                    status="offline",
                    custom_status=None,
                    status_updated_at=None
                )

            return StatusResponse(
                user_id=status.user_id,
                status=status.status,
                custom_status=status.custom_status,
                status_updated_at=status.status_updated_at.isoformat() if status.status_updated_at else None
            )

        except Exception as e:
            logger.error(f"Error getting user status: {e}")
            raise HTTPException(status_code=500, detail="Failed to get user status")

    @router.put("/me", response_model=StatusResponse)
    async def update_my_status(
        request: StatusUpdateRequest,
        current_user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Update current user's status."""
        try:
            user_id = str(current_user["id"])

            # Validate status
            if not user_status_service.validate_status(request.status):
                valid_statuses = user_status_service.get_valid_statuses()
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status. Valid statuses: {', '.join(valid_statuses)}"
                )

            # Update status
            success = await user_status_service.update_user_status(
                user_id=user_id,
                status=request.status,
                custom_status=request.custom_status
            )

            if not success:
                raise HTTPException(status_code=500, detail="Failed to update status")

            # Return updated status
            status = await user_status_service.get_user_status(user_id)
            if not status:
                raise HTTPException(status_code=500, detail="Failed to retrieve updated status")

            return StatusResponse(
                user_id=status.user_id,
                status=status.status,
                custom_status=status.custom_status,
                status_updated_at=status.status_updated_at.isoformat() if status.status_updated_at else None
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating user status: {e}")
            raise HTTPException(status_code=500, detail="Failed to update user status")

    @router.get("/online", response_model=OnlineUsersResponse)
    async def get_online_users(
        limit: int = Query(50, ge=1, le=1000, description="Maximum number of users to return"),
        current_user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get list of online users."""
        try:
            users = await user_status_service.get_online_users()

            # Limit results
            users = users[:limit]

            return OnlineUsersResponse(
                users=users,
                count=len(users)
            )

        except Exception as e:
            logger.error(f"Error getting online users: {e}")
            raise HTTPException(status_code=500, detail="Failed to get online users")

    @router.get("/user/{user_id}", response_model=StatusResponse)
    async def get_user_status(
        user_id: str,
        current_user: Dict[str, Any] = Depends(get_current_user)
    ):
        """Get status for a specific user."""
        try:
            status = await user_status_service.get_user_status(user_id)

            if not status:
                # Return default status if not found
                return StatusResponse(
                    user_id=user_id,
                    status="offline",
                    custom_status=None,
                    status_updated_at=None
                )

            return StatusResponse(
                user_id=status.user_id,
                status=status.status,
                custom_status=status.custom_status,
                status_updated_at=status.status_updated_at.isoformat() if status.status_updated_at else None
            )

        except Exception as e:
            logger.error(f"Error getting user status for {user_id}: {e}")
            raise HTTPException(status_code=500, detail="Failed to get user status")

    @router.post("/online")
    async def set_online(current_user: Dict[str, Any] = Depends(get_current_user)):
        """Set current user status to online."""
        try:
            user_id = str(current_user["id"])
            success = await user_status_service.set_user_online(user_id)

            if not success:
                raise HTTPException(status_code=500, detail="Failed to set status to online")

            return {"message": "Status set to online", "user_id": user_id}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error setting user online: {e}")
            raise HTTPException(status_code=500, detail="Failed to set status to online")

    @router.post("/away")
    async def set_away(current_user: Dict[str, Any] = Depends(get_current_user)):
        """Set current user status to away."""
        try:
            user_id = str(current_user["id"])
            success = await user_status_service.set_user_away(user_id)

            if not success:
                raise HTTPException(status_code=500, detail="Failed to set status to away")

            return {"message": "Status set to away", "user_id": user_id}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error setting user away: {e}")
            raise HTTPException(status_code=500, detail="Failed to set status to away")

    @router.post("/busy")
    async def set_busy(current_user: Dict[str, Any] = Depends(get_current_user)):
        """Set current user status to busy."""
        try:
            user_id = str(current_user["id"])
            success = await user_status_service.set_user_busy(user_id)

            if not success:
                raise HTTPException(status_code=500, detail="Failed to set status to busy")

            return {"message": "Status set to busy", "user_id": user_id}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error setting user busy: {e}")
            raise HTTPException(status_code=500, detail="Failed to set status to busy")

    @router.post("/offline")
    async def set_offline(current_user: Dict[str, Any] = Depends(get_current_user)):
        """Set current user status to offline."""
        try:
            user_id = str(current_user["id"])
            success = await user_status_service.set_user_offline(user_id)

            if not success:
                raise HTTPException(status_code=500, detail="Failed to set status to offline")

            return {"message": "Status set to offline", "user_id": user_id}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error setting user offline: {e}")
            raise HTTPException(status_code=500, detail="Failed to set status to offline")

    @router.get("/valid-statuses")
    async def get_valid_statuses():
        """Get list of valid status values."""
        try:
            return {
                "statuses": user_status_service.get_valid_statuses(),
                "description": "Valid user status values"
            }

        except Exception as e:
            logger.error(f"Error getting valid statuses: {e}")
            raise HTTPException(status_code=500, detail="Failed to get valid statuses")