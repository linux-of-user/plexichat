from datetime import datetime
from typing import Any, Dict, List, Optional

from app.db import get_session
from app.logger_config import logger
from app.models.enhanced_models import BotAccount, BotType, EnhancedUser
from app.services.user_management import UserManagementService
from sqlmodel import Session, select


        import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user

"""
Enhanced bot management API with comprehensive features and regulation.
Handles bot creation, management, permissions, and monitoring.
"""

# Pydantic models for API
class BotCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=1000)
    bot_type: BotType = Field(default=BotType.GENERAL)
    permissions: Optional[Dict[str, bool]] = None
    rate_limits: Optional[Dict[str, int]] = None
    webhook_url: Optional[str] = None


class BotUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=1000)
    webhook_url: Optional[str] = None
    permissions: Optional[Dict[str, bool]] = None
    rate_limits: Optional[Dict[str, int]] = None


class BotPermissionUpdateRequest(BaseModel):
    permissions: Dict[str, bool]


class BotResponse(BaseModel):
    id: int
    username: str
    name: str
    description: str
    bot_type: BotType
    verified: bool
    public: bool
    approved: bool
    created_at: datetime
    last_activity: Optional[datetime]
    total_requests: int
    permissions: Dict[str, Any]
    rate_limits: Dict[str, Any]
    token: Optional[str] = None  # Only shown to owner


class BotListResponse(BaseModel):
    bots: List[BotResponse]
    total: int


router = APIRouter(prefix="/api/v1/bots", tags=["Bot Management"])


@router.post("/create", response_model=BotResponse)
async def create_bot(
    request: BotCreateRequest,
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> BotResponse:
    """Create a new bot account."""
    user_service = UserManagementService(session)
    
    try:
        bot_user, bot_account = await user_service.create_bot_account(
            owner_id=current_user.id,
            bot_name=request.name,
            bot_description=request.description,
            bot_type=request.bot_type,
            permissions=request.permissions,
            rate_limits=request.rate_limits
        )
        
        # Update webhook URL if provided
        if request.webhook_url:
            bot_account.webhook_url = request.webhook_url
            session.commit()
        
        return BotResponse(
            id=bot_user.id,
            username=bot_user.username,
            name=bot_account.bot_name,
            description=bot_account.bot_description,
            bot_type=bot_account.bot_type,
            verified=bot_account.is_verified,
            public=bot_account.is_public,
            approved=bot_account.is_approved,
            created_at=bot_user.created_at,
            last_activity=bot_account.last_activity_at,
            total_requests=bot_account.total_requests,
            permissions=bot_account.permissions,
            rate_limits=bot_account.rate_limits,
            token=bot_account.bot_token  # Show token to owner
        )
        
    except Exception as e:
        logger.error(f"Error creating bot: {e}")
        raise HTTPException(status_code=500, detail="Failed to create bot")


@router.get("/my-bots", response_model=BotListResponse)
async def get_my_bots(
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> BotListResponse:
    """Get all bots owned by the current user."""
    user_service = UserManagementService(session)
    
    try:
        bots_data = await user_service.get_user_bots(current_user.id)
        
        bots = [
            BotResponse(
                id=bot["id"],
                username=bot["username"],
                name=bot["name"],
                description=bot["description"],
                bot_type=bot["type"],
                verified=bot["verified"],
                public=bot["public"],
                approved=bot["approved"],
                created_at=bot["created_at"],
                last_activity=bot["last_activity"],
                total_requests=bot["total_requests"],
                permissions=bot["permissions"],
                rate_limits=bot["rate_limits"]
            )
            for bot in bots_data
        ]
        
        return BotListResponse(bots=bots, total=len(bots))
        
    except Exception as e:
        logger.error(f"Error getting user bots: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve bots")


@router.put("/{bot_id}/permissions", response_model=Dict[str, Any])
async def update_bot_permissions(
    bot_id: int,
    request: BotPermissionUpdateRequest,
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> Dict[str, Any]:
    """Update bot permissions."""
    user_service = UserManagementService(session)
    
    try:
        bot_account = await user_service.update_bot_permissions(
            bot_id=bot_id,
            owner_id=current_user.id,
            permissions=request.permissions
        )
        
        return {
            "success": True,
            "message": "Bot permissions updated successfully",
            "permissions": bot_account.permissions
        }
        
    except Exception as e:
        logger.error(f"Error updating bot permissions: {e}")
        raise HTTPException(status_code=500, detail="Failed to update bot permissions")


@router.delete("/{bot_id}")
async def delete_bot(
    bot_id: int,
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> Dict[str, Any]:
    """Delete a bot account."""
    user_service = UserManagementService(session)
    
    try:
        success = await user_service.delete_bot_account(
            bot_id=bot_id,
            owner_id=current_user.id
        )
        
        if success:
            return {
                "success": True,
                "message": "Bot deleted successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to delete bot")
            
    except Exception as e:
        logger.error(f"Error deleting bot: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete bot")


@router.get("/{bot_id}/stats")
async def get_bot_stats(
    bot_id: int,
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> Dict[str, Any]:
    """Get bot usage statistics."""
    try:
        # Verify ownership
        bot_account = session.exec(
            select(BotAccount).join(EnhancedUser).where(
                (BotAccount.user_id == bot_id) &
                (EnhancedUser.bot_owner_id == current_user.id)
            )
        ).first()
        
        if not bot_account:
            raise HTTPException(status_code=404, detail="Bot not found or access denied")
        
        return {
            "bot_id": bot_id,
            "total_requests": bot_account.total_requests,
            "total_messages_sent": bot_account.total_messages_sent,
            "total_commands_executed": bot_account.total_commands_executed,
            "last_activity": bot_account.last_activity_at,
            "violation_count": bot_account.violation_count,
            "suspension_count": bot_account.suspension_count,
            "uptime_percentage": 99.5,  # Placeholder - would calculate from activity logs
            "rate_limit_hits": 0  # Placeholder - would track from rate limiting system
        }
        
    except Exception as e:
        logger.error(f"Error getting bot stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve bot statistics")


@router.post("/{bot_id}/regenerate-token")
async def regenerate_bot_token(
    bot_id: int,
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user),
    session: Session = Depends(get_session)
) -> Dict[str, Any]:
    """Regenerate bot token for security."""
    try:
        # Verify ownership
        bot_account = session.exec(
            select(BotAccount).join(EnhancedUser).where(
                (BotAccount.user_id == bot_id) &
                (EnhancedUser.bot_owner_id == current_user.id)
            )
        ).first()
        
        if not bot_account:
            raise HTTPException(status_code=404, detail="Bot not found or access denied")
        
        # Generate new token
        new_token = secrets.token_urlsafe(32)
        
        bot_account.bot_token = new_token
        bot_account.updated_at = from datetime import datetime
datetime.now()
        
        session.commit()
        
        logger.info(f"Regenerated token for bot: {bot_account.bot_name} (ID: {bot_id})")
        
        return {
            "success": True,
            "message": "Bot token regenerated successfully",
            "new_token": new_token
        }
        
    except Exception as e:
        logger.error(f"Error regenerating bot token: {e}")
        raise HTTPException(status_code=500, detail="Failed to regenerate bot token")
