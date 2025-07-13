from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlmodel import Session

from datetime import datetime



from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from plexichat.app.db import get_session
from plexichat.app.models.enhanced_models import EnhancedUser
from plexichat.app.models.moderation import ModerationAction, ModerationSeverity
from plexichat.app.services.moderation_service import ModerationService
from plexichat.app.utils.auth import (
    from plexichat.infrastructure.utils.auth import get_current_user,
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User

    from,
    import,
    plexichat.infrastructure.utils.auth,
)

"""
Comprehensive moderation API for PlexiChat.
Handles user moderation, message moderation, moderator roles, and appeals.
"""

# Pydantic models for API
class UserModerationRequest(BaseModel):
    target_user_id: int
    action: ModerationAction
    reason: str
    duration_minutes: Optional[int] = None
    guild_id: Optional[int] = None
    channel_id: Optional[int] = None
    severity: ModerationSeverity = ModerationSeverity.MEDIUM


class MessageModerationRequest(BaseModel):
    message_id: int
    action: ModerationAction
    reason: str
    new_content: Optional[str] = None
    guild_id: Optional[int] = None
    channel_id: Optional[int] = None


class ModeratorRoleRequest(BaseModel):
    user_id: int
    guild_id: Optional[int] = None
    channel_id: Optional[int] = None
    role_name: str = "Moderator"
    permissions: Optional[Dict[str, bool]] = None
    expires_hours: Optional[int] = None


class AppealRequest(BaseModel):
    moderation_log_id: int
    appeal_reason: str


class AppealReviewRequest(BaseModel):
    moderation_log_id: int
    decision: str  # 'approved' or 'denied'
    decision_reason: str


router = APIRouter(prefix="/api/v1/moderation", tags=["Moderation"])


@router.post("/users/moderate")
async def moderate_user(
    request: UserModerationRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Apply moderation action to a user."""
    moderation_service = ModerationService(session)

    success = await moderation_service.moderate_user(
        moderator_id=current_user.id,
        target_user_id=request.target_user_id,
        action=request.action,
        reason=request.reason,
        duration_minutes=request.duration_minutes,
        guild_id=request.guild_id,
        channel_id=request.channel_id,
        severity=request.severity
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": f"Moderation action {request.action.value} applied successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply moderation action"
        )


@router.post("/messages/moderate")
async def moderate_message(
    request: MessageModerationRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Apply moderation action to a message."""
    moderation_service = ModerationService(session)

    success = await moderation_service.moderate_message(
        moderator_id=current_user.id,
        message_id=request.message_id,
        action=request.action,
        reason=request.reason,
        new_content=request.new_content,
        guild_id=request.guild_id,
        channel_id=request.channel_id
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": f"Message moderation action {request.action.value} applied successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply message moderation action"
        )


@router.get("/users/{user_id}/restrictions")
async def get_user_restrictions(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> Dict[str, Any]:
    """Get current moderation restrictions for a user."""
    moderation_service = ModerationService(session)

    # Check if user can view restrictions (moderator or own restrictions)
    if user_id != current_user.id:
        has_permission, _ = await moderation_service.check_moderator_permissions(current_user.id)
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to view user restrictions"
            )

    return await moderation_service.check_user_restrictions(user_id)


@router.post("/roles/grant")
async def grant_moderator_role(
    request: ModeratorRoleRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Grant moderator role to a user."""
    moderation_service = ModerationService(session)

    expires_at = None
    if request.expires_hours:
        from datetime import datetime
expires_at = datetime.now()
datetime.utcnow() + timedelta(hours=request.expires_hours)

    success = await moderation_service.grant_moderator_role(
        granter_id=current_user.id,
        user_id=request.user_id,
        guild_id=request.guild_id,
        channel_id=request.channel_id,
        role_name=request.role_name,
        permissions=request.permissions,
        expires_at=expires_at
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": "Moderator role granted successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to grant moderator role"
        )


@router.delete("/roles/{role_id}")
async def revoke_moderator_role(
    role_id: int,
    reason: str = Query(..., description="Reason for revoking the role"),
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Revoke a moderator role."""
    moderation_service = ModerationService(session)

    success = await moderation_service.revoke_moderator_role(
        revoker_id=current_user.id,
        moderator_role_id=role_id,
        reason=reason
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": "Moderator role revoked successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke moderator role"
        )


@router.post("/appeals/submit")
async def submit_appeal(
    request: AppealRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Submit an appeal for a moderation action."""
    moderation_service = ModerationService(session)

    success = await moderation_service.submit_appeal(
        user_id=current_user.id,
        moderation_log_id=request.moderation_log_id,
        appeal_reason=request.appeal_reason
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": "Appeal submitted successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit appeal"
        )


@router.post("/appeals/review")
async def review_appeal(
    request: AppealReviewRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Review an appeal for a moderation action."""
    moderation_service = ModerationService(session)

    if request.decision not in ["approved", "denied"]:
        raise HTTPException(status_code=400, detail="Decision must be 'approved' or 'denied'")

    success = await moderation_service.review_appeal(
        reviewer_id=current_user.id,
        moderation_log_id=request.moderation_log_id,
        decision=request.decision,
        decision_reason=request.decision_reason
    )

    if success:
        return JSONResponse({
            "success": True,
            "message": f"Appeal {request.decision} successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to review appeal"
        )


@router.get("/logs")
async def get_moderation_logs(
    guild_id: Optional[int] = Query(None),
    target_user_id: Optional[int] = Query(None),
    moderator_id: Optional[int] = Query(None),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> List[Dict[str, Any]]:
    """Get moderation logs with filtering."""
    moderation_service = ModerationService(session)

    # Check moderator permissions
    has_permission, _ = await moderation_service.check_moderator_permissions(
        current_user.id, guild_id
    )

    if not has_permission:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view moderation logs"
        )

    return await moderation_service.get_moderation_logs(
        guild_id=guild_id,
        target_user_id=target_user_id,
        moderator_id=moderator_id,
        limit=limit,
        offset=offset
    )


@router.get("/permissions/check")
async def check_moderator_permissions(
    guild_id: Optional[int] = Query(None),
    channel_id: Optional[int] = Query(None),
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> Dict[str, Any]:
    """Check current user's moderator permissions."""
    moderation_service = ModerationService(session)

    has_permission, moderator_role = await moderation_service.check_moderator_permissions(
        current_user.id, guild_id, channel_id
    )

    if not has_permission:
        return {
            "is_moderator": False,
            "permissions": {}
        }

    return {
        "is_moderator": True,
        "role_name": moderator_role.role_name,
        "permissions": {
            "can_moderate_messages": moderator_role.can_moderate_messages,
            "can_moderate_users": moderator_role.can_moderate_users,
            "can_ban_users": moderator_role.can_ban_users,
            "can_manage_roles": moderator_role.can_manage_roles,
            "max_punishment_severity": moderator_role.max_punishment_severity.value
        },
        "expires_at": moderator_role.expires_at,
        "guild_id": moderator_role.guild_id,
        "channel_id": moderator_role.channel_id
    }


@router.get("/users/{user_id}/history")
async def get_user_moderation_history(
    user_id: int,
    limit: int = Query(20, le=50),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> List[Dict[str, Any]]:
    """Get moderation history for a specific user."""
    moderation_service = ModerationService(session)

    # Check permissions (moderator or own history)
    if user_id != current_user.id:
        has_permission, _ = await moderation_service.check_moderator_permissions(current_user.id)
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to view user moderation history"
            )

    return await moderation_service.get_moderation_logs(
        target_user_id=user_id,
        limit=limit,
        offset=offset
    )
