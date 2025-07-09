"""
Enhanced Moderation API endpoints for NetLink.
Provides comprehensive moderation capabilities with role-based permissions.
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from sqlmodel import Session

from netlink.app.database import get_session
from netlink.app.services.moderation_service import ModerationService, UserRole, Permission
from netlink.app.models.moderation import ModerationAction, ModerationSeverity
from netlink.app.auth import get_current_user
from netlink.app.logger_config import logger


# Pydantic models for API
class RoleAssignmentRequest(BaseModel):
    user_id: int
    role: str
    guild_id: Optional[int] = None
    reason: Optional[str] = None
    duration: Optional[int] = None  # Duration in seconds


class ModerationActionRequest(BaseModel):
    target_user_id: int
    action: str
    reason: str
    guild_id: Optional[int] = None
    channel_id: Optional[int] = None
    duration: Optional[int] = None
    evidence: Optional[Dict[str, Any]] = None


class AppealRequest(BaseModel):
    moderation_log_id: int
    appeal_reason: str
    guild_id: Optional[int] = None


class AppealReviewRequest(BaseModel):
    moderation_log_id: int
    decision: str  # "approved" or "denied"
    review_reason: str
    guild_id: Optional[int] = None


class PermissionCheckRequest(BaseModel):
    user_id: int
    permission: str
    guild_id: Optional[int] = None


router = APIRouter(prefix="/api/v1/moderation", tags=["Enhanced Moderation"])


@router.get("/roles")
async def get_available_roles():
    """Get all available user roles."""
    return {
        "success": True,
        "roles": [
            {
                "name": role.value,
                "description": f"{role.value.title()} role with specific permissions"
            }
            for role in UserRole
        ]
    }


@router.get("/permissions")
async def get_available_permissions():
    """Get all available permissions."""
    return {
        "success": True,
        "permissions": [
            {
                "name": perm.value,
                "description": f"Permission to {perm.value.replace('_', ' ')}"
            }
            for perm in Permission
        ]
    }


@router.get("/user/{user_id}/role")
async def get_user_role(
    user_id: int,
    guild_id: Optional[int] = None,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Get the current role of a user."""
    try:
        moderation_service = ModerationService(session)
        user_role = moderation_service.get_user_role(user_id, guild_id)
        
        return {
            "success": True,
            "user_id": user_id,
            "role": user_role.value,
            "guild_id": guild_id
        }
        
    except Exception as e:
        logger.error(f"Failed to get user role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/user/assign_role")
async def assign_user_role(
    request: RoleAssignmentRequest,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Assign a role to a user."""
    try:
        moderation_service = ModerationService(session)
        
        # Validate role
        try:
            role = UserRole(request.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {request.role}")
        
        # Check if current user has permission to manage roles
        if not moderation_service.has_permission(current_user.id, Permission.MANAGE_ROLES, request.guild_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to manage roles"
            )
        
        # Check if current user can moderate target user
        if not moderation_service.can_moderate_user(current_user.id, request.user_id, request.guild_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot assign role to this user"
            )
        
        success = moderation_service.assign_role(
            user_id=request.user_id,
            role=role,
            assigned_by=current_user.id,
            guild_id=request.guild_id,
            reason=request.reason,
            duration=request.duration
        )
        
        if success:
            return {
                "success": True,
                "message": f"Role {request.role} assigned to user {request.user_id}",
                "user_id": request.user_id,
                "role": request.role
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to assign role")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign user role: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/user/check_permission")
async def check_user_permission(
    request: PermissionCheckRequest,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Check if a user has a specific permission."""
    try:
        moderation_service = ModerationService(session)
        
        # Validate permission
        try:
            permission = Permission(request.permission)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {request.permission}")
        
        has_permission = moderation_service.has_permission(
            request.user_id,
            permission,
            request.guild_id
        )
        
        return {
            "success": True,
            "user_id": request.user_id,
            "permission": request.permission,
            "has_permission": has_permission,
            "guild_id": request.guild_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check user permission: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/action")
async def execute_moderation_action(
    request: ModerationActionRequest,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Execute a moderation action with enhanced role-based permissions."""
    try:
        moderation_service = ModerationService(session)
        
        # Validate action
        try:
            action = ModerationAction(request.action)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid action: {request.action}")
        
        log_id = moderation_service.execute_enhanced_moderation_action(
            moderator_id=current_user.id,
            target_user_id=request.target_user_id,
            action=action,
            reason=request.reason,
            guild_id=request.guild_id,
            channel_id=request.channel_id,
            duration=request.duration,
            evidence=request.evidence
        )
        
        if log_id:
            return {
                "success": True,
                "message": f"Moderation action {request.action} executed successfully",
                "log_id": log_id,
                "target_user_id": request.target_user_id,
                "action": request.action
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to execute moderation action")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute moderation action: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/appeal")
async def create_moderation_appeal(
    request: AppealRequest,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Create an appeal for a moderation action."""
    try:
        moderation_service = ModerationService(session)
        
        success = moderation_service.create_moderation_appeal(
            user_id=current_user.id,
            moderation_log_id=request.moderation_log_id,
            appeal_reason=request.appeal_reason,
            guild_id=request.guild_id
        )
        
        if success:
            return {
                "success": True,
                "message": "Appeal submitted successfully",
                "moderation_log_id": request.moderation_log_id
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to submit appeal")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create moderation appeal: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/appeal/review")
async def review_moderation_appeal(
    request: AppealReviewRequest,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Review a moderation appeal."""
    try:
        moderation_service = ModerationService(session)
        
        if request.decision not in ["approved", "denied"]:
            raise HTTPException(status_code=400, detail="Decision must be 'approved' or 'denied'")
        
        success = moderation_service.review_moderation_appeal(
            moderator_id=current_user.id,
            moderation_log_id=request.moderation_log_id,
            decision=request.decision,
            review_reason=request.review_reason,
            guild_id=request.guild_id
        )
        
        if success:
            return {
                "success": True,
                "message": f"Appeal {request.decision} successfully",
                "moderation_log_id": request.moderation_log_id,
                "decision": request.decision
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to review appeal")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to review moderation appeal: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/user/{user_id}/summary")
async def get_user_moderation_summary(
    user_id: int,
    guild_id: Optional[int] = None,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Get comprehensive moderation summary for a user."""
    try:
        moderation_service = ModerationService(session)
        
        # Check if current user has permission to view moderation data
        if not moderation_service.has_permission(current_user.id, Permission.VIEW_REPORTS, guild_id):
            # Users can view their own summary
            if current_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to view moderation summary"
                )
        
        summary = moderation_service.get_user_moderation_summary(user_id, guild_id)
        
        return {
            "success": True,
            "summary": summary
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user moderation summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/role_permissions")
async def get_role_permissions(
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Get permissions for all roles."""
    try:
        moderation_service = ModerationService(session)
        
        # Check if user has permission to view role information
        if not moderation_service.has_permission(current_user.id, Permission.MANAGE_ROLES):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to view role permissions"
            )
        
        role_permissions = {}
        for role, permissions in moderation_service.role_permissions.items():
            role_permissions[role.value] = [perm.value for perm in permissions]
        
        return {
            "success": True,
            "role_permissions": role_permissions
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role permissions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_moderation_statistics(
    guild_id: Optional[int] = None,
    session: Session = Depends(get_session),
    current_user = Depends(get_current_user)
):
    """Get moderation statistics."""
    try:
        moderation_service = ModerationService(session)
        
        # Check if user has permission to view statistics
        if not moderation_service.has_permission(current_user.id, Permission.VIEW_REPORTS, guild_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to view moderation statistics"
            )
        
        # Get basic statistics from the existing method
        stats = moderation_service.get_moderation_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get moderation statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
