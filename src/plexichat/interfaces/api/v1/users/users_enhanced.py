"""
Enhanced user management API with comprehensive profile and friend system.
Handles user creation, profile management, account operations, and social features.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, status, Query, UploadFile, File
from fastapi.responses import JSONResponse
from sqlmodel import Session
from pydantic import BaseModel, EmailStr

from plexichat.app.db import get_session
from plexichat.app.models.enhanced_models import EnhancedUser, UserStatus, BotType, AccountType
from plexichat.app.services.user_management import UserManagementService
from plexichat.app.utils.auth import get_current_user, get_optional_current_user
from plexichat.app.logger_config import logger


# Pydantic models for API
class UserCreateRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    tags: Optional[List[str]] = None


class UserProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    website: Optional[str] = None
    location: Optional[str] = None
    phone_number: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    tags: Optional[List[str]] = None
    custom_status: Optional[str] = None
    status_emoji: Optional[str] = None
    pronouns: Optional[str] = None
    interests: Optional[List[str]] = None
    skills: Optional[List[str]] = None
    social_links: Optional[Dict[str, str]] = None
    profile_visibility: Optional[str] = None
    show_online_status: Optional[bool] = None
    show_activity: Optional[bool] = None
    allow_friend_requests: Optional[bool] = None
    allow_direct_messages: Optional[bool] = None


class EmailUpdateRequest(BaseModel):
    new_email: EmailStr
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class AccountDeleteRequest(BaseModel):
    password: str
    hard_delete: bool = False


class FriendRequestRequest(BaseModel):
    user_id: int
    message: Optional[str] = None


class FriendRequestResponse(BaseModel):
    friendship_id: int
    accept: bool


class UserProfileResponse(BaseModel):
    id: int
    uuid: str
    username: str
    display_name: Optional[str]
    avatar_url: Optional[str]
    bio: Optional[str]
    tags: List[str]
    custom_status: Optional[str]
    pronouns: Optional[str]
    status: str
    is_verified: bool
    created_at: datetime
    last_activity_at: Optional[datetime]
    # Private fields (only for own profile)
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    two_factor_enabled: Optional[bool] = None
    login_count: Optional[int] = None
    message_count: Optional[int] = None


router = APIRouter(prefix="/api/v1/users", tags=["Enhanced Users"])


@router.post("/register", response_model=UserProfileResponse)
async def register_user(
    request: UserCreateRequest,
    session: Session = Depends(get_session)
) -> UserProfileResponse:
    """Register a new user account."""
    user_service = UserManagementService(session)
    
    user = await user_service.create_user(
        username=request.username,
        email=request.email,
        password=request.password,
        display_name=request.display_name,
        first_name=request.first_name,
        last_name=request.last_name,
        bio=request.bio,
        tags=request.tags
    )
    
    profile = await user_service.get_user_profile(user.id, include_private=True)
    return UserProfileResponse(**profile)


@router.get("/profile/{user_id}", response_model=UserProfileResponse)
async def get_user_profile(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> UserProfileResponse:
    """Get user profile (public or private based on permissions)."""
    user_service = UserManagementService(session)
    
    # Check if requesting own profile
    include_private = current_user and current_user.id == user_id
    
    profile = await user_service.get_user_profile(user_id, include_private=include_private)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserProfileResponse(**profile)


@router.get("/me", response_model=UserProfileResponse)
async def get_my_profile(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> UserProfileResponse:
    """Get current user's profile with private information."""
    user_service = UserManagementService(session)
    
    profile = await user_service.get_user_profile(current_user.id, include_private=True)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserProfileResponse(**profile)


@router.put("/profile", response_model=UserProfileResponse)
async def update_profile(
    request: UserProfileUpdateRequest,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> UserProfileResponse:
    """Update user profile information."""
    user_service = UserManagementService(session)
    
    updates = request.dict(exclude_unset=True)
    user = await user_service.update_user_profile(current_user.id, updates)
    
    profile = await user_service.get_user_profile(user.id, include_private=True)
    return UserProfileResponse(**profile)


@router.put("/email")
async def update_email(
    request: EmailUpdateRequest,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Update user email address."""
    user_service = UserManagementService(session)
    
    success = await user_service.update_user_email(
        current_user.id,
        request.new_email,
        request.password
    )
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "Email updated successfully. Please verify your new email address."
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update email"
        )


@router.put("/password")
async def change_password(
    request: PasswordChangeRequest,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Change user password."""
    user_service = UserManagementService(session)
    
    success = await user_service.change_password(
        current_user.id,
        request.current_password,
        request.new_password
    )
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "Password changed successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )


@router.post("/profile-picture")
async def upload_profile_picture(
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Upload user profile picture."""
    user_service = UserManagementService(session)
    
    # Validate file
    if not file.content_type or not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Read file data
    file_data = await file.read()
    
    avatar_url = await user_service.upload_profile_picture(
        current_user.id,
        file_data,
        file.filename,
        file.content_type
    )
    
    if avatar_url:
        return JSONResponse({
            "success": True,
            "avatar_url": avatar_url,
            "message": "Profile picture updated successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload profile picture"
        )


@router.delete("/account")
async def delete_account(
    request: AccountDeleteRequest,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Delete user account."""
    user_service = UserManagementService(session)
    
    success = await user_service.delete_user_account(
        current_user.id,
        request.password,
        request.hard_delete
    )
    
    if success:
        delete_type = "permanently deleted" if request.hard_delete else "deactivated"
        return JSONResponse({
            "success": True,
            "message": f"Account {delete_type} successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )


# Friend System Endpoints
@router.post("/friends/request")
async def send_friend_request(
    request: FriendRequestRequest,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Send a friend request."""
    user_service = UserManagementService(session)
    
    success = await user_service.send_friend_request(
        current_user.id,
        request.user_id,
        request.message
    )
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "Friend request sent successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send friend request"
        )


@router.post("/friends/respond")
async def respond_to_friend_request(
    request: FriendRequestResponse,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Accept or decline a friend request."""
    user_service = UserManagementService(session)
    
    success = await user_service.respond_to_friend_request(
        request.friendship_id,
        current_user.id,
        request.accept
    )
    
    if success:
        action = "accepted" if request.accept else "declined"
        return JSONResponse({
            "success": True,
            "message": f"Friend request {action} successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to respond to friend request"
        )


@router.delete("/friends/{friend_id}")
async def remove_friend(
    friend_id: int,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Remove a friend."""
    user_service = UserManagementService(session)
    
    success = await user_service.remove_friend(current_user.id, friend_id)
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "Friend removed successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove friend"
        )


@router.post("/block/{user_id}")
async def block_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Block a user."""
    user_service = UserManagementService(session)
    
    success = await user_service.block_user(current_user.id, user_id)
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "User blocked successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to block user"
        )


@router.get("/friends")
async def get_friends_list(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get user's friends list."""
    user_service = UserManagementService(session)
    return await user_service.get_friends_list(current_user.id)


@router.get("/friends/requests")
async def get_friend_requests(
    sent: bool = Query(False, description="Get sent requests instead of received"),
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get pending friend requests."""
    user_service = UserManagementService(session)
    return await user_service.get_pending_friend_requests(current_user.id, sent=sent)


@router.get("/search")
async def search_users(
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(20, le=50, description="Maximum number of results"),
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> List[Dict[str, Any]]:
    """Search for users by username or display name."""
    user_service = UserManagementService(session)

    exclude_user_id = current_user.id if current_user else None
    return await user_service.search_users(q, limit, exclude_user_id)


@router.get("/statistics/{user_id}")
async def get_user_statistics(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get user statistics (public stats or full stats for own profile)."""
    user_service = UserManagementService(session)

    stats = await user_service.get_user_statistics(user_id)
    if not stats:
        raise HTTPException(status_code=404, detail="User not found")

    # If not own profile, return limited stats
    if not current_user or current_user.id != user_id:
        return {
            "user_id": stats["user_id"],
            "friends_count": stats["friends_count"],
            "account_age_days": stats["account_age_days"],
            "is_verified": stats["is_verified"]
        }

    return stats


@router.get("/me/statistics")
async def get_my_statistics(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get current user's full statistics."""
    user_service = UserManagementService(session)

    stats = await user_service.get_user_statistics(current_user.id)
    if not stats:
        raise HTTPException(status_code=404, detail="User statistics not found")

    return stats


@router.post("/activity")
async def update_activity(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Update user's last activity timestamp."""
    user_service = UserManagementService(session)

    success = await user_service.update_user_activity(current_user.id)

    if success:
        return JSONResponse({
            "success": True,
            "message": "Activity updated"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update activity"
        )
