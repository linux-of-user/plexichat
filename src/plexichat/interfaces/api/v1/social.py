from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from plexichat.app.logger_config import logger
from plexichat.app.services.social_service import UserStatus, social_service

"""
Social & Friends API endpoints for PlexiChat.
Provides comprehensive social features including friends, profiles, and activities.
"""

# Pydantic models for API
class ProfileCreateRequest(BaseModel):
    display_name: str
    bio: Optional[str] = None
    privacy_settings: Optional[Dict[str, Any]] = None


class ProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    status_message: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    privacy_settings: Optional[Dict[str, Any]] = None
    social_links: Optional[Dict[str, str]] = None


class StatusUpdateRequest(BaseModel):
    status: str
    status_message: Optional[str] = None


class FriendRequestRequest(BaseModel):
    recipient_id: int
    message: Optional[str] = None


class FriendRequestResponseRequest(BaseModel):
    friendship_id: str
    accept: bool


class UserSearchRequest(BaseModel):
    query: str
    limit: int = 20


router = APIRouter(prefix="/api/v1/social", tags=["Social & Friends"])


@router.post("/profile")
async def create_profile(request: ProfileCreateRequest):
    """Create or update user profile."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        profile = social_service.create_user_profile(
            user_id=user_id,
            display_name=request.display_name,
            bio=request.bio,
            privacy_settings=request.privacy_settings
        )
        
        return {
            "success": True,
            "message": "Profile created/updated successfully",
            "profile": {
                "user_id": profile.user_id,
                "display_name": profile.display_name,
                "bio": profile.bio,
                "status": profile.status.value,
                "joined_at": profile.joined_at.isoformat() if profile.joined_at else None
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to create profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/profile/{user_id}")
async def get_profile(user_id: int):
    """Get user profile."""
    try:
        profile = social_service.get_user_profile(user_id)
        
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        return {
            "success": True,
            "profile": {
                "user_id": profile.user_id,
                "display_name": profile.display_name,
                "bio": profile.bio,
                "status": profile.status.value,
                "status_message": profile.status_message,
                "avatar_url": profile.avatar_url,
                "banner_url": profile.banner_url,
                "location": profile.location,
                "website": profile.website,
                "joined_at": profile.joined_at.isoformat() if profile.joined_at else None,
                "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
                "badges": profile.badges or [],
                "social_links": profile.social_links or {}
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/profile")
async def update_profile(request: ProfileUpdateRequest):
    """Update user profile."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        profile = social_service.get_user_profile(user_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        
        # Update profile fields
        if request.display_name is not None:
            profile.display_name = request.display_name
        if request.bio is not None:
            profile.bio = request.bio
        if request.status_message is not None:
            profile.status_message = request.status_message
        if request.avatar_url is not None:
            profile.avatar_url = request.avatar_url
        if request.banner_url is not None:
            profile.banner_url = request.banner_url
        if request.location is not None:
            profile.location = request.location
        if request.website is not None:
            profile.website = request.website
        if request.privacy_settings is not None:
            profile.privacy_from plexichat.core.config import settings
settings.update(request.privacy_settings)
        if request.social_links is not None:
            profile.social_links = request.social_links
        
        social_service._save_social_data()
        
        return {
            "success": True,
            "message": "Profile updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/status")
async def update_status(request: StatusUpdateRequest):
    """Update user status."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        # Validate status
        try:
            status = UserStatus(request.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {request.status}")
        
        success = social_service.update_user_status(
            user_id=user_id,
            status=status,
            status_message=request.status_message
        )
        
        if success:
            return {
                "success": True,
                "message": "Status updated successfully",
                "status": request.status,
                "status_message": request.status_message
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update status")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/friends/request")
async def send_friend_request(request: FriendRequestRequest):
    """Send a friend request."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        friendship_id = social_service.send_friend_request(
            requester_id=user_id,
            recipient_id=request.recipient_id,
            message=request.message
        )
        
        if friendship_id:
            return {
                "success": True,
                "message": "Friend request sent successfully",
                "friendship_id": friendship_id
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to send friend request")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to send friend request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/friends/respond")
async def respond_friend_request(request: FriendRequestResponseRequest):
    """Respond to a friend request."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        success = social_service.respond_to_friend_request(
            friendship_id=request.friendship_id,
            user_id=user_id,
            accept=request.accept
        )
        
        if success:
            action = "accepted" if request.accept else "declined"
            return {
                "success": True,
                "message": f"Friend request {action} successfully",
                "friendship_id": request.friendship_id,
                "accepted": request.accept
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to respond to friend request")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to respond to friend request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/friends")
async def get_friends_list():
    """Get user's friends list."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        friends = social_service.get_friends_list(user_id)
        
        return {
            "success": True,
            "friends": friends,
            "total_friends": len(friends)
        }
        
    except Exception as e:
        logger.error(f"Failed to get friends list: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/friends/requests")
async def get_friend_requests():
    """Get pending friend requests."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        requests = social_service.get_friend_requests(user_id)
        
        return {
            "success": True,
            "friend_requests": requests,
            "sent_count": len(requests["sent"]),
            "received_count": len(requests["received"])
        }
        
    except Exception as e:
        logger.error(f"Failed to get friend requests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/friends/{friend_id}")
async def remove_friend(friend_id: int):
    """Remove a friend."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        success = social_service.remove_friend(user_id, friend_id)
        
        if success:
            return {
                "success": True,
                "message": "Friend removed successfully",
                "friend_id": friend_id
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to remove friend")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to remove friend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/block/{user_id}")
async def block_user(user_id: int):
    """Block a user."""
    try:
        # In a real implementation, this would get current user_id from authentication
        current_user_id = 1  # Placeholder
        
        success = social_service.block_user(current_user_id, user_id)
        
        if success:
            return {
                "success": True,
                "message": "User blocked successfully",
                "blocked_user_id": user_id
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to block user")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to block user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/block/{user_id}")
async def unblock_user(user_id: int):
    """Unblock a user."""
    try:
        # In a real implementation, this would get current user_id from authentication
        current_user_id = 1  # Placeholder
        
        success = social_service.unblock_user(current_user_id, user_id)
        
        if success:
            return {
                "success": True,
                "message": "User unblocked successfully",
                "unblocked_user_id": user_id
            }
        else:
            return {
                "success": False,
                "message": "User was not blocked"
            }
            
    except Exception as e:
        logger.error(f"Failed to unblock user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search")
async def search_users(request: UserSearchRequest):
    """Search for users."""
    try:
        users = social_service.search_users(request.query, request.limit)
        
        return {
            "success": True,
            "users": users,
            "total_results": len(users),
            "query": request.query
        }
        
    except Exception as e:
        logger.error(f"Failed to search users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/feed")
async def get_social_feed(limit: int = 50):
    """Get social activity feed."""
    try:
        # In a real implementation, this would get user_id from authentication
        user_id = 1  # Placeholder
        
        feed = social_service.get_social_feed(user_id, limit)
        
        return {
            "success": True,
            "feed": feed,
            "total_activities": len(feed)
        }
        
    except Exception as e:
        logger.error(f"Failed to get social feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_social_statistics():
    """Get social system statistics."""
    try:
        stats = social_service.get_social_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Failed to get social statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/friendship/{user1_id}/{user2_id}")
async def check_friendship(user1_id: int, user2_id: int):
    """Check friendship status between two users."""
    try:
        are_friends = social_service.are_friends(user1_id, user2_id)
        is_blocked = social_service.is_user_blocked(user1_id, user2_id)
        
        return {
            "success": True,
            "user1_id": user1_id,
            "user2_id": user2_id,
            "are_friends": are_friends,
            "is_blocked": is_blocked
        }
        
    except Exception as e:
        logger.error(f"Failed to check friendship: {e}")
        raise HTTPException(status_code=500, detail=str(e))
