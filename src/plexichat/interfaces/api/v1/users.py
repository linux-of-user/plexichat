"""
PlexiChat API v1 - Enhanced User Management Endpoints

Comprehensive user management with:
- Enhanced user profiles with custom fields
- User search and discovery
- Profile updates and customization
- Public user information (no auth required)
- Custom field management
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import time

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, EmailStr, Field
from src.plexichat.core.logging import get_logger

from .auth import get_current_user, users_db

# Import global rate limiting system
try:
    from src.plexichat.infrastructure.utils.rate_limiting import rate_limiter
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    RATE_LIMITING_AVAILABLE = False
    logger.warning("Rate limiting system not available")

# Rate limiting dependency
async def apply_rate_limit(request: Request):
    """Apply global rate limiting to all endpoints."""
    if not RATE_LIMITING_AVAILABLE:
        return

    try:
        client_ip = request.client.host if request.client else "unknown"
        endpoint = f"{request.method}:{request.url.path}"

        # Get system load for dynamic scaling
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory_usage = psutil.virtual_memory().percent

        # Calculate dynamic rate limit based on system load
        base_limit = 100  # requests per minute
        if cpu_usage > 80 or memory_usage > 80:
            rate_limit = int(base_limit * 0.5)  # Reduce by 50% under high load
        elif cpu_usage > 60 or memory_usage > 60:
            rate_limit = int(base_limit * 0.75)  # Reduce by 25% under medium load
        else:
            rate_limit = base_limit

        # Check rate limit
        if not rate_limiter.check_rate_limit(
            key=f"user_endpoint:{client_ip}",
            max_attempts=rate_limit,
            window_minutes=1,
            algorithm="sliding_window"
        ):
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Current limit: {rate_limit}/min based on system load",
                headers={"Retry-After": "60"}
            )

        # Record the attempt
        rate_limiter.record_attempt(f"user_endpoint:{client_ip}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Rate limiting error: {e}")
        # Don't block requests if rate limiting fails

# Use existing logging system
logger = get_logger(__name__)
router = APIRouter(prefix="/users", tags=["Enhanced Users"])

# Enhanced Models with Custom Fields Support
class CustomField(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    value: Any
    type: str = Field(default="text", pattern="^(text|number|boolean|date|url|email|phone|select|multiselect)$")
    is_public: bool = Field(default=False, description="Whether this field is visible to other users")
    is_searchable: bool = Field(default=False, description="Whether this field can be searched")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    created_at: datetime
    last_active: Optional[datetime] = None
    is_active: bool
    is_verified: bool = False
    custom_fields: Dict[str, CustomField] = Field(default_factory=dict)

class PublicUserProfile(BaseModel):
    """Public user profile (no authentication required)"""
    id: str
    username: str
    display_name: str
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    is_verified: bool = False
    member_since: datetime
    public_custom_fields: Dict[str, Any] = Field(default_factory=dict)

class UserUpdate(BaseModel):
    display_name: Optional[str] = Field(None, max_length=100)
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    location: Optional[str] = Field(None, max_length=100)
    website: Optional[str] = Field(None, max_length=200)
    avatar_url: Optional[str] = Field(None, max_length=500)

class CustomFieldUpdate(BaseModel):
    custom_fields: Dict[str, CustomField]

class UserSearch(BaseModel):
    id: str
    username: str
    display_name: str
    avatar_url: Optional[str] = None
    is_verified: bool = False
    is_online: bool = False
    match_score: float = 0.0  # Relevance score for search results

# Enhanced Endpoints with Custom Fields and Rate Limiting
@router.get("/me", response_model=UserProfile)
async def get_my_profile(
    current_user: dict = Depends(get_current_user),
    _: None = Depends(apply_rate_limit)
):
    """Get current user's complete profile including custom fields."""
    try:
        # Convert custom fields to proper format
        custom_fields = {}
        if 'custom_fields' in current_user and current_user['custom_fields']:
            for name, field_data in current_user['custom_fields'].items():
                if isinstance(field_data, dict):
                    custom_fields[name] = CustomField(**field_data)
                else:
                    # Legacy format - convert to new format
                    custom_fields[name] = CustomField(
                        name=name,
                        value=field_data,
                        type="text",
                        is_public=False,
                        is_searchable=False
                    )

        return UserProfile(
            id=current_user['id'],
            username=current_user['username'],
            email=current_user['email'],
            display_name=current_user.get('display_name', current_user['username']),
            first_name=current_user.get('first_name'),
            last_name=current_user.get('last_name'),
            bio=current_user.get('bio'),
            avatar_url=current_user.get('avatar_url'),
            location=current_user.get('location'),
            website=current_user.get('website'),
            created_at=current_user['created_at'],
            last_active=current_user.get('last_active'),
            is_active=current_user.get('is_active', True),
            is_verified=current_user.get('is_verified', False),
            custom_fields=custom_fields
        )
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve profile")

@router.put("/me")
async def update_my_profile(
    update_data: UserUpdate,
    current_user: dict = Depends(get_current_user),
    _: None = Depends(apply_rate_limit)
):
    """Update current user's profile with enhanced fields."""
    try:
        user_id = current_user['id']
        user = users_db[user_id]

        # Update all provided fields
        if update_data.display_name is not None:
            user['display_name'] = update_data.display_name
        if update_data.first_name is not None:
            user['first_name'] = update_data.first_name
        if update_data.last_name is not None:
            user['last_name'] = update_data.last_name
        if update_data.bio is not None:
            user['bio'] = update_data.bio
        if update_data.location is not None:
            user['location'] = update_data.location
        if update_data.website is not None:
            user['website'] = update_data.website
        if update_data.avatar_url is not None:
            user['avatar_url'] = update_data.avatar_url

        user['updated_at'] = datetime.now()

        logger.info(f"User profile updated: {current_user['username']}")

        return {
            "success": True,
            "message": "Profile updated successfully",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "display_name": user.get('display_name', user['username']),
                "first_name": user.get('first_name'),
                "last_name": user.get('last_name'),
                "bio": user.get('bio'),
                "location": user.get('location'),
                "website": user.get('website'),
                "avatar_url": user.get('avatar_url')
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        raise HTTPException(status_code=500, detail="Profile update failed")

@router.get("/search")
async def search_users(
    query: str = Query(..., min_length=1),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    """Search for users."""
    try:
        results = []
        query_lower = query.lower()
        
        for user in users_db.values():
            if user['id'] == current_user['id']:
                continue
                
            if (query_lower in user['username'].lower() or 
                query_lower in user['display_name'].lower() or
                query_lower in user['email'].lower()):
                
                results.append(UserSearch(
                    id=user['id'],
                    username=user['username'],
                    display_name=user['display_name'],
                    is_online=False  # Would check session status in real app
                ))
                
                if len(results) >= limit:
                    break
        
        return {
            "users": results,
            "count": len(results),
            "query": query
        }
        
    except Exception as e:
        logger.error(f"User search error: {e}")
        raise HTTPException(status_code=500, detail="Search failed")

@router.get("/{user_id}", response_model=UserProfile)
async def get_user_profile(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a user's public profile."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users_db[user_id]
        
        return UserProfile(
            id=user['id'],
            username=user['username'],
            email=user['email'],  # In real app, might hide email for privacy
            display_name=user['display_name'],
            created_at=user['created_at'],
            is_active=user['is_active']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user profile error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user profile")

@router.get("/")
async def list_users(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """List all users (paginated)."""
    try:
        all_users = list(users_db.values())
        total = len(all_users)
        
        # Apply pagination
        paginated_users = all_users[offset:offset + limit]
        
        users_list = []
        for user in paginated_users:
            users_list.append({
                "id": user['id'],
                "username": user['username'],
                "display_name": user['display_name'],
                "created_at": user['created_at'],
                "is_active": user['is_active']
            })
        
        return {
            "users": users_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }
        
    except Exception as e:
        logger.error(f"List users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")

@router.delete("/me")
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    """Delete current user's account."""
    try:
        user_id = current_user['id']
        
        # Remove user from database
        if user_id in users_db:
            del users_db[user_id]
        
        # Remove all sessions for this user
        from .auth import sessions_db
        sessions_to_remove = [
            sid for sid, session in sessions_db.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        logger.info(f"User account deleted: {current_user['username']}")
        
        return {
            "success": True,
            "message": "Account deleted successfully"
        }
        
    except Exception as e:
        logger.error(f"Delete account error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account")

# Custom Fields Management Endpoints
@router.put("/me/custom-fields")
async def update_custom_fields(
    field_update: CustomFieldUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update user's custom fields."""
    try:
        user_id = current_user['id']
        user = users_db[user_id]

        # Initialize custom_fields if not exists
        if 'custom_fields' not in user:
            user['custom_fields'] = {}

        # Validate and update custom fields
        for field_name, field_data in field_update.custom_fields.items():
            # Validate field name
            if len(field_name) > 50:
                raise HTTPException(status_code=400, detail=f"Field name '{field_name}' too long (max 50 chars)")

            # Convert to dict for storage
            user['custom_fields'][field_name] = {
                "name": field_data.name,
                "value": field_data.value,
                "type": field_data.type,
                "is_public": field_data.is_public,
                "is_searchable": field_data.is_searchable,
                "created_at": field_data.created_at.isoformat() if hasattr(field_data.created_at, 'isoformat') else str(field_data.created_at),
                "updated_at": datetime.now().isoformat()
            }

        user['updated_at'] = datetime.now()

        logger.info(f"Custom fields updated for user: {current_user['username']}")

        return {
            "success": True,
            "message": "Custom fields updated successfully",
            "custom_fields": user['custom_fields']
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Custom fields update error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update custom fields")

@router.delete("/me/custom-fields/{field_name}")
async def delete_custom_field(
    field_name: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a specific custom field."""
    try:
        user_id = current_user['id']
        user = users_db[user_id]

        if 'custom_fields' not in user or field_name not in user['custom_fields']:
            raise HTTPException(status_code=404, detail="Custom field not found")

        del user['custom_fields'][field_name]
        user['updated_at'] = datetime.now()

        logger.info(f"Custom field '{field_name}' deleted for user: {current_user['username']}")

        return {
            "success": True,
            "message": f"Custom field '{field_name}' deleted successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Custom field deletion error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete custom field")

# Public endpoint - no authentication required but still rate limited
@router.get("/{user_id}/public", response_model=PublicUserProfile)
async def get_public_user_profile(
    user_id: str,
    request: Request,
    _: None = Depends(apply_rate_limit)
):
    """Get public user profile information (no authentication required)."""
    try:
        user = None
        for u in users_db.values():
            if u['id'] == user_id:
                user = u
                break

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Extract only public custom fields
        public_custom_fields = {}
        if 'custom_fields' in user and user['custom_fields']:
            for name, field_data in user['custom_fields'].items():
                if isinstance(field_data, dict) and field_data.get('is_public', False):
                    public_custom_fields[name] = field_data.get('value')

        return PublicUserProfile(
            id=user['id'],
            username=user['username'],
            display_name=user.get('display_name', user['username']),
            bio=user.get('bio'),
            avatar_url=user.get('avatar_url'),
            location=user.get('location'),
            website=user.get('website'),
            is_verified=user.get('is_verified', False),
            member_since=user['created_at'],
            public_custom_fields=public_custom_fields
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting public user profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve public profile")

@router.get("/stats/summary")
async def get_user_stats(current_user: dict = Depends(get_current_user)):
    """Get user statistics summary."""
    return {
        "total_users": len(users_db),
        "active_users": sum(1 for u in users_db.values() if u.get('is_active', False)),
        "timestamp": datetime.now()
    }
