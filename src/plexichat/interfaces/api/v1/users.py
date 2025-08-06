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

from .auth import get_current_user

# Import database service layer
try:
    from plexichat.core.services.database_service import get_database_service
    DATABASE_SERVICE_AVAILABLE = True
except ImportError:
    DATABASE_SERVICE_AVAILABLE = False
    async def get_database_service(): return None

# Use existing logging system
logger = get_logger(__name__)
router = APIRouter(prefix="/users", tags=["Enhanced Users"])

# Import caching system
try:
    from plexichat.core.caching.unified_cache_integration import (
        cache_get, cache_set, cache_delete, CacheKeyBuilder
    )
    CACHE_AVAILABLE = True
except ImportError:
    # Fallback if cache not available
    async def cache_get(key: str, default=None): return default
    async def cache_set(key: str, value, ttl=None): return True
    async def cache_delete(key: str): return True
    class CacheKeyBuilder:
        @staticmethod
        def user_profile_key(user_id: str): return f"user_profile:{user_id}"
        @staticmethod
        def user_search_key(query: str, limit: int): return f"user_search:{hash(query)}:{limit}"
        @staticmethod
        def user_list_key(offset: int, limit: int): return f"user_list:{offset}:{limit}"
        @staticmethod
        def public_profile_key(user_id: str): return f"public_profile:{user_id}"
    CACHE_AVAILABLE = False

# Fallback in-memory storage (for backward compatibility)
users_db = {}

# Import global rate limiting system
try:
    from src.plexichat.infrastructure.utils.rate_limiting import rate_limiter
    RATE_LIMITING_AVAILABLE = True
except ImportError:
    try:
        from plexichat.infrastructure.utils.rate_limiting import rate_limiter
        RATE_LIMITING_AVAILABLE = True
    except ImportError:
        RATE_LIMITING_AVAILABLE = False
        logger.warning("Rate limiting system not available")

# Import security utilities
try:
    from src.plexichat.infrastructure.utils.security_utils import (
        sanitize_input, validate_input, check_sql_injection, check_xss
    )
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    SECURITY_UTILS_AVAILABLE = False
    logger.warning("Security utilities not available")

# Comprehensive security and rate limiting dependency
async def apply_security_and_rate_limit(request: Request):
    """Apply comprehensive security checks and rate limiting to all endpoints."""
    client_ip = request.client.host if request.client else "unknown"
    endpoint = f"{request.method}:{request.url.path}"

    # 1. Security Headers Check
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }

    # 2. Input Validation and Sanitization
    if SECURITY_UTILS_AVAILABLE:
        try:
            # Check for common attack patterns in URL
            if check_sql_injection(str(request.url)) or check_xss(str(request.url)):
                logger.warning(f"Potential attack detected from {client_ip}: {request.url}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid request format",
                    headers=security_headers
                )

            # Check request headers for suspicious patterns
            for header_name, header_value in request.headers.items():
                if check_sql_injection(header_value) or check_xss(header_value):
                    logger.warning(f"Suspicious header from {client_ip}: {header_name}={header_value}")
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid request headers",
                        headers=security_headers
                    )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security validation error: {e}")

    # 3. Rate Limiting with Dynamic Scaling
    if RATE_LIMITING_AVAILABLE:
        try:
            # Get system load for dynamic scaling
            import psutil
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory_usage = psutil.virtual_memory().percent

            # Calculate dynamic rate limit based on system load
            base_limit = 100  # requests per minute
            if cpu_usage > 80 or memory_usage > 80:
                rate_limit = int(base_limit * 0.3)  # Reduce by 70% under high load
            elif cpu_usage > 60 or memory_usage > 60:
                rate_limit = int(base_limit * 0.6)  # Reduce by 40% under medium load
            else:
                rate_limit = base_limit

            # Check rate limit
            if not rate_limiter.check_rate_limit(
                key=f"user_endpoint:{client_ip}",
                max_attempts=rate_limit,
                window_minutes=1,
                algorithm="sliding_window"
            ):
                logger.warning(f"Rate limit exceeded for {client_ip}: {rate_limit}/min")
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Current limit: {rate_limit}/min based on system load",
                    headers={**security_headers, "Retry-After": "60"}
                )

            # Record the attempt
            rate_limiter.record_attempt(f"user_endpoint:{client_ip}")

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")

    # 4. Request Size Validation
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            size = int(content_length)
            max_size = 10 * 1024 * 1024  # 10MB limit
            if size > max_size:
                logger.warning(f"Request too large from {client_ip}: {size} bytes")
                raise HTTPException(
                    status_code=413,
                    detail="Request entity too large",
                    headers=security_headers
                )
        except ValueError:
            pass

    # 5. Log security event
    logger.info(f"Security check passed for {client_ip} accessing {endpoint}")

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
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: None = Depends(apply_security_and_rate_limit)
):
    """Get current user's complete profile including custom fields with caching and database service."""
    try:
        user_id = current_user['id']

        # Try to get from cache first
        cache_key = CacheKeyBuilder.user_profile_key(user_id)
        cached_profile = await cache_get(cache_key)
        if cached_profile is not None:
            logger.debug(f"Cache hit for user profile: {user_id}")
            return cached_profile

        # Get fresh user data from database service
        db_service = await get_database_service()
        user_data = await db_service.get_user(user_id)

        if not user_data:
            # Fallback to current_user data if database service fails
            user_data = current_user

        # Convert custom fields to proper format
        custom_fields = {}
        if 'custom_fields' in user_data and user_data['custom_fields']:
            for name, field_data in user_data['custom_fields'].items():
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

        profile = UserProfile(
            id=user_data['id'],
            username=user_data['username'],
            email=user_data['email'],
            display_name=user_data.get('display_name', user_data['username']),
            first_name=user_data.get('first_name'),
            last_name=user_data.get('last_name'),
            bio=user_data.get('bio'),
            avatar_url=user_data.get('avatar_url'),
            location=user_data.get('location'),
            website=user_data.get('website'),
            created_at=user_data['created_at'],
            last_active=user_data.get('last_active'),
            is_active=user_data.get('is_active', True),
            is_verified=user_data.get('is_verified', False),
            custom_fields=custom_fields
        )

        # Cache for 15 minutes (user profiles don't change very often)
        await cache_set(cache_key, profile, ttl=900)
        logger.debug(f"Cached user profile: {user_id}")

        return profile
    except Exception as e:
        logger.error(f"Error getting user profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve profile")

@router.put("/me")
async def update_my_profile(
    update_data: UserUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
    _: None = Depends(apply_security_and_rate_limit)
):
    """Update current user's profile with enhanced fields and security validation."""
    try:
        user_id = current_user['id']
        db_service = await get_database_service()

        # Security validation for all input fields
        if SECURITY_UTILS_AVAILABLE:
            fields_to_check = {
                'display_name': update_data.display_name,
                'first_name': update_data.first_name,
                'last_name': update_data.last_name,
                'bio': update_data.bio,
                'location': update_data.location,
                'website': update_data.website,
                'avatar_url': update_data.avatar_url
            }

            for field_name, field_value in fields_to_check.items():
                if field_value is not None:
                    # Check for XSS and SQL injection
                    if check_xss(str(field_value)) or check_sql_injection(str(field_value)):
                        logger.warning(f"Malicious input detected in {field_name} from user {user_id}")
                        raise HTTPException(
                            status_code=400,
                            detail=f"Invalid characters in {field_name}"
                        )

                    # Sanitize input
                    sanitized_value = sanitize_input(str(field_value))
                    if sanitized_value != str(field_value):
                        logger.info(f"Input sanitized for {field_name} from user {user_id}")

        # Prepare update data with sanitized values
        updates = {}
        if update_data.display_name is not None:
            updates['display_name'] = sanitize_input(update_data.display_name) if SECURITY_UTILS_AVAILABLE else update_data.display_name
        if update_data.first_name is not None:
            updates['first_name'] = sanitize_input(update_data.first_name) if SECURITY_UTILS_AVAILABLE else update_data.first_name
        if update_data.last_name is not None:
            updates['last_name'] = sanitize_input(update_data.last_name) if SECURITY_UTILS_AVAILABLE else update_data.last_name
        if update_data.bio is not None:
            updates['bio'] = sanitize_input(update_data.bio) if SECURITY_UTILS_AVAILABLE else update_data.bio
        if update_data.location is not None:
            updates['location'] = sanitize_input(update_data.location) if SECURITY_UTILS_AVAILABLE else update_data.location
        if update_data.website is not None:
            # Additional URL validation for website
            import re
            url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
            if not url_pattern.match(update_data.website):
                raise HTTPException(status_code=400, detail="Invalid website URL format")
            updates['website'] = update_data.website
        if update_data.avatar_url is not None:
            # Additional URL validation for avatar
            import re
            url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
            if not url_pattern.match(update_data.avatar_url):
                raise HTTPException(status_code=400, detail="Invalid avatar URL format")
            updates['avatar_url'] = update_data.avatar_url

        # Update user in database
        success = await db_service.update_user(user_id, updates)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update profile")

        # Get updated user data for response
        updated_user = await db_service.get_user(user_id)

        # Invalidate relevant caches
        user_id = current_user['id']
        await cache_delete(CacheKeyBuilder.user_profile_key(user_id))
        await cache_delete(CacheKeyBuilder.public_profile_key(user_id))

        # Invalidate user search cache (since profile data might affect search results)
        # Note: In a real implementation, you'd want a more sophisticated cache invalidation strategy
        # For now, we'll let search caches expire naturally since they have short TTL

        # Invalidate user list cache (first page most commonly accessed)
        await cache_delete(CacheKeyBuilder.user_list_key(0, 20))

        logger.info(f"User profile updated: {current_user['username']}")
        logger.debug(f"Invalidated profile caches for user: {user_id}")

        return {
            "success": True,
            "message": "Profile updated successfully",
            "user": {
                "id": updated_user['id'] if updated_user else user_id,
                "username": updated_user.get('username', '') if updated_user else '',
                "display_name": updated_user.get('display_name', updated_user.get('username', '')) if updated_user else '',
                "first_name": updated_user.get('first_name') if updated_user else None,
                "last_name": updated_user.get('last_name') if updated_user else None,
                "bio": updated_user.get('bio') if updated_user else None,
                "location": updated_user.get('location') if updated_user else None,
                "website": updated_user.get('website') if updated_user else None,
                "avatar_url": updated_user.get('avatar_url') if updated_user else None
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
    """Search for users with caching."""
    try:
        # Try to get from cache first
        cache_key = CacheKeyBuilder.user_search_key(query, limit)
        cached_results = await cache_get(cache_key)
        if cached_results is not None:
            # Filter out the current user from cached results
            filtered_users = [u for u in cached_results["users"] if u["id"] != current_user['id']]
            cached_results["users"] = filtered_users
            cached_results["count"] = len(filtered_users)
            logger.debug(f"Cache hit for user search: {query}")
            return cached_results

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

        search_results = {
            "users": results,
            "count": len(results),
            "query": query
        }

        # Cache for 5 minutes (search results can change as users update profiles)
        await cache_set(cache_key, search_results, ttl=300)
        logger.debug(f"Cached user search results: {query}")

        return search_results

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
    """List all users (paginated) with caching."""
    try:
        # Try to get from cache first
        cache_key = CacheKeyBuilder.user_list_key(offset, limit)
        cached_list = await cache_get(cache_key)
        if cached_list is not None:
            logger.debug(f"Cache hit for user list: offset={offset}, limit={limit}")
            return cached_list

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

        result = {
            "users": users_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }

        # Cache for 10 minutes (user list changes when new users register)
        await cache_set(cache_key, result, ttl=600)
        logger.debug(f"Cached user list: offset={offset}, limit={limit}")

        return result

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

        # Invalidate relevant caches
        user_id = current_user['id']
        await cache_delete(CacheKeyBuilder.user_profile_key(user_id))
        await cache_delete(CacheKeyBuilder.public_profile_key(user_id))

        logger.info(f"Custom fields updated for user: {current_user['username']}")
        logger.debug(f"Invalidated profile caches for custom fields update: {user_id}")

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

# Public endpoint - no authentication required but still secured and rate limited
@router.get("/{user_id}/public", response_model=PublicUserProfile)
async def get_public_user_profile(
    user_id: str,
    request: Request,
    _: None = Depends(apply_security_and_rate_limit)
):
    """Get public user profile information (no authentication required but secured) with caching."""
    try:
        # Validate user_id format for security
        if SECURITY_UTILS_AVAILABLE:
            if check_sql_injection(user_id) or check_xss(user_id):
                logger.warning(f"Malicious user_id parameter: {user_id}")
                raise HTTPException(status_code=400, detail="Invalid user ID format")

        # Additional user_id format validation
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID format")

        # Try to get from cache first
        cache_key = CacheKeyBuilder.public_profile_key(user_id)
        cached_profile = await cache_get(cache_key)
        if cached_profile is not None:
            logger.debug(f"Cache hit for public profile: {user_id}")
            return cached_profile

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

        profile = PublicUserProfile(
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

        # Cache for 30 minutes (public profiles are accessed frequently and change less often)
        await cache_set(cache_key, profile, ttl=1800)
        logger.debug(f"Cached public profile: {user_id}")

        return profile
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
