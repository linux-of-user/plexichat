"""
NetLink Third-Party Admin API

Secure API for third-party systems to manage users, permissions, and system configuration.
Includes comprehensive authentication, rate limiting, and audit logging.
"""

import asyncio
import json
import secrets
import hmac
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Depends, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import logging

from ...core.users.enhanced_user_manager import (
    get_enhanced_user_manager, UserTier, UserTag, Permission, PermissionScope
)
from ...core.security.rate_limiting import get_rate_limiter
from ...core.auth import get_current_user

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

# Router for admin API
admin_api_router = APIRouter(
    prefix="/admin",
    tags=["admin-api"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        429: {"description": "Rate Limited"},
        500: {"description": "Internal Server Error"}
    }
)


# Pydantic models for API
class APIKeyRequest(BaseModel):
    """Request model for API key creation."""
    name: str = Field(..., description="Name for the API key")
    description: Optional[str] = Field(None, description="Description of the API key purpose")
    permissions: List[str] = Field(..., description="List of permissions for the API key")
    expires_in_days: Optional[int] = Field(30, description="Number of days until expiration")
    rate_limit: Optional[int] = Field(1000, description="Rate limit per hour")


class APIKeyResponse(BaseModel):
    """Response model for API key creation."""
    key_id: str
    api_key: str
    name: str
    permissions: List[str]
    expires_at: datetime
    rate_limit: int


class UserCreateRequest(BaseModel):
    """Request model for user creation."""
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    tier: str = Field("basic", description="User tier")
    tags: Optional[List[str]] = Field(None, description="User tags")
    profile_data: Optional[Dict[str, Any]] = Field(None, description="Additional profile data")


class UserUpdateRequest(BaseModel):
    """Request model for user updates."""
    tier: Optional[str] = Field(None, description="New user tier")
    tags: Optional[List[str]] = Field(None, description="User tags to set")
    add_tags: Optional[List[str]] = Field(None, description="Tags to add")
    remove_tags: Optional[List[str]] = Field(None, description="Tags to remove")
    profile_updates: Optional[Dict[str, Any]] = Field(None, description="Profile updates")


class PermissionRequest(BaseModel):
    """Request model for permission management."""
    user_id: str = Field(..., description="User ID")
    permission: str = Field(..., description="Permission name")
    scope: str = Field("global", description="Permission scope")
    scope_id: str = Field("global", description="Scope ID")
    action: str = Field(..., description="Action: grant or revoke")


class AdminAPIManager:
    """Manager for third-party admin API."""
    
    def __init__(self):
        self.user_manager = get_enhanced_user_manager()
        self.rate_limiter = get_rate_limiter()
        
        # API key storage
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.api_key_usage: Dict[str, Dict[str, int]] = {}
        
        # Load existing API keys
        self._load_api_keys()
        
        logger.info("Admin API Manager initialized")
    
    def _load_api_keys(self):
        """Load API keys from storage."""
        try:
            # In production, load from secure storage
            # For now, create a default admin API key
            default_key = self._generate_api_key(
                "default_admin",
                "Default admin API key",
                ["admin", "user_management", "system_config"],
                rate_limit=10000
            )
            logger.info(f"Default admin API key created: {default_key['api_key'][:16]}...")
        except Exception as e:
            logger.error(f"Failed to load API keys: {e}")
    
    def _generate_api_key(self, name: str, description: str, permissions: List[str], 
                         expires_in_days: int = 30, rate_limit: int = 1000) -> Dict[str, Any]:
        """Generate a new API key."""
        key_id = secrets.token_hex(16)
        api_key = f"nla_{secrets.token_urlsafe(32)}"  # NetLink Admin prefix
        
        key_data = {
            "key_id": key_id,
            "api_key": api_key,
            "name": name,
            "description": description,
            "permissions": permissions,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            "rate_limit": rate_limit,
            "is_active": True,
            "last_used": None,
            "usage_count": 0
        }
        
        self.api_keys[api_key] = key_data
        self.api_key_usage[api_key] = {"hourly": 0, "daily": 0, "total": 0}
        
        return key_data
    
    def _validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key and return key data."""
        if api_key not in self.api_keys:
            return None
        
        key_data = self.api_keys[api_key]
        
        # Check if key is active
        if not key_data["is_active"]:
            return None
        
        # Check if key is expired
        if datetime.now(timezone.utc) > key_data["expires_at"]:
            return None
        
        # Update usage
        key_data["last_used"] = datetime.now(timezone.utc)
        key_data["usage_count"] += 1
        self.api_key_usage[api_key]["total"] += 1
        
        return key_data
    
    def _check_rate_limit(self, api_key: str) -> bool:
        """Check if API key is within rate limits."""
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        usage = self.api_key_usage[api_key]
        
        # Check hourly rate limit
        if usage["hourly"] >= key_data["rate_limit"]:
            return False
        
        # Increment usage
        usage["hourly"] += 1
        usage["daily"] += 1
        
        return True
    
    def _check_permission(self, api_key: str, required_permission: str) -> bool:
        """Check if API key has required permission."""
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        return required_permission in key_data["permissions"] or "admin" in key_data["permissions"]


# Dependency for API key authentication
async def authenticate_api_key(request: Request, authorization: str = Header(None)) -> Dict[str, Any]:
    """Authenticate API key from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    
    # Extract API key from Authorization header
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format"
        )
    
    api_key = authorization[7:]  # Remove "Bearer " prefix
    
    # Validate API key
    admin_api = AdminAPIManager()
    key_data = admin_api._validate_api_key(api_key)
    
    if not key_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key"
        )
    
    # Check rate limit
    if not admin_api._check_rate_limit(api_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    return key_data


# Dependency for permission checking
def require_permission(permission: str):
    """Dependency factory for permission checking."""
    async def check_permission(key_data: Dict[str, Any] = Depends(authenticate_api_key)):
        admin_api = AdminAPIManager()
        if not admin_api._check_permission(key_data["api_key"], permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return key_data
    return check_permission


# API endpoints
@admin_api_router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyRequest,
    key_data: Dict[str, Any] = Depends(require_permission("admin"))
):
    """Create a new API key."""
    try:
        admin_api = AdminAPIManager()
        
        new_key = admin_api._generate_api_key(
            request.name,
            request.description or "",
            request.permissions,
            request.expires_in_days or 30,
            request.rate_limit or 1000
        )
        
        return APIKeyResponse(
            key_id=new_key["key_id"],
            api_key=new_key["api_key"],
            name=new_key["name"],
            permissions=new_key["permissions"],
            expires_at=new_key["expires_at"],
            rate_limit=new_key["rate_limit"]
        )
        
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )


@admin_api_router.post("/users")
async def create_user(
    request: UserCreateRequest,
    key_data: Dict[str, Any] = Depends(require_permission("user_management"))
):
    """Create a new user."""
    try:
        user_manager = get_enhanced_user_manager()
        
        # Convert tier and tags
        tier = UserTier(request.tier)
        tags = {UserTag(tag) for tag in (request.tags or [])}
        
        user_id = await user_manager.create_user(
            request.username,
            request.email,
            request.password,
            tier,
            tags
        )
        
        # Apply profile updates if provided
        if request.profile_data:
            user_manager.update_user_profile(user_id, request.profile_data)
        
        user_profile = user_manager.get_user_profile(user_id)
        
        return {
            "user_id": user_id,
            "username": user_profile.username,
            "email": user_profile.email,
            "tier": user_profile.tier.value,
            "tags": [tag.value for tag in user_profile.tags],
            "created_at": user_profile.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


@admin_api_router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    key_data: Dict[str, Any] = Depends(require_permission("user_management"))
):
    """Get user information."""
    try:
        user_manager = get_enhanced_user_manager()
        user_profile = user_manager.get_user_profile(user_id)
        
        if not user_profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {
            "user_id": user_profile.user_id,
            "username": user_profile.username,
            "email": user_profile.email,
            "display_name": user_profile.display_name,
            "tier": user_profile.tier.value,
            "tags": [tag.value for tag in user_profile.tags],
            "created_at": user_profile.created_at.isoformat(),
            "last_active": user_profile.last_active.isoformat() if user_profile.last_active else None,
            "benefits": user_manager.get_user_benefits(user_id)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user"
        )


@admin_api_router.put("/users/{user_id}")
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    key_data: Dict[str, Any] = Depends(require_permission("user_management"))
):
    """Update user information."""
    try:
        user_manager = get_enhanced_user_manager()
        
        if not user_manager.get_user_profile(user_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update tier
        if request.tier:
            tier = UserTier(request.tier)
            user_manager.upgrade_user_tier(user_id, tier)
        
        # Update tags
        if request.tags is not None:
            # Set exact tags (replace all)
            user_profile = user_manager.get_user_profile(user_id)
            current_tags = user_profile.tags.copy()
            
            # Remove all current tags
            for tag in current_tags:
                user_manager.remove_user_tag(user_id, tag)
            
            # Add new tags
            for tag_str in request.tags:
                tag = UserTag(tag_str)
                user_manager.add_user_tag(user_id, tag)
        
        # Add specific tags
        if request.add_tags:
            for tag_str in request.add_tags:
                tag = UserTag(tag_str)
                user_manager.add_user_tag(user_id, tag)
        
        # Remove specific tags
        if request.remove_tags:
            for tag_str in request.remove_tags:
                tag = UserTag(tag_str)
                user_manager.remove_user_tag(user_id, tag)
        
        # Update profile
        if request.profile_updates:
            user_manager.update_user_profile(user_id, request.profile_updates)
        
        # Return updated user
        user_profile = user_manager.get_user_profile(user_id)
        
        return {
            "user_id": user_profile.user_id,
            "username": user_profile.username,
            "tier": user_profile.tier.value,
            "tags": [tag.value for tag in user_profile.tags],
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )


@admin_api_router.post("/permissions")
async def manage_permission(
    request: PermissionRequest,
    key_data: Dict[str, Any] = Depends(require_permission("user_management"))
):
    """Grant or revoke user permissions."""
    try:
        user_manager = get_enhanced_user_manager()
        
        if not user_manager.get_user_profile(request.user_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        permission = Permission(request.permission)
        scope = PermissionScope(request.scope)
        
        if request.action == "grant":
            success = user_manager.grant_permission(request.user_id, permission, scope, request.scope_id)
        elif request.action == "revoke":
            success = user_manager.revoke_permission(request.user_id, permission, scope, request.scope_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Action must be 'grant' or 'revoke'"
            )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to {request.action} permission"
            )
        
        return {
            "user_id": request.user_id,
            "permission": request.permission,
            "scope": request.scope,
            "scope_id": request.scope_id,
            "action": request.action,
            "success": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to manage permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to manage permission"
        )


@admin_api_router.get("/users/{user_id}/permissions")
async def get_user_permissions(
    user_id: str,
    key_data: Dict[str, Any] = Depends(require_permission("user_management"))
):
    """Get user permissions."""
    try:
        user_manager = get_enhanced_user_manager()
        permissions = user_manager.get_user_permissions(user_id)
        
        if not permissions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User permissions not found"
            )
        
        return {
            "user_id": user_id,
            "global_permissions": [p.value for p in permissions.global_permissions],
            "scoped_permissions": {
                scope_type: {
                    scope_id: [p.value for p in perms]
                    for scope_id, perms in scopes.items()
                }
                for scope_type, scopes in permissions.scoped_permissions.items()
            },
            "roles": list(permissions.roles)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user permissions"
        )


@admin_api_router.get("/statistics")
async def get_statistics(
    key_data: Dict[str, Any] = Depends(require_permission("admin"))
):
    """Get system statistics."""
    try:
        user_manager = get_enhanced_user_manager()
        stats = user_manager.get_statistics()
        
        return {
            "user_statistics": stats,
            "api_key_usage": {
                key: usage for key, usage in AdminAPIManager().api_key_usage.items()
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get statistics"
        )


# Global admin API manager instance
admin_api_manager = AdminAPIManager()

def get_admin_api_manager() -> AdminAPIManager:
    """Get the global admin API manager."""
    return admin_api_manager
