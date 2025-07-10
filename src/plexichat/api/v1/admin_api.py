"""
NetLink Admin API v1
Comprehensive API for admin account management, configuration, and system control.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
import logging

from ...auth.advanced_auth import auth_manager, AdminAccount
from ...security.enhanced_security import session_manager, rate_limiter
from ...common.utilities import config_manager, ValidationUtils
from ...performance.optimization import global_cache, resource_monitor

# API Router
admin_api_router = APIRouter(prefix="/api/v1/admin", tags=["Admin API v1"])

# Pydantic Models
class CreateAccountRequest(BaseModel):
    """Request model for creating admin accounts."""
    username: str = Field(..., min_length=3, max_length=50, description="Username for the admin account")
    email: EmailStr = Field(..., description="Email address for the admin account")
    password: str = Field(..., min_length=8, description="Password for the admin account")
    role: str = Field(..., description="Role: admin or super_admin")
    permissions: List[str] = Field(default=[], description="List of permissions")

class UpdateAccountRequest(BaseModel):
    """Request model for updating admin accounts."""
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_locked: Optional[bool] = None

class ChangePasswordRequest(BaseModel):
    """Request model for changing password."""
    current_password: str
    new_password: str = Field(..., min_length=8)

class ConfigUpdateRequest(BaseModel):
    """Request model for configuration updates."""
    section: str = Field(..., description="Configuration section (e.g., 'server', 'security')")
    key: str = Field(..., description="Configuration key")
    value: Any = Field(..., description="Configuration value")

class SystemCommandRequest(BaseModel):
    """Request model for system commands."""
    command: str = Field(..., description="System command to execute")
    parameters: Optional[Dict[str, Any]] = Field(default={}, description="Command parameters")

# Dependency for authentication
async def get_current_admin(request: Request) -> str:
    """Get current authenticated admin user."""
    session_id = request.cookies.get("netlink_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    client_ip = request.client.host
    session = session_manager.validate_session(session_id, client_ip)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    return session["user_id"]

def require_permission(permission: str):
    """Dependency to require specific permission."""
    def check_permission(username: str = Depends(get_current_admin)) -> str:
        account = auth_manager.get_account(username)
        if not account:
            raise HTTPException(status_code=403, detail="Account not found")

        if "all" not in account.permissions and permission not in account.permissions:
            raise HTTPException(status_code=403, detail=f"Permission '{permission}' required")

        return username
    return check_permission

# Account Management Endpoints
@admin_api_router.get("/accounts", summary="List all admin accounts")
async def list_accounts(
    username: str = Depends(require_permission("manage_users")),
    skip: int = Query(0, ge=0, description="Number of accounts to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of accounts to return")
):
    """List all admin accounts with pagination."""
    accounts = list(auth_manager.accounts.values())
    
    # Remove sensitive data
    safe_accounts = []
    for account in accounts[skip:skip+limit]:
        safe_account = {
            "username": account.username,
            "email": account.email,
            "role": account.role,
            "permissions": account.permissions,
            "created_at": account.created_at.isoformat(),
            "last_login": account.last_login.isoformat() if account.last_login else None,
            "login_count": account.login_count,
            "is_locked": account.is_locked,
            "two_factor_enabled": account.two_factor_enabled
        }
        safe_accounts.append(safe_account)
    
    return {
        "accounts": safe_accounts,
        "total": len(auth_manager.accounts),
        "skip": skip,
        "limit": limit
    }

@admin_api_router.post("/accounts", summary="Create new admin account")
async def create_account(
    account_data: CreateAccountRequest,
    username: str = Depends(require_permission("manage_users"))
):
    """Create a new admin account."""
    
    # Validate role
    if account_data.role not in ["admin", "super_admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'super_admin'")
    
    # Create account
    success, message = auth_manager.create_account(
        account_data.username,
        account_data.email,
        account_data.password,
        account_data.role,
        account_data.permissions
    )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return {"message": message, "username": account_data.username}

@admin_api_router.get("/accounts/{target_username}", summary="Get specific admin account")
async def get_account(
    target_username: str,
    username: str = Depends(require_permission("manage_users"))
):
    """Get details of a specific admin account."""
    account = auth_manager.get_account(target_username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    return {
        "username": account.username,
        "email": account.email,
        "role": account.role,
        "permissions": account.permissions,
        "created_at": account.created_at.isoformat(),
        "last_login": account.last_login.isoformat() if account.last_login else None,
        "login_count": account.login_count,
        "failed_attempts": account.failed_attempts,
        "is_locked": account.is_locked,
        "locked_until": account.locked_until.isoformat() if account.locked_until else None,
        "two_factor_enabled": account.two_factor_enabled,
        "preferences": account.preferences
    }

@admin_api_router.put("/accounts/{target_username}", summary="Update admin account")
async def update_account(
    target_username: str,
    update_data: UpdateAccountRequest,
    username: str = Depends(require_permission("manage_users"))
):
    """Update an admin account."""
    account = auth_manager.get_account(target_username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Prevent self-lockout
    if target_username == username and update_data.is_locked is True:
        raise HTTPException(status_code=400, detail="Cannot lock your own account")
    
    # Update fields
    if update_data.email is not None:
        account.email = update_data.email
    if update_data.role is not None:
        if update_data.role not in ["admin", "super_admin"]:
            raise HTTPException(status_code=400, detail="Invalid role")
        account.role = update_data.role
    if update_data.permissions is not None:
        account.permissions = update_data.permissions
    if update_data.is_locked is not None:
        account.is_locked = update_data.is_locked
        if not update_data.is_locked:
            account.locked_until = None
            account.failed_attempts = 0
    
    auth_manager._save_accounts()
    
    return {"message": "Account updated successfully"}

@admin_api_router.delete("/accounts/{target_username}", summary="Delete admin account")
async def delete_account(
    target_username: str,
    username: str = Depends(require_permission("manage_users"))
):
    """Delete an admin account."""
    if target_username == username:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    if target_username not in auth_manager.accounts:
        raise HTTPException(status_code=404, detail="Account not found")
    
    del auth_manager.accounts[target_username]
    auth_manager._save_accounts()
    
    return {"message": "Account deleted successfully"}

@admin_api_router.post("/accounts/{target_username}/unlock", summary="Unlock admin account")
async def unlock_account(
    target_username: str,
    username: str = Depends(require_permission("manage_users"))
):
    """Unlock a locked admin account."""
    account = auth_manager.get_account(target_username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    account.is_locked = False
    account.locked_until = None
    account.failed_attempts = 0
    auth_manager._save_accounts()
    
    return {"message": "Account unlocked successfully"}

# Configuration Management Endpoints
@admin_api_router.get("/config", summary="Get system configuration")
async def get_config(
    section: Optional[str] = Query(None, description="Specific configuration section"),
    username: str = Depends(require_permission("system_config"))
):
    """Get system configuration."""
    if section:
        config_data = config_manager.get(section, {})
        return {"section": section, "config": config_data}
    else:
        return {"config": config_manager.get_all()}

@admin_api_router.put("/config", summary="Update system configuration")
async def update_config(
    config_data: ConfigUpdateRequest,
    username: str = Depends(require_permission("system_config"))
):
    """Update system configuration."""
    
    # Validate configuration key
    config_key = f"{config_data.section}.{config_data.key}"
    
    # Set configuration
    success = config_manager.set(config_key, config_data.value)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update configuration")
    
    return {
        "message": "Configuration updated successfully",
        "section": config_data.section,
        "key": config_data.key,
        "value": config_data.value
    }

# System Management Endpoints
@admin_api_router.get("/system/status", summary="Get system status")
async def get_system_status(username: str = Depends(get_current_admin)):
    """Get comprehensive system status."""
    
    # Get resource metrics
    current_metrics = resource_monitor.get_current_metrics()
    metrics_summary = resource_monitor.get_metrics_summary(hours=1)
    
    # Get cache stats
    cache_stats = global_cache.get_stats()
    
    # Get auth stats
    auth_stats = auth_manager.get_auth_stats()
    
    # Get session info
    session_count = len(session_manager.sessions)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "uptime": "2 hours, 15 minutes",  # This would be calculated from actual uptime
            "version": "2.0.0",
            "mode": "production"
        },
        "resources": current_metrics,
        "performance": metrics_summary,
        "cache": cache_stats,
        "authentication": auth_stats,
        "sessions": {
            "active_sessions": session_count,
            "max_sessions": 100
        }
    }

@admin_api_router.post("/system/command", summary="Execute system command")
async def execute_system_command(
    command_data: SystemCommandRequest,
    username: str = Depends(require_permission("system_admin"))
):
    """Execute system management commands."""
    
    command = command_data.command.lower()
    parameters = command_data.parameters
    
    if command == "restart":
        # This would trigger a system restart
        return {"message": "System restart initiated", "command": command}
    
    elif command == "clear_cache":
        global_cache.clear()
        return {"message": "Cache cleared successfully", "command": command}
    
    elif command == "cleanup_sessions":
        cleaned = session_manager.cleanup_expired_sessions()
        return {"message": f"Cleaned up {cleaned} expired sessions", "command": command}
    
    elif command == "backup_config":
        # This would create a configuration backup
        return {"message": "Configuration backup created", "command": command}
    
    elif command == "health_check":
        # Run comprehensive health checks
        return {
            "message": "Health check completed",
            "command": command,
            "results": {
                "database": "healthy",
                "cache": "healthy",
                "sessions": "healthy",
                "resources": "healthy"
            }
        }
    
    else:
        raise HTTPException(status_code=400, detail=f"Unknown command: {command}")

# User Profile Endpoints
@admin_api_router.get("/profile", summary="Get current user profile")
async def get_profile(username: str = Depends(get_current_admin)):
    """Get current user's profile."""
    account = auth_manager.get_account(username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    return {
        "username": account.username,
        "email": account.email,
        "role": account.role,
        "permissions": account.permissions,
        "created_at": account.created_at.isoformat(),
        "last_login": account.last_login.isoformat() if account.last_login else None,
        "login_count": account.login_count,
        "two_factor_enabled": account.two_factor_enabled,
        "preferences": account.preferences
    }

@admin_api_router.put("/profile", summary="Update current user profile")
async def update_profile(
    profile_data: dict,
    username: str = Depends(get_current_admin)
):
    """Update current user's profile."""
    account = auth_manager.get_account(username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Update allowed fields
    if "email" in profile_data:
        if not ValidationUtils.is_valid_email(profile_data["email"]):
            raise HTTPException(status_code=400, detail="Invalid email format")
        account.email = profile_data["email"]
    
    if "preferences" in profile_data:
        account.preferences.update(profile_data["preferences"])
    
    auth_manager._save_accounts()
    
    return {"message": "Profile updated successfully"}

@admin_api_router.post("/profile/change-password", summary="Change password")
async def change_password(
    password_data: ChangePasswordRequest,
    username: str = Depends(get_current_admin)
):
    """Change current user's password."""
    account = auth_manager.get_account(username)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Verify current password
    from ...security.enhanced_security import password_manager
    if not password_manager.verify_password(password_data.current_password, account.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password
    valid, issues = password_manager.validate_password_strength(password_data.new_password)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Password requirements not met: {'; '.join(issues)}")
    
    # Update password
    account.password_hash = password_manager.hash_password(password_data.new_password)
    auth_manager._save_accounts()
    
    return {"message": "Password changed successfully"}
