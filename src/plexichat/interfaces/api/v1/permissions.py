"""
Permissions Management API Endpoints
Comprehensive API for managing roles and permissions.
"""

from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from plexichat.app.logger_config import logger
from plexichat.app.security.permissions import Permission, PermissionManager, PermissionScope, Role

router = APIRouter(prefix="/api/v1/permissions", tags=["Permissions"])
security = HTTPBearer()

# Global instance
permission_manager = None

def get_permission_manager():
    """Get permission manager instance."""
    global permission_manager
    if permission_manager is None:
        permission_manager = PermissionManager()
    return permission_manager

# Pydantic models
class RoleCreate(BaseModel):
    name: str = Field(..., description="Role name (unique identifier)")
    display_name: str = Field(..., description="Human-readable role name")
    description: str = Field(..., description="Role description")
    permissions: List[str] = Field(default_factory=list, description="List of permission names")
    priority: int = Field(100, description="Role priority (higher = more important)")
    color: str = Field("#ffffff", description="Role color in hex format")
    is_default: bool = Field(False, description="Whether this is the default role for new users")

class RoleUpdate(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    priority: Optional[int] = None
    color: Optional[str] = None
    is_default: Optional[bool] = None

class RoleResponse(BaseModel):
    name: str
    display_name: str
    description: str
    permissions: List[str]
    priority: int
    color: str
    is_default: bool
    is_system: bool
    created_at: datetime
    updated_at: datetime

class UserRoleAssignment(BaseModel):
    user_id: str
    role_name: str
    scope: str = "global"  # global, server, channel
    scope_id: Optional[str] = None

class PermissionGrant(BaseModel):
    user_id: str
    permission: str
    scope_id: str = "global"

class PermissionCheckRequest(BaseModel):
    user_id: str
    permission: str
    scope: str = "global"  # global, server, channel
    scope_id: Optional[str] = None

class PermissionCheckResponse(BaseModel):
    user_id: str
    permission: str
    scope: str
    scope_id: Optional[str]
    granted: bool
    reason: str
    roles_checked: List[str]
    timestamp: datetime

class UserPermissionsResponse(BaseModel):
    user_id: str
    global_roles: List[str]
    server_roles: Dict[str, List[str]]
    channel_roles: Dict[str, List[str]]
    explicit_permissions: Dict[str, List[str]]
    denied_permissions: Dict[str, List[str]]
    is_active: bool
    created_at: datetime
    updated_at: datetime

async def verify_admin_permission(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify user has admin permissions for role/permission management."""
    try:
        # Extract user ID from token (simplified - implement proper JWT validation)
        user_id = "admin"  # TODO: Extract from JWT token
        
        perm_manager = get_permission_manager()
        check = perm_manager.check_permission(user_id, Permission.MANAGE_ROLES)
        
        if not check.granted:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        
        return user_id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")

@router.get("/permissions", response_model=List[str])
async def get_all_permissions():
    """Get list of all available permissions."""
    return [perm.value for perm in Permission]

@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(admin_user: str = Depends(verify_admin_permission)):
    """Get all roles."""
    try:
        perm_manager = get_permission_manager()
        roles = []
        
        for role in perm_manager.roles.values():
            roles.append(RoleResponse(
                name=role.name,
                display_name=role.display_name,
                description=role.description,
                permissions=[p.value for p in role.permissions],
                priority=role.priority,
                color=role.color,
                is_default=role.is_default,
                is_system=role.is_system,
                created_at=role.created_at,
                updated_at=role.updated_at
            ))
        
        return sorted(roles, key=lambda r: r.priority, reverse=True)
    except Exception as e:
        logger.error(f"Failed to get roles: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve roles")

@router.post("/roles")
async def create_role(
    role_data: RoleCreate,
    admin_user: str = Depends(verify_admin_permission)
):
    """Create a new role."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate permissions
        try:
            permissions = set(Permission(p) for p in role_data.permissions)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {e}")
        
        role = Role(
            name=role_data.name,
            display_name=role_data.display_name,
            description=role_data.description,
            permissions=permissions,
            priority=role_data.priority,
            color=role_data.color,
            is_default=role_data.is_default
        )
        
        success = perm_manager.create_role(role)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to create role (may already exist)")
        
        logger.info(f"✅ Created role: {role.name}")
        return {"message": "Role created successfully", "role_name": role.name}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create role: {e}")
        raise HTTPException(status_code=500, detail="Failed to create role")

@router.get("/roles/{role_name}", response_model=RoleResponse)
async def get_role(
    role_name: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Get a specific role."""
    try:
        perm_manager = get_permission_manager()
        
        if role_name not in perm_manager.roles:
            raise HTTPException(status_code=404, detail="Role not found")
        
        role = perm_manager.roles[role_name]
        return RoleResponse(
            name=role.name,
            display_name=role.display_name,
            description=role.description,
            permissions=[p.value for p in role.permissions],
            priority=role.priority,
            color=role.color,
            is_default=role.is_default,
            is_system=role.is_system,
            created_at=role.created_at,
            updated_at=role.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get role: {e}")
        raise HTTPException(status_code=500, detail="Failed to get role")

@router.put("/roles/{role_name}")
async def update_role(
    role_name: str,
    role_updates: RoleUpdate,
    admin_user: str = Depends(verify_admin_permission)
):
    """Update an existing role."""
    try:
        perm_manager = get_permission_manager()
        
        if role_name not in perm_manager.roles:
            raise HTTPException(status_code=404, detail="Role not found")
        
        updates = role_updates.dict(exclude_unset=True)
        
        # Validate permissions if provided
        if "permissions" in updates:
            try:
                updates["permissions"] = set(Permission(p) for p in updates["permissions"])
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid permission: {e}")
        
        success = perm_manager.update_role(role_name, updates)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to update role")
        
        logger.info(f"✅ Updated role: {role_name}")
        return {"message": "Role updated successfully", "role_name": role_name}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update role")

@router.delete("/roles/{role_name}")
async def delete_role(
    role_name: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Delete a role."""
    try:
        perm_manager = get_permission_manager()
        
        success = perm_manager.delete_role(role_name)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to delete role (may be system role or not found)")
        
        logger.info(f"✅ Deleted role: {role_name}")
        return {"message": "Role deleted successfully", "role_name": role_name}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete role: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete role")

@router.post("/assign-role")
async def assign_role(
    assignment: UserRoleAssignment,
    admin_user: str = Depends(verify_admin_permission)
):
    """Assign a role to a user."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate scope
        try:
            scope = PermissionScope(assignment.scope)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scope: {assignment.scope}")
        
        success = perm_manager.assign_role(
            assignment.user_id,
            assignment.role_name,
            scope,
            assignment.scope_id
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to assign role")
        
        logger.info(f"✅ Assigned role {assignment.role_name} to user {assignment.user_id}")
        return {"message": "Role assigned successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign role: {e}")
        raise HTTPException(status_code=500, detail="Failed to assign role")

@router.post("/revoke-role")
async def revoke_role(
    assignment: UserRoleAssignment,
    admin_user: str = Depends(verify_admin_permission)
):
    """Revoke a role from a user."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate scope
        try:
            scope = PermissionScope(assignment.scope)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scope: {assignment.scope}")
        
        success = perm_manager.revoke_role(
            assignment.user_id,
            assignment.role_name,
            scope,
            assignment.scope_id
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to revoke role")
        
        logger.info(f"✅ Revoked role {assignment.role_name} from user {assignment.user_id}")
        return {"message": "Role revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke role: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke role")

@router.post("/grant-permission")
async def grant_permission(
    grant: PermissionGrant,
    admin_user: str = Depends(verify_admin_permission)
):
    """Grant explicit permission to a user."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate permission
        try:
            permission = Permission(grant.permission)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {grant.permission}")
        
        success = perm_manager.grant_permission(grant.user_id, permission, grant.scope_id)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to grant permission")
        
        logger.info(f"✅ Granted permission {grant.permission} to user {grant.user_id}")
        return {"message": "Permission granted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to grant permission: {e}")
        raise HTTPException(status_code=500, detail="Failed to grant permission")

@router.post("/deny-permission")
async def deny_permission(
    grant: PermissionGrant,
    admin_user: str = Depends(verify_admin_permission)
):
    """Explicitly deny permission to a user."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate permission
        try:
            permission = Permission(grant.permission)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid permission: {grant.permission}")
        
        success = perm_manager.deny_permission(grant.user_id, permission, grant.scope_id)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to deny permission")
        
        logger.info(f"✅ Denied permission {grant.permission} to user {grant.user_id}")
        return {"message": "Permission denied successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deny permission: {e}")
        raise HTTPException(status_code=500, detail="Failed to deny permission")

@router.post("/check-permission", response_model=PermissionCheckResponse)
async def check_permission(check_request: PermissionCheckRequest):
    """Check if a user has a specific permission."""
    try:
        perm_manager = get_permission_manager()
        
        # Validate permission and scope
        try:
            permission = Permission(check_request.permission)
            scope = PermissionScope(check_request.scope)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid value: {e}")
        
        check_result = perm_manager.check_permission(
            check_request.user_id,
            permission,
            scope,
            check_request.scope_id
        )
        
        return PermissionCheckResponse(
            user_id=check_result.user_id,
            permission=check_result.permission.value,
            scope=check_result.scope.value,
            scope_id=check_result.scope_id,
            granted=check_result.granted,
            reason=check_result.reason,
            roles_checked=check_result.roles_checked,
            timestamp=check_result.timestamp
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check permission: {e}")
        raise HTTPException(status_code=500, detail="Failed to check permission")

@router.get("/users/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions(
    user_id: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Get all permissions for a specific user."""
    try:
        perm_manager = get_permission_manager()
        
        if user_id not in perm_manager.user_permissions:
            raise HTTPException(status_code=404, detail="User permissions not found")
        
        user_perms = perm_manager.user_permissions[user_id]
        
        return UserPermissionsResponse(
            user_id=user_perms.user_id,
            global_roles=user_perms.global_roles,
            server_roles=user_perms.server_roles,
            channel_roles=user_perms.channel_roles,
            explicit_permissions={
                scope_id: [p.value for p in perms]
                for scope_id, perms in user_perms.explicit_permissions.items()
            },
            denied_permissions={
                scope_id: [p.value for p in perms]
                for scope_id, perms in user_perms.denied_permissions.items()
            },
            is_active=user_perms.is_active,
            created_at=user_perms.created_at,
            updated_at=user_perms.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user permissions: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user permissions")
