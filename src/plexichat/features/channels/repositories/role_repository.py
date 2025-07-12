"""
PlexiChat Role Repository

Data access layer for Discord-like roles with permission management.
"""

from typing import List, Optional, Dict, Any
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from ....core_system.database.repository.base_repository import BaseRepository
from ....core_system.database.dao.base_dao import BaseDAO, FilterCriteria, SortCriteria, PaginationParams
from ....core_system.database.engines import get_session
from ..models.role import Role, Permissions


class RoleRepository(BaseRepository[Role, Dict[str, Any], Dict[str, Any]]):
    """
    Role repository with Discord-like role and permission management.
    
    Provides business logic for role operations including hierarchy and permissions.
    """
    
    def __init__(self, session_factory=None):
        # Create DAO instance
        dao = BaseDAO(Role, session_factory or get_session)
        super().__init__(dao)
    
    async def find_by_server(self, server_id: str) -> List[Role]:
        """Find all roles in a server ordered by position."""
        filters = [FilterCriteria(field="server_id", operator="eq", value=server_id)]
        sorts = [SortCriteria(field="position", direction="desc")]  # Higher position = higher in hierarchy
        result = await self.find_all(filters=filters, sorts=sorts)
        return result.data
    
    async def find_by_name(self, server_id: str, name: str) -> Optional[Role]:
        """Find role by exact name in a server."""
        filters = [
            FilterCriteria(field="server_id", operator="eq", value=server_id),
            FilterCriteria(field="name", operator="eq", value=name)
        ]
        result = await self.find_all(filters=filters)
        return result.data[0] if result.data else None
    
    async def find_everyone_role(self, server_id: str) -> Optional[Role]:
        """Find the @everyone role for a server."""
        return await self.find_by_name(server_id, "@everyone")
    
    async def find_by_permissions(self, server_id: str, permission: Permissions) -> List[Role]:
        """Find roles that have a specific permission."""
        filters = [FilterCriteria(field="server_id", operator="eq", value=server_id)]
        result = await self.find_all(filters=filters)
        
        # Filter roles that have the permission
        matching_roles = []
        for role in result.data:
            if role.permissions & permission:
                matching_roles.append(role)
        
        return matching_roles
    
    async def find_administrator_roles(self, server_id: str) -> List[Role]:
        """Find all roles with administrator permission."""
        return await self.find_by_permissions(server_id, Permissions.ADMINISTRATOR)
    
    async def find_manageable_roles(self, server_id: str, user_highest_role_position: int) -> List[Role]:
        """Find roles that can be managed by a user based on role hierarchy."""
        filters = [
            FilterCriteria(field="server_id", operator="eq", value=server_id),
            FilterCriteria(field="position", operator="lt", value=user_highest_role_position)
        ]
        sorts = [SortCriteria(field="position", direction="desc")]
        result = await self.find_all(filters=filters, sorts=sorts)
        return result.data
    
    async def get_next_position(self, server_id: str) -> int:
        """Get the next position for a new role."""
        filters = [FilterCriteria(field="server_id", operator="eq", value=server_id)]
        sorts = [SortCriteria(field="position", direction="desc")]
        pagination = PaginationParams(page=1, page_size=1)
        result = await self.find_all(filters=filters, sorts=sorts, pagination=pagination)
        
        if result.data:
            return result.data[0].position + 1
        return 1  # @everyone role is typically position 0
    
    async def reorder_roles(self, server_id: str, role_positions: List[Dict[str, Any]]) -> bool:
        """Reorder roles in a server."""
        try:
            for position_data in role_positions:
                role_id = position_data["role_id"]
                new_position = position_data["position"]
                await self.update(role_id, {"position": new_position})
            return True
        except Exception:
            return False
    
    async def get_role_hierarchy(self, server_id: str) -> List[Role]:
        """Get complete role hierarchy for a server."""
        return await self.find_by_server(server_id)
    
    async def search_roles(self, server_id: str, query: str, limit: int = 10) -> List[Role]:
        """Search roles by name in a server."""
        filters = [
            FilterCriteria(field="server_id", operator="eq", value=server_id),
            FilterCriteria(field="name", operator="ilike", value=f"%{query}%")
        ]
        pagination = PaginationParams(page=1, page_size=limit)
        result = await self.find_all(filters=filters, pagination=pagination)
        return result.data
    
    async def get_role_stats(self, role_id: str) -> Dict[str, Any]:
        """Get comprehensive role statistics."""
        role = await self.find_by_id(role_id)
        if not role:
            return {}
        
        # TODO: Implement with actual database queries
        return {
            "role_id": role_id,
            "member_count": 0,  # Would query ServerMember table
            "permission_count": bin(role.permissions).count('1'),
            "is_mentionable": role.mentionable,
            "is_hoisted": role.hoist,
            "created_at": role.created_at.isoformat() if role.created_at else None,
        }
    
    async def get_members_with_role(self, role_id: str) -> List[str]:
        """Get list of user IDs who have this role."""
        # TODO: Implement with ServerMember query
        return []
    
    # Business logic methods
    
    async def create_role_with_defaults(self, role_data: Dict[str, Any]) -> Role:
        """Create role with default settings."""
        # Set default position if not provided
        if "position" not in role_data:
            role_data["position"] = await self.get_next_position(role_data["server_id"])
        
        # Set default permissions if not provided
        if "permissions" not in role_data:
            role_data["permissions"] = 0  # No permissions by default
        
        # Create the role
        role = await self.create(role_data)
        
        return role
    
    async def create_everyone_role(self, server_id: str) -> Role:
        """Create the default @everyone role for a server."""
        role_data = {
            "server_id": server_id,
            "name": "@everyone",
            "permissions": int(Permissions.VIEW_CHANNEL | Permissions.SEND_MESSAGES | Permissions.READ_MESSAGE_HISTORY),
            "color": 0,
            "hoist": False,
            "mentionable": False,
            "position": 0,
            "managed": False
        }
        
        return await self.create(role_data)
    
    async def delete_role_cascade(self, role_id: str) -> bool:
        """Delete role and remove from all members."""
        # TODO: Implement cascade deletion
        # This would remove the role from all ServerMember records
        return await self.delete(role_id)
    
    async def assign_role_to_member(self, role_id: str, user_id: str, server_id: str) -> bool:
        """Assign role to a server member."""
        # TODO: Implement with ServerMember update
        return True
    
    async def remove_role_from_member(self, role_id: str, user_id: str, server_id: str) -> bool:
        """Remove role from a server member."""
        # TODO: Implement with ServerMember update
        return True
    
    async def can_user_manage_role(self, user_id: str, role_id: str, server_id: str) -> bool:
        """Check if user can manage a specific role."""
        # TODO: Implement with permission checking
        # This would check if user has MANAGE_ROLES permission and role hierarchy
        return False
    
    # Validation methods
    
    async def _validate_create(self, create_data: Dict[str, Any]) -> bool:
        """Validate role creation data."""
        # Check required fields
        if not create_data.get("name"):
            raise ValueError("Role name is required")
        
        if not create_data.get("server_id"):
            raise ValueError("Server ID is required")
        
        # Check name length
        name = create_data["name"]
        if len(name) < 1 or len(name) > 100:
            raise ValueError("Role name must be between 1 and 100 characters")
        
        # Check for duplicate role names in server
        server_id = create_data["server_id"]
        existing_role = await self.find_by_name(server_id, name)
        if existing_role:
            raise ValueError(f"Role name '{name}' already exists in this server")
        
        return True
    
    async def _validate_update(self, role_id: str, update_data: Dict[str, Any]) -> bool:
        """Validate role update data."""
        # Check name length if name is being updated
        if "name" in update_data:
            name = update_data["name"]
            if len(name) < 1 or len(name) > 100:
                raise ValueError("Role name must be between 1 and 100 characters")
            
            # Check for duplicate role names
            role = await self.find_by_id(role_id)
            if role:
                existing_role = await self.find_by_name(role.server_id, name)
                if existing_role and existing_role.role_id != role_id:
                    raise ValueError(f"Role name '{name}' already exists in this server")
        
        return True
