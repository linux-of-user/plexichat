"""
PlexiChat Permission Overwrite Repository

Data access layer for channel-specific permission overrides.
"""

from typing import Any, Dict, List, Optional

from ....core_system.database.dao.base_dao import BaseDAO, FilterCriteria
from ....core_system.database.engines import get_session
from ....core_system.database.repository.base_repository import BaseRepository
from ..models.permission_overwrite import OverwriteType, PermissionOverwrite
from ..models.role import Permissions


class PermissionOverwriteRepository(BaseRepository[PermissionOverwrite, Dict[str, Any], Dict[str, Any]]):
    """
    Permission overwrite repository for channel-specific permissions.
    
    Manages fine-grained permission control for roles and users in channels.
    """
    
    def __init__(self, session_factory=None):
        # Create DAO instance
        dao = BaseDAO(PermissionOverwrite, session_factory or get_session)
        super().__init__(dao)
    
    async def find_by_channel(self, channel_id: str) -> List[PermissionOverwrite]:
        """Find all permission overwrites for a channel."""
        filters = [FilterCriteria(field="channel_id", operator="eq", value=channel_id)]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def find_by_target(self, channel_id: str, target_id: str, target_type: OverwriteType) -> Optional[PermissionOverwrite]:
        """Find permission overwrite for a specific target."""
        filters = [
            FilterCriteria(field="channel_id", operator="eq", value=channel_id),
            FilterCriteria(field="target_id", operator="eq", value=target_id),
            FilterCriteria(field="target_type", operator="eq", value=target_type)
        ]
        result = await self.find_all(filters=filters)
        return result.data[0] if result.data else None
    
    async def find_role_overwrites(self, channel_id: str) -> List[PermissionOverwrite]:
        """Find all role permission overwrites for a channel."""
        filters = [
            FilterCriteria(field="channel_id", operator="eq", value=channel_id),
            FilterCriteria(field="target_type", operator="eq", value=OverwriteType.ROLE)
        ]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def find_member_overwrites(self, channel_id: str) -> List[PermissionOverwrite]:
        """Find all member permission overwrites for a channel."""
        filters = [
            FilterCriteria(field="channel_id", operator="eq", value=channel_id),
            FilterCriteria(field="target_type", operator="eq", value=OverwriteType.MEMBER)
        ]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def find_user_overwrites(self, user_id: str) -> List[PermissionOverwrite]:
        """Find all permission overwrites for a specific user across channels."""
        filters = [
            FilterCriteria(field="target_id", operator="eq", value=user_id),
            FilterCriteria(field="target_type", operator="eq", value=OverwriteType.MEMBER)
        ]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def find_role_overwrites_by_role(self, role_id: str) -> List[PermissionOverwrite]:
        """Find all permission overwrites for a specific role across channels."""
        filters = [
            FilterCriteria(field="target_id", operator="eq", value=role_id),
            FilterCriteria(field="target_type", operator="eq", value=OverwriteType.ROLE)
        ]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def get_effective_overwrites(self, channel_id: str, user_id: str, role_ids: List[str]) -> List[PermissionOverwrite]:
        """Get all effective permission overwrites for a user in a channel."""
        overwrites = []
        
        # Get role overwrites
        for role_id in role_ids:
            role_overwrite = await self.find_by_target(channel_id, role_id, OverwriteType.ROLE)
            if role_overwrite:
                overwrites.append(role_overwrite)
        
        # Get member overwrite (highest priority)
        member_overwrite = await self.find_by_target(channel_id, user_id, OverwriteType.MEMBER)
        if member_overwrite:
            overwrites.append(member_overwrite)
        
        return overwrites
    
    # Business logic methods
    
    async def create_or_update_overwrite(self, overwrite_data: Dict[str, Any]) -> PermissionOverwrite:
        """Create or update a permission overwrite."""
        existing = await self.find_by_target(
            overwrite_data["channel_id"],
            overwrite_data["target_id"],
            overwrite_data["target_type"]
        )
        
        if existing:
            # Update existing overwrite
            update_data = {
                "allow": overwrite_data.get("allow", existing.allow),
                "deny": overwrite_data.get("deny", existing.deny)
            }
            return await self.update(existing.overwrite_id, update_data)
        else:
            # Create new overwrite
            return await self.create(overwrite_data)
    
    async def delete_overwrite_by_target(self, channel_id: str, target_id: str, target_type: OverwriteType) -> bool:
        """Delete permission overwrite by target."""
        existing = await self.find_by_target(channel_id, target_id, target_type)
        if existing:
            return await self.delete(existing.overwrite_id)
        return False
    
    async def clear_channel_overwrites(self, channel_id: str) -> bool:
        """Clear all permission overwrites for a channel."""
        overwrites = await self.find_by_channel(channel_id)
        try:
            for overwrite in overwrites:
                await self.delete(overwrite.overwrite_id)
            return True
        except Exception:
            return False
    
    async def clear_role_overwrites(self, role_id: str) -> bool:
        """Clear all permission overwrites for a role across all channels."""
        overwrites = await self.find_role_overwrites_by_role(role_id)
        try:
            for overwrite in overwrites:
                await self.delete(overwrite.overwrite_id)
            return True
        except Exception:
            return False
    
    async def clear_user_overwrites(self, user_id: str) -> bool:
        """Clear all permission overwrites for a user across all channels."""
        overwrites = await self.find_user_overwrites(user_id)
        try:
            for overwrite in overwrites:
                await self.delete(overwrite.overwrite_id)
            return True
        except Exception:
            return False
    
    async def copy_overwrites_to_channel(self, source_channel_id: str, target_channel_id: str) -> bool:
        """Copy permission overwrites from one channel to another."""
        source_overwrites = await self.find_by_channel(source_channel_id)
        
        try:
            for overwrite in source_overwrites:
                overwrite_data = {
                    "channel_id": target_channel_id,
                    "target_id": overwrite.target_id,
                    "target_type": overwrite.target_type,
                    "allow": overwrite.allow,
                    "deny": overwrite.deny
                }
                await self.create(overwrite_data)
            return True
        except Exception:
            return False
    
    async def sync_category_permissions(self, category_id: str, child_channel_ids: List[str]) -> bool:
        """Sync category permissions to child channels."""
        category_overwrites = await self.find_by_channel(category_id)
        
        try:
            for child_channel_id in child_channel_ids:
                # Clear existing overwrites
                await self.clear_channel_overwrites(child_channel_id)
                
                # Copy category overwrites
                for overwrite in category_overwrites:
                    overwrite_data = {
                        "channel_id": child_channel_id,
                        "target_id": overwrite.target_id,
                        "target_type": overwrite.target_type,
                        "allow": overwrite.allow,
                        "deny": overwrite.deny
                    }
                    await self.create(overwrite_data)
            return True
        except Exception:
            return False
    
    # Permission calculation helpers
    
    async def calculate_permissions_for_user(self, channel_id: str, user_id: str, role_ids: List[str], base_permissions: int) -> int:
        """Calculate final permissions for a user in a channel."""
        # Start with base permissions from roles
        permissions = base_permissions
        
        # Administrator bypasses all overwrites
        if permissions & Permissions.ADMINISTRATOR:
            return permissions
        
        # Apply role overwrites (in order of role hierarchy)
        role_overwrites = []
        for role_id in role_ids:
            overwrite = await self.find_by_target(channel_id, role_id, OverwriteType.ROLE)
            if overwrite:
                role_overwrites.append(overwrite)
        
        # Apply role overwrites
        for overwrite in role_overwrites:
            permissions &= ~overwrite.deny  # Remove denied permissions
            permissions |= overwrite.allow  # Add allowed permissions
        
        # Apply member overwrite (highest priority)
        member_overwrite = await self.find_by_target(channel_id, user_id, OverwriteType.MEMBER)
        if member_overwrite:
            permissions &= ~member_overwrite.deny  # Remove denied permissions
            permissions |= member_overwrite.allow  # Add allowed permissions
        
        return permissions
    
    # Validation methods
    
    async def _validate_create(self, create_data: Dict[str, Any]) -> bool:
        """Validate permission overwrite creation data."""
        # Check required fields
        required_fields = ["channel_id", "target_id", "target_type"]
        for field in required_fields:
            if not create_data.get(field):
                raise ValueError(f"{field} is required")
        
        # Validate target type
        if create_data["target_type"] not in [OverwriteType.ROLE, OverwriteType.MEMBER]:
            raise ValueError("Invalid target type")
        
        # TODO: Validate channel exists
        # TODO: Validate target exists (role or user)
        
        return True
    
    async def _validate_update(self, overwrite_id: str, update_data: Dict[str, Any]) -> bool:
        """Validate permission overwrite update data."""
        # Validate permission values
        if "allow" in update_data:
            if not isinstance(update_data["allow"], int) or update_data["allow"] < 0:
                raise ValueError("Allow permissions must be a non-negative integer")
        
        if "deny" in update_data:
            if not isinstance(update_data["deny"], int) or update_data["deny"] < 0:
                raise ValueError("Deny permissions must be a non-negative integer")
        
        return True
