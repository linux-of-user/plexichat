"""
PlexiChat Server Repository

Data access layer for Discord-like servers with business logic.
"""

from typing import List, Optional, Dict, Any
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from ....core_system.database.repository.base_repository import BaseRepository
from ....core_system.database.dao.base_dao import BaseDAO, FilterCriteria, SortCriteria, PaginationParams
from ....core_system.database.engines import get_session
from ..models.server import Server
from ..models.server_member import ServerMember


class ServerRepository(BaseRepository[Server, Dict[str, Any], Dict[str, Any]]):
    """
    Server repository with Discord-like server management.
    
    Provides business logic for server operations including membership management.
    """
    
    def __init__(self, session_factory=None):
        # Create DAO instance
        dao = BaseDAO(Server, session_factory or get_session)
        super().__init__(dao)
    
    async def find_by_owner(self, owner_id: str) -> List[Server]:
        """Find all servers owned by a user."""
        filters = [FilterCriteria(field="owner_id", operator="eq", value=owner_id)]
        result = await self.find_all(filters=filters)
        return result.data
    
    async def find_by_member(self, user_id: str) -> List[Server]:
        """Find all servers where user is a member."""
        # This would require a join with ServerMember table
        # For now, return empty list - will be implemented when database is integrated
        return []
    
    async def find_by_name(self, name: str) -> Optional[Server]:
        """Find server by exact name."""
        filters = [FilterCriteria(field="name", operator="eq", value=name)]
        result = await self.find_all(filters=filters)
        return result.data[0] if result.data else None
    
    async def search_by_name(self, name_pattern: str, limit: int = 10) -> List[Server]:
        """Search servers by name pattern."""
        filters = [FilterCriteria(field="name", operator="ilike", value=f"%{name_pattern}%")]
        pagination = PaginationParams(page=1, page_size=limit)
        result = await self.find_all(filters=filters, pagination=pagination)
        return result.data
    
    async def find_public_servers(self, limit: int = 50) -> List[Server]:
        """Find public servers for discovery."""
        # Add business logic for public server discovery
        sorts = [SortCriteria(field="member_count", direction="desc")]
        pagination = PaginationParams(page=1, page_size=limit)
        result = await self.find_all(sorts=sorts, pagination=pagination)
        return result.data
    
    async def get_server_stats(self, server_id: str) -> Dict[str, Any]:
        """Get comprehensive server statistics."""
        server = await self.find_by_id(server_id)
        if not server:
            return {}
        
        # TODO: Implement with actual database queries
        return {
            "server_id": server_id,
            "member_count": 0,  # Would query ServerMember table
            "channel_count": 0,  # Would query Channel table
            "role_count": 0,    # Would query Role table
            "message_count": 0, # Would query Message table
            "created_at": server.created_at.isoformat() if server.created_at else None,
        }
    
    async def update_member_count(self, server_id: str) -> bool:
        """Update server member count from actual membership."""
        # TODO: Implement with actual member count query
        # This would count ServerMember records for the server
        return True
    
    async def is_member(self, server_id: str, user_id: str) -> bool:
        """Check if user is a member of the server."""
        # TODO: Implement with ServerMember query
        return False
    
    async def is_owner(self, server_id: str, user_id: str) -> bool:
        """Check if user is the owner of the server."""
        server = await self.find_by_id(server_id)
        return server and server.owner_id == user_id
    
    async def can_user_join(self, server_id: str, user_id: str) -> bool:
        """Check if user can join the server based on verification level."""
        server = await self.find_by_id(server_id)
        if not server:
            return False
        
        # TODO: Implement verification level checks
        # This would check user verification status against server requirements
        return True
    
    # Business logic methods
    
    async def create_server_with_defaults(self, server_data: Dict[str, Any]) -> Server:
        """Create server with default channels and roles."""
        # Create the server
        server = await self.create(server_data)
        
        # TODO: Create default @everyone role
        # TODO: Create default channels (general, etc.)
        # TODO: Add owner as first member
        
        return server
    
    async def delete_server_cascade(self, server_id: str) -> bool:
        """Delete server and all associated data."""
        # TODO: Implement cascade deletion
        # This would delete all channels, roles, members, messages, etc.
        return await self.delete(server_id)
    
    async def transfer_ownership(self, server_id: str, new_owner_id: str) -> bool:
        """Transfer server ownership to another user."""
        server = await self.find_by_id(server_id)
        if not server:
            return False
        
        # TODO: Verify new owner is a member
        # TODO: Update server owner
        update_data = {"owner_id": new_owner_id}
        updated_server = await self.update(server_id, update_data)
        return updated_server is not None
    
    # Validation methods
    
    async def _validate_create(self, create_data: Dict[str, Any]) -> bool:
        """Validate server creation data."""
        # Check name uniqueness
        if "name" in create_data:
            existing = await self.find_by_name(create_data["name"])
            if existing:
                raise ValueError(f"Server name '{create_data['name']}' already exists")
        
        return True
    
    async def _validate_update(self, server_id: str, update_data: Dict[str, Any]) -> bool:
        """Validate server update data."""
        # Check name uniqueness if name is being updated
        if "name" in update_data:
            existing = await self.find_by_name(update_data["name"])
            if existing and existing.server_id != server_id:
                raise ValueError(f"Server name '{update_data['name']}' already exists")
        
        return True
