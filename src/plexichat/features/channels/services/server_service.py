# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from typing import Any, Dict, List, Optional

from ..models.server import Server
from ..repositories.server_repository import ServerRepository


"""
PlexiChat Server Service

Business logic service for Discord-like server management.
"""

logger = logging.getLogger(__name__)


class ServerService:
    """
    Server service providing business logic for Discord-like servers.

    Handles server creation, management, membership, and permissions.
    """

    def __init__(self, server_repository: Optional[ServerRepository] = None):
        self.server_repository = server_repository or ServerRepository()

    async def create_server(self, owner_id: str, server_data: Dict[str, Any]) -> Server:
        """
        Create a new server with default setup.

        Args:
            owner_id: ID of the user creating the server
            server_data: Server configuration data

        Returns:
            Created server with default channels and roles
        """
        try:
            # Validate server data
            await self._validate_server_creation(owner_id, server_data)

            # Set owner
            server_data["owner_id"] = owner_id

            # Create server with defaults
            server = await self.server_repository.create_server_with_defaults(
                server_data
            )

            logger.info(f"Server created: {server.server_id} by user {owner_id}")
            return server

        except Exception as e:
            logger.error(f"Failed to create server: {e}")
            raise

    async def get_server(self, server_id: str, user_id: Optional[str] = None) -> Optional[Server]:
        """
        Get server details with permission checking.

        Args:
            server_id: Server ID
            user_id: User requesting the server (optional)

        Returns:
            Server if user has access, None otherwise
        """
        try:
            server = await self.server_repository.find_by_id(server_id)
            if not server:
                return None

            # Check if user has access to view server
            if user_id and not await self._can_user_view_server(server_id, user_id):
                return None

            return server

        except Exception as e:
            logger.error(f"Failed to get server {server_id}: {e}")
            return None

    async def update_server(
        self, server_id: str, user_id: str, update_data: Dict[str, Any]
    ) -> Optional[Server]:
        """
                Update server from plexichat.core.config import settings
        settings.

                Args:
                    server_id: Server ID
                    user_id: User making the update
                    update_data: Data to update

                Returns:
                    Updated server if successful, None otherwise
        """
        try:
            # Check permissions
            if not await self._can_user_manage_server(server_id, user_id):
                raise PermissionError("User does not have permission to manage server")

            # Update server
            server = await self.server_repository.update(server_id, update_data)

            if server:
                logger.info(f"Server {server_id} updated by user {user_id}")

            return server

        except Exception as e:
            logger.error(f"Failed to update server {server_id}: {e}")
            raise

    async def delete_server(self, server_id: str, user_id: str) -> bool:
        """
        Delete server (owner only).

        Args:
            server_id: Server ID
            user_id: User requesting deletion

        Returns:
            True if deleted successfully
        """
        try:
            # Check if user is owner
            if not await self.server_repository.is_owner(server_id, user_id):
                raise PermissionError("Only server owner can delete server")

            # Delete server and all associated data
            success = await self.server_repository.delete_server_cascade(server_id)

            if success:
                logger.info(f"Server {server_id} deleted by owner {user_id}")

            return success

        except Exception as e:
            logger.error(f"Failed to delete server {server_id}: {e}")
            raise

    async def join_server(
        self, server_id: str, user_id: str, invite_code: Optional[str] = None
    ) -> bool:
        """
        Join a server.

        Args:
            server_id: Server ID
            user_id: User joining
            invite_code: Invite code (optional)

        Returns:
            True if joined successfully
        """
        try:
            # Check if user can join
            if not await self.server_repository.can_user_join(server_id, user_id):
                return False

            # Check if already a member
            if await self.server_repository.is_member(server_id, user_id):
                return True  # Already a member

            # TODO: Create ServerMember record
            # TODO: Assign default @everyone role
            # TODO: Update server member count

            logger.info(f"User {user_id} joined server {server_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to join server {server_id}: {e}")
            return False

    async def leave_server(self, server_id: str, user_id: str) -> bool:
        """
        Leave a server.

        Args:
            server_id: Server ID
            user_id: User leaving

        Returns:
            True if left successfully
        """
        try:
            # Check if user is owner (owners cannot leave)
            if await self.server_repository.is_owner(server_id, user_id):
                raise ValueError("Server owner cannot leave server")

            # TODO: Remove ServerMember record
            # TODO: Update server member count

            logger.info(f"User {user_id} left server {server_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to leave server {server_id}: {e}")
            return False

    async def get_user_servers(self, user_id: str) -> List[Server]:
        """
        Get all servers where user is a member.

        Args:
            user_id: User ID

        Returns:
            List of servers
        """
        try:
            # Get servers where user is owner
            owned_servers = await self.server_repository.find_by_owner(user_id)

            # Get servers where user is member
            member_servers = await self.server_repository.find_by_member(user_id)

            # Combine and deduplicate
            all_servers = owned_servers + member_servers
            unique_servers = {server.server_id: server for server in all_servers}

            return list(unique_servers.values())

        except Exception as e:
            logger.error(f"Failed to get user servers for {user_id}: {e}")
            return []

    async def get_server_members(
        self, server_id: str, user_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get server members list.

        Args:
            server_id: Server ID
            user_id: User requesting the list

        Returns:
            List of server members
        """
        try:
            # Check permissions
            if not await self._can_user_view_server(server_id, user_id):
                raise PermissionError(
                    "User does not have permission to view server members"
                )

            # TODO: Get ServerMember records with user details
            return []

        except Exception as e:
            logger.error(f"Failed to get server members for {server_id}: {e}")
            raise

    async def kick_member(
        self, server_id: str, user_id: str, target_user_id: str
    ) -> bool:
        """
        Kick a member from the server.

        Args:
            server_id: Server ID
            user_id: User performing the kick
            target_user_id: User being kicked

        Returns:
            True if kicked successfully
        """
        try:
            # Check permissions
            if not await self._can_user_kick_members(server_id, user_id):
                raise PermissionError("User does not have permission to kick members")

            # Cannot kick server owner
            if await self.server_repository.is_owner(server_id, target_user_id):
                raise ValueError("Cannot kick server owner")

            # TODO: Remove ServerMember record
            # TODO: Update server member count

            logger.info(
                f"User {target_user_id} kicked from server {server_id} by {user_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to kick member from server {server_id}: {e}")
            raise

    # Permission checking methods

    async def _can_user_view_server(self, server_id: str, user_id: str) -> bool:
        """Check if user can view server."""
        # User can view if they are a member or owner
        return await self.server_repository.is_member(
            server_id, user_id
        ) or await self.server_repository.is_owner(server_id, user_id)

    async def _can_user_manage_server(self, server_id: str, user_id: str) -> bool:
        """Check if user can manage server."""
        # TODO: Check for MANAGE_GUILD permission
        return await self.server_repository.is_owner(server_id, user_id)

    async def _can_user_kick_members(self, server_id: str, user_id: str) -> bool:
        """Check if user can kick members."""
        # TODO: Check for KICK_MEMBERS permission
        return await self.server_repository.is_owner(server_id, user_id)

    # Validation methods

    async def _validate_server_creation(
        self, owner_id: str, server_data: Dict[str, Any]
    ) -> None:
        """Validate server creation data."""
        # Check required fields
        if not server_data.get("name"):
            raise ValueError("Server name is required")

        # Check name length
        name = server_data["name"]
        if len(name) < 2 or len(name) > 100:
            raise ValueError("Server name must be between 2 and 100 characters")

        # TODO: Check user server limit
        # TODO: Validate other server settings
