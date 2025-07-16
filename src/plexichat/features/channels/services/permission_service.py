# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import List, Optional

from ..models.permission_overwrite import OverwriteType, PermissionOverwrite
from ..models.role import Permissions, Role
from ..models.server_member import ServerMember


"""
PlexiChat Permission Service

Core permission calculation service with Discord-like permission system.
"""


class PermissionService:
    """
    Core permission calculation service.

    Handles complex permission resolution including roles, overwrites, and hierarchy.
    """

    @staticmethod
    def calculate_base_permissions(member: ServerMember, roles: List[Role]) -> int:
        """
        Calculate base permissions from roles.

        Args:
            member: Server member
            roles: List of roles the member has

        Returns:
            Combined permission bitfield
        """
        # Start with @everyone role permissions
        everyone_role = next((role for role in roles if role.name == "@everyone"), None)
        permissions = everyone_role.permissions if everyone_role else 0

        # Add permissions from all member roles
        member_roles = [role for role in roles if role.role_id in member.roles]
        for role in member_roles:
            permissions |= role.permissions

        # Administrator permission grants all permissions
        if permissions & Permissions.ADMINISTRATOR:
            return (
                int(Permissions.ADMINISTRATOR) | 0x7FFFFFFFFFFFFFFF
            )  # All permissions

        return permissions

    @staticmethod
    def calculate_overwrites(
        base_permissions: int,
        member: ServerMember,
        roles: List[Role],
        overwrites: List[PermissionOverwrite],
    ) -> int:
        """
        Apply permission overwrites to base permissions.

        Args:
            base_permissions: Base permissions from roles
            member: Server member
            roles: List of roles the member has
            overwrites: Channel permission overwrites

        Returns:
            Final permission bitfield after overwrites
        """
        # Administrator bypasses all overwrites
        if base_permissions & Permissions.ADMINISTRATOR:
            return base_permissions

        permissions = base_permissions

        # Apply role overwrites first (in role hierarchy order)
        member_roles = [role for role in roles if role.role_id in member.roles]
        member_roles.sort(key=lambda r: r.position)  # Sort by hierarchy

        for role in member_roles:
            role_overwrite = next(
                (
                    ow
                    for ow in overwrites
                    if ow.target_id == role.role_id
                    and ow.target_type == OverwriteType.ROLE
                ),
                None,
            )
            if role_overwrite:
                permissions &= ~role_overwrite.deny  # Remove denied permissions
                permissions |= role_overwrite.allow  # Add allowed permissions

        # Apply member-specific overwrites last (highest priority)
        member_overwrite = next(
            (
                ow
                for ow in overwrites
                if ow.target_id == member.user_id
                and ow.target_type == OverwriteType.MEMBER
            ),
            None,
        )
        if member_overwrite:
            permissions &= ~member_overwrite.deny  # Remove denied permissions
            permissions |= member_overwrite.allow  # Add allowed permissions

        return permissions

    @staticmethod
    def calculate_permissions(
        member: ServerMember,
        roles: List[Role],
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> int:
        """
        Calculate final permissions for a member.

        Args:
            member: Server member
            roles: All server roles
            overwrites: Channel permission overwrites (optional)

        Returns:
            Final permission bitfield
        """
        # Calculate base permissions from roles
        base_permissions = PermissionService.calculate_base_permissions(member, roles)

        # Apply channel overwrites if provided
        if overwrites:
            return PermissionService.calculate_overwrites(
                base_permissions, member, roles, overwrites
            )

        return base_permissions

    @staticmethod
    def has_permission(
        member: ServerMember,
        roles: List[Role],
        permission: Permissions,
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> bool:
        """
        Check if member has a specific permission.

        Args:
            member: Server member
            roles: All server roles
            permission: Permission to check
            overwrites: Channel permission overwrites (optional)

        Returns:
            True if member has the permission
        """
        final_permissions = PermissionService.calculate_permissions(
            member, roles, overwrites
        )
        return bool(final_permissions & permission)

    @staticmethod
    def has_any_permission(
        member: ServerMember,
        roles: List[Role],
        permissions: List[Permissions],
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> bool:
        """
        Check if member has any of the specified permissions.

        Args:
            member: Server member
            roles: All server roles
            permissions: List of permissions to check
            overwrites: Channel permission overwrites (optional)

        Returns:
            True if member has any of the permissions
        """
        final_permissions = PermissionService.calculate_permissions(
            member, roles, overwrites
        )
        return any(bool(final_permissions & perm) for perm in permissions)

    @staticmethod
    def has_all_permissions(
        member: ServerMember,
        roles: List[Role],
        permissions: List[Permissions],
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> bool:
        """
        Check if member has all of the specified permissions.

        Args:
            member: Server member
            roles: All server roles
            permissions: List of permissions to check
            overwrites: Channel permission overwrites (optional)

        Returns:
            True if member has all of the permissions
        """
        final_permissions = PermissionService.calculate_permissions(
            member, roles, overwrites
        )
        return all(bool(final_permissions & perm) for perm in permissions)

    @staticmethod
    def is_administrator(member: ServerMember, roles: List[Role]) -> bool:
        """
        Check if member has administrator permission.

        Args:
            member: Server member
            roles: All server roles

        Returns:
            True if member is administrator
        """
        return PermissionService.has_permission(
            member, roles, Permissions.ADMINISTRATOR
        )

    @staticmethod
    def can_manage_channel(
        member: ServerMember,
        roles: List[Role],
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> bool:
        """
        Check if member can manage channels.

        Args:
            member: Server member
            roles: All server roles
            overwrites: Channel permission overwrites (optional)

        Returns:
            True if member can manage channels
        """
        return PermissionService.has_any_permission(
            member,
            roles,
            [Permissions.ADMINISTRATOR, Permissions.MANAGE_CHANNELS],
            overwrites,
        )

    @staticmethod
    def can_send_messages(
        member: ServerMember,
        roles: List[Role],
        overwrites: Optional[List[PermissionOverwrite]] = None,
    ) -> bool:
        """
        Check if member can send messages in a channel.

        Args:
            member: Server member
            roles: All server roles
            overwrites: Channel permission overwrites (optional)

        Returns:
            True if member can send messages
        """
        return PermissionService.has_all_permissions(
            member,
            roles,
            [Permissions.VIEW_CHANNEL, Permissions.SEND_MESSAGES],
            overwrites,
        )

    @staticmethod
    def get_permission_names(permissions: int) -> List[str]:
        """
        Get list of permission names from bitfield.

        Args:
            permissions: Permission bitfield

        Returns:
            List of permission names
        """
        permission_names = []
        for perm in Permissions:
            if permissions & perm:
                permission_names.append(perm.name)
        return permission_names
