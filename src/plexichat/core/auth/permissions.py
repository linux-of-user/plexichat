from enum import Enum


class DBOperation(Enum):
    """Enumeration for database operations."""

    READ = "read"
    WRITE = "write"  # Covers INSERT and UPDATE
    DELETE = "delete"
    EXECUTE_RAW = "execute_raw"


class ResourceType(Enum):
    """Enumeration for resource types."""

    TABLE = "table"
    DATABASE = "db"


def format_permission(
    resource_type: ResourceType, operation: DBOperation, resource_name: str = "any"
) -> str:
    """Formats a permission string in a standardized way."""
    return f"{resource_type.value}:{operation.value}:{resource_name}"


class PermissionError(Exception):
    """Custom exception raised when a permission check fails."""

    pass


def check_permission(required_permission: str, user_permissions: set[str]) -> None:
    """
    Checks if a user has the required permission.
    Raises PermissionError if the check fails.

    A generic permission (e.g., 'table:write:any') grants access to all resources of that type.
    """
    if not user_permissions:
        raise PermissionError(
            f"Permission denied for '{required_permission}'. No permissions provided."
        )

    # Check for specific permission
    if required_permission in user_permissions:
        return

    # Check for generic wildcard permission
    parts = required_permission.split(":")
    if len(parts) == 3:
        resource_type, operation, _ = parts
        generic_permission = f"{resource_type}:{operation}:any"
        if generic_permission in user_permissions:
            return

    raise PermissionError(
        f"Permission denied. Required: '{required_permission}', but not found in user permissions."
    )


# Example Usage:
#
# from .permissions import check_permission, format_permission, DBOperation, ResourceType, PermissionError
#
# user_perms = {"table:read:users", "table:write:messages"}
#
# try:
#     # Check if user can write to the 'messages' table
#     required = format_permission(ResourceType.TABLE, DBOperation.WRITE, "messages")
#     check_permission(required, user_perms)
#     print("Permission granted!")
# except PermissionError as e:
#     print(e)
#
# try:
#     # Check if user can delete from the 'users' table (this will fail)
#     required = format_permission(ResourceType.TABLE, DBOperation.DELETE, "users")
#     check_permission(required, user_perms)
#     print("Permission granted!")
# except PermissionError as e:
#     print(e)
