"""
User Service Implementation
Handles user management operations with repository pattern.
"""

from datetime import UTC, datetime

from plexichat.core.authentication import Role
from plexichat.core.logging.logger import get_logger
from plexichat.core.security import get_security_system

from ..config import get_auth_config
from .interfaces import IUserService

logger = get_logger(__name__)


class UserService(IUserService):
    """
    User service implementing user management operations.
    Provides user registration, password management, and role operations.
    """

    def __init__(self, security_system=None):
        super().__init__()
        self.config = get_auth_config()
        self.security_system = security_system or get_security_system()

    def register_user(
        self,
        username: str,
        password: str,
        permissions: set[str] | None = None,
        roles: set[Role] | None = None,
    ) -> tuple[bool, list[str]]:
        """
        Register a new user with validation and security checks.

        Args:
            username: Unique username
            password: User password
            permissions: Initial permissions
            roles: Initial roles

        Returns:
            Tuple of (success, error_messages)
        """
        try:
            issues = []

            # Validate username
            if not username or len(username.strip()) == 0:
                issues.append("Username cannot be empty")

            if len(username) < 3:
                issues.append("Username must be at least 3 characters long")

            if len(username) > 50:
                issues.append("Username cannot exceed 50 characters")

            # Check if user already exists
            if self.security_system.user_credentials.get(username):
                issues.append("Username already exists")

            # Validate password against policy
            if hasattr(self.config, "password_policy"):
                policy_valid, policy_issues = self._validate_password_policy(
                    password, username
                )
                if not policy_valid:
                    issues.extend(policy_issues)

            # Validate password strength
            strength_valid, strength_issues = (
                self.security_system.password_manager.validate_password_strength(
                    password
                )
            )
            if not strength_valid:
                issues.extend(strength_issues)

            if issues:
                logger.warning(f"User registration failed for {username}: {issues}")
                return False, issues

            # Hash password
            password_hash, salt = self.security_system.password_manager.hash_password(
                password
            )

            # Expand role permissions
            final_permissions = permissions or set()
            if roles:
                role_permissions = self._expand_role_permissions(roles)
                final_permissions.update(role_permissions)

            # Create user credentials
            from plexichat.core.security.security_manager import UserCredentials

            credentials = UserCredentials(
                username=username,
                password_hash=password_hash,
                salt=salt,
                permissions=final_permissions,
                failed_attempts=0,
                locked_until=None,
            )

            # Store in security system
            self.security_system.user_credentials[username] = credentials

            logger.info(f"User registered successfully: {username}")
            logger.security(
                "User registration",
                user_id=username,
                permissions=list(final_permissions),
                roles=[role.value for role in (roles or set())],
            )

            return True, []

        except Exception as e:
            logger.error(f"Error registering user {username}: {e}")
            return False, [f"Registration failed: {e!s}"]

    async def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> tuple[bool, list[str]]:
        """
        Change user password with validation.

        Args:
            user_id: User identifier
            old_password: Current password
            new_password: New password

        Returns:
            Tuple of (success, error_messages)
        """
        try:
            # Get user credentials
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False, ["User not found"]

            # Verify old password
            success, _ = await self.security_system.authenticate_user(
                user_id, old_password
            )
            if not success:
                logger.security(
                    "Password change failed - invalid old password", user_id=user_id
                )
                return False, ["Invalid current password"]

            # Validate new password
            issues = []

            # Check password policy
            if hasattr(self.config, "password_policy"):
                policy_valid, policy_issues = self._validate_password_policy(
                    new_password, user_id
                )
                if not policy_valid:
                    issues.extend(policy_issues)

            # Check password strength
            strength_valid, strength_issues = (
                self.security_system.password_manager.validate_password_strength(
                    new_password
                )
            )
            if not strength_valid:
                issues.extend(strength_issues)

            # Check password history (if enabled)
            if self.config.settings.enable_password_history:
                if self._is_password_in_history(user_id, new_password):
                    issues.append(
                        "Password cannot be the same as recently used passwords"
                    )

            if issues:
                return False, issues

            # Hash new password
            password_hash, salt = self.security_system.password_manager.hash_password(
                new_password
            )

            # Update credentials
            old_hash = credentials.password_hash
            credentials.password_hash = password_hash
            credentials.salt = salt
            credentials.password_changed_at = datetime.now(UTC)

            # Add to password history
            if self.config.settings.enable_password_history:
                self._add_to_password_history(user_id, old_hash)

            logger.security("Password changed successfully", user_id=user_id)
            logger.audit(
                "Password changed", user_id=user_id, event_type="password_changed"
            )

            return True, []

        except Exception as e:
            logger.error(f"Error changing password for {user_id}: {e}")
            return False, [f"Password change failed: {e!s}"]

    def get_user_permissions(self, user_id: str) -> set[str]:
        """Get user permissions."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            return credentials.permissions if credentials else set()
        except Exception as e:
            logger.error(f"Error getting permissions for {user_id}: {e}")
            return set()

    def update_user_permissions(self, user_id: str, permissions: set[str]) -> bool:
        """Update user permissions."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False

            old_permissions = credentials.permissions.copy()
            credentials.permissions = permissions

            logger.security(
                "User permissions updated",
                user_id=user_id,
                old_permissions=list(old_permissions),
                new_permissions=list(permissions),
            )

            return True

        except Exception as e:
            logger.error(f"Error updating permissions for {user_id}: {e}")
            return False

    def assign_role(self, user_id: str, role: Role) -> bool:
        """Assign role to user."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False

            # Get role permissions
            role_permissions = self._expand_role_permissions({role})

            # Add role permissions to user
            credentials.permissions.update(role_permissions)

            logger.security(
                "Role assigned",
                user_id=user_id,
                role=role.value,
                new_permissions=list(role_permissions),
            )

            return True

        except Exception as e:
            logger.error(f"Error assigning role to {user_id}: {e}")
            return False

    def revoke_role(self, user_id: str, role: Role) -> bool:
        """Revoke role from user."""
        try:
            credentials = self.security_system.user_credentials.get(user_id)
            if not credentials:
                return False

            # Get role permissions
            role_permissions = self._expand_role_permissions({role})

            # Remove role permissions from user
            credentials.permissions.difference_update(role_permissions)

            logger.security(
                "Role revoked",
                user_id=user_id,
                role=role.value,
                removed_permissions=list(role_permissions),
            )

            return True

        except Exception as e:
            logger.error(f"Error revoking role from {user_id}: {e}")
            return False

    def _validate_password_policy(
        self, password: str, username: str
    ) -> tuple[bool, list[str]]:
        """Validate password against policy."""
        issues = []

        try:
            policy = self.config.password_policy

            # Length check
            if len(password) < policy.min_length:
                issues.append(
                    f"Password must be at least {policy.min_length} characters"
                )

            if len(password) > policy.max_length:
                issues.append(
                    f"Password must be no more than {policy.max_length} characters"
                )

            # Character requirements
            if policy.require_uppercase and not any(c.isupper() for c in password):
                issues.append("Password must contain uppercase letters")

            if policy.require_lowercase and not any(c.islower() for c in password):
                issues.append("Password must contain lowercase letters")

            if policy.require_numbers and not any(c.isdigit() for c in password):
                issues.append("Password must contain numbers")

            if policy.require_special_chars:
                special_chars = sum(1 for c in password if not c.isalnum())
                if special_chars < policy.min_special_chars:
                    issues.append(
                        f"Password must contain at least {policy.min_special_chars} special characters"
                    )

            # Common password check
            if policy.prevent_common_passwords and password.lower() in [
                "password",
                "123456",
                "qwerty",
            ]:
                issues.append("Password is too common")

            # Personal info check
            if policy.prevent_personal_info and username.lower() in password.lower():
                issues.append("Password cannot contain username")

        except Exception as e:
            logger.error(f"Error validating password policy: {e}")
            issues.append("Password validation failed")

        return len(issues) == 0, issues

    def _expand_role_permissions(self, roles: set[Role]) -> set[str]:
        """Expand roles to their permissions."""
        permissions = set()

        role_permissions = {
            Role.GUEST: set(),
            Role.USER: {"read", "write_own"},
            Role.MODERATOR: {"read", "write_own", "moderate", "delete_others"},
            Role.ADMIN: {
                "read",
                "write_own",
                "moderate",
                "delete_others",
                "admin",
                "user_management",
            },
            Role.SUPER_ADMIN: {"*"},
            Role.SYSTEM: {"*"},
        }

        for role in roles:
            role_perms = role_permissions.get(role, set())
            if "*" in role_perms:
                return {"*"}
            permissions.update(role_perms)

        return permissions

    def _is_password_in_history(self, user_id: str, password: str) -> bool:
        """Check if password is in user's history."""
        # This would typically check against a database
        # For now, return False (not implemented)
        return False

    def _add_to_password_history(self, user_id: str, password_hash: str):
        """Add password to user's history."""
        # This would typically store in a database
        # For now, do nothing (not implemented)
        pass


__all__ = ["UserService"]
