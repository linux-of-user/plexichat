# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import UTC, datetime, timedelta
from enum import Enum
import logging
import time
from typing import Any

from fastapi import HTTPException, status
from sqlmodel import Session, select


# Placeholder imports for dependencies
class EnhancedUser:
    pass


class Message:
    pass


class ModerationAction:
    BAN = "ban"
    KICK = "kick"
    MUTE = "mute"
    DELETE_MESSAGE = "delete_message"
    EDIT_MESSAGE = "edit_message"
    PIN_MESSAGE = "pin_message"
    UNPIN_MESSAGE = "unpin_message"
    RESTRICT = "restrict"
    WARN = "warn"


class ModerationLog:
    pass


class ModerationSeverity:
    MEDIUM = "medium"


class ModerationStatus:
    BANNED = "banned"
    MUTED = "muted"
    RESTRICTED = "restricted"
    APPEALED = "appealed"
    REVOKED = "revoked"


class ModeratorRole:
    pass


class UserModerationStatus:
    pass


logger = logging.getLogger(__name__)


class UserRole(Enum):
    """Enhanced user roles with hierarchical permissions."""

    OWNER = "owner"  # Server owner (highest permissions)
    ADMIN = "admin"  # Server administrator
    MODERATOR = "moderator"  # Server moderator
    TRUSTED = "trusted"  # Trusted user
    MEMBER = "member"  # Regular member
    RESTRICTED = "restricted"  # Restricted user
    MUTED = "muted"  # Muted user
    BANNED = "banned"  # Banned user


class Permission(Enum):
    """Granular permissions system."""

    # Message permissions
    SEND_MESSAGES = "send_messages"
    DELETE_MESSAGES = "delete_messages"
    EDIT_MESSAGES = "edit_messages"
    PIN_MESSAGES = "pin_messages"

    # File permissions
    UPLOAD_FILES = "upload_files"
    DELETE_FILES = "delete_files"

    # User management
    KICK_USERS = "kick_users"
    BAN_USERS = "ban_users"
    MUTE_USERS = "mute_users"
    MANAGE_ROLES = "manage_roles"

    # Server management
    MANAGE_SERVER = "manage_server"
    MANAGE_CHANNELS = "manage_channels"
    VIEW_AUDIT_LOG = "view_audit_log"

    # Moderation
    MODERATE_CONTENT = "moderate_content"
    VIEW_REPORTS = "view_reports"
    HANDLE_APPEALS = "handle_appeals"


class ModerationService:
    """Service for comprehensive moderation operations."""

    def __init__(self, session: Session):
        self.session = session
        self.role_permissions = self._initialize_role_permissions()
        self.user_roles_cache = {}

    def _initialize_role_permissions(self) -> dict[UserRole, set[Permission]]:
        """Initialize default permissions for each role."""
        return {
            UserRole.OWNER: {
                Permission.SEND_MESSAGES,
                Permission.DELETE_MESSAGES,
                Permission.EDIT_MESSAGES,
                Permission.PIN_MESSAGES,
                Permission.UPLOAD_FILES,
                Permission.DELETE_FILES,
                Permission.KICK_USERS,
                Permission.BAN_USERS,
                Permission.MUTE_USERS,
                Permission.MANAGE_ROLES,
                Permission.MANAGE_SERVER,
                Permission.MANAGE_CHANNELS,
                Permission.VIEW_AUDIT_LOG,
                Permission.MODERATE_CONTENT,
                Permission.VIEW_REPORTS,
                Permission.HANDLE_APPEALS,
            },
            UserRole.ADMIN: {
                Permission.SEND_MESSAGES,
                Permission.DELETE_MESSAGES,
                Permission.EDIT_MESSAGES,
                Permission.PIN_MESSAGES,
                Permission.UPLOAD_FILES,
                Permission.DELETE_FILES,
                Permission.KICK_USERS,
                Permission.BAN_USERS,
                Permission.MUTE_USERS,
                Permission.MANAGE_ROLES,
                Permission.MANAGE_CHANNELS,
                Permission.VIEW_AUDIT_LOG,
                Permission.MODERATE_CONTENT,
                Permission.VIEW_REPORTS,
                Permission.HANDLE_APPEALS,
            },
            UserRole.MODERATOR: {
                Permission.SEND_MESSAGES,
                Permission.DELETE_MESSAGES,
                Permission.EDIT_MESSAGES,
                Permission.PIN_MESSAGES,
                Permission.UPLOAD_FILES,
                Permission.KICK_USERS,
                Permission.MUTE_USERS,
                Permission.VIEW_AUDIT_LOG,
                Permission.MODERATE_CONTENT,
                Permission.VIEW_REPORTS,
            },
            UserRole.TRUSTED: {
                Permission.SEND_MESSAGES,
                Permission.EDIT_MESSAGES,
                Permission.UPLOAD_FILES,
                Permission.PIN_MESSAGES,
            },
            UserRole.MEMBER: {Permission.SEND_MESSAGES, Permission.UPLOAD_FILES},
            UserRole.RESTRICTED: {Permission.SEND_MESSAGES},
            UserRole.MUTED: set(),
            UserRole.BANNED: set(),
        }

    def get_user_role(self, user_id: int, guild_id: int | None = None) -> UserRole:
        """Get the current role of a user."""
        try:
            # Check cache first
            cache_key = f"{user_id}_{guild_id}"
            if cache_key in self.user_roles_cache:
                cached_role, cached_time = self.user_roles_cache[cache_key]
                if time.time() - cached_time < 300:
                    return cached_role

            # Check for active moderation status
            statement = select(UserModerationStatus).where(
                (UserModerationStatus.user_id == user_id)
                & (UserModerationStatus.is_active)
            )
            if guild_id:
                statement = statement.where(UserModerationStatus.guild_id == guild_id)
            moderation_status = self.session.exec(statement).first()

            if moderation_status:
                if moderation_status.status == ModerationStatus.BANNED:
                    role = UserRole.BANNED
                elif moderation_status.status == ModerationStatus.MUTED:
                    role = UserRole.MUTED
                elif moderation_status.status == ModerationStatus.RESTRICTED:
                    role = UserRole.RESTRICTED
                else:
                    role = UserRole.MEMBER
            else:
                # Check for moderator role
                mod_statement = select(ModeratorRole).where(
                    (ModeratorRole.user_id == user_id) & (ModeratorRole.is_active)
                )
                if guild_id:
                    mod_statement = mod_statement.where(
                        ModeratorRole.guild_id == guild_id
                    )
                moderator_role = self.session.exec(mod_statement).first()

                if moderator_role:
                    if moderator_role.role_level >= 3:
                        role = UserRole.ADMIN
                    elif moderator_role.role_level >= 2:
                        role = UserRole.MODERATOR
                    else:
                        role = UserRole.TRUSTED
                else:
                    role = UserRole.MEMBER

            self.user_roles_cache[cache_key] = (role, time.time())
            return role

        except Exception as e:
            logger.error(f"Failed to get user role: {e}")
            return UserRole.MEMBER

    def has_permission(
        self, user_id: int, permission: Permission, guild_id: int | None = None
    ) -> bool:
        """Check if a user has a specific permission."""
        try:
            user_role = self.get_user_role(user_id, guild_id)
            return permission in self.role_permissions.get(user_role, set())
        except Exception as e:
            logger.error(f"Failed to check permission: {e}")
            return False

    def can_moderate_user(
        self, moderator_id: int, target_user_id: int, guild_id: int | None = None
    ) -> bool:
        """Check if a moderator can moderate a target user."""
        try:
            moderator_role = self.get_user_role(moderator_id, guild_id)
            target_role = self.get_user_role(target_user_id, guild_id)

            role_hierarchy = {
                UserRole.BANNED: 0,
                UserRole.MUTED: 1,
                UserRole.RESTRICTED: 2,
                UserRole.MEMBER: 3,
                UserRole.TRUSTED: 4,
                UserRole.MODERATOR: 5,
                UserRole.ADMIN: 6,
                UserRole.OWNER: 7,
            }

            moderator_level = role_hierarchy.get(moderator_role, 0)
            target_level = role_hierarchy.get(target_role, 0)

            return moderator_level > target_level

        except Exception as e:
            logger.error(f"Failed to check moderation permissions: {e}")
            return False

    def assign_role(
        self,
        user_id: int,
        role: UserRole,
        assigned_by: int,
        guild_id: int | None = None,
        reason: str | None = None,
        duration: int | None = None,
    ) -> bool:
        """Assign a role to a user."""
        try:
            cache_key = f"{user_id}_{guild_id}"
            if cache_key in self.user_roles_cache:
                del self.user_roles_cache[cache_key]

            expires_at = None
            if duration:
                expires_at = datetime.now(UTC) + timedelta(seconds=duration)

            if role in [UserRole.BANNED, UserRole.MUTED, UserRole.RESTRICTED]:
                existing_status = self.session.exec(
                    select(UserModerationStatus).where(
                        (UserModerationStatus.user_id == user_id)
                        & (UserModerationStatus.guild_id == guild_id)
                        & (UserModerationStatus.is_active)
                    )
                ).first()

                if existing_status:
                    existing_status.is_active = False
                    self.session.add(existing_status)

                status_mapping = {
                    UserRole.BANNED: ModerationStatus.BANNED,
                    UserRole.MUTED: ModerationStatus.MUTED,
                    UserRole.RESTRICTED: ModerationStatus.RESTRICTED,
                }

                new_status = UserModerationStatus(
                    user_id=user_id,
                    guild_id=guild_id,
                    status=status_mapping[role],
                    reason=reason or f"Role assigned: {role.value}",
                    moderator_id=assigned_by,
                    expires_at=expires_at,
                    is_active=True,
                )
                self.session.add(new_status)

            elif role in [UserRole.MODERATOR, UserRole.ADMIN, UserRole.TRUSTED]:
                existing_mod = self.session.exec(
                    select(ModeratorRole).where(
                        (ModeratorRole.user_id == user_id)
                        & (ModeratorRole.guild_id == guild_id)
                        & (ModeratorRole.is_active)
                    )
                ).first()

                if existing_mod:
                    existing_mod.is_active = False
                    self.session.add(existing_mod)

                level_mapping = {
                    UserRole.TRUSTED: 1,
                    UserRole.MODERATOR: 2,
                    UserRole.ADMIN: 3,
                }

                new_mod = ModeratorRole(
                    user_id=user_id,
                    guild_id=guild_id,
                    role_level=level_mapping[role],
                    assigned_by=assigned_by,
                    expires_at=expires_at,
                    is_active=True,
                )
                self.session.add(new_mod)

            self.session.commit()
            logger.info(f" Assigned role {role.value} to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to assign role: {e}")
            self.session.rollback()
            return False

    def execute_enhanced_moderation_action(
        self,
        moderator_id: int,
        target_user_id: int,
        action: ModerationAction,
        reason: str,
        guild_id: int | None = None,
        channel_id: int | None = None,
        duration: int | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> int | None:
        """Execute an enhanced moderation action with role-based permissions."""
        try:
            if not self.can_moderate_user(moderator_id, target_user_id, guild_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to moderate this user",
                )

            required_permission = None
            if action == ModerationAction.BAN:
                required_permission = Permission.BAN_USERS
            elif action == ModerationAction.KICK:
                required_permission = Permission.KICK_USERS
            elif action == ModerationAction.MUTE:
                required_permission = Permission.MUTE_USERS
            elif action in [
                ModerationAction.DELETE_MESSAGE,
                ModerationAction.EDIT_MESSAGE,
            ]:
                required_permission = Permission.DELETE_MESSAGES

            if required_permission and not self.has_permission(
                moderator_id, required_permission, guild_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permission: {required_permission.value}",
                )

            log_id = self.moderate_user(
                moderator_id=moderator_id,
                target_user_id=target_user_id,
                action=action,
                reason=reason,
                guild_id=guild_id,
                channel_id=channel_id,
                duration=duration,
                evidence=evidence,
            )

            if action == ModerationAction.BAN:
                self.assign_role(
                    target_user_id,
                    UserRole.BANNED,
                    moderator_id,
                    guild_id,
                    reason,
                    duration,
                )
            elif action == ModerationAction.MUTE:
                self.assign_role(
                    target_user_id,
                    UserRole.MUTED,
                    moderator_id,
                    guild_id,
                    reason,
                    duration,
                )
            elif action == ModerationAction.RESTRICT:
                self.assign_role(
                    target_user_id,
                    UserRole.RESTRICTED,
                    moderator_id,
                    guild_id,
                    reason,
                    duration,
                )

            logger.info(
                f" Enhanced moderation action {action.value} executed on user {target_user_id}"
            )
            return log_id

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to execute enhanced moderation action: {e}")
            return None

    def create_moderation_appeal(
        self,
        user_id: int,
        moderation_log_id: int,
        appeal_reason: str,
        guild_id: int | None = None,
    ) -> bool:
        """Create an appeal for a moderation action."""
        try:
            log_entry = self.session.get(ModerationLog, moderation_log_id)
            if not log_entry or log_entry.target_user_id != user_id:
                return False

            if log_entry.appeal_reason:
                return False

            log_entry.appeal_reason = appeal_reason
            log_entry.appeal_status = "pending"
            log_entry.appeal_submitted_at = datetime.now(UTC)

            self.session.add(log_entry)
            self.session.commit()
            logger.info(f" Appeal submitted for moderation log {moderation_log_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to create moderation appeal: {e}")
            self.session.rollback()
            return False

    def review_moderation_appeal(
        self,
        moderator_id: int,
        moderation_log_id: int,
        decision: str,
        review_reason: str,
        guild_id: int | None = None,
    ) -> bool:
        """Review a moderation appeal."""
        try:
            if not self.has_permission(
                moderator_id, Permission.HANDLE_APPEALS, guild_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to handle appeals",
                )

            log_entry = self.session.get(ModerationLog, moderation_log_id)
            if not log_entry or log_entry.appeal_status != "pending":
                return False

            log_entry.appeal_status = decision
            log_entry.appeal_reviewed_by = moderator_id
            log_entry.appeal_reviewed_at = datetime.now(UTC)
            log_entry.appeal_review_reason = review_reason

            if decision == "approved":
                log_entry.is_active = False
                active_status = self.session.exec(
                    select(UserModerationStatus).where(
                        (UserModerationStatus.user_id == log_entry.target_user_id)
                        & (UserModerationStatus.guild_id == guild_id)
                        & (UserModerationStatus.is_active)
                    )
                ).first()

                if active_status:
                    active_status.is_active = False
                    self.session.add(active_status)

                cache_key = f"{log_entry.target_user_id}_{guild_id}"
                if cache_key in self.user_roles_cache:
                    del self.user_roles_cache[cache_key]
                logger.info(f" Appeal approved for moderation log {moderation_log_id}")
            else:
                logger.info(f" Appeal denied for moderation log {moderation_log_id}")

            self.session.add(log_entry)
            self.session.commit()
            return True

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to review moderation appeal: {e}")
            self.session.rollback()
            return False

    def get_user_moderation_summary(
        self, user_id: int, guild_id: int | None = None
    ) -> dict[str, Any]:
        """Get comprehensive moderation summary for a user."""
        try:
            current_role = self.get_user_role(user_id, guild_id)
            history_statement = select(ModerationLog).where(
                ModerationLog.target_user_id == user_id
            )
            if guild_id:
                history_statement = history_statement.where(
                    ModerationLog.guild_id == guild_id
                )
            history = self.session.exec(
                history_statement.order_by(ModerationLog.created_at.desc())
            ).all()

            active_status = self.session.exec(
                select(UserModerationStatus).where(
                    (UserModerationStatus.user_id == user_id)
                    & (UserModerationStatus.guild_id == guild_id)
                    & (UserModerationStatus.is_active)
                )
            ).first()

            action_counts = {}
            for log in history:
                action = log.action.value
                action_counts[action] = action_counts.get(action, 0) + 1

            pending_appeals = [log for log in history if log.appeal_status == "pending"]

            return {
                "user_id": user_id,
                "current_role": current_role.value,
                "active_status": {
                    "status": active_status.status.value if active_status else None,
                    "reason": active_status.reason if active_status else None,
                    "expires_at": (
                        active_status.expires_at.isoformat()
                        if active_status and active_status.expires_at
                        else None
                    ),
                    "moderator_id": (
                        active_status.moderator_id if active_status else None
                    ),
                },
                "moderation_history": {
                    "total_actions": len(history),
                    "action_counts": action_counts,
                    "recent_actions": [
                        {
                            "id": log.id,
                            "action": log.action.value,
                            "reason": log.reason,
                            "moderator_id": log.moderator_id,
                            "created_at": log.created_at.isoformat(),
                            "is_active": log.is_active,
                            "appeal_status": log.appeal_status,
                        }
                        for log in history[:10]
                    ],
                },
                "pending_appeals": len(pending_appeals),
                "permissions": [
                    perm.value
                    for perm in self.role_permissions.get(current_role, set())
                ],
            }

        except Exception as e:
            logger.error(f"Failed to get user moderation summary: {e}")
            return {"user_id": user_id, "error": str(e)}

    async def check_moderator_permissions(
        self,
        user_id: int,
        guild_id: int | None = None,
        channel_id: int | None = None,
        required_action: ModerationAction | None = None,
    ) -> tuple[bool, ModeratorRole | None]:
        """Check if user has moderator permissions for the specified context."""
        try:
            statement = select(ModeratorRole).where(
                (ModeratorRole.user_id == user_id) & (ModeratorRole.is_active)
            )
            if guild_id:
                statement = statement.where(
                    (ModeratorRole.guild_id == guild_id)
                    | (ModeratorRole.guild_id.is_(None))
                )
            if channel_id:
                statement = statement.where(
                    (ModeratorRole.channel_id == channel_id)
                    | (ModeratorRole.channel_id.is_(None))
                )
            moderator_role = self.session.exec(statement).first()

            if not moderator_role:
                return False, None

            if moderator_role.expires_at and moderator_role.expires_at < datetime.now(
                UTC
            ):
                return False, None

            if required_action:
                if required_action in [
                    ModerationAction.DELETE_MESSAGE,
                    ModerationAction.EDIT_MESSAGE,
                ]:
                    if not moderator_role.can_moderate_messages:
                        return False, None
                elif required_action in [
                    ModerationAction.MUTE,
                    ModerationAction.KICK,
                    ModerationAction.BAN,
                ]:
                    if not moderator_role.can_moderate_users:
                        return False, None
                    if (
                        required_action == ModerationAction.BAN
                        and not moderator_role.can_ban_users
                    ):
                        return False, None

            return True, moderator_role

        except Exception as e:
            logger.error(f"Error checking moderator permissions: {e}")
            return False, None

    async def moderate_user(
        self,
        moderator_id: int,
        target_user_id: int,
        action: ModerationAction,
        reason: str,
        duration_minutes: int | None = None,
        guild_id: int | None = None,
        channel_id: int | None = None,
        severity: ModerationSeverity = ModerationSeverity.MEDIUM,
    ) -> bool:
        """Apply moderation action to a user."""
        try:
            has_permission, moderator_role = await self.check_moderator_permissions(
                moderator_id, guild_id, channel_id, action
            )
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient moderator permissions",
                )

            if (
                moderator_role
                and severity.value > moderator_role.max_punishment_severity.value
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Action severity exceeds moderator permissions",
                )

            user_status = self.session.exec(
                select(UserModerationStatus).where(
                    UserModerationStatus.user_id == target_user_id
                )
            ).first()

            if not user_status:
                user_status = UserModerationStatus(user_id=target_user_id)
                self.session.add(user_status)

            expires_at = None
            if duration_minutes:
                expires_at = datetime.now(UTC) + timedelta(minutes=duration_minutes)

            if action == ModerationAction.MUTE:
                user_status.is_muted = True
                user_status.mute_expires_at = expires_at
                user_status.mute_reason = reason
            elif action == ModerationAction.BAN:
                user_status.is_banned = True
                user_status.ban_expires_at = expires_at
                user_status.ban_reason = reason
            elif action == ModerationAction.TIMEOUT:
                user_status.is_timed_out = True
                user_status.timeout_expires_at = expires_at
                user_status.timeout_reason = reason
            elif action == ModerationAction.WARN:
                user_status.warning_count += 1
                user_status.last_warning_at = datetime.now(UTC)

            user_status.updated_at = datetime.now(UTC)

            log_entry = ModerationLog(
                action=action,
                severity=severity,
                moderator_id=moderator_id,
                target_user_id=target_user_id,
                guild_id=guild_id,
                channel_id=channel_id,
                reason=reason,
                duration_minutes=duration_minutes,
                expires_at=expires_at,
            )
            self.session.add(log_entry)
            self.session.commit()

            logger.info(
                f"Moderation action {action.value} applied to user {target_user_id} by {moderator_id}"
            )
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error applying moderation action: {e}")
            return False

    async def moderate_message(
        self,
        moderator_id: int,
        message_id: int,
        action: ModerationAction,
        reason: str,
        new_content: str | None = None,
        guild_id: int | None = None,
        channel_id: int | None = None,
    ) -> bool:
        """Apply moderation action to a message."""
        try:
            has_permission, _ = await self.check_moderator_permissions(
                moderator_id, guild_id, channel_id, action
            )
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient moderator permissions",
                )

            message = self.session.get(Message, message_id)
            if not message:
                raise HTTPException(status_code=404, detail="Message not found")

            original_content = message.content

            if action == ModerationAction.DELETE_MESSAGE:
                message.is_deleted = True
                message.content = "[Message deleted by moderator]"
            elif action == ModerationAction.EDIT_MESSAGE:
                if not new_content:
                    raise HTTPException(
                        status_code=400, detail="New content required for message edit"
                    )
                message.content = new_content
                message.edited_timestamp = datetime.utcnow()
                message.is_edited = True
            elif action == ModerationAction.PIN_MESSAGE:
                message.is_pinned = True
            elif action == ModerationAction.UNPIN_MESSAGE:
                message.is_pinned = False

            log_entry = ModerationLog(
                action=action,
                severity=ModerationSeverity.MEDIUM,
                moderator_id=moderator_id,
                target_message_id=message_id,
                target_user_id=message.sender_id or message.author_id,
                guild_id=guild_id,
                channel_id=channel_id,
                reason=reason,
                original_content=original_content,
                new_content=new_content,
            )
            self.session.add(log_entry)
            self.session.commit()

            logger.info(
                f"Message moderation action {action.value} applied to message {message_id}"
            )
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error moderating message: {e}")
            return False

    async def check_user_restrictions(self, user_id: int) -> dict[str, Any]:
        """Check current moderation restrictions for a user."""
        try:
            user_status = self.session.exec(
                select(UserModerationStatus).where(
                    UserModerationStatus.user_id == user_id
                )
            ).first()

            if not user_status:
                return {
                    "is_muted": False,
                    "is_banned": False,
                    "is_timed_out": False,
                    "warning_count": 0,
                }

            now = datetime.now(UTC)

            if (
                user_status.is_muted
                and user_status.mute_expires_at
                and user_status.mute_expires_at < now
            ):
                user_status.is_muted = False
                user_status.mute_expires_at = None
                user_status.mute_reason = None
            if (
                user_status.is_banned
                and user_status.ban_expires_at
                and user_status.ban_expires_at < now
            ):
                user_status.is_banned = False
                user_status.ban_expires_at = None
                user_status.ban_reason = None
            if (
                user_status.is_timed_out
                and user_status.timeout_expires_at
                and user_status.timeout_expires_at < now
            ):
                user_status.is_timed_out = False
                user_status.timeout_expires_at = None
                user_status.timeout_reason = None

            self.session.commit()

            return {
                "is_muted": user_status.is_muted,
                "is_banned": user_status.is_banned,
                "is_timed_out": user_status.is_timed_out,
                "warning_count": user_status.warning_count,
                "mute_expires_at": user_status.mute_expires_at,
                "ban_expires_at": user_status.ban_expires_at,
                "timeout_expires_at": user_status.timeout_expires_at,
                "mute_reason": user_status.mute_reason,
                "ban_reason": user_status.ban_reason,
                "timeout_reason": user_status.timeout_reason,
                "last_warning_at": user_status.last_warning_at,
            }

        except Exception as e:
            logger.error(f"Error checking user restrictions: {e}")
            return {"error": "Failed to check restrictions"}

    async def grant_moderator_role(
        self,
        granter_id: int,
        user_id: int,
        guild_id: int | None = None,
        channel_id: int | None = None,
        role_name: str = "Moderator",
        permissions: dict[str, bool] | None = None,
        expires_at: datetime | None = None,
    ) -> bool:
        """Grant moderator role to a user."""
        try:
            has_permission, granter_role = await self.check_moderator_permissions(
                granter_id, guild_id, channel_id
            )
            if (
                not has_permission
                or not granter_role
                or not granter_role.can_manage_roles
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to grant moderator roles",
                )

            existing_role = self.session.exec(
                select(ModeratorRole).where(
                    (ModeratorRole.user_id == user_id)
                    & (ModeratorRole.guild_id == guild_id)
                    & (ModeratorRole.channel_id == channel_id)
                    & (ModeratorRole.is_active)
                )
            ).first()
            if existing_role:
                raise HTTPException(
                    status_code=400,
                    detail="User already has a moderator role in this context",
                )

            if not permissions:
                permissions = {
                    "can_moderate_messages": True,
                    "can_moderate_users": True,
                    "can_ban_users": False,
                    "can_manage_roles": False,
                }

            moderator_role = ModeratorRole(
                user_id=user_id,
                guild_id=guild_id,
                channel_id=channel_id,
                role_name=role_name,
                permissions=permissions,
                can_moderate_messages=permissions.get("can_moderate_messages", True),
                can_moderate_users=permissions.get("can_moderate_users", True),
                can_ban_users=permissions.get("can_ban_users", False),
                can_manage_roles=permissions.get("can_manage_roles", False),
                expires_at=expires_at,
                granted_by=granter_id,
            )
            self.session.add(moderator_role)
            self.session.commit()
            logger.info(f"Granted moderator role to user {user_id} by {granter_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error granting moderator role: {e}")
            return False

    async def revoke_moderator_role(
        self, revoker_id: int, moderator_role_id: int, reason: str
    ) -> bool:
        """Revoke a moderator role."""
        try:
            moderator_role = self.session.get(ModeratorRole, moderator_role_id)
            if not moderator_role:
                raise HTTPException(status_code=404, detail="Moderator role not found")

            has_permission, revoker_role = await self.check_moderator_permissions(
                revoker_id, moderator_role.guild_id, moderator_role.channel_id
            )
            if (
                not has_permission
                or not revoker_role
                or not revoker_role.can_manage_roles
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to revoke moderator roles",
                )

            moderator_role.is_active = False
            moderator_role.revoked_at = datetime.now(UTC)
            moderator_role.revoked_by = revoker_id

            self.session.commit()
            logger.info(f"Revoked moderator role {moderator_role_id} by {revoker_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error revoking moderator role: {e}")
            return False

    async def submit_appeal(
        self, user_id: int, moderation_log_id: int, appeal_reason: str
    ) -> bool:
        """Submit an appeal for a moderation action."""
        try:
            moderation_log = self.session.get(ModerationLog, moderation_log_id)
            if not moderation_log:
                raise HTTPException(status_code=404, detail="Moderation log not found")

            if moderation_log.target_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Can only appeal your own moderation actions",
                )

            if moderation_log.appeal_submitted_at:
                raise HTTPException(status_code=400, detail="Appeal already submitted")

            moderation_log.appeal_reason = appeal_reason
            moderation_log.appeal_submitted_at = datetime.now(UTC)
            moderation_log.status = ModerationStatus.APPEALED

            self.session.commit()
            logger.info(
                f"Appeal submitted for moderation log {moderation_log_id} by user {user_id}"
            )
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error submitting appeal: {e}")
            return False

    async def review_appeal(
        self,
        reviewer_id: int,
        moderation_log_id: int,
        decision: str,
        decision_reason: str,
    ) -> bool:
        """Review an appeal for a moderation action."""
        try:
            moderation_log = self.session.get(ModerationLog, moderation_log_id)
            if not moderation_log:
                raise HTTPException(status_code=404, detail="Moderation log not found")

            has_permission, _ = await self.check_moderator_permissions(
                reviewer_id, moderation_log.guild_id, moderation_log.channel_id
            )
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to review appeals",
                )

            if not moderation_log.appeal_submitted_at:
                raise HTTPException(status_code=400, detail="No appeal to review")

            moderation_log.appeal_reviewed_by = reviewer_id
            moderation_log.appeal_decision = decision
            moderation_log.appeal_decision_reason = decision_reason
            moderation_log.resolved_at = datetime.now(UTC)

            if decision == "approved":
                moderation_log.status = ModerationStatus.REVOKED
                if moderation_log.target_user_id:
                    user_status = self.session.exec(
                        select(UserModerationStatus).where(
                            UserModerationStatus.user_id
                            == moderation_log.target_user_id
                        )
                    ).first()

                    if user_status:
                        if moderation_log.action == ModerationAction.MUTE:
                            user_status.is_muted = False
                            user_status.mute_expires_at = None
                            user_status.mute_reason = None
                        elif moderation_log.action == ModerationAction.BAN:
                            user_status.is_banned = False
                            user_status.ban_expires_at = None
                            user_status.ban_reason = None
                        elif moderation_log.action == ModerationAction.TIMEOUT:
                            user_status.is_timed_out = False
                            user_status.timeout_expires_at = None
                            user_status.timeout_reason = None

                        user_status.updated_at = datetime.now(UTC)

            self.session.commit()
            logger.info(
                f"Appeal {decision} for moderation log {moderation_log_id} by reviewer {reviewer_id}"
            )
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error reviewing appeal: {e}")
            return False

    async def get_moderation_logs(
        self,
        guild_id: int | None = None,
        target_user_id: int | None = None,
        moderator_id: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Get moderation logs with filtering."""
        try:
            statement = select(ModerationLog)

            if guild_id:
                statement = statement.where(ModerationLog.guild_id == guild_id)
            if target_user_id:
                statement = statement.where(
                    ModerationLog.target_user_id == target_user_id
                )
            if moderator_id:
                statement = statement.where(ModerationLog.moderator_id == moderator_id)

            statement = (
                statement.order_by(ModerationLog.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            logs = self.session.exec(statement).all()

            result = []
            for log in logs:
                moderator = self.session.get(EnhancedUser, log.moderator_id)
                target_user = (
                    self.session.get(EnhancedUser, log.target_user_id)
                    if log.target_user_id
                    else None
                )

                result.append(
                    {
                        "id": log.id,
                        "uuid": log.uuid,
                        "action": log.action.value,
                        "severity": log.severity.value,
                        "status": log.status.value,
                        "moderator": (
                            {
                                "id": moderator.id,
                                "username": moderator.username,
                                "display_name": moderator.display_name,
                            }
                            if moderator
                            else None
                        ),
                        "target_user": (
                            {
                                "id": target_user.id,
                                "username": target_user.username,
                                "display_name": target_user.display_name,
                            }
                            if target_user
                            else None
                        ),
                        "reason": log.reason,
                        "duration_minutes": log.duration_minutes,
                        "created_at": log.created_at,
                        "expires_at": log.expires_at,
                        "appeal_submitted": log.appeal_submitted_at is not None,
                        "appeal_decision": log.appeal_decision,
                        "original_content": log.original_content,
                        "new_content": log.new_content,
                    }
                )

            return result

        except Exception as e:
            logger.error(f"Error getting moderation logs: {e}")
            return []
