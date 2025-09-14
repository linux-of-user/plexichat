# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
import hashlib
import logging
import secrets
from typing import Any

from fastapi import HTTPException, status
from sqlmodel import Session, select


# Placeholder imports for dependencies
class FileAccessLevel:
    PUBLIC = "public"


class FileAccessLog:
    pass


class FilePermission:
    pass


class FilePermissionType:
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"
    ADMIN = "admin"


class FileRecord:
    pass


class FileShare:
    pass


logger = logging.getLogger(__name__)


class FilePermissionService:
    """Service for managing file permissions and access control."""

    def __init__(self, session: Session):
        self.session = session

    async def check_file_access(
        self,
        file_id: int,
        user_id: int | None,
        permission_type: FilePermissionType,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """
        Check if user has access to file with specified permission.
        Returns (has_access, error_message, access_context)
        """
        try:
            # Get file record
            file_record = self.session.get(FileRecord, file_id)
            if not file_record:
                return False, "File not found", None

            # Check if file is deleted or inactive
            if not file_record.is_active:
                return False, "File is not available", None

            access_context = {
                "file_id": file_id,
                "user_id": user_id,
                "permission_type": permission_type,
                "access_level": file_record.access_level,
            }

            # Owner always has full access
            if user_id and file_record.uploaded_by == user_id:
                access_context["permission_source"] = "owner"
                await self._log_access(
                    file_id,
                    user_id,
                    permission_type.value,
                    True,
                    ip_address,
                    user_agent,
                    access_context,
                )
                return True, None, access_context

            # Check public access
            if file_record.access_level == FileAccessLevel.PUBLIC:
                if (
                    permission_type == FilePermissionType.READ
                    and file_record.allow_public_read
                ) or (
                    permission_type == FilePermissionType.READ
                    and file_record.allow_public_download
                ):
                    access_context["permission_source"] = "public"
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        True,
                        ip_address,
                        user_agent,
                        access_context,
                    )
                    return True, None, access_context

            # Anonymous users can only access public files
            if not user_id:
                await self._log_access(
                    file_id,
                    user_id,
                    permission_type.value,
                    False,
                    ip_address,
                    user_agent,
                    access_context,
                    "Access denied for anonymous user",
                )
                return False, "Authentication required", None

            # Check explicit permissions
            permission = await self._get_user_permission(file_id, user_id)
            if permission and permission.is_active:
                # Check if permission has expired
                if permission.expires_at and permission.expires_at < datetime.utcnow():
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        False,
                        ip_address,
                        user_agent,
                        access_context,
                        "Permission expired",
                    )
                    return False, "Permission expired", None

                # Check specific permission type
                has_permission = False
                if (
                    (permission_type == FilePermissionType.READ and permission.can_read)
                    or (
                        permission_type == FilePermissionType.WRITE
                        and permission.can_write
                    )
                    or (
                        permission_type == FilePermissionType.DELETE
                        and permission.can_delete
                    )
                    or (
                        permission_type == FilePermissionType.SHARE
                        and permission.can_share
                    )
                    or (
                        permission_type == FilePermissionType.ADMIN
                        and permission.can_admin
                    )
                ):
                    has_permission = True

                if has_permission:
                    access_context["permission_source"] = "permission"
                    access_context["permission_id"] = permission.id
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        True,
                        ip_address,
                        user_agent,
                        access_context,
                    )
                    return True, None, access_context

            # Check file shares
            share = await self._get_user_share(file_id, user_id)
            if share and share.is_active:
                # Check if share has expired
                if share.expires_at and share.expires_at < datetime.utcnow():
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        False,
                        ip_address,
                        user_agent,
                        access_context,
                        "Share expired",
                    )
                    return False, "Share expired", None

                # Check download limits
                if (
                    permission_type == FilePermissionType.READ
                    and share.max_downloads
                    and share.download_count >= share.max_downloads
                ):
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        False,
                        ip_address,
                        user_agent,
                        access_context,
                        "Download limit exceeded",
                    )
                    return False, "Download limit exceeded", None

                # Check share permissions
                has_share_permission = False
                if (
                    permission_type == FilePermissionType.READ
                    and (share.can_view or share.can_download)
                ) or (permission_type == FilePermissionType.SHARE and share.can_share):
                    has_share_permission = True

                if has_share_permission:
                    access_context["permission_source"] = "share"
                    access_context["share_id"] = share.id
                    await self._log_access(
                        file_id,
                        user_id,
                        permission_type.value,
                        True,
                        ip_address,
                        user_agent,
                        access_context,
                    )
                    return True, None, access_context

            # Access denied
            await self._log_access(
                file_id,
                user_id,
                permission_type.value,
                False,
                ip_address,
                user_agent,
                access_context,
                "No valid permissions found",
            )
            return False, "Access denied", None

        except Exception as e:
            logger.error(f"Error checking file access: {e}")
            await self._log_access(
                file_id,
                user_id,
                permission_type.value,
                False,
                ip_address,
                user_agent,
                {},
                f"System error: {e!s}",
            )
            return False, "System error", None

    async def grant_permission(
        self,
        file_id: int,
        target_user_id: int,
        granted_by_user_id: int,
        permissions: dict[str, bool],
        expires_at: datetime | None = None,
        max_downloads: int | None = None,
    ) -> bool:
        """Grant permissions to a user for a file."""
        try:
            # Check if granter has admin permission
            can_grant, _, _ = await self.check_file_access(
                file_id, granted_by_user_id, FilePermissionType.ADMIN
            )
            if not can_grant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to grant access",
                )

            # Check if permission already exists
            existing_permission = await self._get_user_permission(
                file_id, target_user_id
            )
            if existing_permission:
                # Update existing permission
                for perm_type, value in permissions.items():
                    setattr(existing_permission, f"can_{perm_type}", value)
                existing_permission.expires_at = expires_at
                existing_permission.max_downloads = max_downloads
                existing_permission.granted_by = granted_by_user_id
                existing_permission.granted_at = datetime.utcnow()
                existing_permission.is_active = True
                existing_permission.revoked_at = None
            else:
                # Create new permission
                new_permission = FilePermission(
                    file_id=file_id,
                    user_id=target_user_id,
                    granted_by=granted_by_user_id,
                    expires_at=expires_at,
                    max_downloads=max_downloads,
                    **{f"can_{k}": v for k, v in permissions.items()},
                )
                self.session.add(new_permission)

            self.session.commit()
            logger.info(
                f"Granted permissions to user {target_user_id} for file {file_id}"
            )
            return True

        except Exception as e:
            self.session.rollback()
            logger.error(f"Error granting permission: {e}")
            return False

    async def revoke_permission(
        self, file_id: int, target_user_id: int, revoked_by_user_id: int
    ) -> bool:
        """Revoke permissions for a user on a file."""
        try:
            # Check if revoker has admin permission
            can_revoke, _, _ = await self.check_file_access(
                file_id, revoked_by_user_id, FilePermissionType.ADMIN
            )
            if not can_revoke:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to revoke access",
                )

            permission = await self._get_user_permission(file_id, target_user_id)
            if permission:
                permission.is_active = False
                permission.revoked_at = datetime.utcnow()
                self.session.commit()
                logger.info(
                    f"Revoked permissions for user {target_user_id} on file {file_id}"
                )
                return True

            return False

        except Exception as e:
            self.session.rollback()
            logger.error(f"Error revoking permission: {e}")
            return False

    async def create_share_link(
        self,
        file_id: int,
        shared_by_user_id: int,
        shared_with_user_id: int,
        permissions: dict[str, bool],
        expires_at: datetime | None = None,
        max_downloads: int | None = None,
        share_message: str | None = None,
        require_password: bool = False,
    ) -> str | None:
        """Create a share link for a file."""
        try:
            # Check if sharer has share permission
            can_share, _, _ = await self.check_file_access(
                file_id, shared_by_user_id, FilePermissionType.SHARE
            )
            if not can_share:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to share file",
                )

            # Generate password
            password = secrets.token_urlsafe(12)
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Create share record
            share = FileShare(
                file_id=file_id,
                shared_by=shared_by_user_id,
                shared_with=shared_with_user_id,
                expires_at=expires_at,
                max_downloads=max_downloads,
                share_message=share_message,
                require_password=require_password,
                password_hash=password_hash,
                **permissions,
            )

            self.session.add(share)
            self.session.commit()
            self.session.refresh(share)

            logger.info(f"Created share link {share.uuid} for file {file_id}")
            return share.uuid

        except Exception as e:
            self.session.rollback()
            logger.error(f"Error creating share link: {e}")
            return None

    async def _get_user_permission(
        self, file_id: int, user_id: int
    ) -> FilePermission | None:
        """Get user's explicit permission for a file."""
        statement = select(FilePermission).where(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user_id,
            FilePermission.is_active,
        )
        return self.session.exec(statement).first()

    async def _get_user_share(self, file_id: int, user_id: int) -> FileShare | None:
        """Get user's share access for a file."""
        statement = select(FileShare).where(
            FileShare.file_id == file_id,
            FileShare.shared_with == user_id,
            FileShare.is_active,
        )
        return self.session.exec(statement).first()

    async def _log_access(
        self,
        file_id: int,
        user_id: int | None,
        action: str,
        success: bool,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: dict[str, Any] | None = None,
        error_message: str | None = None,
    ):
        """Log file access attempt."""
        try:
            log_entry = FileAccessLog(
                file_id=file_id,
                user_id=user_id,
                action=action,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {},
                error_message=error_message,
                permission_source=details.get("permission_source") if details else None,
                share_id=details.get("share_id") if details else None,
            )

            self.session.add(log_entry)
            self.session.commit()

        except Exception as e:
            logger.error(f"Error logging file access: {e}")
