# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select


from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from plexichat.app.db import get_session
from plexichat.app.models.files import ()
    from plexichat.infrastructure.utils.auth import get_current_user,
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User
from plexichat.features.users.user import User

    API,
    Enhanced,
    FileAccessLevel,
    FileAccessLog,
    FilePermission,
    FilePermissionService,
    FilePermissionType,
    FileRecord,
    Supports,
    User,
    """,
    access,
    and,
    comprehensive,
    control.,
    embedding,
    file,
    from,
    get_optional_current_user,
    import,
    in,
    management,
    messages,
    permission,
    permissions,
    plexichat.app.models.files,
    plexichat.app.models.user,
    plexichat.app.services.file_permissions,
    plexichat.app.utils.auth,
    plexichat.infrastructure.utils.auth,
    proper,
    validation.,
    with,
)


# Pydantic models for API
class FilePermissionRequest(BaseModel):
    user_id: int
    permissions: Dict[str, bool]  # e.g., {"read": True, "write": False, "share": True}
    expires_at: Optional[datetime] = None
    max_downloads: Optional[int] = None


class FileShareRequest(BaseModel):
    shared_with_user_id: int
    can_download: bool = True
    can_view: bool = True
    can_share: bool = False
    can_comment: bool = False
    expires_at: Optional[datetime] = None
    max_downloads: Optional[int] = None
    share_message: Optional[str] = None
    require_password: bool = False


class FileAccessResponse(BaseModel):
    has_access: bool
    file_id: int
    file_uuid: str
    filename: str
    size: int
    mime_type: Optional[str]
    access_level: str
    permission_source: Optional[str] = None
    download_url: Optional[str] = None
    expires_at: Optional[datetime] = None


class FileEmbedInfo(BaseModel):
    """Information for embedding files in messages."""
    file_id: int
    file_uuid: str
    filename: str
    size: int
    mime_type: Optional[str]
    thumbnail_url: Optional[str] = None
    is_accessible: bool
    access_level: str


router = APIRouter(prefix="/api/v1/files", tags=["Enhanced Files"])


@router.get("/check-access/{file_id}")
async def check_file_access()
    file_id: int,
    request: Request,
    permission_type: FilePermissionType = Query(FilePermissionType.READ),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_optional_current_user)
) -> FileAccessResponse:
    """
    Check if user has access to a file with specified permission.
    Used by message system to validate file embeds.
    """
    permission_service = FilePermissionService(session)

    user_id = current_user.id if current_user else None
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent")

    has_access, error_message, access_context = await permission_service.check_file_access()
        file_id, user_id, permission_type, ip_address, user_agent
    )

    if not has_access:
        # Still return file info but mark as not accessible
        file_record = session.get(FileRecord, file_id)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")

        return FileAccessResponse()
            has_access=False,
            file_id=file_id,
            file_uuid=file_record.uuid,
            filename=file_record.filename,
            size=file_record.size,
            mime_type=file_record.mime_type,
            access_level=file_record.access_level.value
        )

    # Get file details
    file_record = session.get(FileRecord, file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    download_url = f"/api/v1/files/download/{file_record.uuid}" if has_access else None

    return FileAccessResponse()
        has_access=True,
        file_id=file_id,
        file_uuid=file_record.uuid,
        filename=file_record.filename,
        size=file_record.size,
        mime_type=file_record.mime_type,
        access_level=file_record.access_level.value,
        permission_source=access_context.get("permission_source") if access_context else None,
        download_url=download_url,
        expires_at=access_context.get("expires_at") if access_context else None
    )


@router.get("/embed-info/{file_id}")
async def get_file_embed_info()
    file_id: int,
    request: Request,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_optional_current_user)
) -> FileEmbedInfo:
    """
    Get file information for embedding in messages.
    Returns basic info regardless of access, but marks accessibility.
    """
    file_record = session.get(FileRecord, file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    permission_service = FilePermissionService(session)
    user_id = current_user.id if current_user else None

    has_access, _, _ = await permission_service.check_file_access()
        file_id, user_id, FilePermissionType.READ,
        request.client.host, request.headers.get("user-agent")
    )

    # Generate thumbnail URL for images
    thumbnail_url = None
    if file_record.mime_type and file_record.mime_type.startswith('image/'):
        thumbnail_url = f"/api/v1/files/thumbnail/{file_record.uuid}"

    return FileEmbedInfo()
        file_id=file_id,
        file_uuid=file_record.uuid,
        filename=file_record.filename,
        size=file_record.size,
        mime_type=file_record.mime_type,
        thumbnail_url=thumbnail_url,
        is_accessible=has_access,
        access_level=file_record.access_level.value
    )


@router.post("/permissions/{file_id}")
async def grant_file_permission()
    file_id: int,
    permission_request: FilePermissionRequest,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Grant permissions to a user for a file."""
    permission_service = FilePermissionService(session)

    success = await permission_service.grant_permission()
        file_id=file_id,
        target_user_id=permission_request.user_id,
        granted_by_user_id=current_user.id,
        permissions=permission_request.permissions,
        expires_at=permission_request.expires_at,
        max_downloads=permission_request.max_downloads
    )

    if success:
        return JSONResponse({)
            "success": True,
            "message": "Permissions granted successfully"
        })
    else:
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to grant permissions"
        )


@router.delete("/permissions/{file_id}/{user_id}")
async def revoke_file_permission()
    file_id: int,
    user_id: int,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Revoke permissions for a user on a file."""
    permission_service = FilePermissionService(session)

    success = await permission_service.revoke_permission()
        file_id=file_id,
        target_user_id=user_id,
        revoked_by_user_id=current_user.id
    )

    if success:
        return JSONResponse({)
            "success": True,
            "message": "Permissions revoked successfully"
        })
    else:
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke permissions"
        )


@router.get("/permissions/{file_id}")
async def list_file_permissions()
    file_id: int,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> List[Dict[str, Any]]:
    """List all permissions for a file."""
    permission_service = FilePermissionService(session)

    # Check if user has admin access to the file
    has_access, _, _ = await permission_service.check_file_access()
        file_id, current_user.id, FilePermissionType.ADMIN
    )

    if not has_access:
        raise HTTPException()
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view file permissions"
        )

    # Get all active permissions for the file
    statement = select(FilePermission).where()
        FilePermission.file_id == file_id,
        FilePermission.is_active
    )
    permissions = session.exec(statement).all()

    result = []
    for perm in permissions:
        user = session.get(User, perm.user_id)
        result.append({)
            "permission_id": perm.id,
            "user_id": perm.user_id,
            "username": user.username if user else "Unknown",
            "permissions": {
                "read": perm.can_read,
                "write": perm.can_write,
                "delete": perm.can_delete,
                "share": perm.can_share,
                "admin": perm.can_admin
            },
            "granted_by": perm.granted_by,
            "granted_at": perm.granted_at,
            "expires_at": perm.expires_at,
            "max_downloads": perm.max_downloads,
            "download_count": perm.download_count
        })

    return result


@router.post("/share/{file_id}")
async def create_file_share()
    file_id: int,
    share_request: FileShareRequest,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Create a share link for a file."""
    permission_service = FilePermissionService(session)

    permissions = {
        "can_download": share_request.can_download,
        "can_view": share_request.can_view,
        "can_share": share_request.can_share,
        "can_comment": share_request.can_comment
    }

    share_uuid = await permission_service.create_share_link()
        file_id=file_id,
        shared_by_user_id=current_user.id,
        shared_with_user_id=share_request.shared_with_user_id,
        permissions=permissions,
        expires_at=share_request.expires_at,
        max_downloads=share_request.max_downloads,
        share_message=share_request.share_message,
        require_password=share_request.require_password
    )

    if share_uuid:
        return JSONResponse({)
            "success": True,
            "share_uuid": share_uuid,
            "share_url": f"/api/v1/files/shared/{share_uuid}",
            "message": "Share link created successfully"
        })
    else:
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create share link"
        )


@router.put("/access-level/{file_id}")
async def update_file_access_level()
    file_id: int,
    access_level: FileAccessLevel,
    allow_public_read: bool = False,
    allow_public_download: bool = False,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Update file access level and public permissions."""
    permission_service = FilePermissionService(session)

    # Check if user has admin access to the file
    has_access, _, _ = await permission_service.check_file_access()
        file_id, current_user.id, FilePermissionType.ADMIN
    )

    if not has_access:
        raise HTTPException()
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify file access level"
        )

    file_record = session.get(FileRecord, file_id)
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    file_record.access_level = access_level
    file_record.allow_public_read = allow_public_read
    file_record.allow_public_download = allow_public_download

    # Update legacy is_public field for backward compatibility
    file_record.is_public = (access_level == FileAccessLevel.PUBLIC)

    session.commit()

    return JSONResponse({)
        "success": True,
        "message": "File access level updated successfully",
        "access_level": access_level.value,
        "allow_public_read": allow_public_read,
        "allow_public_download": allow_public_download
    })


@router.get("/access-logs/{file_id}")
async def get_file_access_logs()
    file_id: int,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
) -> List[Dict[str, Any]]:
    """Get access logs for a file (admin only)."""
    permission_service = FilePermissionService(session)

    # Check if user has admin access to the file
    has_access, _, _ = await permission_service.check_file_access()
        file_id, current_user.id, FilePermissionType.ADMIN
    )

    if not has_access:
        raise HTTPException()
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view access logs"
        )

    statement = select(FileAccessLog).where()
        FileAccessLog.file_id == file_id
    ).order_by(FileAccessLog.accessed_at.desc()).offset(offset).limit(limit)

    logs = session.exec(statement).all()

    result = []
    for log in logs:
        user = session.get(User, log.user_id) if log.user_id else None
        result.append({)
            "id": log.id,
            "user_id": log.user_id,
            "username": user.username if user else "Anonymous",
            "action": log.action,
            "success": log.success,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "permission_source": log.permission_source,
            "error_message": log.error_message,
            "response_time_ms": log.response_time_ms,
            "bytes_transferred": log.bytes_transferred,
            "accessed_at": log.accessed_at,
            "details": log.details
        })

    return result
