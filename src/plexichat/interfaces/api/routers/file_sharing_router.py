"""
Enhanced File Sharing API Router

Provides REST API endpoints for advanced file sharing features:
- File upload with drag-and-drop support
- File sharing and permissions management
- File versioning
- File previews
- Batch operations
"""

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from plexichat.core.auth.fastapi_adapter import get_current_user
from plexichat.core.files import get_file_data, get_file_metadata
from plexichat.core.files import upload_file as core_upload_file
from plexichat.core.files.enhanced_file_sharing import (
    batch_delete_files,
    check_file_access,
    create_file_version,
    get_file_versions,
    get_user_files,
    share_file,
)

logger = logging.getLogger(__name__)

# Router
file_sharing_router = APIRouter(prefix="/files", tags=["File Sharing"])


# Pydantic models
class FileShareRequest(BaseModel):
    """Request model for sharing a file."""

    shared_with: list[int] = Field(..., description="List of user IDs to share with")
    can_download: bool = Field(
        True, description="Whether shared users can download the file"
    )
    can_share: bool = Field(
        True, description="Whether shared users can share the file further"
    )


class FileVersionRequest(BaseModel):
    """Request model for creating a file version."""

    filename: str = Field(..., description="Name of the new version file")


class BatchDeleteRequest(BaseModel):
    """Request model for batch file deletion."""

    file_ids: list[str] = Field(..., description="List of file IDs to delete")


class FileMetadataResponse(BaseModel):
    """Response model for file metadata."""

    file_id: str
    filename: str
    original_filename: str
    file_path: str
    file_size: int
    content_type: str
    checksum: str
    uploaded_by: int
    uploaded_at: str
    is_public: bool
    tags: list[str]
    metadata: dict[str, Any]
    sharing_permissions: dict[str, Any]
    version: int
    parent_version_id: str | None
    preview_path: str | None
    thumbnail_path: str | None


# File sharing endpoints
@file_sharing_router.post("/upload", response_model=FileMetadataResponse)
async def upload_file_enhanced(
    file: UploadFile = File(...),
    tags: str | None = Form(None),
    is_public: bool = Form(False),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """
    Upload a file with enhanced features.

    Supports drag-and-drop uploads and automatic preview generation.
    """
    try:
        # Read file content
        file_content = await file.read()

        # Parse tags
        tag_list = []
        if tags:
            try:
                tag_list = json.loads(tags)
            except json.JSONDecodeError:
                tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]

        # Get current user ID from authenticated user
        user_id = current_user.get("user_id") or current_user.get("id")

        # Upload file using core functionality
        metadata = await core_upload_file(
            file_data=file_content,
            filename=file.filename,
            uploaded_by=user_id,
            content_type=file.content_type,
            is_public=is_public,
            tags=tag_list,
        )

        if not metadata:
            raise HTTPException(status_code=500, detail="Failed to upload file")

        # Convert to response model
        response = FileMetadataResponse(
            file_id=metadata.file_id,
            filename=metadata.filename,
            original_filename=metadata.original_filename,
            file_path=metadata.file_path,
            file_size=metadata.file_size,
            content_type=metadata.content_type,
            checksum=metadata.checksum,
            uploaded_by=metadata.uploaded_by,
            uploaded_at=metadata.uploaded_at.isoformat(),
            is_public=metadata.is_public,
            tags=metadata.tags,
            metadata=metadata.metadata,
            sharing_permissions=metadata.sharing_permissions,
            version=metadata.version,
            parent_version_id=metadata.parent_version_id,
            preview_path=metadata.preview_path,
            thumbnail_path=metadata.thumbnail_path,
        )

        return response

    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {e!s}")


@file_sharing_router.post("/{file_id}/share")
async def share_file_endpoint(
    file_id: str,
    share_request: FileShareRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Share a file with specific users."""
    try:
        user_id = current_user.get("user_id") or current_user.get("id")

        success = await share_file(
            file_id=file_id,
            user_id=user_id,
            shared_with=share_request.shared_with,
            can_download=share_request.can_download,
            can_share=share_request.can_share,
        )

        if not success:
            raise HTTPException(status_code=400, detail="Failed to share file")

        return {
            "message": "File shared successfully",
            "file_id": file_id,
            "shared_with": share_request.shared_with,
        }

    except Exception as e:
        logger.error(f"Error sharing file: {e}")
        raise HTTPException(status_code=500, detail=f"Share failed: {e!s}")


@file_sharing_router.post("/{file_id}/version", response_model=FileMetadataResponse)
async def create_file_version_endpoint(
    file_id: str,
    file: UploadFile = File(...),
    filename: str | None = Form(None),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Create a new version of an existing file."""
    try:
        # Read file content
        file_content = await file.read()

        # Use provided filename or original filename
        version_filename = filename or file.filename

        user_id = current_user.get("user_id") or current_user.get("id")

        metadata = await create_file_version(
            file_id=file_id,
            user_id=user_id,
            new_file_data=file_content,
            filename=version_filename,
        )

        if not metadata:
            raise HTTPException(status_code=400, detail="Failed to create file version")

        # Convert to response model
        response = FileMetadataResponse(
            file_id=metadata.file_id,
            filename=metadata.filename,
            original_filename=metadata.original_filename,
            file_path=metadata.file_path,
            file_size=metadata.file_size,
            content_type=metadata.content_type,
            checksum=metadata.checksum,
            uploaded_by=metadata.uploaded_by,
            uploaded_at=metadata.uploaded_at.isoformat(),
            is_public=metadata.is_public,
            tags=metadata.tags,
            metadata=metadata.metadata,
            sharing_permissions=metadata.sharing_permissions,
            version=metadata.version,
            parent_version_id=metadata.parent_version_id,
            preview_path=metadata.preview_path,
            thumbnail_path=metadata.thumbnail_path,
        )

        return response

    except Exception as e:
        logger.error(f"Error creating file version: {e}")
        raise HTTPException(status_code=500, detail=f"Version creation failed: {e!s}")


@file_sharing_router.get(
    "/{file_id}/versions", response_model=list[FileMetadataResponse]
)
async def get_file_versions_endpoint(
    file_id: str, current_user: dict[str, Any] = Depends(get_current_user)
):
    """Get all versions of a file."""
    try:
        versions = await get_file_versions(file_id)

        # Convert to response models
        response_versions = []
        for metadata in versions:
            response = FileMetadataResponse(
                file_id=metadata.file_id,
                filename=metadata.filename,
                original_filename=metadata.original_filename,
                file_path=metadata.file_path,
                file_size=metadata.file_size,
                content_type=metadata.content_type,
                checksum=metadata.checksum,
                uploaded_by=metadata.uploaded_by,
                uploaded_at=metadata.uploaded_at.isoformat(),
                is_public=metadata.is_public,
                tags=metadata.tags,
                metadata=metadata.metadata,
                sharing_permissions=metadata.sharing_permissions,
                version=metadata.version,
                parent_version_id=metadata.parent_version_id,
                preview_path=metadata.preview_path,
                thumbnail_path=metadata.thumbnail_path,
            )
            response_versions.append(response)

        return response_versions

    except Exception as e:
        logger.error(f"Error getting file versions: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get versions: {e!s}")


@file_sharing_router.get("/{file_id}/download")
async def download_file(
    file_id: str, current_user: dict[str, Any] = Depends(get_current_user)
):
    """Download a file with access control."""
    try:
        user_id = current_user.get("user_id") or current_user.get("id")

        # Check access
        has_access, access_message = await check_file_access(file_id, user_id)
        if not has_access:
            raise HTTPException(status_code=403, detail=access_message)

        # Get file metadata
        metadata = await get_file_metadata(file_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="File not found")

        # Check download permissions
        permissions = metadata.sharing_permissions
        if not permissions.get("can_download", True):
            raise HTTPException(status_code=403, detail="Download not permitted")

        # Get file data
        file_data = await get_file_data(file_id)
        if not file_data:
            raise HTTPException(status_code=404, detail="File data not found")

        # Return file as streaming response
        return StreamingResponse(
            iter([file_data]),
            media_type=metadata.content_type,
            headers={
                "Content-Disposition": f"attachment; filename={metadata.original_filename}"
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {e!s}")


@file_sharing_router.get("/{file_id}/preview")
async def get_file_preview(
    file_id: str, current_user: dict[str, Any] = Depends(get_current_user)
):
    """Get file preview (thumbnail or small version)."""
    try:
        user_id = current_user.get("user_id") or current_user.get("id")

        # Check access
        has_access, access_message = await check_file_access(file_id, user_id)
        if not has_access:
            raise HTTPException(status_code=403, detail=access_message)

        # Get file metadata
        metadata = await get_file_metadata(file_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="File not found")

        # Try to get thumbnail first, then preview
        preview_path = metadata.thumbnail_path or metadata.preview_path

        if not preview_path:
            raise HTTPException(status_code=404, detail="Preview not available")

        # Read preview file
        from pathlib import Path

        preview_file = Path(preview_path)
        if not preview_file.exists():
            raise HTTPException(status_code=404, detail="Preview file not found")

        with open(preview_file, "rb") as f:
            preview_data = f.read()

        return StreamingResponse(iter([preview_data]), media_type=metadata.content_type)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting file preview: {e}")
        raise HTTPException(status_code=500, detail=f"Preview failed: {e!s}")


@file_sharing_router.delete("/batch")
async def batch_delete_files_endpoint(
    delete_request: BatchDeleteRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Delete multiple files in batch."""
    try:
        user_id = current_user.get("user_id") or current_user.get("id")

        results = await batch_delete_files(
            file_ids=delete_request.file_ids, user_id=user_id
        )

        return {"message": "Batch delete completed", "results": results}

    except Exception as e:
        logger.error(f"Error in batch delete: {e}")
        raise HTTPException(status_code=500, detail=f"Batch delete failed: {e!s}")


@file_sharing_router.get("/my-files", response_model=list[FileMetadataResponse])
async def get_user_files_endpoint(
    include_shared: bool = Query(True),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    """Get all files for the current user."""
    try:
        user_id = current_user.get("user_id") or current_user.get("id")

        files = await get_user_files(user_id=user_id, include_shared=include_shared)

        # Convert to response models
        response_files = []
        for metadata in files:
            response = FileMetadataResponse(
                file_id=metadata.file_id,
                filename=metadata.filename,
                original_filename=metadata.original_filename,
                file_path=metadata.file_path,
                file_size=metadata.file_size,
                content_type=metadata.content_type,
                checksum=metadata.checksum,
                uploaded_by=metadata.uploaded_by,
                uploaded_at=metadata.uploaded_at.isoformat(),
                is_public=metadata.is_public,
                tags=metadata.tags,
                metadata=metadata.metadata,
                sharing_permissions=metadata.sharing_permissions,
                version=metadata.version,
                parent_version_id=metadata.parent_version_id,
                preview_path=metadata.preview_path,
                thumbnail_path=metadata.thumbnail_path,
            )
            response_files.append(response)

        return response_files

    except Exception as e:
        logger.error(f"Error getting user files: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get files: {e!s}")


# Export router for compatibility
router = file_sharing_router
logger.info("[CHECK] Enhanced file sharing router initialized with all endpoints")
