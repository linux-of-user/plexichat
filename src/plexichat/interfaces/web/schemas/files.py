"""
File schemas for PlexiChat API.
Enhanced with comprehensive validation and security.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class FileType(str, Enum):
    """File type enumeration."""

    IMAGE = "image"
    DOCUMENT = "document"
    VIDEO = "video"
    AUDIO = "audio"
    ARCHIVE = "archive"
    OTHER = "other"


class FileStatus(str, Enum):
    """File status enumeration."""

    UPLOADING = "uploading"
    PROCESSING = "processing"
    READY = "ready"
    ERROR = "error"
    DELETED = "deleted"


class FileBase(BaseModel):
    """Base file schema."""

    filename: str = Field(
        ..., min_length=1, max_length=255, description="Original filename"
    )
    content_type: str = Field(..., description="MIME content type")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v):
        if not v.strip():
            raise ValueError("Filename cannot be empty")
        # Basic filename validation
        import re

        if re.search(r'[<>:"/\\|?*]', v):
            raise ValueError("Filename contains invalid characters")
        return v.strip()


class FileUpload(BaseModel):
    """File upload schema."""

    filename: str = Field(
        ..., min_length=1, max_length=255, description="Original filename"
    )
    content_type: str | None = Field(None, description="MIME content type")
    description: str | None = Field(
        None, max_length=500, description="File description"
    )
    tags: list[str] | None = Field(None, description="File tags")
    is_public: bool = Field(default=False, description="Public access flag")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v):
        if not v.strip():
            raise ValueError("Filename cannot be empty")
        import re

        if re.search(r'[<>:"/\\|?*]', v):
            raise ValueError("Filename contains invalid characters")
        return v.strip()

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        if v is not None:
            # Limit number of tags and tag length
            if len(v) > 10:
                raise ValueError("Maximum 10 tags allowed")
            for tag in v:
                if len(tag) > 50:
                    raise ValueError("Tag length cannot exceed 50 characters")
        return v


class FileResponse(FileBase):
    """File response schema."""

    id: int = Field(..., description="File ID")
    file_path: str = Field(..., description="File storage path")
    file_size: int = Field(..., description="File size in bytes")
    file_type: FileType = Field(..., description="File type category")
    status: FileStatus = Field(..., description="File processing status")
    user_id: int = Field(..., description="Owner user ID")
    upload_date: datetime = Field(..., description="Upload timestamp")
    last_accessed: datetime | None = Field(None, description="Last access timestamp")
    download_count: int = Field(default=0, description="Download count")
    is_public: bool = Field(default=False, description="Public access flag")
    description: str | None = Field(None, description="File description")
    tags: list[str] | None = Field(None, description="File tags")
    metadata: dict[str, Any] | None = Field(None, description="File metadata")

    class Config:
        from_attributes = True


class FileListResponse(BaseModel):
    """File list response schema."""

    files: list[FileResponse] = Field(..., description="List of files")
    total_count: int = Field(..., description="Total number of files")
    total_size: int = Field(..., description="Total size in bytes")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class FileUpdate(BaseModel):
    """File update schema."""

    filename: str | None = Field(
        None, min_length=1, max_length=255, description="Updated filename"
    )
    description: str | None = Field(
        None, max_length=500, description="Updated description"
    )
    tags: list[str] | None = Field(None, description="Updated tags")
    is_public: bool | None = Field(None, description="Updated public access flag")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError("Filename cannot be empty")
            import re

            if re.search(r'[<>:"/\\|?*]', v):
                raise ValueError("Filename contains invalid characters")
            return v.strip()
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        if v is not None:
            if len(v) > 10:
                raise ValueError("Maximum 10 tags allowed")
            for tag in v:
                if len(tag) > 50:
                    raise ValueError("Tag length cannot exceed 50 characters")
        return v


class FileSearch(BaseModel):
    """File search schema."""

    query: str | None = Field(
        None, min_length=1, max_length=100, description="Search query"
    )
    file_type: FileType | None = Field(None, description="Filter by file type")
    content_type: str | None = Field(None, description="Filter by content type")
    tags: list[str] | None = Field(None, description="Filter by tags")
    min_size: int | None = Field(None, ge=0, description="Minimum file size")
    max_size: int | None = Field(None, ge=0, description="Maximum file size")
    start_date: datetime | None = Field(None, description="Start date filter")
    end_date: datetime | None = Field(None, description="End date filter")
    is_public: bool | None = Field(None, description="Filter by public status")

    @field_validator("query")
    @classmethod
    def validate_query(cls, v):
        if v is not None and not v.strip():
            raise ValueError("Search query cannot be empty")
        return v.strip() if v else v


class FileStats(BaseModel):
    """File statistics schema."""

    total_files: int = Field(default=0, description="Total file count")
    total_size: int = Field(default=0, description="Total size in bytes")
    files_today: int = Field(default=0, description="Files uploaded today")
    files_this_week: int = Field(default=0, description="Files uploaded this week")
    files_this_month: int = Field(default=0, description="Files uploaded this month")
    average_file_size: float = Field(default=0.0, description="Average file size")
    file_types: dict[str, int] = Field(default={}, description="File count by type")
    storage_usage_mb: float = Field(default=0.0, description="Storage usage in MB")


class FileShare(BaseModel):
    """File sharing schema."""

    file_id: int = Field(..., description="File ID to share")
    share_with_users: list[int] | None = Field(
        None, description="User IDs to share with"
    )
    share_publicly: bool = Field(default=False, description="Make publicly accessible")
    expires_at: datetime | None = Field(None, description="Share expiration time")
    download_limit: int | None = Field(None, ge=1, description="Maximum download count")
    password: str | None = Field(None, min_length=4, description="Access password")


class FileShareResponse(BaseModel):
    """File share response schema."""

    share_id: str = Field(..., description="Unique share ID")
    share_url: str = Field(..., description="Share URL")
    expires_at: datetime | None = Field(None, description="Expiration time")
    download_count: int = Field(default=0, description="Current download count")
    download_limit: int | None = Field(None, description="Download limit")
    created_at: datetime = Field(..., description="Share creation time")
