from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

"""
File management Pydantic schemas for request/response validation.
"""


class FileTypeEnum(str, Enum):
    """Supported file types."""

    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    DATA = "data"
    CODE = "code"
    VIDEO = "video"
    AUDIO = "audio"
    OTHER = "other"


class FileActionEnum(str, Enum):
    """File actions for logging."""

    UPLOAD = "upload"
    DOWNLOAD = "download"
    VIEW = "view"
    SHARE = "share"
    DELETE = "delete"
    UPDATE = "update"
    SCAN = "scan"


class ThreatLevelEnum(str, Enum):
    """Security threat levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Request Schemas
class FileUploadRequest(BaseModel):
    """File upload request schema."""

    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = Field(default_factory=list)
    category_id: Optional[int] = None
    is_public: bool = False
    auto_extract_metadata: bool = True


class FileUpdateRequest(BaseModel):
    """File update request schema."""

    filename: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = None
    category_id: Optional[int] = None
    is_public: Optional[bool] = None


class FileShareRequest(BaseModel):
    """File sharing request schema."""

    user_id: int
    can_download: bool = True
    can_view: bool = True
    can_share: bool = False
    expires_in_hours: Optional[int] = Field(None, ge=1, le=8760)  # Max 1 year


class FileBulkActionRequest(BaseModel):
    """Bulk file action request schema."""

    file_ids: List[int] = Field(..., min_items=1, max_items=100)
    action: FileActionEnum
    parameters: Optional[Dict[str, Any]] = None


# Response Schemas
class FileUploadResponse(BaseModel):
    """File upload response schema."""

    id: int
    filename: str
    size: int
    file_hash: Optional[str] = None
    mime_type: Optional[str] = None
    upload_date: datetime
    message: str = "File uploaded successfully"


class FileInfoResponse(BaseModel):
    """File information response schema."""

    id: int
    filename: str
    original_filename: str
    size: int
    mime_type: Optional[str] = None
    extension: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_public: bool
    uploaded_by: int
    upload_date: datetime
    last_accessed: Optional[datetime] = None
    download_count: int = 0
    view_count: int = 0
    is_active: bool = True
    is_quarantined: bool = False


class FileListResponse(BaseModel):
    """File list response schema."""

    files: List[FileInfoResponse]
    total: int
    page: int
    limit: int
    has_more: bool
    filters_applied: Optional[Dict[str, Any]] = None


class FileShareResponse(BaseModel):
    """File share response schema."""

    id: int
    file_id: int
    shared_with: int
    can_download: bool
    can_view: bool
    can_share: bool
    expires_at: Optional[datetime] = None
    created_at: datetime
    is_active: bool


class FileVersionResponse(BaseModel):
    """File version response schema."""

    id: int
    version_number: int
    size: int
    file_hash: str
    change_description: Optional[str] = None
    uploaded_by: int
    upload_date: datetime
    is_current: bool
    is_active: bool


class FileStatsResponse(BaseModel):
    """File statistics response schema."""

    total_files: int
    total_size: int
    files_by_type: Dict[str, int]
    files_by_user: Dict[str, int]
    recent_uploads: List[FileInfoResponse]
    most_downloaded: List[FileInfoResponse]
    storage_usage: Dict[str, Any]


class FileQuotaResponse(BaseModel):
    """File quota response schema."""

    user_id: int
    max_storage_bytes: int
    max_files: int
    max_file_size: int
    used_storage_bytes: int
    used_files: int
    storage_percentage: float
    files_percentage: float
    quota_exceeded: bool
    warnings: List[str] = Field(default_factory=list)


class FileScanResponse(BaseModel):
    """File scan result response schema."""

    id: int
    file_id: int
    scan_type: str
    scanner_name: str
    is_clean: bool
    threat_level: ThreatLevelEnum
    threats_found: List[str] = Field(default_factory=list)
    scan_details: Dict[str, Any] = Field(default_factory=dict)
    scanned_at: datetime
    scan_status: str


class FileAccessLogResponse(BaseModel):
    """File access log response schema."""

    id: int
    file_id: int
    user_id: int
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    accessed_at: datetime
    success: bool
    error_message: Optional[str] = None


class FileBackupResponse(BaseModel):
    """File backup response schema."""

    id: int
    file_id: int
    backup_type: str
    size: int
    checksum: str
    compression_ratio: Optional[float] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    backup_status: str
    error_message: Optional[str] = None


class FileCategoryResponse(BaseModel):
    """File category response schema."""

    id: int
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    icon: Optional[str] = None
    parent_id: Optional[int] = None
    allowed_extensions: List[str] = Field(default_factory=list)
    max_file_size: Optional[int] = None
    is_active: bool


class FileTagResponse(BaseModel):
    """File tag response schema."""

    id: int
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    usage_count: int
    created_at: datetime
    last_used: Optional[datetime] = None
    is_active: bool


# Utility Schemas
class FileSearchRequest(BaseModel):
    """File search request schema."""

    query: Optional[str] = None
    file_type: Optional[FileTypeEnum] = None
    tags: Optional[List[str]] = None
    category_id: Optional[int] = None
    uploaded_by: Optional[int] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    min_size: Optional[int] = Field(None, ge=0)
    max_size: Optional[int] = Field(None, ge=0)
    is_public: Optional[bool] = None
    sort_by: Optional[str] = Field(
        "upload_date", regex="^(filename|size|upload_date|download_count)$"
    )
    sort_order: Optional[str] = Field("desc", regex="^(asc|desc)$")
    page: int = Field(1, ge=1)
    limit: int = Field(20, ge=1, le=100)

    @validator("max_size")
    def validate_size_range(cls, v, values):
        if v is not None and "min_size" in values and values["min_size"] is not None:
            if v < values["min_size"]:
                raise ValueError("max_size must be greater than min_size")
        return v


class FileBulkOperationResponse(BaseModel):
    """Bulk file operation response schema."""

    total_requested: int
    successful: int
    failed: int
    results: List[Dict[str, Any]]
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class FileHealthCheckResponse(BaseModel):
    """File system health check response."""

    total_files: int
    active_files: int
    quarantined_files: int
    missing_files: int
    corrupted_files: int
    total_storage_used: int
    storage_health: str
    last_check: datetime
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


# Configuration Schemas
class FileSystemConfigResponse(BaseModel):
    """File system configuration response."""

    max_file_size: int
    allowed_extensions: Dict[str, List[str]]
    upload_directory: str
    backup_enabled: bool
    virus_scanning_enabled: bool
    auto_thumbnail_generation: bool
    quota_enforcement: bool
    default_quota_gb: int
    retention_policy_days: Optional[int] = None
