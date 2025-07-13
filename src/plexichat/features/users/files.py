import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, Relationship, SQLModel



from sqlalchemy import DateTime, Index, Text

"""
File management database models.
"""

class FilePermissionType(str, Enum):
    """File permission types."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SHARE = "share"
    ADMIN = "admin"


class FileAccessLevel(str, Enum):
    """File access levels."""
    PRIVATE = "private"  # Only owner
    SHARED = "shared"    # Specific users/groups
    PUBLIC = "public"    # Everyone
    RESTRICTED = "restricted"  # Requires approval

class FileRecord(SQLModel, table=True):
    """Enhanced file record model with comprehensive metadata and permissions."""
    __tablename__ = "files"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    filename: str = Field(max_length=255, index=True)
    original_filename: str = Field(max_length=255)
    file_path: str = Field(max_length=500)
    file_hash: str = Field(max_length=64, index=True, unique=True)
    size: int = Field(ge=0)
    mime_type: Optional[str] = Field(max_length=100)
    extension: str = Field(max_length=10, index=True)

    # Metadata and description
    description: Optional[str] = Field(sa_column=Column(Text))
    tags: List[str] = Field(default=[], sa_column=Column(JSON))
    metadata: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))

    # Enhanced access control
    access_level: FileAccessLevel = Field(default=FileAccessLevel.PRIVATE, index=True)
    is_public: bool = Field(default=False, index=True)  # Kept for backward compatibility
    uploaded_by: int = Field(foreign_key="users.id", index=True)

    # Permission settings
    allow_public_read: bool = Field(default=False)
    allow_public_download: bool = Field(default=False)
    require_approval: bool = Field(default=False)
    max_downloads: Optional[int] = Field(default=None)
    download_count: int = Field(default=0)
    
    # Timestamps
    upload_date: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    last_accessed: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Usage statistics
    download_count: int = Field(default=0)
    view_count: int = Field(default=0)
    
    # Status
    is_active: bool = Field(default=True, index=True)
    is_quarantined: bool = Field(default=False)
    quarantine_reason: Optional[str] = Field(max_length=500)
    
    # Relationships
    shares: List["FileShare"] = Relationship(back_populates="file")
    versions: List["FileVersion"] = Relationship(back_populates="file")
    permissions: List["FilePermission"] = Relationship(back_populates="file")
    access_logs: List["FileAccessLog"] = Relationship(back_populates="file")


class FilePermission(SQLModel, table=True):
    """Granular file permissions for users and groups."""
    __tablename__ = "file_permissions"

    id: Optional[int] = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="files.id", index=True)

    # Permission target (user or group)
    user_id: Optional[int] = Field(foreign_key="users.id", index=True)
    group_id: Optional[int] = Field(default=None, index=True)  # For future group support

    # Permission types
    can_read: bool = Field(default=True)
    can_write: bool = Field(default=False)
    can_delete: bool = Field(default=False)
    can_share: bool = Field(default=False)
    can_admin: bool = Field(default=False)  # Can modify permissions

    # Access restrictions
    max_downloads: Optional[int] = Field(default=None)
    download_count: int = Field(default=0)
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Metadata
    granted_by: int = Field(foreign_key="users.id", index=True)
    granted_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    revoked_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    is_active: bool = Field(default=True, index=True)

    # Relationships
    file: Optional[FileRecord] = Relationship(back_populates="permissions")

    # Indexes
    __table_args__ = (
        Index('idx_file_permission_user', 'file_id', 'user_id'),
        Index('idx_file_permission_active', 'is_active', 'expires_at'),
    )

class FileShare(SQLModel, table=True):
    """Enhanced file sharing model with comprehensive access control."""
    __tablename__ = "file_shares"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    file_id: int = Field(foreign_key="files.id", index=True)
    shared_by: int = Field(foreign_key="users.id", index=True)
    shared_with: int = Field(foreign_key="users.id", index=True)

    # Enhanced permissions
    can_download: bool = Field(default=True)
    can_view: bool = Field(default=True)
    can_share: bool = Field(default=False)
    can_comment: bool = Field(default=False)
    can_edit_metadata: bool = Field(default=False)

    # Access restrictions
    max_downloads: Optional[int] = Field(default=None)
    download_count: int = Field(default=0)
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Share settings
    share_message: Optional[str] = Field(sa_column=Column(Text))
    require_password: bool = Field(default=False)
    password_hash: Optional[str] = Field(max_length=255)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    accessed_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    last_downloaded_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Status
    is_active: bool = Field(default=True, index=True)
    revoked_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Status
    is_active: bool = Field(default=True, index=True)

    # Relationships
    file: Optional[FileRecord] = Relationship(back_populates="shares")

    # Indexes
    __table_args__ = (
        Index('idx_file_share_active', 'is_active', 'expires_at'),
        Index('idx_file_share_user', 'shared_with', 'is_active'),
    )

class FileVersion(SQLModel, table=True):
    """File version tracking for updates."""
    __tablename__ = "file_versions"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="files.id", index=True)
    version_number: int = Field(ge=1)
    file_path: str = Field(max_length=500)
    file_hash: str = Field(max_length=64, index=True)
    size: int = Field(ge=0)
    
    # Change information
    change_description: Optional[str] = Field(sa_column=Column(Text))
    uploaded_by: int = Field(foreign_key="users.id", index=True)
    upload_date: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    
    # Status
    is_current: bool = Field(default=False, index=True)
    is_active: bool = Field(default=True, index=True)
    
    # Relationships
    file: Optional[FileRecord] = Relationship(back_populates="versions")

class FileCategory(SQLModel, table=True):
    """File categories for organization."""
    __tablename__ = "file_categories"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=100, unique=True, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))
    color: Optional[str] = Field(max_length=7)  # Hex color code
    icon: Optional[str] = Field(max_length=50)
    
    # Hierarchy
    parent_id: Optional[int] = Field(foreign_key="file_categories.id")
    
    # Configuration
    allowed_extensions: List[str] = Field(default=[], sa_column=Column(JSON))
    max_file_size: Optional[int] = Field(ge=0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Status
    is_active: bool = Field(default=True, index=True)

class FileTag(SQLModel, table=True):
    """File tags for flexible categorization."""
    __tablename__ = "file_tags"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=50, unique=True, index=True)
    description: Optional[str] = Field(max_length=200)
    color: Optional[str] = Field(max_length=7)  # Hex color code
    
    # Usage statistics
    usage_count: int = Field(default=0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    last_used: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Status
    is_active: bool = Field(default=True, index=True)

class FileAccessLog(SQLModel, table=True):
    """Enhanced file access logging for comprehensive audit trails."""
    __tablename__ = "file_access_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="files.id", index=True)
    user_id: Optional[int] = Field(foreign_key="users.id", index=True)  # Optional for anonymous access

    # Access details
    action: str = Field(max_length=50, index=True)  # download, view, share, delete, etc.
    ip_address: Optional[str] = Field(max_length=45)
    user_agent: Optional[str] = Field(max_length=500)

    # Enhanced context
    details: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    success: bool = Field(default=True, index=True)
    error_message: Optional[str] = Field(sa_column=Column(Text))

    # Permission context
    permission_source: Optional[str] = Field(max_length=50)  # 'owner', 'share', 'public', 'permission'
    share_id: Optional[int] = Field(foreign_key="file_shares.id")

    # Performance metrics
    response_time_ms: Optional[int] = Field(ge=0)
    bytes_transferred: Optional[int] = Field(ge=0)

    # Timestamp
    accessed_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)

    # Relationships
    file: Optional[FileRecord] = Relationship(back_populates="access_logs")

    # Indexes
    __table_args__ = (
        Index('idx_file_access_user_time', 'user_id', 'accessed_at'),
        Index('idx_file_access_action_time', 'action', 'accessed_at'),
        Index('idx_file_access_success', 'success', 'accessed_at'),
    )
    
    # Status
    success: bool = Field(default=True, index=True)
    error_message: Optional[str] = Field(max_length=500)

class FileQuota(SQLModel, table=True):
    """User file quotas and usage tracking."""
    __tablename__ = "file_quotas"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", unique=True, index=True)
    
    # Quota limits
    max_storage_bytes: int = Field(default=1024*1024*1024)  # 1GB default
    max_files: int = Field(default=1000)
    max_file_size: int = Field(default=100*1024*1024)  # 100MB default
    
    # Current usage
    used_storage_bytes: int = Field(default=0)
    used_files: int = Field(default=0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))
    updated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Status
    is_active: bool = Field(default=True, index=True)
    quota_exceeded: bool = Field(default=False, index=True)

class FileBackup(SQLModel, table=True):
    """File backup tracking."""
    __tablename__ = "file_backups"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="files.id", index=True)
    backup_path: str = Field(max_length=500)
    backup_type: str = Field(max_length=50, index=True)  # full, incremental, differential
    
    # Backup details
    size: int = Field(ge=0)
    checksum: str = Field(max_length=64)
    compression_ratio: Optional[float] = Field(ge=0.0, le=1.0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Status
    is_active: bool = Field(default=True, index=True)
    backup_status: str = Field(default="completed", max_length=50, index=True)
    error_message: Optional[str] = Field(max_length=500)

class FileScanResult(SQLModel, table=True):
    """File security scan results."""
    __tablename__ = "file_scan_results"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    file_id: int = Field(foreign_key="files.id", index=True)
    
    # Scan details
    scan_type: str = Field(max_length=50, index=True)  # virus, malware, content, etc.
    scanner_name: str = Field(max_length=100)
    scanner_version: str = Field(max_length=50)
    
    # Results
    is_clean: bool = Field(index=True)
    threat_level: str = Field(default="none", max_length=20, index=True)  # none, low, medium, high, critical
    threats_found: List[str] = Field(default=[], sa_column=Column(JSON))
    scan_details: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    
    # Timestamps
    scanned_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime), index=True)
    
    # Status
    scan_status: str = Field(default="completed", max_length=50, index=True)
    error_message: Optional[str] = Field(max_length=500)
