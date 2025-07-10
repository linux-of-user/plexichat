# app/models/enhanced_models.py
"""
Enhanced database models with improved structure, relationships, 
indexing, and additional features for production use.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid
import json

from sqlmodel import SQLModel, Field, Relationship, Column, Index, Text, JSON
from sqlalchemy import DateTime, String, Boolean, Integer, Float, LargeBinary
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func


class UserStatus(str, Enum):
    """User account status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"
    DELETED = "deleted"


class AccountType(str, Enum):
    """Account type enumeration."""
    USER = "user"
    BOT = "bot"
    ADMIN = "admin"
    SERVICE = "service"


class BotType(str, Enum):
    """Bot type enumeration for different bot categories."""
    GENERAL = "general"
    MODERATION = "moderation"
    UTILITY = "utility"
    INTEGRATION = "integration"
    CUSTOM = "custom"


class PermissionLevel(str, Enum):
    """Permission level enumeration."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    OWNER = "owner"


class MessageStatus(str, Enum):
    """Message status enumeration."""
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
    DELETED = "deleted"


class MessageType(str, Enum):
    """Message type enumeration."""
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"
    ENCRYPTED = "encrypted"


class SessionStatus(str, Enum):
    """Session status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuditAction(str, Enum):
    """Audit log action enumeration."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    PASSWORD_CHANGE = "password_change"
    PERMISSION_CHANGE = "permission_change"


# Enhanced User Model
class EnhancedUser(SQLModel, table=True):
    """Enhanced user model with comprehensive features."""
    
    __tablename__ = "users_enhanced"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    username: str = Field(max_length=50, unique=True, index=True)
    email: str = Field(max_length=254, unique=True, index=True)
    password_hash: str = Field(max_length=255)

    # Account type and bot features
    account_type: AccountType = Field(default=AccountType.USER, index=True)
    bot_type: Optional[BotType] = Field(default=None, index=True)
    bot_owner_id: Optional[int] = Field(default=None, foreign_key="users_enhanced.id")
    bot_token: Optional[str] = Field(default=None, max_length=255)  # API token for bots
    bot_permissions: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    bot_rate_limits: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    bot_webhook_url: Optional[str] = Field(default=None, max_length=500)
    bot_description: Optional[str] = Field(default=None, max_length=1000)
    bot_verified: bool = Field(default=False, index=True)
    
    # Enhanced Profile information
    display_name: Optional[str] = Field(default=None, max_length=100)
    first_name: Optional[str] = Field(default=None, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=500)
    profile_picture_file_id: Optional[int] = Field(default=None, foreign_key="files.id")
    banner_url: Optional[str] = Field(default=None, max_length=500)
    banner_file_id: Optional[int] = Field(default=None, foreign_key="files.id")
    bio: Optional[str] = Field(default=None, max_length=2000)
    website: Optional[str] = Field(default=None, max_length=500)
    location: Optional[str] = Field(default=None, max_length=100)
    birth_date: Optional[datetime] = Field(default=None)

    # Enhanced User tags and labels
    tags: List[str] = Field(default=[], sa_column=Column(JSON))
    custom_status: Optional[str] = Field(default=None, max_length=200)
    status_emoji: Optional[str] = Field(default=None, max_length=10)
    pronouns: Optional[str] = Field(default=None, max_length=50)

    # Social and activity features
    social_links: Optional[Dict[str, str]] = Field(default=None, sa_column=Column(JSON))
    interests: List[str] = Field(default=[], sa_column=Column(JSON))
    skills: List[str] = Field(default=[], sa_column=Column(JSON))
    badges: List[str] = Field(default=[], sa_column=Column(JSON))
    achievements: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))

    # Privacy and visibility settings
    profile_visibility: str = Field(default="public", max_length=20)  # public, friends, private
    show_online_status: bool = Field(default=True)
    show_activity: bool = Field(default=True)
    allow_friend_requests: bool = Field(default=True)
    allow_direct_messages: bool = Field(default=True)
    
    # Contact information
    phone_number: Optional[str] = Field(default=None, max_length=20)
    timezone: Optional[str] = Field(default="UTC", max_length=50)
    language: Optional[str] = Field(default="en", max_length=10)
    
    # Security fields
    public_key: Optional[str] = Field(default=None, sa_column=Column(Text))
    private_key_encrypted: Optional[str] = Field(default=None, sa_column=Column(Text))
    two_factor_secret: Optional[str] = Field(default=None, max_length=255)
    two_factor_enabled: bool = Field(default=False)
    backup_codes: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Status and permissions
    status: UserStatus = Field(default=UserStatus.ACTIVE, index=True)
    is_admin: bool = Field(default=False, index=True)
    is_verified: bool = Field(default=False, index=True)
    permissions: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: Optional[datetime] = Field(default=None, index=True)
    last_activity_at: Optional[datetime] = Field(default=None, index=True)
    email_verified_at: Optional[datetime] = Field(default=None)
    password_changed_at: Optional[datetime] = Field(default=None)
    
    # Soft delete
    deleted_at: Optional[datetime] = Field(default=None, index=True)
    
    # Statistics
    login_count: int = Field(default=0)
    message_count: int = Field(default=0)
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Relationships
    sent_messages: List["EnhancedMessage"] = Relationship(
        back_populates="sender",
        sa_relationship_kwargs={"foreign_keys": "EnhancedMessage.sender_id"}
    )
    received_messages: List["EnhancedMessage"] = Relationship(
        back_populates="recipient",
        sa_relationship_kwargs={"foreign_keys": "EnhancedMessage.recipient_id"}
    )
    sessions: List["UserSession"] = Relationship(back_populates="user")
    audit_logs: List["AuditLog"] = Relationship(back_populates="user")

    # Bot relationships
    owned_bots: List["EnhancedUser"] = Relationship(
        back_populates="bot_owner",
        sa_relationship_kwargs={"foreign_keys": "EnhancedUser.bot_owner_id"}
    )
    bot_owner: Optional["EnhancedUser"] = Relationship(
        back_populates="owned_bots",
        sa_relationship_kwargs={"remote_side": "EnhancedUser.id"}
    )
    bot_account: Optional["BotAccount"] = Relationship(back_populates="user")

    # Indexes
    __table_args__ = (
        Index('idx_users_status_created', 'status', 'created_at'),
        Index('idx_users_email_status', 'email', 'status'),
        Index('idx_users_last_activity', 'last_activity_at'),
    )


# Bot Account Management
class BotAccount(SQLModel, table=True):
    """Specialized bot account management with advanced features and regulation."""

    __tablename__ = "bot_accounts"

    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users_enhanced.id", unique=True, index=True)
    bot_token: str = Field(max_length=255, unique=True, index=True)
    bot_secret: str = Field(max_length=255)  # For webhook verification

    # Bot configuration
    bot_type: BotType = Field(default=BotType.GENERAL, index=True)
    bot_name: str = Field(max_length=100)
    bot_description: str = Field(max_length=1000)
    bot_version: str = Field(default="1.0.0", max_length=20)
    bot_author: str = Field(max_length=100)
    bot_website: Optional[str] = Field(default=None, max_length=500)
    bot_support_url: Optional[str] = Field(default=None, max_length=500)

    # Permissions and regulation
    permissions: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    rate_limits: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    allowed_servers: List[str] = Field(default=[], sa_column=Column(JSON))  # Server UUIDs
    blocked_servers: List[str] = Field(default=[], sa_column=Column(JSON))
    allowed_channels: List[str] = Field(default=[], sa_column=Column(JSON))
    blocked_channels: List[str] = Field(default=[], sa_column=Column(JSON))

    # Advanced features
    webhook_url: Optional[str] = Field(default=None, max_length=500)
    webhook_secret: Optional[str] = Field(default=None, max_length=255)
    slash_commands: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    event_subscriptions: List[str] = Field(default=[], sa_column=Column(JSON))

    # Regulation and monitoring
    is_verified: bool = Field(default=False, index=True)
    is_public: bool = Field(default=False, index=True)
    is_approved: bool = Field(default=False, index=True)
    approval_notes: Optional[str] = Field(default=None, max_length=1000)
    violation_count: int = Field(default=0)
    last_violation_at: Optional[datetime] = Field(default=None)
    suspension_count: int = Field(default=0)
    last_suspension_at: Optional[datetime] = Field(default=None)

    # Usage statistics
    total_requests: int = Field(default=0)
    total_messages_sent: int = Field(default=0)
    total_commands_executed: int = Field(default=0)
    last_activity_at: Optional[datetime] = Field(default=None, index=True)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    approved_at: Optional[datetime] = Field(default=None)
    verified_at: Optional[datetime] = Field(default=None)

    # Relationships
    user: "EnhancedUser" = Relationship(back_populates="bot_account")

    # Indexes
    __table_args__ = (
        Index('idx_bot_accounts_type_verified', 'bot_type', 'is_verified'),
        Index('idx_bot_accounts_public_approved', 'is_public', 'is_approved'),
        Index('idx_bot_accounts_activity', 'last_activity_at'),
    )


# User Tag System
class UserTag(SQLModel, table=True):
    """User tags for categorization and organization."""
    __tablename__ = "user_tags"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=50, unique=True, index=True)
    description: Optional[str] = Field(max_length=200)
    color: Optional[str] = Field(max_length=7)  # Hex color code
    icon: Optional[str] = Field(max_length=50)  # Icon name or emoji

    # Tag metadata
    is_system: bool = Field(default=False)  # System-defined tags
    is_public: bool = Field(default=True)   # Visible to other users
    created_by: Optional[int] = Field(foreign_key="users_enhanced.id")

    # Usage statistics
    usage_count: int = Field(default=0)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Status
    is_active: bool = Field(default=True, index=True)


# Friend System Models
class FriendshipStatus(str, Enum):
    """Friendship status types."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    BLOCKED = "blocked"
    DECLINED = "declined"


class Friendship(SQLModel, table=True):
    """Friend relationships between users."""
    __tablename__ = "friendships"

    id: Optional[int] = Field(default=None, primary_key=True)
    requester_id: int = Field(foreign_key="users_enhanced.id", index=True)
    addressee_id: int = Field(foreign_key="users_enhanced.id", index=True)

    # Friendship details
    status: FriendshipStatus = Field(default=FriendshipStatus.PENDING, index=True)
    message: Optional[str] = Field(max_length=500)  # Friend request message

    # Timestamps
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    responded_at: Optional[datetime] = Field(default=None)

    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))

    # Indexes
    __table_args__ = (
        Index('idx_friendship_users', 'requester_id', 'addressee_id', unique=True),
        Index('idx_friendship_status', 'status', 'requested_at'),
    )


# Enhanced Message Model
class EnhancedMessage(SQLModel, table=True):
    """Enhanced message model with encryption and metadata support."""
    
    __tablename__ = "messages_enhanced"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # User relationships
    sender_id: int = Field(foreign_key="users_enhanced.id", index=True)
    recipient_id: int = Field(foreign_key="users_enhanced.id", index=True)
    
    # Message content
    content: str = Field(sa_column=Column(Text))
    content_encrypted: Optional[str] = Field(default=None, sa_column=Column(Text))
    content_type: MessageType = Field(default=MessageType.TEXT, index=True)
    
    # Message metadata
    subject: Optional[str] = Field(default=None, max_length=255)
    thread_id: Optional[str] = Field(default=None, max_length=255, index=True)
    reply_to_id: Optional[int] = Field(default=None, foreign_key="messages_enhanced.id")
    
    # Status and delivery
    status: MessageStatus = Field(default=MessageStatus.SENT, index=True)
    is_encrypted: bool = Field(default=False, index=True)
    encryption_algorithm: Optional[str] = Field(default=None, max_length=50)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    delivered_at: Optional[datetime] = Field(default=None, index=True)
    read_at: Optional[datetime] = Field(default=None, index=True)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    
    # Soft delete
    deleted_at: Optional[datetime] = Field(default=None, index=True)
    deleted_by_sender: bool = Field(default=False)
    deleted_by_recipient: bool = Field(default=False)
    
    # File attachments
    attachments: Optional[List[Dict[str, Any]]] = Field(default=None, sa_column=Column(JSON))
    file_size: Optional[int] = Field(default=None)
    
    # Message priority and flags
    priority: int = Field(default=0, index=True)  # 0=normal, 1=high, -1=low
    is_system_message: bool = Field(default=False, index=True)
    is_broadcast: bool = Field(default=False, index=True)
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Relationships
    sender: EnhancedUser = Relationship(
        back_populates="sent_messages",
        sa_relationship_kwargs={"foreign_keys": "EnhancedMessage.sender_id"}
    )
    recipient: EnhancedUser = Relationship(
        back_populates="received_messages",
        sa_relationship_kwargs={"foreign_keys": "EnhancedMessage.recipient_id"}
    )
    replies: List["EnhancedMessage"] = Relationship(
        back_populates="parent_message",
        sa_relationship_kwargs={"remote_side": "EnhancedMessage.id"}
    )
    parent_message: Optional["EnhancedMessage"] = Relationship(
        back_populates="replies",
        sa_relationship_kwargs={"remote_side": "EnhancedMessage.reply_to_id"}
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_messages_sender_created', 'sender_id', 'created_at'),
        Index('idx_messages_recipient_created', 'recipient_id', 'created_at'),
        Index('idx_messages_thread', 'thread_id', 'created_at'),
        Index('idx_messages_status_created', 'status', 'created_at'),
        Index('idx_messages_type_created', 'content_type', 'created_at'),
    )


# User Session Model
class UserSession(SQLModel, table=True):
    """User session tracking for security and analytics."""
    
    __tablename__ = "user_sessions"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(unique=True, index=True, max_length=255)
    user_id: int = Field(foreign_key="users_enhanced.id", index=True)
    
    # Session information
    status: SessionStatus = Field(default=SessionStatus.ACTIVE, index=True)
    ip_address: str = Field(max_length=45, index=True)  # IPv6 compatible
    user_agent: Optional[str] = Field(default=None, max_length=500)
    device_fingerprint: Optional[str] = Field(default=None, max_length=255)
    
    # Geographic information
    country: Optional[str] = Field(default=None, max_length=2)
    region: Optional[str] = Field(default=None, max_length=100)
    city: Optional[str] = Field(default=None, max_length=100)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    last_activity_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    expires_at: datetime = Field(index=True)
    revoked_at: Optional[datetime] = Field(default=None)
    
    # Session metadata
    login_method: Optional[str] = Field(default=None, max_length=50)  # password, 2fa, oauth, etc.
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Relationships
    user: EnhancedUser = Relationship(back_populates="sessions")
    
    # Indexes
    __table_args__ = (
        Index('idx_sessions_user_status', 'user_id', 'status'),
        Index('idx_sessions_ip_created', 'ip_address', 'created_at'),
        Index('idx_sessions_expires', 'expires_at'),
    )


# Audit Log Model
class AuditLog(SQLModel, table=True):
    """Comprehensive audit logging for security and compliance."""
    
    __tablename__ = "audit_logs"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # User and session information
    user_id: Optional[int] = Field(default=None, foreign_key="users_enhanced.id", index=True)
    session_id: Optional[str] = Field(default=None, max_length=255, index=True)
    
    # Action details
    action: AuditAction = Field(index=True)
    resource_type: str = Field(max_length=50, index=True)  # user, message, session, etc.
    resource_id: Optional[str] = Field(default=None, max_length=255, index=True)
    
    # Request information
    ip_address: str = Field(max_length=45, index=True)
    user_agent: Optional[str] = Field(default=None, max_length=500)
    endpoint: Optional[str] = Field(default=None, max_length=255)
    method: Optional[str] = Field(default=None, max_length=10)
    
    # Change tracking
    old_values: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    new_values: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Result and metadata
    success: bool = Field(default=True, index=True)
    error_message: Optional[str] = Field(default=None, max_length=1000)
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Timestamp
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    
    # Relationships
    user: Optional[EnhancedUser] = Relationship(back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_ip_created', 'ip_address', 'created_at'),
        Index('idx_audit_success_created', 'success', 'created_at'),
    )


# System Configuration Model
class SystemConfig(SQLModel, table=True):
    """System configuration storage with versioning."""
    
    __tablename__ = "system_config"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(unique=True, index=True, max_length=255)
    value: str = Field(sa_column=Column(Text))
    
    # Metadata
    description: Optional[str] = Field(default=None, max_length=1000)
    category: str = Field(default="general", max_length=50, index=True)
    data_type: str = Field(default="string", max_length=20)  # string, int, float, bool, json
    is_sensitive: bool = Field(default=False)
    is_readonly: bool = Field(default=False)
    
    # Versioning
    version: int = Field(default=1)
    previous_value: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_by: Optional[int] = Field(default=None, foreign_key="users_enhanced.id")
    
    # Indexes
    __table_args__ = (
        Index('idx_config_category_key', 'category', 'key'),
    )


# File Storage Model
class FileStorage(SQLModel, table=True):
    """File storage tracking and metadata."""
    
    __tablename__ = "file_storage"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # File information
    filename: str = Field(max_length=255, index=True)
    original_filename: str = Field(max_length=255)
    file_path: str = Field(max_length=1000)
    file_size: int = Field(index=True)
    mime_type: str = Field(max_length=100, index=True)
    file_hash: str = Field(max_length=255, unique=True, index=True)  # SHA-256
    
    # Ownership and access
    uploaded_by: int = Field(foreign_key="users_enhanced.id", index=True)
    is_public: bool = Field(default=False, index=True)
    access_count: int = Field(default=0)
    
    # Storage information
    storage_backend: str = Field(default="local", max_length=50)  # local, s3, etc.
    is_encrypted: bool = Field(default=False)
    encryption_key_id: Optional[str] = Field(default=None, max_length=255)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    last_accessed_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    
    # Soft delete
    deleted_at: Optional[datetime] = Field(default=None, index=True)
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Indexes
    __table_args__ = (
        Index('idx_files_user_created', 'uploaded_by', 'created_at'),
        Index('idx_files_type_size', 'mime_type', 'file_size'),
    )


# Rate Limiting Model
class RateLimit(SQLModel, table=True):
    """Rate limiting tracking and enforcement."""
    
    __tablename__ = "rate_limits"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    identifier: str = Field(max_length=255, index=True)  # IP, user_id, etc.
    identifier_type: str = Field(max_length=50, index=True)  # ip, user, api_key
    
    # Rate limiting information
    endpoint: str = Field(max_length=255, index=True)
    method: str = Field(max_length=10, index=True)
    request_count: int = Field(default=1)
    window_start: datetime = Field(index=True)
    window_end: datetime = Field(index=True)
    
    # Limits and status
    limit_per_window: int = Field(default=100)
    is_blocked: bool = Field(default=False, index=True)
    block_expires_at: Optional[datetime] = Field(default=None, index=True)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index('idx_ratelimit_identifier_endpoint', 'identifier', 'endpoint'),
        Index('idx_ratelimit_window', 'window_start', 'window_end'),
        Index('idx_ratelimit_blocked', 'is_blocked', 'block_expires_at'),
    )


# Notification Model
class Notification(SQLModel, table=True):
    """User notifications and alerts."""
    
    __tablename__ = "notifications"
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # User relationship
    user_id: int = Field(foreign_key="users_enhanced.id", index=True)
    
    # Notification content
    title: str = Field(max_length=255)
    message: str = Field(sa_column=Column(Text))
    notification_type: str = Field(max_length=50, index=True)  # info, warning, error, success
    category: str = Field(max_length=50, index=True)  # message, system, security, etc.
    
    # Status and delivery
    is_read: bool = Field(default=False, index=True)
    is_delivered: bool = Field(default=False, index=True)
    delivery_method: Optional[str] = Field(default=None, max_length=50)  # email, push, sms
    
    # Action and linking
    action_url: Optional[str] = Field(default=None, max_length=500)
    related_resource_type: Optional[str] = Field(default=None, max_length=50)
    related_resource_id: Optional[str] = Field(default=None, max_length=255)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    read_at: Optional[datetime] = Field(default=None)
    delivered_at: Optional[datetime] = Field(default=None)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    
    # Metadata
    metadata: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    # Indexes
    __table_args__ = (
        Index('idx_notifications_user_read', 'user_id', 'is_read'),
        Index('idx_notifications_type_created', 'notification_type', 'created_at'),
        Index('idx_notifications_category_created', 'category', 'created_at'),
    )
