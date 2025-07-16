# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlmodel import JSON, Column, Field, Relationship, SQLModel


from sqlalchemy import DateTime, Index, Text

"""
Voice and video calling models with end-to-end encryption.
Supports WebRTC, secure key exchange, and call management.
"""


class CallType(str, Enum):
    """Types of calls."""

    VOICE = "voice"
    VIDEO = "video"
    SCREEN_SHARE = "screen_share"
    GROUP_VOICE = "group_voice"
    GROUP_VIDEO = "group_video"


class CallStatus(str, Enum):
    """Call status states."""

    INITIATING = "initiating"
    RINGING = "ringing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ON_HOLD = "on_hold"
    ENDED = "ended"
    FAILED = "failed"
    DECLINED = "declined"
    MISSED = "missed"
    BUSY = "busy"


class EncryptionMethod(str, Enum):
    """Encryption methods for calls."""

    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    AES_128_GCM = "aes_128_gcm"


class CallSession(SQLModel, table=True):
    """Call session with end-to-end encryption."""

    __tablename__ = "call_sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Call identification
    call_id: str = Field(unique=True, index=True)
    call_type: CallType = Field(index=True)

    # Participants
    initiator_id: int = Field(foreign_key="users_enhanced.id", index=True)
    participants: List[int] = Field(default=[], sa_column=Column(JSON))
    max_participants: int = Field(default=2, ge=2, le=50)

    # Call status
    status: CallStatus = Field(default=CallStatus.INITIATING, index=True)

    # Encryption details
    encryption_method: EncryptionMethod = Field(default=EncryptionMethod.AES_256_GCM)
    master_key_hash: str = Field(max_length=128)  # Hashed master key
    session_keys: Dict[str, str] = Field(
        default={}, sa_column=Column(JSON)
    )  # Per-participant keys

    # WebRTC details
    ice_servers: List[Dict[str, Any]] = Field(default=[], sa_column=Column(JSON))
    stun_servers: List[str] = Field(default=[], sa_column=Column(JSON))
    turn_servers: List[Dict[str, str]] = Field(default=[], sa_column=Column(JSON))

    # Call quality settings
    video_quality: Optional[str] = Field(default="720p")  # 480p, 720p, 1080p, 4k
    audio_quality: Optional[str] = Field(default="high")  # low, medium, high
    bitrate_limit: Optional[int] = Field(default=None, ge=64, le=10000)  # kbps

    # Recording settings
    recording_enabled: bool = Field(default=False)
    recording_encrypted: bool = Field(default=True)
    recording_path: Optional[str] = Field(max_length=500)

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    started_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    ended_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Call metrics
    duration_seconds: Optional[int] = Field(default=0, ge=0)
    connection_quality: Optional[float] = Field(ge=0.0, le=1.0)  # 0-1 quality score
    packet_loss: Optional[float] = Field(ge=0.0, le=1.0)  # Packet loss percentage

    # Security features
    end_to_end_verified: bool = Field(default=False)
    security_warnings: List[str] = Field(default=[], sa_column=Column(JSON))

    # Call metadata
    metadata: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))

    # Relationships
    initiator: Optional["EnhancedUser"] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_call_session_status", "status", "created_at"),
        Index("idx_call_session_initiator", "initiator_id", "status"),
        Index("idx_call_session_type", "call_type", "status"),
    )


class CallParticipant(SQLModel, table=True):
    """Individual call participant details."""

    __tablename__ = "call_participants"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Participant details
    call_session_id: int = Field(foreign_key="call_sessions.id", index=True)
    user_id: int = Field(foreign_key="users_enhanced.id", index=True)

    # Connection details
    peer_id: str = Field(max_length=255, index=True)  # WebRTC peer ID
    connection_id: str = Field(max_length=255)

    # Participant status
    status: CallStatus = Field(default=CallStatus.CONNECTING, index=True)
    is_muted: bool = Field(default=False)
    is_video_enabled: bool = Field(default=True)
    is_screen_sharing: bool = Field(default=False)

    # Encryption keys
    public_key: str = Field(sa_column=Column(Text))  # RSA public key for key exchange
    session_key_encrypted: str = Field(max_length=512)  # Encrypted session key

    # Connection timestamps
    invited_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    joined_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    left_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Connection quality
    connection_quality: Optional[float] = Field(ge=0.0, le=1.0)
    latency_ms: Optional[int] = Field(ge=0)
    bandwidth_kbps: Optional[int] = Field(ge=0)

    # Device information
    device_info: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    browser_info: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))

    # Relationships
    call_session: Optional[CallSession] = Relationship()
    user: Optional["EnhancedUser"] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_call_participant_session", "call_session_id", "status"),
        Index("idx_call_participant_user", "user_id", "status"),
    )


class CallInvitation(SQLModel, table=True):
    """Call invitations and notifications."""

    __tablename__ = "call_invitations"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Invitation details
    call_session_id: int = Field(foreign_key="call_sessions.id", index=True)
    inviter_id: int = Field(foreign_key="users_enhanced.id", index=True)
    invitee_id: int = Field(foreign_key="users_enhanced.id", index=True)

    # Invitation status
    status: str = Field(
        default="pending", max_length=50, index=True
    )  # pending, accepted, declined, expired

    # Invitation message
    message: Optional[str] = Field(max_length=500)

    # Timestamps
    sent_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    responded_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    expires_at: datetime = Field(index=True)  # Auto-expire invitations

    # Response details
    response_message: Optional[str] = Field(max_length=500)

    # Relationships
    call_session: Optional[CallSession] = Relationship()
    inviter: Optional["EnhancedUser"] = Relationship()
    invitee: Optional["EnhancedUser"] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_call_invitation_invitee", "invitee_id", "status"),
        Index("idx_call_invitation_session", "call_session_id", "status"),
    )


class CallRecording(SQLModel, table=True):
    """Call recordings with encryption."""

    __tablename__ = "call_recordings"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Recording details
    call_session_id: int = Field(foreign_key="call_sessions.id", index=True)
    recording_type: str = Field(max_length=50, index=True)  # audio, video, screen

    # File details
    file_path: str = Field(max_length=500)
    file_size_bytes: int = Field(ge=0)
    duration_seconds: int = Field(ge=0)

    # Encryption details
    is_encrypted: bool = Field(default=True, index=True)
    encryption_key_hash: str = Field(max_length=128)
    encryption_method: EncryptionMethod = Field(default=EncryptionMethod.AES_256_GCM)

    # Recording metadata
    format: str = Field(max_length=20)  # webm, mp4, wav, etc.
    codec: str = Field(max_length=50)
    quality: str = Field(max_length=20)

    # Access control
    access_participants: List[int] = Field(default=[], sa_column=Column(JSON))
    public_access: bool = Field(default=False)
    download_allowed: bool = Field(default=True)

    # Timestamps
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Auto-deletion
    auto_delete_after_days: Optional[int] = Field(ge=1, le=365)
    deletion_scheduled_at: Optional[datetime] = Field(sa_column=Column(DateTime))

    # Relationships
    call_session: Optional[CallSession] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_call_recording_session", "call_session_id", "is_encrypted"),
        Index("idx_call_recording_deletion", "deletion_scheduled_at"),
    )


class CallAnalytics(SQLModel, table=True):
    """Call analytics and quality metrics."""

    __tablename__ = "call_analytics"

    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(
        default_factory=lambda: str(uuid.uuid4()), unique=True, index=True
    )

    # Analytics details
    call_session_id: int = Field(foreign_key="call_sessions.id", index=True)
    participant_id: int = Field(foreign_key="call_participants.id", index=True)

    # Quality metrics
    avg_latency_ms: float = Field(ge=0)
    max_latency_ms: float = Field(ge=0)
    packet_loss_percentage: float = Field(ge=0.0, le=100.0)
    jitter_ms: float = Field(ge=0)

    # Bandwidth metrics
    avg_bandwidth_kbps: float = Field(ge=0)
    peak_bandwidth_kbps: float = Field(ge=0)
    total_data_mb: float = Field(ge=0)

    # Connection events
    connection_drops: int = Field(default=0, ge=0)
    reconnection_attempts: int = Field(default=0, ge=0)

    # Audio/Video quality
    audio_quality_score: Optional[float] = Field(ge=0.0, le=1.0)
    video_quality_score: Optional[float] = Field(ge=0.0, le=1.0)

    # Timestamps
    measurement_start: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    measurement_end: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Raw metrics data
    raw_metrics: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))

    # Relationships
    call_session: Optional[CallSession] = Relationship()
    participant: Optional[CallParticipant] = Relationship()

    # Indexes
    __table_args__ = (
        Index("idx_call_analytics_session", "call_session_id", "measurement_start"),
        Index(
            "idx_call_analytics_quality", "audio_quality_score", "video_quality_score"
        ),
    )
