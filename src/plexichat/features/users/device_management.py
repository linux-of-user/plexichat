import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Index, Text
from sqlmodel import JSON, Column, Field, Relationship, SQLModel

"""
Device management models for intelligent shard distribution.
Handles device-based backup storage and smart shard placement.
"""

class DeviceType(str, Enum):
    """Types of devices that can store shards."""
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SERVER = "server"
    MOBILE = "mobile"
    TABLET = "tablet"
    BACKUP_NODE = "backup_node"
    CLOUD_STORAGE = "cloud_storage"


class DeviceStatus(str, Enum):
    """Device online status."""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    UNREACHABLE = "unreachable"


class ConnectionType(str, Enum):
    """Device connection types."""
    ETHERNET = "ethernet"
    WIFI = "wifi"
    CELLULAR = "cellular"
    SATELLITE = "satellite"
    DIRECT = "direct"


class StorageDevice(SQLModel, table=True):
    """Represents a device capable of storing backup shards."""
    __tablename__ = "storage_devices"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Device identification
    device_name: str = Field(max_length=255, index=True)
    device_type: DeviceType = Field(index=True)
    hardware_id: str = Field(max_length=255, unique=True, index=True)  # MAC address, serial, etc.
    
    # Owner information
    user_id: Optional[int] = Field(foreign_key="users_enhanced.id", index=True)
    is_shared_device: bool = Field(default=False)  # Can be used by multiple users
    
    # Network information
    ip_address: Optional[str] = Field(max_length=45)  # IPv4 or IPv6
    hostname: Optional[str] = Field(max_length=255)
    port: Optional[int] = Field(ge=1, le=65535)
    connection_type: ConnectionType = Field(default=ConnectionType.WIFI)
    
    # Storage capabilities
    total_storage_bytes: int = Field(ge=0)
    available_storage_bytes: int = Field(ge=0)
    used_storage_bytes: int = Field(default=0, ge=0)
    max_shard_count: int = Field(default=1000, ge=0)
    current_shard_count: int = Field(default=0, ge=0)
    
    # Performance metrics
    upload_speed_mbps: Optional[float] = Field(ge=0)
    download_speed_mbps: Optional[float] = Field(ge=0)
    average_latency_ms: Optional[float] = Field(ge=0)
    reliability_score: float = Field(default=1.0, ge=0, le=1.0)  # 0-1 based on uptime
    
    # Device preferences
    prefer_own_messages: bool = Field(default=True)  # Prefer storing user's own message shards
    allow_critical_data: bool = Field(default=True)  # Allow storing critical system data
    storage_priority: int = Field(default=5, ge=1, le=10)  # 1=low, 10=high priority
    
    # Status and availability
    status: DeviceStatus = Field(default=DeviceStatus.OFFLINE, index=True)
    last_seen_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    last_heartbeat_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    uptime_percentage: Optional[float] = Field(ge=0, le=100)
    
    # Security settings
    encryption_enabled: bool = Field(default=True)
    access_key_hash: Optional[str] = Field(max_length=128)
    security_level: str = Field(default="standard", max_length=50)
    
    # Geographic and network information
    geographic_region: Optional[str] = Field(max_length=100)
    network_zone: Optional[str] = Field(max_length=100)  # For network topology optimization
    
    # Timestamps
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Device capabilities
    capabilities: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Relationships
    shard_assignments: List["DeviceShardAssignment"] = Relationship(back_populates="device")
    
    # Indexes
    __table_args__ = (
        Index('idx_device_user_status', 'user_id', 'status'),
        Index('idx_device_type_status', 'device_type', 'status'),
        Index('idx_device_storage', 'available_storage_bytes', 'current_shard_count'),
        Index('idx_device_performance', 'reliability_score', 'average_latency_ms'),
    )


class DeviceShardAssignment(SQLModel, table=True):
    """Tracks which shards are assigned to which devices."""
    __tablename__ = "device_shard_assignments"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Assignment details
    device_id: int = Field(foreign_key="storage_devices.id", index=True)
    shard_id: int = Field(foreign_key="enhanced_backup_shards.id", index=True)
    backup_id: int = Field(foreign_key="enhanced_backups.id", index=True)
    
    # Assignment metadata
    assignment_reason: str = Field(max_length=100)  # 'user_preference', 'optimal_placement', 'redundancy'
    priority_level: int = Field(default=5, ge=1, le=10)
    
    # Storage details
    local_path: str = Field(max_length=1000)
    storage_size_bytes: int = Field(ge=0)
    
    # Status tracking
    is_active: bool = Field(default=True, index=True)
    is_verified: bool = Field(default=False, index=True)
    last_verified_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    verification_failures: int = Field(default=0)
    
    # Performance tracking
    upload_time_ms: Optional[float] = Field(ge=0)
    download_time_ms: Optional[float] = Field(ge=0)
    last_access_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    access_count: int = Field(default=0)
    
    # Timestamps
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Relationships
    device: Optional[StorageDevice] = Relationship(back_populates="shard_assignments")
    
    # Indexes
    __table_args__ = (
        Index('idx_assignment_device_active', 'device_id', 'is_active'),
        Index('idx_assignment_shard_device', 'shard_id', 'device_id', unique=True),
        Index('idx_assignment_backup_device', 'backup_id', 'device_id'),
        Index('idx_assignment_verification', 'is_verified', 'last_verified_at'),
    )


class DeviceCapabilityReport(SQLModel, table=True):
    """Periodic reports of device capabilities and status."""
    __tablename__ = "device_capability_reports"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="storage_devices.id", index=True)
    
    # System information
    cpu_usage_percent: Optional[float] = Field(ge=0, le=100)
    memory_usage_percent: Optional[float] = Field(ge=0, le=100)
    disk_usage_percent: Optional[float] = Field(ge=0, le=100)
    network_usage_mbps: Optional[float] = Field(ge=0)
    
    # Storage information
    available_storage_bytes: int = Field(ge=0)
    total_storage_bytes: int = Field(ge=0)
    storage_health_score: Optional[float] = Field(ge=0, le=1.0)
    
    # Network performance
    upload_speed_mbps: Optional[float] = Field(ge=0)
    download_speed_mbps: Optional[float] = Field(ge=0)
    latency_ms: Optional[float] = Field(ge=0)
    packet_loss_percent: Optional[float] = Field(ge=0, le=100)
    
    # Device health
    temperature_celsius: Optional[float]
    battery_level_percent: Optional[float] = Field(ge=0, le=100)
    uptime_hours: Optional[float] = Field(ge=0)
    
    # Shard statistics
    stored_shards_count: int = Field(default=0, ge=0)
    verified_shards_count: int = Field(default=0, ge=0)
    corrupted_shards_count: int = Field(default=0, ge=0)
    
    # Timestamp
    reported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    
    # Additional metrics
    custom_metrics: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Indexes
    __table_args__ = (
        Index('idx_capability_device_time', 'device_id', 'reported_at'),
    )


class ShardDistributionStrategy(SQLModel, table=True):
    """Configuration for shard distribution strategies."""
    __tablename__ = "shard_distribution_strategies"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Strategy identification
    strategy_name: str = Field(max_length=100, unique=True, index=True)
    description: str = Field(sa_column=Column(Text))
    is_active: bool = Field(default=False, index=True)
    
    # Strategy parameters
    redundancy_factor: int = Field(default=5, ge=3, le=20)
    prefer_user_devices: bool = Field(default=True)
    geographic_distribution: bool = Field(default=True)
    network_topology_aware: bool = Field(default=True)
    load_balancing_enabled: bool = Field(default=True)
    
    # Device selection criteria
    min_reliability_score: float = Field(default=0.8, ge=0, le=1.0)
    min_storage_gb: float = Field(default=1.0, ge=0)
    max_latency_ms: Optional[float] = Field(ge=0)
    preferred_device_types: List[str] = Field(default=[], sa_column=Column(JSON))
    
    # Performance thresholds
    min_upload_speed_mbps: Optional[float] = Field(ge=0)
    min_download_speed_mbps: Optional[float] = Field(ge=0)
    max_cpu_usage_percent: Optional[float] = Field(ge=0, le=100)
    max_memory_usage_percent: Optional[float] = Field(ge=0, le=100)
    
    # Advanced settings
    enable_smart_placement: bool = Field(default=True)
    enable_predictive_scaling: bool = Field(default=True)
    enable_automatic_rebalancing: bool = Field(default=True)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: int = Field(foreign_key="users_enhanced.id")
    
    # Strategy configuration
    configuration: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))


class DeviceNetworkTopology(SQLModel, table=True):
    """Network topology information for optimal shard placement."""
    __tablename__ = "device_network_topology"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    
    # Network relationship
    device_a_id: int = Field(foreign_key="storage_devices.id", index=True)
    device_b_id: int = Field(foreign_key="storage_devices.id", index=True)
    
    # Network metrics
    latency_ms: float = Field(ge=0)
    bandwidth_mbps: float = Field(ge=0)
    packet_loss_percent: float = Field(default=0, ge=0, le=100)
    
    # Network path information
    hop_count: Optional[int] = Field(ge=0)
    network_distance: Optional[float] = Field(ge=0)  # Calculated network distance
    geographic_distance_km: Optional[float] = Field(ge=0)
    
    # Connection quality
    connection_stability: float = Field(default=1.0, ge=0, le=1.0)
    last_measured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Indexes
    __table_args__ = (
        Index('idx_topology_devices', 'device_a_id', 'device_b_id', unique=True),
        Index('idx_topology_latency', 'latency_ms'),
        Index('idx_topology_bandwidth', 'bandwidth_mbps'),
    )
