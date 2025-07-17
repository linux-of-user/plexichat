"""
PlexiChat Device Management Models

Data models for device management.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Device:
    """Device model."""
    id: str
    name: str
    type: str
    user_id: str
    created_at: datetime
    last_seen: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class DeviceSession:
    """Device session model."""
    id: str
    device_id: str
    user_id: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    ip_address: Optional[str] = None

__all__ = ["Device", "DeviceSession"]
