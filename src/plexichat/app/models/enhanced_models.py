# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Enhanced Models

Enhanced data models for the application.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

@dataclass
class EnhancedUser:
    """Enhanced user model."""
id: str
username: str
email: str
created_at: datetime
last_login: Optional[datetime] = None
preferences: Optional[Dict[str, Any]] = None
roles: Optional[List[str]] = None

@dataclass
class EnhancedMessage:
    """Enhanced message model."""
id: str
content: str
user_id: str
channel_id: str
created_at: datetime
edited_at: Optional[datetime] = None
metadata: Optional[Dict[str, Any]] = None

__all__ = ["EnhancedUser", "EnhancedMessage"]
