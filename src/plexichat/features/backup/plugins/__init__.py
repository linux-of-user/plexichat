# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .archive_system import ArchiveStatus, ArchiveSystemPlugin, ArchiveType
from typing import Optional


"""
PlexiChat Backup System Plugins

Advanced plugins that extend the backup system capabilities:
- Archive System: Versioning and archival through shard system
- Additional plugins can be added here
"""

__all__ = ["ArchiveSystemPlugin", "ArchiveType", "ArchiveStatus"]
