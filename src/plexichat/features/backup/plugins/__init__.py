"""
PlexiChat Backup System Plugins

Advanced plugins that extend the backup system capabilities:
- Archive System: Versioning and archival through shard system
- Additional plugins can be added here
"""

from .archive_system import ArchiveSystemPlugin, ArchiveType, ArchiveStatus

__all__ = [
    'ArchiveSystemPlugin',
    'ArchiveType', 
    'ArchiveStatus'
]
