"""PlexiChat Backup"""

import logging
from typing import Any, Dict, List, Optional

try:
    from .backup_manager import (
        BackupManager, BackupInfo,
        backup_manager, create_database_backup, create_files_backup,
        create_full_backup, restore_backup, list_backups
    )
    logger = logging.getLogger(__name__)
    logger.info("Backup modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import backup modules: {e}")

__all__ = [
    "BackupManager",
    "BackupInfo",
    "backup_manager",
    "create_database_backup",
    "create_files_backup",
    "create_full_backup",
    "restore_backup",
    "list_backups",
]

__version__ = "1.0.0"
