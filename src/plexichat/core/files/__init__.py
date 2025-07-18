"""PlexiChat Files"""

import logging
from typing import Any, Dict, Optional, List

try:
    from .file_manager import ()
        FileManager, FileMetadata,
        file_manager, upload_file, get_file_metadata,
        get_file_data, delete_file
    )
    logger = logging.getLogger(__name__)
    logger.info("File modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import file modules: {e}")

__all__ = [
    "FileManager",
    "FileMetadata",
    "file_manager",
    "upload_file",
    "get_file_metadata",
    "get_file_data",
    "delete_file",
]

__version__ = "1.0.0"
