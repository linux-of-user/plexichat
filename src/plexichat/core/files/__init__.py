"""PlexiChat Files"""

import logging
from typing import Any, Dict, List, Optional

# Use shared fallback implementations
logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (
        FileManager,
        FileMetadata,
        delete_file,
        get_fallback_instance,
        get_file_data,
        get_file_metadata,
        upload_file,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for files")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    file_manager = get_fallback_instance("FileManager")
else:
    # Local fallbacks (preserved for compatibility)
    class FileManager:  # type: ignore
        def __init__(self):
            pass

    class FileMetadata:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    file_manager = None

    def upload_file(*args, **kwargs):  # type: ignore
        return None

    def get_file_metadata(*args, **kwargs):  # type: ignore
        return None

    def get_file_data(*args, **kwargs):  # type: ignore
        return None

    def delete_file(*args, **kwargs):  # type: ignore
        return False


__all__ = [
    "FileManager",
    "FileMetadata",
    "file_manager",
    "upload_file",
    "get_file_metadata",
    "get_file_data",
    "delete_file",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
