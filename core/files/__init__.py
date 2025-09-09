"""Core files module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import (
        FileManager,
        FileMetadata,
        get_fallback_instance,
        get_file_metadata,
        get_module_version,
        upload_file,
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = [
    "FileManager",
    "FileMetadata",
    "file_manager",
    "upload_file",
    "get_file_metadata",
]

file_manager = get_fallback_instance("FileManager")
