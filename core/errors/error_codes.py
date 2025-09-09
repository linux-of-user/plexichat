"""Comprehensive error codes system."""
from .base import ErrorCategory, ErrorSeverity, ErrorCodeMapping, PlexiChatErrorCode, ERROR_MAPPINGS

# Minimal changes: retain all 100+ error codes and mappings as primary source
# No duplicated enums or functions; import from base
# Example: all codes already defined in base, but can extend if needed

# Additional mappings if any beyond base (none per plan, but structure preserved)
# Expected: ~680 lines of codes/mappings, but consolidated to base for shared use