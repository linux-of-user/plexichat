"""Core middleware module with fallback implementations."""

from typing import List
from plexichat.core.utils.fallbacks import MiddlewareBase, get_module_version

__version__ = get_module_version()
__all__: List[str] = []
