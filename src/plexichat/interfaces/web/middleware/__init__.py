# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# from typing import Optional  # Unused import
"""
PlexiChat Web Middleware

Consolidated middleware components from the app directory.
All FastAPI middleware for security, logging, etc. are located here.
"""

import importlib

def import_module(module_name):
    return importlib.import_module(module_name)

# Import all middleware for easy access
__all__ = []

# Only import unified_security_middleware
try:
    import_module("unified_security_middleware")
except ImportError as e:
    pass
