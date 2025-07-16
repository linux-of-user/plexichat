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

# Try to import middleware and add them to __all__
middleware_modules = [
    "security_middleware",
    "comprehensive_security_middleware",
    "government_security",
    "message_security_middleware",
]

for module_name in middleware_modules:
    try:
        module = importlib.import_module(f".{module_name}", __name__)
        # Add all public classes from the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and not attr_name.startswith("_")
                and hasattr(attr, "__module__")
                and attr.__module__.startswith(__name__)
            ):
                globals()[attr_name] = attr
                __all__.append(attr_name)
    except ImportError:
        pass
