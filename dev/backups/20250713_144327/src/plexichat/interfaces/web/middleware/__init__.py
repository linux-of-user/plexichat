"""
PlexiChat Web Middleware

Consolidated middleware components from the app directory.
All FastAPI middleware for security, logging, etc. are located here.
"""

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
        module = __import__(f".{module_name}", package=__name__, level=1)
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
