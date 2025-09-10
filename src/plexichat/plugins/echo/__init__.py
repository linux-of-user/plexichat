"""PlexiChat echo plugin shim that delegates to the canonical plugin under plugins/echo.
This keeps import paths stable (src.plexichat.plugins.echo) without duplicating features.
"""

from importlib import import_module as _import_module

# Try to import the canonical plugin implementation from the plugins workspace
# Fallback to local minimal implementation if the external package is not present.
try:
    _impl = _import_module('plugins.echo.main')
except Exception:
    _impl = None

if _impl and hasattr(_impl, 'EchoPlugin'):
    EchoPlugin = getattr(_impl, 'EchoPlugin')  # type: ignore
else:
    class EchoPlugin:  # Minimal fallback preserving interface
        def __init__(self):
            self.name = "echo"
        def echo(self, message: str) -> str:
            return message

__all__ = ['EchoPlugin']
