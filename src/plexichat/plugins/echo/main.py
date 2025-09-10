"""
Echo plugin for PlexiChat.
"""

try:
    from plugins.echo.main import EchoPlugin as EchoPlugin  # canonical source
except Exception:
    class EchoPlugin:  # fallback
        def __init__(self):
            self.name = "echo"
        def echo(self, message: str) -> str:
            return message

# class EchoPlugin:
    """Echo plugin implementation."""

    def __init__(self):
        self.name = "echo"

    def echo(self, message: str) -> str:
        """Echo the message."""
        return message