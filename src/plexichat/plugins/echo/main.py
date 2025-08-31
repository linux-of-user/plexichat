"""
Echo plugin for PlexiChat.
"""

class EchoPlugin:
    """Echo plugin implementation."""

    def __init__(self):
        self.name = "echo"

    def echo(self, message: str) -> str:
        """Echo the message."""
        return message