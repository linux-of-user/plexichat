"""
PlexiChat Interface Layer - Clean Recreated Version

- Registers web, gui, webui, and cli interfaces
- Ensures webui and gui both use the CLI from interfaces/cli
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class InterfaceManager:
    def __init__(self):
        self.interfaces: Dict[str, bool] = {}

    def register_interface(self, name: str, status: bool = True):
        self.interfaces[name] = status
        logger.info(f"Registered interface: {name} (status: {status})")

    def is_available(self, name: str) -> bool:
        return self.interfaces.get(name, False)

interface_manager = InterfaceManager()

def register_interfaces():
    try:
        # Web interface
        try:
            from plexichat.interfaces.web import app
            interface_manager.register_interface("web", app is not None)
        except ImportError:
            interface_manager.register_interface("web", False)

        # CLI interface (used by gui and webui)
        try:
            from plexichat.interfaces.cli import cli_app
            interface_manager.register_interface("cli", True)
            interface_manager.register_interface("gui", True)  # GUI uses CLI
            interface_manager.register_interface("webui", True)  # WebUI uses CLI
        except ImportError:
            interface_manager.register_interface("cli", False)
            interface_manager.register_interface("gui", False)
            interface_manager.register_interface("webui", False)

        logger.info("Interfaces registered successfully")
    except Exception as e:
        logger.error(f"Error registering interfaces: {e}")

register_interfaces()

def web_available() -> bool:
    return interface_manager.is_available("web")

def cli_available() -> bool:
    return interface_manager.is_available("cli")

def gui_available() -> bool:
    return interface_manager.is_available("gui")

def webui_available() -> bool:
    return interface_manager.is_available("webui")

__all__ = [
    "interface_manager",
    "web_available",
    "cli_available",
    "gui_available",
    "webui_available",
]