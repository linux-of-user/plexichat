from typing import Dict, List, Optional, Any

import sys


try:
    from .core.config_manager import ConfigurationManager as ConfigManager
except ImportError:
    try:
        from .core_system.config import get_config
        class ConfigManager:
            def __init__(self):
                self.config = type('Config', (), {
                    'server': type('Server', (), {
                        'host': '127.0.0.1',
                        'port': 8000,
                        'reload': False,
                        'workers': 1
                    })()
                })()
    except ImportError:
        class ConfigManager:
            def __init__(self):
                self.config = type('Config', (), {
                    'server': type('Server', (), {
                        'host': '127.0.0.1',
                        'port': 8000,
                        'reload': False,
                        'workers': 1
                    })()
                })()
from .main import app


import uvicorn
import logging


"""
PlexiChat Module Entry Point
Allows running PlexiChat as a module: python -m src.plexichat
"""

logger = logging.getLogger(__name__)


def main():
    """Main entry point for module execution."""
    try:
        config_manager = ConfigManager()
        config = config_manager.config

        uvicorn.run(
            app,
            host=getattr(config.server, "host", "127.0.0.1"),
            port=getattr(config.server, "port", 8000),
            reload=getattr(config.server, "reload", False),
            workers=(
                1
                if getattr(config.server, "reload", False)
                else getattr(config.server, "workers", 1)
            ),
            log_level="info",
        )
    except Exception as e:
        logger.info(f" Failed to start PlexiChat: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
