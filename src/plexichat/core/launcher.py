import asyncio
import logging
import sys
from dataclasses import dataclass
from typing import Optional

import uvicorn

from plexichat.core.auth import initialize_auth_system
from plexichat.core.database import initialize_database_system_legacy, shutdown_database_system
from plexichat.features.backup import initialize_backup_system
from plexichat.features.security import initialize_security_features
from plexichat.interfaces.web import create_app

"""
PlexiChat Launcher System
Provides centralized application launching and initialization.
"""

logger = logging.getLogger(__name__)


@dataclass
class LaunchConfig:
    """Launch configuration."""
    debug: bool = False
    host: str = "localhost"
    port: int = 8000
    reload: bool = False
    workers: int = 1
    log_level: str = "info"
    config_file: Optional[str] = None


class PlexiChatLauncher:
    """Main PlexiChat application launcher."""
    
    def __init__(self, config: Optional[LaunchConfig] = None):
        self.config = config or LaunchConfig()
        self.app = None
        self.server = None
        self._initialized = False
    
    async def initialize(self) -> bool:
        """Initialize the launcher and all systems."""
        try:
            logger.info(" Initializing PlexiChat Launcher...")
            
            # Initialize core systems
            await self._initialize_core_systems()
            
            # Initialize features
            await self._initialize_features()
            
            # Initialize interfaces
            await self._initialize_interfaces()
            
            self._initialized = True
            logger.info(" PlexiChat Launcher initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f" Failed to initialize launcher: {e}")
            return False
    
    async def _initialize_core_systems(self):
        """Initialize core systems."""
        try:
            # Database system
            await initialize_database_system_legacy()
            
            # Authentication system
            await initialize_auth_system()
            
            logger.info(" Core systems initialized")
            
        except ImportError as e:
            logger.warning(f"Some core systems not available: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize core systems: {e}")
            raise
    
    async def _initialize_features(self):
        """Initialize feature systems."""
        try:
            # Backup system
            await initialize_backup_system()
            
            # Security features
            await initialize_security_features()
            
            logger.info(" Features initialized")
            
        except ImportError as e:
            logger.warning(f"Some features not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to initialize some features: {e}")
    
    async def _initialize_interfaces(self):
        """Initialize interface systems."""
        try:
            # Web interface
            self.app = create_app()
            
            logger.info(" Interfaces initialized")
            
        except ImportError as e:
            logger.warning(f"Some interfaces not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to initialize interfaces: {e}")
    
    async def start(self) -> bool:
        """Start the application."""
        try:
            if not self._initialized:
                if not await self.initialize():
                    return False
            
            logger.info(f" Starting PlexiChat on {self.config.host}:{self.config.port}")
            
            # Start the server
            config = uvicorn.Config(
                self.app,
                host=self.config.host,
                port=self.config.port,
                log_level=self.config.log_level,
                reload=self.config.reload
            )
            
            server = uvicorn.Server(config)
            await server.serve()
            
            return True
            
        except Exception as e:
            logger.error(f" Failed to start application: {e}")
            return False
    
    async def stop(self):
        """Stop the application."""
        try:
            logger.info(" Stopping PlexiChat...")
            
            if self.server:
                self.server.should_exit = True
            
            # Shutdown systems
            await self._shutdown_systems()
            
            logger.info(" PlexiChat stopped successfully")
            
        except Exception as e:
            logger.error(f" Failed to stop application: {e}")
    
    async def _shutdown_systems(self):
        """Shutdown all systems gracefully."""
        try:
            # Shutdown database
            await shutdown_database_system()
            
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    def run(self):
        """Run the application (blocking)."""
        try:
            asyncio.run(self.start())
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Application error: {e}")
            sys.exit(1)


# Convenience function
def create_launcher(config: Optional[LaunchConfig] = None) -> PlexiChatLauncher:
    """Create a new launcher instance."""
    return PlexiChatLauncher(config)
