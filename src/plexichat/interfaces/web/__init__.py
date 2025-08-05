"""
PlexiChat Web Interface

Enhanced web interface with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Optional

# FastAPI imports
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.staticfiles import StaticFiles
except ImportError:
    FastAPI = None
    CORSMiddleware = None
    GZipMiddleware = None
    StaticFiles = None

# Use EXISTING performance optimization engine
try:
    from ...core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    try:
        from plexichat.core.logging_advanced.performance_logger import get_performance_logger
    except ImportError:
        get_performance_logger = None

# Configuration imports
config_manager = None
try:
    from ...core.config_manager import ConfigurationManager
    config_manager = ConfigurationManager()
except ImportError:
    try:
        from plexichat.core.config_manager import ConfigurationManager
        config_manager = ConfigurationManager()
    except ImportError:
        pass

if config_manager:
    class Settings:
        DEBUG = config_manager.get('system.debug', False)
        APP_NAME = config_manager.get('system.name', 'PlexiChat')
        APP_VERSION = config_manager.get('system.version', 'b.1.1-93')
    settings = Settings()
else:
    class MockSettings:
        DEBUG = False
        APP_NAME = "PlexiChat"
        APP_VERSION = "b.1.1-93"
    settings = MockSettings()

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

def create_app() -> Optional[Any]:
    """Create FastAPI application with enhanced configuration."""
    try:
        if not FastAPI:
            logger.error("FastAPI not available")
            return None

        # Create FastAPI app
        app = FastAPI(
            title=getattr(settings, 'APP_NAME', 'PlexiChat'),
            version=getattr(settings, 'APP_VERSION', 'b.1.1-86'),
            description="Enhanced PlexiChat API with comprehensive functionality",
            debug=getattr(settings, 'DEBUG', False)
        )

        # Add middleware
        if CORSMiddleware:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],  # Configure appropriately for production
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

        if GZipMiddleware:
            app.add_middleware(GZipMiddleware, minimum_size=1000)

        # Add custom middleware
        try:
            from plexichat.interfaces.web.middleware.rate_limiting import RateLimitingMiddleware  # type: ignore
            app.add_middleware(RateLimitingMiddleware)
        except ImportError:
            logger.warning("Rate limiting middleware not available")

        try:
            from plexichat.interfaces.web.middleware.government_security import GovernmentSecurityMiddleware  # type: ignore
            app.add_middleware(GovernmentSecurityMiddleware)
        except ImportError:
            logger.warning("Government security middleware not available")

        # Include routers
        _include_routers(app)

        # Add static files
        if StaticFiles:
            try:
                from pathlib import Path
                static_path = Path(__file__).parent / "static"
                if static_path.exists():
                    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
                    logger.info(f"Static files mounted from {static_path}")
                else:
                    logger.warning(f"Static directory not found at {static_path}")
            except Exception as e:
                logger.warning(f"Could not mount static files: {e}")

        # Add startup/shutdown events
        @app.on_event("startup")
        async def startup_event():
            logger.info("PlexiChat web interface starting up")
            if performance_logger:
                performance_logger.record_metric("app_startups", 1, "count")

        @app.on_event("shutdown")
        async def shutdown_event():
            logger.info("PlexiChat web interface shutting down")
            if performance_logger:
                performance_logger.record_metric("app_shutdowns", 1, "count")

        # Add health check endpoint
        @app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "timestamp": "2024-01-01T00:00:00Z",
                "version": getattr(settings, 'APP_VERSION', 'b.1.1-86')
            }

        return app

    except Exception as e:
        logger.error(f"Error creating FastAPI app: {e}")
        return None

def _include_routers(app):
    """Include all routers in the FastAPI app."""
    try:
        # Core routers
        routers = [
            ("auth", "/auth"),
            ("users", "/users"),
            ("messages", "/messages"),
            ("files", "/files"),
            ("admin", "/admin"),
            ("system", "/system"),
            ("status", "/status"),
            ("webhooks", "/webhooks"),
            ("webui", "/ui"),
            ("ultimate_webui", "/ultimate"),
            ("login", "/login"),
            ("updates", "/updates"),
            ("cluster", "/cluster"),
            ("database_setup", "/database"),
            ("file_management", "/file-management"),
            ("messaging_websocket_router", "/ws"),
            ("config_management", "/config"),
            ("backup_management", "/backup"),

        ]

        for router_name, prefix in routers:
            try:
                # Try multiple import paths
                import_paths = [
                    f"plexichat.interfaces.web.routers.{router_name}",
                    f"src.plexichat.interfaces.web.routers.{router_name}",
                    f".routers.{router_name}"
                ]

                module = None
                for import_path in import_paths:
                    try:
                        if import_path.startswith('.'):
                            # Relative import
                            # # from . import routers
                            module = getattr(routers, router_name, None)
                        else:
                            # Absolute import
                            module = __import__(import_path, fromlist=[router_name])
                        if module:
                            break
                    except (ImportError, AttributeError):
                        continue

                if module and hasattr(module, 'router'):
                    app.include_router(module.router, prefix=prefix)
                    logger.info(f"Included router: {router_name} at {prefix}")
                else:
                    logger.warning(f"Router {router_name} not found or has no 'router' attribute")
            except ImportError as e:
                logger.warning(f"Could not import router {router_name}: {e}")
            except Exception as e:
                logger.error(f"Error including router {router_name}: {e}")

    except Exception as e:
        logger.error(f"Error including routers: {e}")

# Create the app instance
app = create_app()

# Export commonly used items
__all__ = [
    "app",
    "create_app",
]

# Version info - load from config
try:
    __version__ = settings.APP_VERSION
except:
    __version__ = "b.1.1-86"
