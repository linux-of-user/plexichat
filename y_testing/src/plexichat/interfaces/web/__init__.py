# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Web Interface

Enhanced web interface with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from typing import Any, Dict, Optional

# FastAPI imports
try:
    from fastapi import FastAPI, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.staticfiles import StaticFiles
except ImportError:
    FastAPI = None
    Request = None
    Response = None
    CORSMiddleware = None
    GZipMiddleware = None
    StaticFiles = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        DEBUG = False
        APP_NAME = "PlexiChat"
        APP_VERSION = "1.0.0"
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
        app = FastAPI()
            title=getattr(settings, 'APP_NAME', 'PlexiChat'),
            version=getattr(settings, 'APP_VERSION', '1.0.0'),
            description="Enhanced PlexiChat API with comprehensive functionality",
            debug=getattr(settings, 'DEBUG', False)
        )

        # Add middleware
        if CORSMiddleware:
            app.add_middleware()
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
                app.mount("/static", StaticFiles(directory="static"), name="static")
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
                "version": getattr(settings, 'APP_VERSION', '1.0.0')
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
            ("login", "/login"),
            ("updates", "/updates"),
            ("cluster", "/cluster"),
            ("database_setup", "/database"),
            ("file_management", "/file-management"),
            ("messaging_websocket_router", "/ws"),
        ]

        for router_name, prefix in routers:
            try:
                module = __import__(f"plexichat.interfaces.web.routers.{router_name}", fromlist=[router_name])
                if hasattr(module, 'router'):
                    app.include_router(module.router, prefix=prefix)
                    logger.info(f"Included router: {router_name} at {prefix}")
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

# Version info
__version__ = "1.0.0"
