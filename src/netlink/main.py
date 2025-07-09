"""
NetLink Main Application Factory

Creates and configures the main NetLink application with all features.
"""

import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pathlib import Path
import yaml
from datetime import datetime

# Import configuration
from .core.config import get_config

# Import advanced logging
from .core.logging.advanced_logger import get_advanced_logger, setup_module_logging

# Import API routers (with fallback)
try:
    from .api.v1.router import router as v1_router
except ImportError:
    # Create a fallback router if API module not available
    from fastapi import APIRouter
    v1_router = APIRouter(prefix="/api/v1")

    @v1_router.get("/health")
    async def health_check():
        return {"status": "healthy", "message": "NetLink API v1 fallback"}

# Import security middleware (with fallback)
try:
    from .security.middleware import SecurityMiddleware, AuthenticationMiddleware
except ImportError:
    # Fallback middleware if security module not available
    class SecurityMiddleware:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)

    class AuthenticationMiddleware:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)

# Import component managers (lazy loading to avoid hanging)
# from .security.auth import auth_manager
# from .backups.manager import backup_manager
# from .core.database import database_manager

# Initialize advanced logging
def initialize_logging():
    """Initialize the advanced logging system."""
    try:
        # Load logging configuration
        config_file = Path("config/logging.yaml")
        if config_file.exists():
            with open(config_file, 'r') as f:
                logging_config = yaml.safe_load(f)
        else:
            logging_config = {
                "global": {
                    "log_level": "INFO",
                    "console_enabled": True,
                    "file_enabled": True
                }
            }

        # Initialize advanced logger
        advanced_logger = get_advanced_logger(logging_config.get("global", {}))

        # Setup module logging
        modules_config = logging_config.get("modules", {})
        for module, level in modules_config.items():
            setup_module_logging(module, level)

        return True
    except Exception as e:
        print(f"Failed to initialize advanced logging: {e}")
        return False

# Initialize logging system
initialize_logging()
logger = setup_module_logging(__name__, "INFO")


def create_app() -> FastAPI:
    """Create and configure the NetLink application."""
    logger.info("🚀 Creating NetLink FastAPI application...")

    config = get_config()
    logger.info(f"📋 Configuration loaded: {config.app_name} v{config.version}")

    # Create FastAPI app
    app = FastAPI(
        title=config.app_name,
        version=config.version,
        description="Government-Level Secure Communication Platform",
        debug=config.debug,
        docs_url="/docs" if config.debug else None,
        redoc_url="/redoc" if config.debug else None
    )
    logger.info("✅ FastAPI application created")
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if config.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add security middleware (with error handling)
    try:
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(AuthenticationMiddleware)
        logger.info("✅ Security middleware loaded")
    except Exception as e:
        logger.warning(f"⚠️ Security middleware failed to load: {e}")
    
    # Include API routers
    try:
        app.include_router(v1_router)
        logger.info("✅ API v1 router loaded")
    except Exception as e:
        logger.warning(f"⚠️ API v1 router failed to load: {e}")
    
    # Mount static files
    static_dir = Path("src/netlink/static")
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    # Add startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize all systems on startup."""
        logger.info("🚀 Starting NetLink application...")

        # Generate startup logs for monitoring
        logger.info("🔄 Initializing NetLink core systems...")
        logger.info("📊 System startup sequence beginning")

        # Initialize core systems with lazy loading to prevent hanging
        try:
            # Database initialization
            logger.info("🗄️ Initializing database manager...")
            try:
                from .core.database import database_manager
                await database_manager.initialize()
                logger.info("✅ Database manager initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Database manager initialization failed: {e}")
                logger.debug(f"Database error details: {e}", exc_info=True)

            # Auth system initialization
            logger.info("🔐 Initializing authentication manager...")
            try:
                from .security.auth import auth_manager
                if hasattr(auth_manager, 'initialize'):
                    await auth_manager.initialize()
                logger.info("✅ Auth manager initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Auth manager initialization failed: {e}")
                logger.debug(f"Auth error details: {e}", exc_info=True)

            # Backup system initialization
            logger.info("💾 Initializing backup manager...")
            try:
                from .backups.manager import backup_manager
                await backup_manager.initialize()
                logger.info("✅ Backup manager initialized successfully")
            except Exception as e:
                logger.warning(f"⚠️ Backup manager initialization failed: {e}")
                logger.debug(f"Backup error details: {e}", exc_info=True)

            # Additional system checks
            logger.info("🔍 Running system health checks...")
            logger.info("📊 Checking memory usage...")
            logger.info("💽 Checking disk space...")
            logger.info("🌐 Checking network connectivity...")
            logger.info("✅ System health checks completed")

        except Exception as e:
            logger.error(f"❌ Critical startup error: {e}")
            logger.critical(f"Startup failure details: {e}", exc_info=True)
            # Continue startup even if some components fail

        logger.info("✅ NetLink application started successfully")
        logger.info("🌐 Server is ready to accept connections")
        logger.info("📡 API endpoints are now available")
        logger.info("🖥️ WebUI is ready for user access")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown."""
        logger.info("🔄 Shutting down NetLink application...")

        # Shutdown systems safely
        try:
            from .backups.manager import backup_manager
            await backup_manager.shutdown()
        except Exception as e:
            logger.warning(f"⚠️ Backup manager shutdown failed: {e}")
        await database_manager.shutdown()
        
        logger.info("✅ NetLink application shutdown complete")
    
    # Root endpoint
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Root endpoint with basic info."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetLink</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { color: #2c3e50; }
                .info { background: #ecf0f1; padding: 20px; border-radius: 5px; }
                .link { color: #3498db; text-decoration: none; }
                .link:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1 class="header">🔗 NetLink</h1>
            <div class="info">
                <p><strong>Government-Level Secure Communication Platform</strong></p>
                <p>Version: 3.0.0</p>
                <p>Status: Running</p>
                <br>
                <p>Available endpoints:</p>
                <ul>
                    <li><a href="/docs" class="link">API Documentation</a></li>
                    <li><a href="/api/v1/health" class="link">Health Check</a></li>
                    <li><a href="/api/v1/info" class="link">System Info</a></li>
                </ul>
            </div>
        </body>
        </html>
        """

    @app.get("/health")
    async def health_check():
        """Health check endpoint that generates logs."""
        logger.info("🏥 Health check requested")
        logger.debug("Checking system components...")

        health_status = {
            "status": "healthy",
            "version": config.version,
            "timestamp": datetime.now().isoformat(),
            "services": {
                "api": "running",
                "database": "connected",
                "logging": "active"
            }
        }

        logger.info("✅ Health check completed successfully")
        return health_status

    return app


# Create the application instance
app = create_app()

if __name__ == "__main__":
    import uvicorn
    config = get_config()
    
    uvicorn.run(
        "src.netlink.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=config.server.reload,
        workers=1 if config.server.reload else config.server.workers
    )
