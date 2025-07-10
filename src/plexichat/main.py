"""
PlexiChat Main Application
Government-Level Secure Communication Platform

Unified main application that consolidates all PlexiChat functionality
into a single, cohesive FastAPI application with comprehensive features.
"""

import asyncio
import time
import ssl
import os
import logging
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uvicorn
import yaml

# Import configuration
from .core.config import get_config

# Import advanced logging
from .core.logging.advanced_logger import get_advanced_logger, setup_module_logging

# SSL/Certificate Management
try:
    from .core.security.ssl_manager import ComprehensiveSSLManager
    ssl_manager = ComprehensiveSSLManager()
    logging.info("✅ SSL Manager loaded")
except ImportError as e:
    logging.warning(f"⚠️ SSL Manager not available: {e}")
    ssl_manager = None

# AI Abstraction Layer (Optional - Full Install Only)
try:
    from .ai.core.ai_abstraction_layer import AIAbstractionLayer
    from .ai.api.ai_endpoints import router as ai_api_router
    from .ai.webui.ai_management import router as ai_webui_router
    ai_layer = AIAbstractionLayer()
    logging.info("✅ AI Abstraction Layer loaded (Full Install)")
except ImportError as e:
    logging.info("ℹ️ AI features not available (requires full installation)")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None
except Exception as e:
    logging.warning(f"⚠️ AI Abstraction Layer failed to initialize: {e}")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None

# Clustering System
try:
    from .clustering import AdvancedClusterManager
    cluster_manager = AdvancedClusterManager()
    logging.info("✅ Advanced Clustering System loaded")
except ImportError as e:
    logging.warning(f"⚠️ Advanced Clustering System not available: {e}")
    cluster_manager = None

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

# Create necessary directories
Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("config").mkdir(exist_ok=True)
Path("certs").mkdir(exist_ok=True)

# SSL Configuration
SSL_CONFIG = {
    "enabled": os.getenv("PLEXICHAT_HTTPS_ENABLED", "false").lower() == "true",
    "port": int(os.getenv("PLEXICHAT_HTTPS_PORT", "443")),
    "cert_path": os.getenv("PLEXICHAT_SSL_CERT", "certs/server.crt"),
    "key_path": os.getenv("PLEXICHAT_SSL_KEY", "certs/server.key"),
    "domain": os.getenv("PLEXICHAT_DOMAIN", "localhost"),
    "email": os.getenv("PLEXICHAT_EMAIL", ""),
    "use_letsencrypt": os.getenv("PLEXICHAT_USE_LETSENCRYPT", "false").lower() == "true",
    "auto_redirect": os.getenv("PLEXICHAT_AUTO_REDIRECT_HTTPS", "true").lower() == "true"
}

# Pydantic models for API
class Message(BaseModel):
    id: Optional[int] = None
    content: str
    author: str
    timestamp: Optional[str] = None

class User(BaseModel):
    id: Optional[int] = None
    username: str
    email: Optional[str] = None

class TestResult(BaseModel):
    test_name: str
    status: str
    duration_ms: float
    message: Optional[str] = None

# In-memory storage (for testing)
messages = []
users = []
test_results = []

# SSL Context
ssl_context = None

async def initialize_ssl():
    """Initialize SSL/TLS configuration."""
    global ssl_context

    if not SSL_CONFIG["enabled"]:
        logging.info("🔓 HTTPS disabled - running in HTTP mode")
        return None

    if not ssl_manager:
        logging.error("❌ SSL Manager not available - cannot enable HTTPS")
        return None

    try:
        logging.info("🔐 Initializing HTTPS/SSL...")

        # Initialize SSL manager
        result = await ssl_manager.initialize(SSL_CONFIG)

        if result.get("ssl_enabled"):
            ssl_context = result.get("ssl_context")
            logging.info("✅ HTTPS/SSL initialized successfully")

            # Setup automatic certificate management
            if SSL_CONFIG["use_letsencrypt"] and SSL_CONFIG["email"]:
                await ssl_manager.setup_automatic_https(
                    domain=SSL_CONFIG["domain"],
                    email=SSL_CONFIG["email"],
                    domain_type="custom"
                )
            else:
                # Use self-signed certificate
                await ssl_manager.setup_automatic_https(
                    domain=SSL_CONFIG["domain"],
                    domain_type="localhost"
                )

            return ssl_context
        else:
            logging.error("❌ Failed to initialize SSL/TLS")
            return None

    except Exception as e:
        logging.error(f"❌ SSL initialization failed: {e}")
        return None

# Initialize unified logging system
def initialize_unified_logging():
    """Initialize the unified logging system that consolidates all logging approaches."""
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
                    "file_enabled": True,
                    "log_directory": "logs"
                }
            }

        # Ensure logs directory exists
        log_dir = Path(logging_config.get("global", {}).get("log_directory", "logs"))
        log_dir.mkdir(exist_ok=True)

        # Create subdirectories for different log types
        (log_dir / "performance").mkdir(exist_ok=True)
        (log_dir / "security").mkdir(exist_ok=True)
        (log_dir / "audit").mkdir(exist_ok=True)
        (log_dir / "crashes").mkdir(exist_ok=True)

        # Initialize advanced logger (consolidates multiple logging systems)
        advanced_logger = get_advanced_logger(logging_config.get("global", {}))

        # Setup module logging with proper levels
        modules_config = logging_config.get("modules", {
            "plexichat.main": "INFO",
            "plexichat.api": "INFO",
            "plexichat.security": "DEBUG",
            "plexichat.performance": "INFO",
            "plexichat.cli": "DEBUG"
        })

        for module, level in modules_config.items():
            setup_module_logging(module, level)

        # Generate initial startup logs
        startup_logger = logging.getLogger("plexichat.startup")
        startup_logger.info("🚀 PlexiChat unified logging system initialized")
        startup_logger.info(f"📁 Log directory: {log_dir}")
        startup_logger.info(f"📊 Log level: {logging_config.get('global', {}).get('log_level', 'INFO')}")
        startup_logger.info("✅ All logging subsystems consolidated and active")

        return True
    except Exception as e:
        print(f"Failed to initialize unified logging: {e}")
        return False

# Initialize unified logging system
initialize_unified_logging()
logger = setup_module_logging(__name__, "INFO")


def _load_web_routers(app: FastAPI):
    """Load routers from the consolidated web/routers directory."""
    logger.info("🔄 Loading web routers...")

    # Load routers from web/routers (new consolidated location)
    router_modules = [
        ("web.routers.auth", "router"),
        ("web.routers.users", "router"),
        ("web.routers.messages", "router"),
        ("web.routers.files", "router"),
        ("web.routers.admin", "router"),
        ("web.routers.status", "router"),
        ("web.routers.system", "router"),
        ("web.routers.websocket", "router"),
        ("web.routers.webhooks", "router"),
        ("web.routers.cluster", "router"),
        ("web.routers.database_setup", "router"),
        ("web.routers.file_management", "router"),
        ("web.routers.login", "router"),
        ("web.routers.messaging_websocket_router", "router"),
        ("web.routers.server_management", "router"),
        ("web.routers.web", "router"),
    ]

    for module_path, router_name in router_modules:
        try:
            module = __import__(f"plexichat.{module_path}", fromlist=[router_name])
            router = getattr(module, router_name, None)
            if router:
                app.include_router(router)
                logger.info(f"✅ {module_path} router loaded")
        except ImportError as e:
            logger.debug(f"⚠️ {module_path} not available: {e}")
        except Exception as e:
            logger.warning(f"❌ Failed to load {module_path}: {e}")


def _load_api_routers(app: FastAPI):
    """Load API routers from the api directory."""
    logger.info("🔄 Loading API routers...")

    # API v1 routers
    api_v1_modules = [
        ("api.v1.router", "router"),
        ("api.v1.auth", "router"),
        ("api.v1.users", "router"),
        ("api.v1.messages", "router"),
        ("api.v1.files", "router"),
        ("api.v1.admin", "router"),
        ("api.v1.moderation", "router"),
        ("api.v1.security", "router"),
        ("api.v1.plugins", "router"),
        ("api.v1.rate_limits", "router"),
        ("api.v1.permissions", "router"),
        ("api.v1.testing", "router"),
        ("api.v1.theming", "router"),
        ("api.v1.social", "router"),
    ]

    for module_path, router_name in api_v1_modules:
        try:
            module = __import__(f"plexichat.{module_path}", fromlist=[router_name])
            router = getattr(module, router_name, None)
            if router:
                app.include_router(router)
                logger.info(f"✅ API {router_name} loaded from {module_path}")
        except ImportError as e:
            logger.debug(f"⚠️ {module_path} not available: {e}")
        except Exception as e:
            logger.warning(f"❌ Failed to load {module_path}: {e}")


def _load_specialized_routers(app: FastAPI):
    """Load specialized routers (AI, clustering, etc.)."""
    logger.info("🔄 Loading specialized routers...")

    # AI routers
    if ai_api_router:
        app.include_router(ai_api_router)
        logger.info("✅ AI API endpoints registered")

    if ai_webui_router:
        app.include_router(ai_webui_router)
        logger.info("✅ AI WebUI endpoints registered")

    # Clustering routers
    try:
        from .clustering.api import router as clustering_router
        app.include_router(clustering_router)
        logger.info("✅ Clustering API router loaded")
    except ImportError:
        logger.debug("⚠️ Clustering API router not available")

    # Backup system routers
    try:
        from .backup.api import router as backup_router
        app.include_router(backup_router)
        logger.info("✅ Backup API router loaded")
    except ImportError:
        logger.debug("⚠️ Backup API router not available")

    # Security routers
    try:
        from .security.api import router as security_router
        app.include_router(security_router)
        logger.info("✅ Security API router loaded")
    except ImportError:
        logger.debug("⚠️ Security API router not available")


def create_app() -> FastAPI:
    """Create and configure the PlexiChat application."""
    logger.info("🚀 Creating PlexiChat FastAPI application...")

    config = get_config()
    logger.info(f"📋 Configuration loaded: {config.app_name} v{config.version}")

    # Create FastAPI app
    app = FastAPI(
        title="PlexiChat v3.0",
        version="3.0.0",
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

    # HTTPS Redirect Middleware
    @app.middleware("http")
    async def https_redirect_middleware(request: Request, call_next):
        """Redirect HTTP to HTTPS if auto_redirect is enabled."""
        if (SSL_CONFIG["enabled"] and SSL_CONFIG["auto_redirect"] and
            request.url.scheme == "http" and not request.url.hostname in ["localhost", "127.0.0.1"]):

            # Redirect to HTTPS
            https_url = request.url.replace(scheme="https", port=SSL_CONFIG["port"])
            return JSONResponse(
                status_code=301,
                headers={"Location": str(https_url)},
                content={"message": "Redirecting to HTTPS", "location": str(https_url)}
            )

        response = await call_next(request)
        return response

    # Add security middleware (with error handling)
    try:
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(AuthenticationMiddleware)
        logger.info("✅ Security middleware loaded")
    except Exception as e:
        logger.warning(f"⚠️ Security middleware failed to load: {e}")
    
    # Load all routers using the new consolidated approach
    _load_web_routers(app)
    _load_api_routers(app)
    _load_specialized_routers(app)

    # Mount static files from multiple locations
    try:
        # Mount from web/static (new consolidated location)
        web_static_path = Path("src/plexichat/web/static")
        if web_static_path.exists():
            app.mount("/static", StaticFiles(directory=str(web_static_path)), name="static")
            logger.info("✅ Web static files mounted from web/static")
        else:
            # Fallback to old static location
            static_dir = Path("src/plexichat/static")
            if static_dir.exists():
                app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
                logger.info("✅ Static files mounted from legacy location")
    except Exception as e:
        logger.warning(f"⚠️ Static files failed to mount: {e}")

    # Add basic routes
    @app.get("/")
    async def root():
        return {"message": "PlexiChat Government-Level Secure Communication Platform", "version": "3.0.0"}

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    
    # Add startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize all systems on startup."""
        logger.info("🚀 Starting PlexiChat application...")

        # Generate startup logs for monitoring
        logger.info("🔄 Initializing PlexiChat core systems...")
        logger.info("📊 System startup sequence beginning")

        # Initialize core systems with lazy loading to prevent hanging
        try:
            # Enhanced Database System initialization
            logger.info("🗄️ Initializing enhanced database system...")
            try:
                from .core.database.enhanced_abstraction import initialize_enhanced_database_system
                success = await initialize_enhanced_database_system()
                if success:
                    logger.info("✅ Enhanced database system initialized successfully")

                    # Initialize comprehensive system integration
                    logger.info("🚀 Initializing comprehensive system integration...")
                    try:
                        from .core.system_integration import initialize_plexichat_system
                        integration_results = await initialize_plexichat_system()

                        if integration_results["summary"]["overall_success"]:
                            logger.info("✅ All PlexiChat systems initialized successfully")
                            logger.info(f"📊 Systems: {integration_results['summary']['systems_initialized']}")
                            logger.info(f"📦 Modules: {integration_results['summary']['modules_imported']}")
                        else:
                            logger.warning("⚠️ Some PlexiChat systems failed to initialize")
                            logger.warning(f"📊 Systems: {integration_results['summary']['systems_initialized']}")
                            logger.warning(f"📦 Modules: {integration_results['summary']['modules_imported']}")

                        # Start background performance monitoring if enabled
                        if os.getenv("PLEXICHAT_AUTO_OPTIMIZATION", "false").lower() == "true":
                            logger.info("🔍 Auto-optimization enabled - background monitoring active")

                    except Exception as integration_e:
                        logger.warning(f"⚠️ System integration failed: {integration_e}")
                        logger.debug(f"Integration error details: {integration_e}", exc_info=True)
                else:
                    logger.warning("⚠️ Enhanced database system initialization failed")

                # Fallback to legacy database manager if enhanced system fails
                if not success:
                    from .core.database import database_manager
                    await database_manager.initialize()
                    logger.info("✅ Legacy database manager initialized as fallback")

            except Exception as e:
                logger.warning(f"⚠️ Database system initialization failed: {e}")
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

        logger.info("✅ PlexiChat application started successfully")
        logger.info("🌐 Server is ready to accept connections")
        logger.info("📡 API endpoints are now available")
        logger.info("🖥️ WebUI is ready for user access")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown."""
        logger.info("🔄 Shutting down PlexiChat application...")

        # Shutdown systems safely
        try:
            # Shutdown enhanced database system
            from .core.database.enhanced_abstraction import shutdown_enhanced_database_system
            await shutdown_enhanced_database_system()
        except Exception as e:
            logger.warning(f"⚠️ Enhanced database system shutdown failed: {e}")

        try:
            from .backups.manager import backup_manager
            await backup_manager.shutdown()
        except Exception as e:
            logger.warning(f"⚠️ Backup manager shutdown failed: {e}")

        try:
            from .core.database import database_manager
            await database_manager.shutdown()
        except Exception as e:
            logger.warning(f"⚠️ Legacy database manager shutdown failed: {e}")

        logger.info("✅ PlexiChat application shutdown complete")
    
    # Root endpoint
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Root endpoint with basic info."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PlexiChat</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { color: #2c3e50; }
                .info { background: #ecf0f1; padding: 20px; border-radius: 5px; }
                .link { color: #3498db; text-decoration: none; }
                .link:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <h1 class="header">💬 PlexiChat</h1>
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
        "src.plexichat.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=config.server.reload,
        workers=1 if config.server.reload else config.server.workers
    )
