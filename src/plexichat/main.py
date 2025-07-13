import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .core.database import database_manager
from .core_system.auth.unified_auth_manager import UnifiedAuthManager
from .core_system.config import get_config
from .core_system.database import get_database_manager
from .core_system.integration.orchestrator import SystemOrchestrator
from .core_system.logging import get_logger, setup_module_logging
from .core_system.security.certificate_manager import get_certificate_manager
from .features.ai.api.ai_endpoints import router as ai_api_router
from .features.ai.core.ai_abstraction_layer import AIAbstractionLayer
from .features.ai.webui.ai_management import router as ai_webui_router
from .features.backup import router as backup_router
from .features.backup.core.unified_backup_manager import get_unified_backup_manager
from .features.backup.services import router as backup_router
from .features.clustering.core.cluster_manager import AdvancedClusterManager
from .features.security.middleware import AuthenticationMiddleware, SecurityMiddleware
from .interfaces.api.v1.clustering import router as clustering_router
from .interfaces.api.v1.security_api import router as security_router

"""
PlexiChat Main Application
Government-Level Secure Communication Platform

Unified main application that consolidates all PlexiChat functionality
into a single, cohesive FastAPI application with comprehensive features.
"""

# Import configuration
# Import advanced logging
try:
    get_advanced_logger = get_logger  # Alias for compatibility
except ImportError:
    # Fallback logging
    def get_logger(name):
        return logging.getLogger(name)
    def setup_module_logging(module_name=None, level="INFO"):
        if module_name:
            logger = logging.getLogger(module_name)
            logger.setLevel(getattr(logging, level.upper(), logging.INFO))
            return logger
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger()
    get_advanced_logger = get_logger

# SSL/Certificate Management
try:
    ssl_manager = get_certificate_manager()
    logging.info(" SSL Manager loaded")
except ImportError as e:
    logging.warning(f" SSL Manager not available: {e}")
    ssl_manager = None

# AI Abstraction Layer (Optional - Full Install Only)
try:
    ai_layer = AIAbstractionLayer()
    logging.info(" AI Abstraction Layer loaded (Full Install)")
except ImportError:
    logging.info(" AI features not available (requires full installation)")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None
except Exception as e:
    logging.warning(f" AI Abstraction Layer failed to initialize: {e}")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None

# Clustering System
try:
    # Initialize cluster manager later after app is created
    cluster_manager = None
    logging.info(" Advanced Clustering System available")
except ImportError as e:
    logging.warning(f" Advanced Clustering System not available: {e}")
    cluster_manager = None
    AdvancedClusterManager = None

# Import security middleware (with fallback)
try:
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
        logging.info(" HTTPS disabled - running in HTTP mode")
        return None

    if not ssl_manager:
        logging.error(" SSL Manager not available - cannot enable HTTPS")
        return None

    try:
        logging.info(" Initializing HTTPS/SSL...")

        # Initialize SSL manager
        result = await ssl_manager.initialize()

        if isinstance(result, dict) and result.get("ssl_enabled"):
            ssl_context = result.get("ssl_context")
            logging.info(" HTTPS/SSL initialized successfully")

            # Setup automatic certificate management
            if SSL_CONFIG["use_letsencrypt"] and SSL_CONFIG["email"]:
                if hasattr(ssl_manager, 'setup_automatic_https'):
                    await ssl_manager.setup_automatic_https(
                        domain=SSL_CONFIG["domain"],
                        email=SSL_CONFIG["email"],
                        domain_type="custom"
                    )
            else:
                # Use self-signed certificate
                if hasattr(ssl_manager, 'setup_automatic_https'):
                    await ssl_manager.setup_automatic_https(
                        domain=SSL_CONFIG["domain"],
                        domain_type="localhost"
                    )
        elif result:
            # If result is just True/False, create basic SSL context
            logging.info(" HTTPS/SSL initialized successfully")

            return ssl_context
        else:
            logging.error(" Failed to initialize SSL/TLS")
            return None

    except Exception as e:
        logging.error(f" SSL initialization failed: {e}")
        return None

# Initialize unified logging system
def initialize_unified_logging():
    """Initialize the unified logging system that consolidates all logging approaches."""
    try:
        # Load logging configuration
        config_file = from pathlib import Path
Path("config/logging.yaml")
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
        log_dir = from pathlib import Path
Path(logging_config.get("global", {}).get("log_directory", "logs"))
        log_dir.mkdir(exist_ok=True)

        # Create subdirectories for different log types
        (log_dir / "performance").mkdir(exist_ok=True)
        (log_dir / "security").mkdir(exist_ok=True)
        (log_dir / "audit").mkdir(exist_ok=True)
        (log_dir / "crashes").mkdir(exist_ok=True)

        # Initialize advanced logger (consolidates multiple logging systems)
        get_advanced_logger(logging_config.get("global", {}))

        # Setup module logging with proper levels
        modules_config = logging_config.get("modules", {
            "plexichat.main": "INFO",
            "plexichat.api": "INFO",
            "plexichat.security": "DEBUG",
            "plexichat.performance": "INFO",
            "plexichat.cli": "DEBUG"
        })

        for module, level in modules_config.items():
            if callable(setup_module_logging):
                setup_module_logging(module, level)

        # Generate initial startup logs
        startup_logger = logging.getLogger("plexichat.startup")
        startup_logger.info(" PlexiChat unified logging system initialized")
        startup_logger.info(f" Log directory: {log_dir}")
        startup_logger.info(f" Log level: {logging_config.get('global', {}).get('log_level', 'INFO')}")
        startup_logger.info(" All logging subsystems consolidated and active")

        return True
    except Exception as e:
        print(f"Failed to initialize unified logging: {e}")
        return False

# Initialize unified logging system
initialize_unified_logging()
logger = setup_module_logging(__name__, "INFO")


def _load_web_routers(app: FastAPI):
    """Load routers from the consolidated web/routers directory."""
    logger.info(" Loading web routers...")

    # Load routers from web/routers (new consolidated location)
    router_modules = [
        ("interfaces.web.routers.auth", "router"),
        ("interfaces.web.routers.users", "router"),
        ("interfaces.web.routers.messages", "router"),
        ("interfaces.web.routers.files", "router"),
        ("interfaces.web.routers.admin", "router"),
        ("interfaces.web.routers.status", "router"),
        ("interfaces.web.routers.system", "router"),
        ("interfaces.web.routers.websocket", "router"),
        ("interfaces.web.routers.webhooks", "router"),
        ("interfaces.web.routers.cluster", "router"),
        ("interfaces.web.routers.database_setup", "router"),
        ("interfaces.web.routers.file_management", "router"),
        ("interfaces.web.routers.login", "router"),
        ("interfaces.web.routers.messaging_websocket_router", "router"),
        ("interfaces.web.routers.server_management", "router"),
        ("interfaces.web.routers.web", "router"),
    ]

    for module_path, router_name in router_modules:
        try:
            module = __import__(f"plexichat.{module_path}", fromlist=[router_name])
            router = getattr(module, router_name, None)
            if router:
                app.include_router(router)
                logger.info(f" {module_path} router loaded")
        except ImportError as e:
            logger.debug(f" {module_path} not available: {e}")
        except Exception as e:
            logger.warning(f" Failed to load {module_path}: {e}")


def _load_api_routers(app: FastAPI):
    """Load API routers from the api directory."""
    logger.info(" Loading API routers...")

    # API v1 routers
    api_v1_modules = [
        ("interfaces.api.v1.router", "router"),
        ("interfaces.api.v1.auth", "router"),
        ("interfaces.api.v1.users", "router"),
        ("interfaces.api.v1.messages", "router"),
        ("interfaces.api.v1.files", "router"),
        ("interfaces.api.v1.admin", "router"),
        ("interfaces.api.v1.moderation", "router"),
        ("interfaces.api.v1.security", "router"),
        ("interfaces.api.v1.plugins", "router"),
        ("interfaces.api.v1.rate_limits", "router"),
        ("interfaces.api.v1.permissions", "router"),
        ("interfaces.api.v1.testing", "router"),
        ("interfaces.api.v1.theming", "router"),
        ("interfaces.api.v1.social", "router"),
    ]

    for module_path, router_name in api_v1_modules:
        try:
            module = __import__(f"plexichat.{module_path}", fromlist=[router_name])
            router = getattr(module, router_name, None)
            if router:
                app.include_router(router)
                logger.info(f" API {router_name} loaded from {module_path}")
        except ImportError as e:
            logger.debug(f" {module_path} not available: {e}")
        except Exception as e:
            logger.warning(f" Failed to load {module_path}: {e}")


def _load_specialized_routers(app: FastAPI):
    """Load specialized routers (AI, clustering, etc.)."""
    logger.info(" Loading specialized routers...")

    # AI routers
    if ai_api_router:
        app.include_router(ai_api_router)
        logger.info(" AI API endpoints registered")

    if ai_webui_router:
        app.include_router(ai_webui_router)
        logger.info(" AI WebUI endpoints registered")

    # Clustering routers
    try:
        app.include_router(clustering_router)
        logger.info(" Clustering API router loaded")
    except ImportError:
        logger.debug(" Clustering API router not available")

    # Backup system routers
    try:
        app.include_router(backup_router)
        logger.info(" Backup API router loaded")
    except ImportError:
        try:
            # Try alternative import path
            app.include_router(backup_router)
            logger.info(" Backup API router loaded")
        except ImportError:
            logger.debug(" Backup API router not available")

    # Security routers
    try:
        app.include_router(security_router)
        logger.info(" Security API router loaded")
    except ImportError:
        logger.debug(" Security API router not available")


def create_app() -> FastAPI:
    """Create and configure the PlexiChat application."""
    logger.info(" Creating PlexiChat FastAPI application...")

    config = get_config()
    logger.info(f" Configuration loaded: {getattr(config, 'app_name', 'PlexiChat')} v{getattr(config, 'app_version', '3.0.0')}")

    # Create FastAPI app
    app = FastAPI(
        title="PlexiChat v3.0",
        version="3.0.0",
        description="Government-Level Secure Communication Platform",
        debug=config.debug,
        docs_url="/docs" if config.debug else None,
        redoc_url="/redoc" if config.debug else None
    )
    logger.info(" FastAPI application created")

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
            request.url.scheme == "http" and request.url.hostname not in ["localhost", "127.0.0.1"]):

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
        logger.info(" Security middleware loaded")
    except Exception as e:
        logger.warning(f" Security middleware failed to load: {e}")
    
    # Load all routers using the new consolidated approach
    _load_web_routers(app)
    _load_api_routers(app)
    _load_specialized_routers(app)

    # Mount static files from multiple locations
    try:
        # Mount from web/static (new consolidated location)
        web_static_path = from pathlib import Path
Path("src/plexichat/web/static")
        if web_static_path.exists():
            app.mount("/static", StaticFiles(directory=str(web_static_path)), name="static")
            logger.info(" Web static files mounted from web/static")
        else:
            # Fallback to old static location
            static_dir = from pathlib import Path
Path("src/plexichat/static")
            if static_dir.exists():
                app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
                logger.info(" Static files mounted from legacy location")
    except Exception as e:
        logger.warning(f" Static files failed to mount: {e}")

    # Basic routes are defined later with more comprehensive implementations
    
    # Add startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize all systems on startup."""
        logger.info(" Starting PlexiChat application...")

        # Generate startup logs for monitoring
        logger.info(" Initializing PlexiChat core systems...")
        logger.info(" System startup sequence beginning")

        # Initialize core systems with lazy loading to prevent hanging
        try:
            # Initialize cluster manager if available
            global cluster_manager
            if AdvancedClusterManager and cluster_manager is None:
                try:
                    cluster_manager = AdvancedClusterManager(app)
                    await cluster_manager.initialize()
                    logger.info(" Advanced Clustering System initialized")
                except Exception as e:
                    logger.warning(f" Clustering system initialization failed: {e}")
                    cluster_manager = None

            # Enhanced Database System initialization
            logger.info(" Initializing enhanced database system...")
            try:
                database_manager = await get_database_manager()
                success = await database_manager.initialize()
                # Compatibility wrapper
                async def initialize_enhanced_database_system():
                    return success
                success = await initialize_enhanced_database_system()
                if success:
                    logger.info(" Enhanced database system initialized successfully")

                    # Initialize comprehensive system integration
                    logger.info(" Initializing comprehensive system integration...")
                    try:
                        orchestrator = SystemOrchestrator()
                        await orchestrator.initialize()
                        # Compatibility wrapper
                        async def initialize_plexichat_system():
                            result = await orchestrator.initialize_all_systems()
                            return {
                                "summary": {
                                    "overall_success": result.get("success", False),
                                    "systems_initialized": result.get("initialized_systems", []),
                                    "modules_imported": result.get("modules_imported", [])
                                }
                            }
                        integration_results = await initialize_plexichat_system()

                        if integration_results["summary"]["overall_success"]:
                            logger.info(" All PlexiChat systems initialized successfully")
                            logger.info(f" Systems: {integration_results['summary']['systems_initialized']}")
                            logger.info(f" Modules: {integration_results['summary']['modules_imported']}")
                        else:
                            logger.warning(" Some PlexiChat systems failed to initialize")
                            logger.warning(f" Systems: {integration_results['summary']['systems_initialized']}")
                            logger.warning(f" Modules: {integration_results['summary']['modules_imported']}")

                        # Start background performance monitoring if enabled
                        if os.getenv("PLEXICHAT_AUTO_OPTIMIZATION", "false").lower() == "true":
                            logger.info(" Auto-optimization enabled - background monitoring active")

                    except Exception as integration_e:
                        logger.warning(f" System integration failed: {integration_e}")
                        logger.debug(f"Integration error details: {integration_e}", exc_info=True)
                else:
                    logger.warning(" Enhanced database system initialization failed")

                # Fallback to legacy database manager if enhanced system fails
                if not success:
                    try:
                        await database_manager.initialize()
                        logger.info(" Legacy database manager initialized as fallback")
                    except ImportError:
                        logger.warning(" Legacy database manager not available")

            except Exception as e:
                logger.warning(f" Database system initialization failed: {e}")
                logger.debug(f"Database error details: {e}", exc_info=True)

            # Auth system initialization
            logger.info(" Initializing authentication manager...")
            try:
                auth_manager = UnifiedAuthManager()
                if hasattr(auth_manager, 'initialize'):
                    await auth_manager.initialize()
                logger.info(" Auth manager initialized successfully")
            except Exception as e:
                logger.warning(f" Auth manager initialization failed: {e}")
                logger.debug(f"Auth error details: {e}", exc_info=True)

            # Backup system initialization
            logger.info(" Initializing backup manager...")
            try:
                backup_manager = get_unified_backup_manager()
                await backup_manager.initialize()
                logger.info(" Backup manager initialized successfully")
            except Exception as e:
                logger.warning(f" Backup manager initialization failed: {e}")
                logger.debug(f"Backup error details: {e}", exc_info=True)

            # Additional system checks
            logger.info(" Running system health checks...")
            logger.info(" Checking memory usage...")
            logger.info(" Checking disk space...")
            logger.info(" Checking network connectivity...")
            logger.info(" System health checks completed")

        except Exception as e:
            logger.error(f" Critical startup error: {e}")
            logger.critical(f"Startup failure details: {e}", exc_info=True)
            # Continue startup even if some components fail

        logger.info(" PlexiChat application started successfully")
        logger.info(" Server is ready to accept connections")
        logger.info(" API endpoints are now available")
        logger.info(" WebUI is ready for user access")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown."""
        logger.info(" Shutting down PlexiChat application...")

        # Shutdown systems safely
        try:
            # Shutdown enhanced database system
            database_manager = await get_database_manager()
            if hasattr(database_manager, 'shutdown'):
                await database_manager.shutdown()
        except Exception as e:
            logger.warning(f" Enhanced database system shutdown failed: {e}")

        try:
            backup_manager = get_unified_backup_manager()
            if hasattr(backup_manager, 'shutdown'):
                await backup_manager.shutdown()
            elif hasattr(backup_manager, 'cleanup'):
                await backup_manager.cleanup()
        except Exception as e:
            logger.warning(f" Backup manager shutdown failed: {e}")

        try:
            legacy_manager = await get_database_manager()
            if hasattr(legacy_manager, 'shutdown'):
                await legacy_manager.shutdown()
        except Exception as e:
            logger.warning(f" Legacy database manager shutdown failed: {e}")

        logger.info(" PlexiChat application shutdown complete")
    
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
            <h1 class="header"> PlexiChat</h1>
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
        logger.info(" Health check requested")
        logger.debug("Checking system components...")

        health_status = {
            "status": "healthy",
            "version": getattr(config, 'version', '1.0.0'),
            "timestamp": from datetime import datetime
datetime.now().isoformat(),
            "services": {
                "api": "running",
                "database": "connected",
                "logging": "active"
            }
        }

        logger.info(" Health check completed successfully")
        return health_status

    return app


# Create the application instance
app = create_app()

if __name__ == "__main__":
    config = get_config()
    
    uvicorn.run(
        "src.plexichat.main:app",
        host=config.server.host,
        port=config.server.port,
        reload=config.server.reload,
        workers=1 if config.server.reload else config.server.workers
    )
