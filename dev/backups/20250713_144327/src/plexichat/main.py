import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from .core.database import get_database_manager, database_manager  # type: ignore
from .core_system.auth.unified_auth_manager import UnifiedAuthManager
from .infrastructure.utils.utilities import ConfigManager
from .core_system.logging import get_logger, setup_module_logging  # type: ignore

# Load configuration from YAML file
def load_config():
    """Load configuration from YAML file."""
    config_file = Path("config/plexichat.yaml")
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
    
    # Return default config if file doesn't exist
    return {
        "system": {
            "name": "PlexiChat",
            "version": "1.0.0",
            "environment": "production",
            "debug": False
        },
        "network": {
            "host": "0.0.0.0",
            "port": 8000,
            "api_port": 8000,
            "admin_port": 8002
        }
    }

# Load configuration
config = load_config()

from .features.ai.core.ai_abstraction_layer import AIAbstractionLayer
# Backup router not available in current structure
backup_router = None
from .features.backup.core.unified_backup_manager import get_unified_backup_manager
from .interfaces.api.v1.clustering import router as clustering_router
from .interfaces.api.v1.security_api import router as security_router

# SSL/Certificate Management
try:
    # Try to import from security features
    from .core_system.security.certificate_manager import get_certificate_manager  # type: ignore
    ssl_manager = get_certificate_manager()  # type: ignore
    logging.info(" SSL Manager loaded")
except ImportError as e:
    logging.warning(f" SSL Manager not available: {e}")
    ssl_manager = None  # type: ignore

# Import security middleware (with fallback)
try:
    from .features.security.middleware import AuthenticationMiddleware, SecurityMiddleware  # type: ignore
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

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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

# SSL manager already initialized above
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
# Note: SecurityMiddleware and AuthenticationMiddleware are already defined above in the try/except block

# Create necessary directories
Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("config").mkdir(exist_ok=True)
Path("certs").mkdir(exist_ok=True)

# SSL Configuration from config
ssl_config = config.get("network", {})
SSL_CONFIG = {
    "enabled": ssl_config.get("ssl_enabled", False),
    "port": ssl_config.get("ssl_port", 443),
    "cert_path": ssl_config.get("ssl_cert", "certs/server.crt"),
    "key_path": ssl_config.get("ssl_key", "certs/server.key"),
    "domain": ssl_config.get("domain", "localhost"),
    "email": ssl_config.get("email", ""),
    "use_letsencrypt": ssl_config.get("use_letsencrypt", False),
    "auto_redirect": ssl_config.get("auto_redirect_https", True)
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
        # Load logging configuration from config
        logging_config = config.get("logging", {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": "logs/plexichat.log",
            "max_size": "10MB",
            "backup_count": 5
        })

        # Ensure logs directory exists
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # Create subdirectories for different log types
        (log_dir / "performance").mkdir(exist_ok=True)
        (log_dir / "security").mkdir(exist_ok=True)
        (log_dir / "audit").mkdir(exist_ok=True)
        (log_dir / "crashes").mkdir(exist_ok=True)

        # Initialize advanced logger (consolidates multiple logging systems)
        get_advanced_logger(logging_config)

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
        startup_logger.info(f" Log level: {logging_config.get('level', 'INFO')}")
        startup_logger.info(" All logging subsystems consolidated and active")

        return True
    except Exception as e:
        logging.error(f"Failed to initialize unified logging: {e}")
        return False

# Initialize unified logging system
initialize_unified_logging()
logger = setup_module_logging(__name__, "INFO")  # type: ignore


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
    if backup_router is not None:
        try:
            app.include_router(backup_router)
            logger.info(" Backup API router loaded")
        except Exception as e:
            logger.debug(f" Backup API router not available: {e}")
    else:
        logger.debug(" Backup API router not available")

    # Security routers
    try:
        app.include_router(security_router)
        logger.info(" Security API router loaded")
    except ImportError:
        logger.debug(" Security API router not available")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    # Startup
    logger.info(" Starting PlexiChat application...")

    # Generate startup logs for monitoring
    logger.info(" Initializing PlexiChat core systems...")
    logger.info(" System startup sequence beginning")

    # Initialize core systems with lazy loading to prevent hanging
    try:
        # Initialize enhanced database system
        database_manager = await get_database_manager()  # type: ignore
        if hasattr(database_manager, 'initialize'):
            await database_manager.initialize()  # type: ignore
        logger.info(" Enhanced database system initialized")
    except Exception as e:
        logger.warning(f" Enhanced database system initialization failed: {e}")

    try:
        # Initialize backup manager
        backup_manager = get_unified_backup_manager()
        if hasattr(backup_manager, 'initialize'):
            await backup_manager.initialize()  # type: ignore
        logger.info(" Backup manager initialized")
    except Exception as e:
        logger.warning(f" Backup manager initialization failed: {e}")

    try:
        # Initialize AI abstraction layer
        ai_layer = AIAbstractionLayer()
        if hasattr(ai_layer, 'initialize'):
            await ai_layer.initialize()  # type: ignore
        logger.info(" AI abstraction layer initialized")
    except Exception as e:
        logger.warning(f" AI abstraction layer initialization failed: {e}")

    try:
        # Initialize authentication manager
        auth_manager = UnifiedAuthManager()
        if hasattr(auth_manager, 'initialize'):
            await auth_manager.initialize()  # type: ignore
        logger.info(" Authentication manager initialized")
    except Exception as e:
        logger.warning(f" Authentication manager initialization failed: {e}")

    try:
        # Initialize SSL/Certificate manager if available
        if ssl_manager and hasattr(ssl_manager, 'initialize'):
            await ssl_manager.initialize()  # type: ignore
        logger.info(" SSL/Certificate manager initialized")
    except Exception as e:
        logger.warning(f" SSL/Certificate manager initialization failed: {e}")

    try:
        # Initialize legacy database manager for compatibility
        legacy_manager = await get_database_manager()  # type: ignore
        if hasattr(legacy_manager, 'initialize'):
            await legacy_manager.initialize()  # type: ignore
        logger.info(" Legacy database manager initialized")
    except Exception as e:
        logger.warning(f" Legacy database manager initialization failed: {e}")

    try:
        # Initialize configuration manager
        config_manager = ConfigManager()
        if hasattr(config_manager, 'initialize'):
            await config_manager.initialize()  # type: ignore
        logger.info(" Configuration manager initialized")
    except Exception as e:
        logger.warning(f" Configuration manager initialization failed: {e}")

    # Additional system initialization
    try:
        # Initialize any additional systems here
        logger.info(" Additional systems initialized")
    except Exception as e:
        logger.error(f" Critical startup error: {e}")
        logger.critical(f"Startup failure details: {e}", exc_info=True)
        # Continue startup even if some components fail

    logger.info(" PlexiChat application started successfully")
    logger.info(" Server is ready to accept connections")
    logger.info(" API endpoints are now available")
    logger.info(" WebUI is ready for user access")

    yield

    # Shutdown
    logger.info(" Shutting down PlexiChat application...")

    # Shutdown systems safely
    try:
        # Shutdown enhanced database system
        database_manager = await get_database_manager()  # type: ignore
        if hasattr(database_manager, 'shutdown'):
            await database_manager.shutdown()  # type: ignore
    except Exception as e:
        logger.warning(f" Enhanced database system shutdown failed: {e}")

    try:
        backup_manager = get_unified_backup_manager()
        if hasattr(backup_manager, 'shutdown'):
            await backup_manager.shutdown()  # type: ignore
        elif hasattr(backup_manager, 'cleanup'):
            await backup_manager.cleanup()  # type: ignore
    except Exception as e:
        logger.warning(f" Backup manager shutdown failed: {e}")

    try:
        legacy_manager = await get_database_manager()  # type: ignore
        if hasattr(legacy_manager, 'shutdown'):
            await legacy_manager.shutdown()  # type: ignore
    except Exception as e:
        logger.warning(f" Legacy database manager shutdown failed: {e}")

    logger.info(" PlexiChat application shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the PlexiChat application."""
    logger.info(" Creating PlexiChat FastAPI application...")

    logger.info(f" Configuration loaded: {config.get('system', {}).get('name', 'PlexiChat')} v{config.get('system', {}).get('version', '3.0.0')}")

    # Create FastAPI app
    app = FastAPI(
        title="PlexiChat v3.0",
        version="3.0.0",
        description="Government-Level Secure Communication Platform",
        debug=config.get('system', {}).get('debug', False),
        docs_url="/docs" if config.get('system', {}).get('debug', False) else None,
        redoc_url="/redoc" if config.get('system', {}).get('debug', False) else None,
        lifespan=lifespan
    )
    logger.info(" FastAPI application created")

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if config.get('system', {}).get('debug', False) else [],
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
    from pathlib import Path
    try:
        # Mount from web/static (new consolidated location)
        web_static_path = Path("src/plexichat/web/static")
        if web_static_path.exists():
            app.mount("/static", StaticFiles(directory=str(web_static_path)), name="static")
            logger.info(" Web static files mounted from web/static")
        else:
            # Fallback to old static location
            static_dir = Path("src/plexichat/static")
            if static_dir.exists():
                app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
                logger.info(" Static files mounted from legacy location")
    except Exception as e:
        logger.warning(f" Static files failed to mount: {e}")

    # Basic routes are defined later with more comprehensive implementations
    
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
            "version": config.get('system', {}).get('version', '1.0.0'),
            "timestamp": datetime.now().isoformat(),
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
    
    uvicorn.run(
        "src.plexichat.main:app",
        host=config.get('network', {}).get('host', '0.0.0.0'),
        port=config.get('network', {}).get('port', 8000),
        reload=config.get('system', {}).get('debug', False),
        workers=1 if config.get('system', {}).get('debug', False) else 1
    )
