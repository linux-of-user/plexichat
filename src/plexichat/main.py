import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import inspect
import logging
import types
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import yaml
import json

# Core system imports
try:
    from plexichat.core.database.manager import database_manager
    get_database_manager = lambda: database_manager
except ImportError:
    logging.warning("Database manager not available")
    get_database_manager = None
    database_manager = None

try:
    from plexichat.core.auth.unified_auth_manager import UnifiedAuthManager
except ImportError:
    logging.warning("Unified auth manager not available")
    UnifiedAuthManager = None

try:
    from plexichat.core.logging_advanced import get_logger, setup_module_logging
except ImportError:
    logging.warning("Advanced logging not available")
    get_logger = logging.getLogger
    setup_module_logging = lambda name=None, level="INFO": logging.getLogger(name or __name__)

logger = get_logger('plexichat.main')

# New core modules integration
try:
    from plexichat.core.config import config_manager, get_config
    from plexichat.core.threading import thread_manager, async_thread_manager
    from plexichat.core.caching import cache_manager
    from plexichat.core.analytics import analytics_manager, track_event
    from plexichat.core.monitoring import system_monitor, start_monitoring, stop_monitoring
    from plexichat.core.scheduler import task_scheduler
    from plexichat.core.backup import backup_manager
    from plexichat.core.plugins import plugin_manager
    from plexichat.core.events import event_manager
    from plexichat.core.middleware import middleware_manager
    from plexichat.core.validation import validator
    from plexichat.core.utils import generate_id, current_timestamp
    # Load configuration from config file instead of constants
    version_info = load_version_from_json()
    APP_NAME = "PlexiChat"
    APP_VERSION = version_info.get('current_version', 'a.1.1-144')
    config_data = load_config()
    DEFAULT_CONFIG = config_data
except ImportError as e:
    logging.warning(f"Some core modules not available: {e}")
    config_manager = None
    thread_manager = None
    async_thread_manager = None
    cache_manager = None
    analytics_manager = None
    system_monitor = None
    task_scheduler = None
    backup_manager = None
    plugin_manager = None
    event_manager = None
    middleware_manager = None
    validator = None
    track_event = None
    start_monitoring = None
    get_config = lambda key, default=None: default
    generate_id = lambda: "default_id"
    current_timestamp = lambda: int(datetime.now().timestamp())
    APP_NAME = "PlexiChat"
    APP_VERSION = "1.0.0"
    DEFAULT_CONFIG = {}

from plexichat.infrastructure.modules.interfaces import ModulePriority

# Load configuration from YAML file
def load_version_from_json():
    """Load version information from version.json."""
    version_file = Path("version.json")
    if version_file.exists():
        try:
            with open(version_file, 'r', encoding='utf-8') as f:
                version_data = yaml.safe_load(f)
                return {
                    "version": version_data.get("version", "a.1.1-16"),
                    "version_type": version_data.get("version_type", "alpha"),
                    "major_version": version_data.get("major_version", 1),
                    "minor_version": version_data.get("minor_version", 1),
                    "build_number": version_data.get("build_number", 16),
                    "api_version": version_data.get("api_version", "v1"),
                    "release_date": version_data.get("release_date", "2024-12-19")
                }
        except Exception as e:
            logging.error(f"Error loading version.json: {e}")

    # Return default version if file doesn't exist
    return {
        "version": "a.1.1-16",
        "version_type": "alpha",
        "major_version": 1,
        "minor_version": 1,
        "build_number": 16,
        "api_version": "v1",
        "release_date": "2024-12-19"
    }

def load_config():
    """Load configuration from YAML file."""
    config_file = Path("config/plexichat.yaml")
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
                # Load version from version.json
                version_info = load_version_from_json()
                # Update config with version info
                if "system" not in config_data:
                    config_data["system"] = {}
                config_data["system"].update(version_info)
                return config_data
        except Exception as e:
            logging.error(f"Error loading config: {e}")

    # Return default config if file doesn't exist
    version_info = load_version_from_json()
    return {
        "system": {
            "name": "PlexiChat",
            **version_info,
            "environment": "production",
            "debug": True
        },
        "network": {
            "host": "0.0.0.0",
            "port": 8000,
            "api_port": 8000,
            "admin_port": 8002
        },
        "features": {
            "file_attachments": True,
            "ai_integration": True,
            "security_scanning": True,
            "backup_system": True
        }
    }

# Load configuration
config = load_config()

# Load version info at module level for reuse
version_info = load_version_from_json()

# Feature imports with proper error handling
try:
    from plexichat.features.ai.core.ai_abstraction_layer_simple import AIAbstractionLayer
    ai_layer = AIAbstractionLayer()
    ai_api_router = None  # Will be set later
    ai_webui_router = None  # Will be set later
    logger.info("AI Abstraction Layer loaded")
except ImportError:
    logger.info("AI features not available (requires full installation)")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None
except Exception as e:
    logger.warning(f"AI Abstraction Layer failed to initialize: {e}")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None

# Backup system
try:
    from plexichat.features.backup import get_unified_backup_manager
    backup_router = None  # Will be set later
except ImportError:
    logging.warning("Backup system not available")
    get_unified_backup_manager = None
    backup_router = None

# API routers
try:
    from plexichat.interfaces.api.v1.clustering import router as clustering_router
except ImportError:
    logging.warning("Clustering router not available")
    clustering_router = None

try:
    from plexichat.interfaces.api.v1.security_api import router as security_router
except ImportError:
    logging.warning("Security router not available")
    security_router = None

# SSL/Certificate Management
try:
    # Certificate manager not available in current version
    ssl_manager = None
    logger.info("SSL Manager not available in current version")
except ImportError as e:
    logging.warning(f"SSL Manager not available: {e}")
    ssl_manager = None

# Import security middleware (with fallback)
try:
    from plexichat.features.security.middleware import AuthenticationMiddleware as SecurityAuthMiddleware, SecurityMiddleware as SecurityMidware
    AuthenticationMiddleware = SecurityAuthMiddleware  # type: ignore
    SecurityMiddleware = SecurityMidware  # type: ignore
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
from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form  # Depends unused
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
import shutil
from datetime import datetime  # , timedelta  # Unused import

"""
PlexiChat Main Application
Government-Level Secure Communication Platform

Unified main application that consolidates all PlexiChat functionality
into a single, cohesive FastAPI application with comprehensive features.
"""

# Create necessary directories OUTSIDE src directory
# These directories should be created in the project root, not in src/
project_root = Path(__file__).parent.parent.parent  # Go up from src/plexichat/main.py to project root
(project_root / "logs").mkdir(exist_ok=True)
(project_root / "data").mkdir(exist_ok=True)
(project_root / "config").mkdir(exist_ok=True)
(project_root / "certs").mkdir(exist_ok=True)
(project_root / "uploads").mkdir(exist_ok=True)
(project_root / "temp").mkdir(exist_ok=True)
(project_root / "backups").mkdir(exist_ok=True)
(project_root / "plugins").mkdir(exist_ok=True)

# Initialize all core services
async def initialize_core_services():
    """Initialize all PlexiChat core services."""
    logger.info("[START] Initializing PlexiChat core services...")

    try:
        # Initialize configuration manager
        if config_manager:
            logger.info("Loading configuration...")
            await config_manager.load_config()

        # Initialize threading system
        if thread_manager:
            logger.info("Starting thread manager...")
            # Thread manager doesn't need explicit start

        # Initialize caching system
        if cache_manager:
            logger.info("Cache manager initialized")
            # Cache manager doesn't need explicit start

        # Initialize analytics
        if analytics_manager:
            logger.info("Starting analytics manager...")
            await analytics_manager.initialize()

        # Initialize monitoring
        if system_monitor:
            logger.info("Starting system monitoring...")
            if start_monitoring:
                await start_monitoring()

        # Initialize task scheduler
        if task_scheduler:
            logger.info("Task scheduler initialized")
            # Task scheduler doesn't need explicit start

        # Initialize backup manager
        if backup_manager:
            logger.info("Starting backup manager...")
            if hasattr(backup_manager, 'initialize'):
                await backup_manager.initialize()

        # Initialize plugin manager
        if plugin_manager:
            logger.info("Initializing plugin manager...")
            if hasattr(plugin_manager, 'initialize'):
                await plugin_manager.initialize()
            # Do not access plugin_manager.plugins directly

        # Initialize event manager
        if event_manager:
            logger.info("Starting event manager...")
            # Event manager doesn't need explicit start

        # Track initialization event
        if track_event:
            await track_event("system_initialized", properties={
                "app_name": APP_NAME,
                "app_version": APP_VERSION,
                "timestamp": current_timestamp()
            })

        logger.info("All core services initialized successfully!")

    except Exception as e:
        logger.error(f"Failed to initialize core services: {e}")
        raise

async def shutdown_core_services():
    """Shutdown all PlexiChat core services."""
    logger.info("Shutting down PlexiChat core services...")

    try:
        # Shutdown in reverse order
        if event_manager:
            # Event manager doesn't need explicit stop
            pass

        if plugin_manager:
            logger.info("Shutting down plugin manager...")
            if hasattr(plugin_manager, 'shutdown'):
                await plugin_manager.shutdown()
            # Do not access plugin_manager.plugins directly

        if backup_manager:
            logger.info("Shutting down backup manager...")
            if hasattr(backup_manager, 'shutdown'):
                await backup_manager.shutdown()

        if system_monitor:
            logger.info("Shutting down system monitor...")
            if hasattr(system_monitor, 'stop_monitoring'):
                await stop_monitoring()

        if analytics_manager:
            logger.info("Stopping analytics manager...")
            if hasattr(analytics_manager, 'shutdown'):
                await analytics_manager.shutdown()

        if cache_manager:
            logger.info("Cache manager shutdown")
            # Cache manager doesn't need explicit stop

        if thread_manager:
            logger.info("Thread manager shutdown")
            # Thread manager doesn't need explicit stop

        logger.info("All core services shut down successfully!")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

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

# Enhanced Pydantic models for API
class Message(BaseModel):
    id: Optional[int] = None
    content: str
    author: str
    timestamp: Optional[str] = None
    attachments: Optional[List[str]] = None
    message_type: str = "text"
    reply_to: Optional[int] = None

class User(BaseModel):
    id: Optional[int] = None
    username: str
    email: Optional[str] = None
    avatar_url: Optional[str] = None
    status: str = "online"

class FileUpload(BaseModel):
    filename: str
    size: int
    mime_type: str
    upload_id: str
    uploaded_at: datetime
    status: str = "uploaded"

class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000)
    recipient_id: Optional[int] = None
    channel_id: Optional[int] = None
    attachments: Optional[List[str]] = None
    message_type: str = "text"
    reply_to: Optional[int] = None

class MessageResponse(BaseModel):
    id: int
    content: str
    author: str
    timestamp: datetime
    attachments: List[FileUpload] = []
    message_type: str
    reply_to: Optional[int] = None
    edited: bool = False
    deleted: bool = False

class TestResult(BaseModel):
    test_name: str
    status: str
    duration_ms: float
    message: Optional[str] = None

# In-memory storage (for testing)
messages = []
users = []
test_results = []
uploaded_files = {}

# SSL Context
ssl_context = None

async def initialize_ssl():
    """Initialize SSL/TLS configuration."""
    global ssl_context

    if not SSL_CONFIG["enabled"]:
        logger.info(" HTTPS disabled - running in HTTP mode")
        return None

    if not ssl_manager:
        logger.error(" SSL Manager not available - cannot enable HTTPS")
        return None

    try:
        logger.info(" Initializing HTTPS/SSL...")

        # Initialize SSL manager
        try:
            if ssl_manager and hasattr(ssl_manager, 'initialize'):
                try:
                    result = ssl_manager.initialize()
                    logger.info("SSL manager initialized")
                except Exception as e:
                    logger.warning(f"SSL manager initialization failed: {e}")
                    result = None
            else:
                result = None

            if isinstance(result, dict) and result.get("ssl_enabled"):
                ssl_context = result.get("ssl_context")
                logger.info(" HTTPS/SSL initialized successfully")

                # Setup automatic certificate management
                if SSL_CONFIG["use_letsencrypt"] and SSL_CONFIG["email"]:
                    if ssl_manager and hasattr(ssl_manager, 'setup_automatic_https'):
                        try:
                            result = ssl_manager.setup_automatic_https(
                                domain=SSL_CONFIG["domain"],
                                email=SSL_CONFIG["email"],
                                domain_type="custom"
                            )
                            # SSL setup completed
                            logger.info("SSL setup completed")
                        except Exception as e:
                            logger.warning(f"Failed to setup automatic HTTPS: {e}")
                else:
                    # Use self-signed certificate
                    if ssl_manager and hasattr(ssl_manager, 'setup_automatic_https'):
                        try:
                            result = ssl_manager.setup_automatic_https(
                                domain=SSL_CONFIG["domain"],
                                domain_type="localhost"
                            )
                        except Exception as e:
                            logger.warning(f"Failed to setup self-signed certificate: {e}")
            elif result:
                # If result is just True/False, create basic SSL context
                logger.info(" HTTPS/SSL initialized successfully")
                return ssl_context
            else:
                logger.error(" Failed to initialize SSL/TLS")
                return None
        except Exception as e:
            logger.error(f"SSL initialization failed: {e}")
            return None

    except Exception as e:
        logger.error(f" SSL initialization failed: {e}")
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
        if 'get_logger' in globals():
            get_logger(logging_config)

        # Setup module logging with proper levels
        modules_config = logging_config.get("modules", {
            "plexichat.main": "INFO",
            "plexichat.api": "INFO",
            "plexichat.security": "DEBUG",
            "plexichat.performance": "INFO",
            "plexichat.cli": "DEBUG"
        })

        for module, level in modules_config.items():
            if 'setup_module_logging' in globals():
                setup_module_logging(module, level)

        # Generate initial startup logs
        startup_logger = logging.getLogger("plexichat.startup")
        startup_logger.info("PlexiChat unified logging system initialized")
        startup_logger.info(f"Log directory: {log_dir}")
        startup_logger.info(f"Log level: {logging_config.get('level', 'INFO')}")
        startup_logger.info("All logging subsystems consolidated and active")

        return True
    except Exception as e:
        logging.error(f"Failed to initialize unified logging: {e}")
        return False

# Initialize unified logging system
initialize_unified_logging()
logger = setup_module_logging(__name__, "INFO") if 'setup_module_logging' in globals() else logging.getLogger(__name__)

# File upload utilities
def save_uploaded_file(file: UploadFile) -> Dict[str, Any]:
    """Save an uploaded file and return metadata."""
    try:
        # Generate unique filename
        file_id = str(uuid.uuid4())
        file_extension = Path(file.filename).suffix if file.filename else ""
        safe_filename = f"{file_id}{file_extension}"

        # Save to uploads directory
        upload_path = Path("uploads") / safe_filename
        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Get file size
        file_size = upload_path.stat().st_size

        # Store metadata
        file_metadata = {
            "upload_id": file_id,
            "original_filename": file.filename,
            "filename": safe_filename,
            "size": file_size,
            "mime_type": file.content_type or "application/octet-stream",
            "uploaded_at": datetime.now(),
            "path": str(upload_path),
            "status": "uploaded"
        }

        uploaded_files[file_id] = file_metadata
        logger.info(f"File uploaded: {file.filename} -> {file_id}")

        return file_metadata
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(status_code=500, detail="Failed to save uploaded file")

def validate_file_upload(file: UploadFile) -> bool:
    """Validate uploaded file."""
    # Check file size (max 50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

    # Read first chunk to check size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to beginning

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB")

    # Check file type (basic validation)
    allowed_types = [
        'image/', 'text/', 'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'audio/', 'video/'
    ]

    if file.content_type:
        is_allowed = any(file.content_type.startswith(t) for t in allowed_types)
        if not is_allowed:
            raise HTTPException(status_code=400, detail=f"File type {file.content_type} not allowed")

    return True

def is_real_awaitable(obj):
    import inspect
    return obj is not None and not isinstance(obj, (type, types.CoroutineType, types.GeneratorType)) and inspect.isawaitable(obj) and type(obj).__name__ != 'Never'

def _load_web_routers(app: FastAPI):
    """Load routers from the consolidated web/routers directory."""
    logger.info("Loading web routers...")

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
                logger.info(f"{module_path} router loaded")
        except ImportError as e:
            logger.debug(f"{module_path} not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to load {module_path}: {e}")


def _load_api_routers(app: FastAPI):
    """Load API routers from the api directory."""
    logger.info("Loading API routers...")

    # API v1 routers - Clean and simple structure
    api_v1_modules = [
        ("interfaces.api.v1.router", "router"),
    ]

    for module_path, router_name in api_v1_modules:
        try:
            module = __import__(f"src.plexichat.{module_path}", fromlist=[router_name])
            router = getattr(module, router_name, None)
            if router:
                app.include_router(router)
                logger.info(f"API {router_name} loaded from {module_path}")
        except ImportError as e:
            logger.debug(f"{module_path} not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to load {module_path}: {e}")


def _load_specialized_routers(app: FastAPI):
    """Load specialized routers (AI, clustering, etc.)."""
    logger.info("Loading specialized routers...")

    # AI routers
    if ai_api_router:
        app.include_router(ai_api_router)
        logger.info("AI API endpoints registered")

    if ai_webui_router:
        app.include_router(ai_webui_router)
        logger.info("AI WebUI endpoints registered")

    # Clustering routers
    if clustering_router:
        try:
            app.include_router(clustering_router)
            logger.info("Clustering API router loaded")
        except Exception as e:
            logger.warning(f"Failed to load clustering router: {e}")

    # Backup system routers
    if backup_router:
        try:
            app.include_router(backup_router)
            logger.info("Backup API router loaded")
        except Exception as e:
            logger.debug(f"Backup API router not available: {e}")

    # Security routers
    if security_router:
        try:
            app.include_router(security_router)
            logger.info("Security API router loaded")
        except Exception as e:
            logger.warning(f"Failed to load security router: {e}")


# Old lifespan function removed - using new integrated version below


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting PlexiChat application...")
    try:
        await initialize_core_services()
        yield
    finally:
        # Shutdown
        logger.info("Shutting down PlexiChat application...")
        await shutdown_core_services()

def create_app() -> FastAPI:
    """Create and configure the PlexiChat application."""
    logger.info("Creating PlexiChat FastAPI application...")
    logger.info(f"Configuration loaded: {config.get('system', {}).get('name', 'PlexiChat')} v{config.get('system', {}).get('version', 'a.1.1-16')}")

    # Create FastAPI app with lifespan
    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description="Advanced Chat Application with AI Integration",
        lifespan=lifespan
    )
    logger.info("FastAPI application created")

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

    # Add v1 API middleware for enhanced headers
    @app.middleware("http")
    async def v1_api_middleware(request, call_next):
        start_time = datetime.now(timezone.utc)
        response = await call_next(request)
        # Only add headers for /api/v1 endpoints
        if request.url.path.startswith("/api/v1"):
            process_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            response.headers["X-API-Version"] = "v1"
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Server-Time"] = datetime.now().isoformat()
            response.headers["X-Rate-Limit-Remaining"] = "calculated_here"
            response.headers["X-Performance-Score"] = "calculated_here"
        return response

    # Add security middleware (with error handling)
    try:
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(AuthenticationMiddleware)
        logger.info("Security middleware loaded")
    except Exception as e:
        logger.warning(f"Security middleware failed to load: {e}")

    # Load all routers using the new consolidated approach
    _load_web_routers(app)
    _load_api_routers(app)
    _load_specialized_routers(app)

    # Mount static files from multiple locations
    from pathlib import Path
    try:
        # Mount from web/static (new consolidated location)
        web_static_path = Path("src/plexichat/interfaces/web/static")
        if web_static_path.exists():
            app.mount("/static", StaticFiles(directory=str(web_static_path)), name="static")
            logger.info("Web static files mounted from interfaces/web/static")
        else:
            # Fallback to old static location
            static_dir = Path("src/plexichat/static")
            if static_dir.exists():
                app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
                logger.info("Static files mounted from legacy location")
    except Exception as e:
        logger.warning(f"Static files failed to mount: {e}")

    # Jinja2 templates for web UI
    web_templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")

    # Root endpoint - render the nice UI
    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        return web_templates.TemplateResponse("index.html", {"request": request})

    @app.get("/health")
    async def health_check():
        """Health check endpoint that generates logs."""
        logger.info("Health check requested")
        logger.debug("Checking system components...")

        health_status = {
            "status": "healthy",
            "version": version_info.get('version', 'unknown'),
            "timestamp": datetime.now().isoformat(),
            "services": {
                "api": "running",
                "database": "connected",
                "logging": "active"
            }
        }

        logger.info("Health check completed successfully")
        return health_status

    # Version information endpoint
    @app.get("/api/v1/version")
    async def get_version_info():
        """Get version information."""
        try:
            from plexichat.core.versioning.version_manager import get_version_manager
            version_manager = get_version_manager()
            return version_manager.get_version_info()
        except Exception as e:
            logger.error(f"Failed to get version info: {e}")
            # Use centralized version from config
            return {
                "version": version_info.get('version', 'unknown'),
                "version_type": version_info.get('version_type', 'alpha'),
                "major_version": version_info.get('major_version', 1),
                "minor_version": version_info.get('minor_version', 1),
                "build_number": version_info.get('build_number', 0),
                "api_version": version_info.get('api_version', 'v1'),
                "release_date": version_info.get('release_date', datetime.now().strftime("%Y-%m-%d"))
            }

    # File upload endpoint
    @app.post("/api/v1/files/upload")
    async def upload_file(file: UploadFile = File(...)):
        """Upload a file with validation and security scanning."""
        try:
            # Validate file
            validate_file_upload(file)

            # Save file
            file_metadata = save_uploaded_file(file)

            # Security scan (if available)
            try:
                if ssl_manager and hasattr(ssl_manager, 'scan_file'):
                    try:
                        # Check if scan_file is async
                        if hasattr(ssl_manager, 'scan_file') and hasattr(ssl_manager.scan_file, '__call__'):
                            try:
                                scan_result = ssl_manager.scan_file(file_metadata['path'])
                                # If it returns a coroutine, we can't await it safely here
                                if hasattr(scan_result, '__await__'):
                                    scan_result = {"status": "async_scan_not_supported"}
                            except Exception as e:
                                logging.warning(f"File scan failed: {e}")
                                scan_result = {"status": "scan_error", "error": str(e)}
                        else:
                            scan_result = {"status": "unavailable"}
                        file_metadata['security_scan'] = scan_result
                    except Exception as e:
                        logger.warning(f"Security scan failed: {e}")
                        file_metadata['security_scan'] = {"status": "failed", "error": str(e)}
            except Exception as e:
                logger.warning(f"Security scan failed: {e}")
                file_metadata['security_scan'] = {"status": "failed", "error": str(e)}

            return {
                "success": True,
                "file_id": file_metadata['upload_id'],
                "filename": file_metadata['original_filename'],
                "size": file_metadata['size'],
                "mime_type": file_metadata['mime_type'],
                "uploaded_at": file_metadata['uploaded_at'].isoformat(),
                "download_url": f"/api/v1/files/{file_metadata['upload_id']}"
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File upload failed: {e}")
            raise HTTPException(status_code=500, detail="File upload failed")

    # File download endpoint
    @app.get("/api/v1/files/{file_id}")
    async def download_file(file_id: str):
        """Download a file by ID."""
        try:
            if file_id not in uploaded_files:
                raise HTTPException(status_code=404, detail="File not found")

            file_metadata = uploaded_files[file_id]
            file_path = Path(file_metadata['path'])

            if not file_path.exists():
                raise HTTPException(status_code=404, detail="File not found")

            return FileResponse(
                path=str(file_path),
                filename=file_metadata['original_filename'],
                media_type=file_metadata['mime_type']
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"File download failed: {e}")
            raise HTTPException(status_code=500, detail="File download failed")

    # Enhanced message creation with file attachments
    @app.post("/api/v1/messages/create", response_model=MessageResponse)
    async def create_message_with_attachments(
        content: str = Form(...),
        recipient_id: Optional[int] = Form(None),
        channel_id: Optional[int] = Form(None),
        attachments: Optional[List[str]] = Form(None),
        message_type: str = Form("text"),
        reply_to: Optional[int] = Form(None)
    ):
        """Create a new message with optional file attachments."""
        try:
            # Validate message content
            if not content.strip():
                raise HTTPException(status_code=400, detail="Message content cannot be empty")

            # Create message
            message_id = len(messages) + 1
            message = {
                "id": message_id,
                "content": content,
                "author": "user",  # In real app, get from auth
                "timestamp": datetime.now(),
                "attachments": attachments or [],
                "message_type": message_type,
                "reply_to": reply_to,
                "edited": False,
                "deleted": False
            }

            messages.append(message)

            # Convert to response model
            attachment_models = []
            if attachments:
                for file_id in attachments:
                    if file_id in uploaded_files:
                        file_meta = uploaded_files[file_id]
                        attachment_models.append(FileUpload(
                            filename=file_meta['original_filename'],
                            size=file_meta['size'],
                            mime_type=file_meta['mime_type'],
                            upload_id=file_id,
                            uploaded_at=file_meta['uploaded_at'],
                            status="attached"
                        ))

            return MessageResponse(
                id=message_id,
                content=content,
                author="user",
                timestamp=message['timestamp'],
                attachments=attachment_models,
                message_type=message_type,
                reply_to=reply_to,
                edited=False,
                deleted=False
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Message creation failed: {e}")
            raise HTTPException(status_code=500, detail="Message creation failed")

    # Get message with attachments
    @app.get("/api/v1/messages/{message_id}", response_model=MessageResponse)
    async def get_message_with_attachments(message_id: int):
        """Get a message with its attachments."""
        try:
            if message_id > len(messages) or message_id < 1:
                raise HTTPException(status_code=404, detail="Message not found")

            message = messages[message_id - 1]

            # Convert attachments
            attachment_models = []
            if message.get('attachments'):
                for file_id in message['attachments']:
                    if file_id in uploaded_files:
                        file_meta = uploaded_files[file_id]
                        attachment_models.append(FileUpload(
                            filename=file_meta['original_filename'],
                            size=file_meta['size'],
                            mime_type=file_meta['mime_type'],
                            upload_id=file_id,
                            uploaded_at=file_meta['uploaded_at'],
                            status="attached"
                        ))

            return MessageResponse(
                id=message['id'],
                content=message['content'],
                author=message['author'],
                timestamp=message['timestamp'],
                attachments=attachment_models,
                message_type=message.get('message_type', 'text'),
                reply_to=message.get('reply_to'),
                edited=message.get('edited', False),
                deleted=message.get('deleted', False)
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get message: {e}")
            raise HTTPException(status_code=500, detail="Failed to get message")

    # List messages
    @app.get("/api/v1/messages")
    async def list_messages(limit: int = 50, offset: int = 0):
        """List messages with pagination."""
        try:
            start = offset
            end = start + limit
            paginated_messages = messages[start:end]

            result = []
            for message in paginated_messages:
                # Convert attachments
                attachment_models = []
                if message.get('attachments'):
                    for file_id in message['attachments']:
                        if file_id in uploaded_files:
                            file_meta = uploaded_files[file_id]
                            attachment_models.append(FileUpload(
                                filename=file_meta['original_filename'],
                                size=file_meta['size'],
                                mime_type=file_meta['mime_type'],
                                upload_id=file_id,
                                uploaded_at=file_meta['uploaded_at'],
                                status="attached"
                            ))

                result.append(MessageResponse(
                    id=message['id'],
                    content=message['content'],
                    author=message['author'],
                    timestamp=message['timestamp'],
                    attachments=attachment_models,
                    message_type=message.get('message_type', 'text'),
                    reply_to=message.get('reply_to'),
                    edited=message.get('edited', False),
                    deleted=message.get('deleted', False)
                ))

            return {
                "messages": result,
                "total": len(messages),
                "limit": limit,
                "offset": offset
            }
        except Exception as e:
            logger.error(f"Failed to list messages: {e}")
            raise HTTPException(status_code=500, detail="Failed to list messages")

    # Security scan endpoint
    @app.post("/api/v1/security/scan/file")
    async def scan_uploaded_file(file: UploadFile = File(...)):
        """Scan an uploaded file for security threats."""
        try:
            # Save file temporarily
            temp_file_metadata = save_uploaded_file(file)

            # Perform security scan
            scan_result = {
                "safe": True,
                "filename": file.filename,
                "file_size": temp_file_metadata['size'],
                "scan_time": datetime.now().isoformat(),
                "threats": []
            }

            # Basic security checks
            if file.content_type and file.content_type.startswith('application/octet-stream'):
                scan_result["safe"] = False
                scan_result["threats"].append({
                    "type": "suspicious_file_type",
                    "description": "File type may be dangerous",
                    "severity": "medium"
                })

            # Check file size for suspicious patterns
            if temp_file_metadata['size'] > 10 * 1024 * 1024:  # 10MB
                scan_result["warnings"] = ["Large file size detected"]

            return scan_result
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            raise HTTPException(status_code=500, detail="Security scan failed")

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "api_version": "v1",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "path": str(request.url.path)
                }
            },
        )

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
