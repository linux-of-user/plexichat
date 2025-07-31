from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def setup_routers(app: FastAPI):
    """Setup API routers with error handling."""
    try:
        # Web interface routes
        from plexichat.interfaces.web.routers.web import router as web_router
        app.include_router(web_router, prefix="/web", tags=["web"])
        logger.info("[CHECK] Web router loaded")
    except ImportError as e:
        logger.warning(f"Web router not available: {e}")
    
    try:
        # Authentication routes
        from plexichat.interfaces.web.routers.auth import router as auth_router
        app.include_router(auth_router, prefix="/auth", tags=["auth"])
        logger.info("[CHECK] Auth router loaded")
    except ImportError as e:
        logger.warning(f"Auth router not available: {e}")
    
    try:
        # API v1 routes
        from plexichat.interfaces.api.v1 import v1_router as api_v1_router, root_router as root_api_router
        app.include_router(api_v1_router, tags=["api-v1"])
        app.include_router(root_api_router, tags=["root-api"])
        logger.info("[CHECK] API v1 router loaded")
    except ImportError as e:
        logger.warning(f"API v1 router not available: {e}")
    
    try:
        # Admin routes
        from plexichat.interfaces.web.routers.admin import router as admin_router
        app.include_router(admin_router, prefix="/admin", tags=["admin"])
        logger.info("[CHECK] Admin router loaded")
    except ImportError as e:
        logger.warning(f"Admin router not available: {e}")

    try:
        # Easter eggs routes (fun endpoints that don't disrupt normal operation)
        from plexichat.interfaces.api.routers.easter_eggs import router as easter_eggs_router
        app.include_router(easter_eggs_router, tags=["easter-eggs"])
        logger.info("[CHECK] Easter eggs router loaded")
    except ImportError as e:
        logger.warning(f"Easter eggs router not available: {e}")

def setup_static_files(app: FastAPI):
    """Setup static files and templates."""
    try:
        # Static files
        static_path = Path("src/plexichat/interfaces/web/static")
        if static_path.exists():
            app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
            logger.info("[CHECK] Static files mounted")
        
        # Templates
        templates_path = Path("src/plexichat/interfaces/web/templates")
        if templates_path.exists():
            templates = Jinja2Templates(directory=str(templates_path))
            logger.info("[CHECK] Templates loaded")
            return templates
        
    except Exception as e:
        logger.warning(f"Could not setup static files/templates: {e}")
    
    return None
