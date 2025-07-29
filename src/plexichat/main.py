#!/usr/bin/env python3
"""
PlexiChat Main Application Module
=================================

This module contains the core FastAPI application and initialization logic.
It should NEVER be run standalone - only imported by run.py.

The main FastAPI app instance is created here and configured with all
the necessary routers, middleware, and startup/shutdown handlers.
"""

import sys
import os
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Prevent standalone execution
if __name__ == "__main__":
    print("[X] This module cannot be run standalone!")
    print("Use 'python run.py' to start PlexiChat.")
    sys.exit(1)

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Core imports with error handling
try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
except ImportError as e:
    print(f"[X] FastAPI not available: {e}")
    print("Install with: pip install fastapi uvicorn")
    sys.exit(1)

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import core modules with fallbacks
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.auth.unified_auth_manager import UnifiedAuthManager
    from plexichat.core.logging_advanced.enhanced_logging_system import get_logger
    logger = get_logger('plexichat.main')
    logger.info("Enhanced logging system initialized")
except ImportError as e:
    logger.warning(f"Core modules not fully available: {e}")
    database_manager = None
    UnifiedAuthManager = None

# Configuration loading
def load_configuration() -> Dict[str, Any]:
    """Load configuration from various sources."""
    try:
        # Try to load from config file
        config_file = Path("config/plexichat.json")
        if config_file.exists():
            import json
            with open(config_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load config file: {e}")
    
    # Return default configuration
    return {
        "system": {
            "name": "PlexiChat",
            "version": "a.1.1-144",
            "environment": "production",
            "debug": False
        },
        "network": {
            "host": "0.0.0.0",
            "port": 8000,
            "api_port": 8000
        },
        "features": {
            "file_attachments": True,
            "ai_integration": True,
            "security_scanning": True,
            "backup_system": True
        }
    }

# Load configuration
config = load_configuration()

# Application lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    logger.info("[ROCKET] Starting PlexiChat application...")
    
    # Startup
    try:
        # Initialize database if available
        if database_manager:
            logger.info("Initializing database...")
            await database_manager.initialize()
        
        # Initialize other core services here
        logger.info("[CHECK] PlexiChat application started successfully")
        
    except Exception as e:
        logger.error(f"[X] Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down PlexiChat application...")
    try:
        # Cleanup resources
        if database_manager:
            logger.info("Closing database connections...")
            await database_manager.cleanup()
        
        logger.info("[CHECK] PlexiChat application shutdown complete")
    except Exception as e:
        logger.error(f"[X] Error during shutdown: {e}")

# Create FastAPI application
app = FastAPI(
    title="PlexiChat API",
    description="Government-Level Secure Communication Platform",
    version=config.get("system", {}).get("version", "1.0.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic health check endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "PlexiChat API",
        "version": config.get("system", {}).get("version", "1.0.0"),
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": config.get("system", {}).get("version", "1.0.0")
    }

# Import and include routers with error handling
def setup_routers():
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
        from plexichat.interfaces.api.v1 import router as api_v1_router
        app.include_router(api_v1_router, prefix="/api/v1", tags=["api-v1"])
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

# Setup static files and templates
def setup_static_files():
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

# Initialize routers and static files
setup_routers()
templates = setup_static_files()

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "path": str(request.url.path)
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An internal server error occurred"
        }
    )

# Module exports
__all__ = ['app', 'config']

logger.info(f"[PACKAGE] PlexiChat main module initialized (config loaded: {bool(config)})")