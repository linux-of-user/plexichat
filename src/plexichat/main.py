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

from plexichat.core.config import settings
from plexichat.core.app_setup import setup_routers, setup_static_files

config = settings

# Application lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown with microsecond optimization."""
    logger.info("[ROCKET] Starting PlexiChat application with microsecond optimization...")

    # Startup
    try:
        # Initialize database if available
        if database_manager:
            logger.info("Initializing database...")
            await database_manager.initialize()

        # Initialize microsecond optimizer
        try:
            from plexichat.core.performance.microsecond_optimizer import start_microsecond_optimization
            await start_microsecond_optimization()
            logger.info("[PERF] Microsecond optimization started")
        except ImportError as e:
            logger.warning(f"Microsecond optimizer not available: {e}")

        # Initialize other core services here
        logger.info("[CHECK] PlexiChat application started successfully with microsecond optimization")

    except Exception as e:
        logger.error(f"[X] Failed to start application: {e}")
        raise

    yield

    # Shutdown
    logger.info("[SHUTDOWN] Shutting down PlexiChat application...")
    try:
        # Stop microsecond optimizer
        try:
            from plexichat.core.performance.microsecond_optimizer import stop_microsecond_optimization
            await stop_microsecond_optimization()
            logger.info("[SHUTDOWN] Microsecond optimization stopped")
        except ImportError:
            pass

        # Cleanup resources
        if database_manager:
            logger.info("Closing database connections...")
            await database_manager.cleanup()

        logger.info("[CHECK] PlexiChat application shutdown complete")
    except Exception as e:
        logger.error(f"[X] Error during shutdown: {e}")

# Create FastAPI application with microsecond optimization
app = FastAPI(
    title=settings.app_name,
    description="Government-Level Secure Communication Platform - Microsecond Optimized",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    # Optimize for performance
    generate_unique_id_function=lambda route: f"{route.tags[0] if route.tags else 'default'}-{route.name}",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1}  # Reduce swagger overhead
)

# Setup routers and static files
setup_routers(app)
setup_static_files(app)

# Add security middleware first (highest priority)
@app.middleware("http")
async def security_middleware(request, call_next):
    """Security middleware to block dangerous HTTP methods and add security headers."""
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    
    # Block dangerous HTTP methods
    dangerous_methods = ["TRACE", "CONNECT"]
    if request.method in dangerous_methods:
        return JSONResponse(
            status_code=405,
            content={"error": "Method Not Allowed", "message": f"HTTP method {request.method} is not allowed"},
            headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"}
        )
    
    response = await call_next(request)
    
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response

# Add microsecond performance middleware second
try:
    @app.middleware("http")
    async def microsecond_performance_middleware(request, call_next):
        """Ultra-high performance middleware for microsecond response times."""
        import time
        start_time = time.time_ns()

        response = await call_next(request)

        # Add microsecond timing
        end_time = time.time_ns()
        duration_us = (end_time - start_time) / 1000.0
        response.headers["X-Response-Time-Microseconds"] = f"{duration_us:.1f}"
        response.headers["X-Performance-Optimized"] = "true"

        return response

    logger.info("[PERF] Microsecond performance middleware added")
except Exception as e:
    logger.warning(f"Microsecond performance middleware error: {e}")

# Add rate limiting middleware
from plexichat.core.middleware.rate_limiting import rate_limiter
app.add_middleware(rate_limiter.__class__)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Basic health check endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    try:
        from plexichat.shared.version_utils import get_version
        version = get_version()
    except ImportError:
        try:
            version = config.get("system", {}).get("version", "b.1.1-91")
        except:
            version = "b.1.1-91"

    return {
        "message": "PlexiChat API",
        "version": version,
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        from plexichat.shared.version_utils import get_health_info
        return get_health_info()
    except ImportError:
        try:
            version = config.get("system", {}).get("version", "b.1.1-91")
        except:
            version = "b.1.1-91"
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": version
        }

@app.get("/performance/stats")
async def performance_stats():
    """Get microsecond-level performance statistics."""
    try:
        from plexichat.core.performance.microsecond_optimizer import get_microsecond_performance_stats
        stats = get_microsecond_performance_stats()
        return {
            "performance_stats": stats,
            "timestamp": datetime.now().isoformat(),
            "optimization_level": "microsecond"
        }
    except ImportError:
        return {
            "error": "Performance optimizer not available",
            "timestamp": datetime.now().isoformat()
        }

from plexichat.core.app_setup import setup_routers, setup_static_files

setup_routers(app)
templates = setup_static_files(app)

from plexichat.core.error_handlers import not_found_handler, internal_error_handler

app.add_exception_handler(404, not_found_handler)
app.add_exception_handler(500, internal_error_handler)

# Module exports
__all__ = ['app', 'config']

logger.info(f"[PACKAGE] PlexiChat main module initialized (config loaded: {bool(config)})")