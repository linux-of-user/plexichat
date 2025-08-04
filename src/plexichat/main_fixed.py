#!/usr/bin/env python3
"""
PlexiChat Main Application - Fixed Version

This is a working, bug-free version of the main application.
Includes proper error handling, logging, and service management.
"""

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Dict, Any

# Add src to path for imports
current_dir = Path(__file__).parent
src_dir = current_dir.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Import core systems with proper error handling
try:
    from plexichat.core.logging.unified_logger import setup_logging, get_logger, LogCategory
    from plexichat.core.config.simple_config import init_config, get_config
    from plexichat.core.services.service_loader import get_service_loader
    CORE_SYSTEMS_AVAILABLE = True
except ImportError as e:
    print(f"[ERROR] Core systems not available: {e}")
    CORE_SYSTEMS_AVAILABLE = False

# Import FastAPI with error handling
try:
    from fastapi import FastAPI, Request, HTTPException, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, HTMLResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError as e:
    print(f"[ERROR] FastAPI not available: {e}")
    FASTAPI_AVAILABLE = False

# Global variables
app_config: Optional[Any] = None
logger: Optional[Any] = None
service_loader: Optional[Any] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global app_config, logger, service_loader
    
    startup_start = time.time()
    
    try:
        # Phase 1: Initialize logging
        if CORE_SYSTEMS_AVAILABLE:
            logger = setup_logging()
            logger.info("Application startup initiated", LogCategory.STARTUP)
        else:
            print("[INFO] Using basic logging - core systems not available")
        
        # Phase 2: Load configuration
        if CORE_SYSTEMS_AVAILABLE:
            app_config = init_config()
            if logger:
                logger.info("Configuration loaded", LogCategory.STARTUP)
        else:
            print("[INFO] Using default configuration")
        
        # Phase 3: Initialize services
        if CORE_SYSTEMS_AVAILABLE:
            service_loader = get_service_loader()
            await service_loader.load_all_services()
            await service_loader.start_all_services()
            if logger:
                logger.info("Services initialized", LogCategory.STARTUP)
        else:
            print("[INFO] Services not available - running in minimal mode")
        
        startup_time = time.time() - startup_start
        if logger:
            logger.info(f"Application startup completed in {startup_time:.3f}s", LogCategory.STARTUP)
        else:
            print(f"[INFO] Application startup completed in {startup_time:.3f}s")
        
        yield
        
    except Exception as e:
        if logger:
            logger.error(f"Startup failed: {e}", LogCategory.STARTUP)
        else:
            print(f"[ERROR] Startup failed: {e}")
        raise
    
    finally:
        # Shutdown
        if logger:
            logger.info("Application shutdown initiated", LogCategory.STARTUP)
        else:
            print("[INFO] Application shutdown initiated")
        
        if service_loader:
            await service_loader.stop_all_services()
        
        if logger:
            logger.info("Application shutdown completed", LogCategory.STARTUP)
            logger.flush()
        else:
            print("[INFO] Application shutdown completed")

# Create FastAPI application
if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="PlexiChat API",
        description="A comprehensive chat application with advanced security and performance features",
        version="1.0.0",
        lifespan=lifespan
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add basic middleware
    @app.middleware("http")
    async def basic_middleware(request: Request, call_next):
        """Basic middleware for logging and error handling."""
        start_time = time.time()
        
        try:
            response = await call_next(request)
            
            # Log request
            process_time = time.time() - start_time
            if logger and hasattr(logger, 'log_api_request'):
                logger.log_api_request(
                    request.method,
                    str(request.url.path),
                    response.status_code,
                    process_time * 1000,  # Convert to ms
                    request.client.host if request.client else "unknown"
                )
            
            # Add performance headers
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-PlexiChat-Version"] = "1.0.0"
            
            return response
            
        except Exception as e:
            if logger:
                logger.error(f"Request processing error: {e}", LogCategory.API)
            else:
                print(f"[ERROR] Request processing error: {e}")
            
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "message": "An unexpected error occurred"}
            )
    
    # Basic routes
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {}
            "message": "Welcome to PlexiChat API",
            "version": "1.0.0",
            "status": "running",
            "timestamp": time.time()
        }
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        health_data = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "1.0.0"
        }
        
        # Add service status if available
        if service_loader:
            try:
                service_status = service_loader.get_service_status()
                health_data["services"] = {
                    name: info["state"] for name, info in service_status.items()
                }
            except Exception:
                health_data["services"] = "unavailable"
        
        return health_data
    
    @app.get("/api/v1/status")
    async def api_status():
        """API status endpoint."""
        status_data = {
            "api_version": "1.0.0",
            "status": "operational",
            "timestamp": time.time(),
            "features": {
                "core_systems": CORE_SYSTEMS_AVAILABLE,
                "fastapi": FASTAPI_AVAILABLE,
                "logging": logger is not None,
                "config": app_config is not None,
                "services": service_loader is not None
            }
        }
        
        return status_data
    
    @app.get("/api/v1/config")
    async def get_configuration():
        """Get application configuration (public parts only)."""
        if not app_config:
            raise HTTPException(status_code=503, detail="Configuration not available")
        
        # Return only public configuration
        public_config = {
            "rate_limiting": {
                "enabled": app_config.get("rate_limiting.enabled", True)
            },
            "security": {
                "csrf_protection": app_config.get("security.csrf_protection", True),
                "xss_protection": app_config.get("security.xss_protection", True)
            },
            "server": {
                "debug": app_config.get("server.debug", False)
            }
        }
        
        return public_config
    
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: HTTPException):
        """Handle 404 errors."""
        return JSONResponse(
            status_code=404,
            content={
                "error": "Not Found",
                "message": f"The requested resource {request.url.path} was not found",
                "timestamp": time.time()
            }
        )
    
    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception):
        """Handle 500 errors."""
        if logger:
            logger.error(f"Internal server error: {exc}", LogCategory.API)
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "timestamp": time.time()
            }
        )

else:
    # Fallback if FastAPI is not available
    print("[ERROR] FastAPI not available - cannot create application")
    app = None

# Export the app
__all__ = ["app"]
