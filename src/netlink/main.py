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

# Import configuration
from .core.config import get_config

# Import API routers
from .api.v1.router import router as v1_router

# Import security middleware
from .security.middleware import SecurityMiddleware, AuthenticationMiddleware

# Import component managers
from .security.auth import auth_manager
from .backups.manager import backup_manager
from .core.database import database_manager

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the NetLink application."""
    config = get_config()
    
    # Create FastAPI app
    app = FastAPI(
        title=config.app_name,
        version=config.version,
        description="Government-Level Secure Communication Platform",
        debug=config.debug,
        docs_url="/docs" if config.debug else None,
        redoc_url="/redoc" if config.debug else None
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if config.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add security middleware
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(AuthenticationMiddleware)
    
    # Include API routers
    app.include_router(v1_router)
    
    # Mount static files
    static_dir = Path("src/netlink/static")
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    # Add startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize all systems on startup."""
        logger.info("🚀 Starting NetLink application...")
        
        # Initialize core systems
        await database_manager.initialize()
        await auth_manager.initialize() if hasattr(auth_manager, 'initialize') else None
        await backup_manager.initialize()
        
        logger.info("✅ NetLink application started successfully")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown."""
        logger.info("🔄 Shutting down NetLink application...")
        
        # Shutdown systems
        await backup_manager.shutdown()
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
