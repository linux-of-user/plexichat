"""
PlexiChat Web Interface
"""

import logging
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    logger.info("FastAPI imports successful")
except ImportError as e:
    logger.error(f"FastAPI import failed: {e}")
    FastAPI = None
    CORSMiddleware = None

# Create the FastAPI app
if FastAPI is None:
    logger.critical("FastAPI is not available - webui cannot be created")
    app = None
else:
    try:
        app = FastAPI(
            title="PlexiChat WebUI",
            description="Government-Level Secure Communication Platform",
            version="0.0.1",
            docs_url="/docs",
            redoc_url="/redoc",
        )

        # Add basic CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Routers
        try:
            from plexichat.interfaces.web.routers.logs import router as logs_router
            from plexichat.interfaces.web.routers.setup import router as setup_router
            from plexichat.interfaces.web.routers.login import router as login_router
            from plexichat.interfaces.web.routers.users import router as users_router
            from plexichat.interfaces.web.routers.admin import router as admin_router
            from plexichat.interfaces.web.routers.webui import router as webui_router
            from plexichat.interfaces.web.routers.messages import router as messages_router

            app.include_router(logs_router)
            app.include_router(setup_router)
            app.include_router(login_router)
            app.include_router(users_router)
            app.include_router(admin_router)
            app.include_router(webui_router)
            app.include_router(messages_router)
            
        except Exception as e:
            logger.warning(f"Failed to include some routers: {e}")

        # Basic endpoints
        @app.get("/")
        async def root():
            return {"message": "PlexiChat WebUI is running", "status": "healthy"}

        @app.get("/health")
        async def health_check():
            return {"status": "healthy", "service": "webui"}

        logger.info("FastAPI app created successfully")

    except Exception as e:
        logger.error(f"Failed to create FastAPI app: {e}")
        app = None

# Export the app for external use
__all__ = ["app"]
