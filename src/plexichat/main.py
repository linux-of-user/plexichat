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
# datetime import removed - not used in main.py
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
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
except ImportError as e:
    print(f"[X] FastAPI not available: {e}")
    print("Install with: pip install fastapi uvicorn")
    sys.exit(1)

# Initialize basic logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize variables
database_manager = None
UnifiedAuthManager = None

# Try to import core modules with fallbacks
try:
    from plexichat.core.database.manager import database_manager
    logger.info("Database manager imported successfully")
except ImportError as e:
    logger.warning(f"Database manager not available: {e}")
    database_manager = None

try:
    from plexichat.core.auth.unified_auth_manager import UnifiedAuthManager
    logger.info("Auth manager imported successfully")
except ImportError as e:
    logger.warning(f"Auth manager not available: {e}")
    UnifiedAuthManager = None

try:
    from plexichat.core.logging_advanced.enhanced_logging_system import get_logger
    logger = get_logger('plexichat.main')
    logger.info("Enhanced logging system initialized")
except ImportError as e:
    logger.warning(f"Enhanced logging not available: {e}")
    # Keep using basic logger

# Load unified configuration system (required)
from plexichat.core.unified_config import get_unified_config
from plexichat.core.config import settings
from plexichat.core.app_setup import setup_routers, setup_static_files

# Initialize unified config
config = get_unified_config()

# Get production mode from unified config
production_mode = config.system.environment == "production"

logger.info(f"[CONFIG] Unified configuration loaded - Environment: {config.system.environment}")
logger.info(f"[CONFIG] Production mode: {production_mode}")
logger.info(f"[CONFIG] CORS origins: {config.network.cors_origins}")
logger.info(f"[CONFIG] Rate limiting: {config.network.rate_limit_enabled}")
logger.info(f"[CONFIG] SSL enabled: {config.network.ssl_enabled}")

# Application lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown with microsecond optimization."""
    logger.info("[ROCKET] Starting PlexiChat application with microsecond optimization...")

    # Startup
    try:
        # Initialize unified configuration system
        try:
            from plexichat.core.unified_config import get_config
            config = get_config()
            logger.info(f"[CONFIG] Unified configuration system initialized for environment: {config.system.environment}")
        except Exception as e:
            logger.error(f"Failed to initialize configuration system: {e}")
            raise

        # Initialize cache system using unified config
        try:
            from plexichat.core.caching.unified_cache_integration import UnifiedCacheIntegration

            # Get cache configuration from unified config
            cache_config = {
                "enabled": config.caching.enabled,
                "l1_max_size": config.caching.l1_max_items,
                "l1_max_memory_mb": config.caching.l1_memory_size_mb,
                "default_ttl_seconds": config.caching.default_ttl_seconds,
                "compression_threshold": config.caching.compression_threshold_bytes,
                "strategy": "cache_aside",
                "warming_enabled": config.caching.warming_enabled,
                "warming_patterns": ["user_profiles", "conversations", "message_stats"],
                "redis": {
                    "enabled": config.caching.l2_redis_enabled,
                    "host": config.caching.l2_redis_host,
                    "port": config.caching.l2_redis_port,
                    "db": config.caching.l2_redis_db,
                    "password": config.caching.l2_redis_password,
                    "max_connections": 50
                },
                "memcached": {
                    "enabled": config.caching.l3_memcached_enabled,
                    "host": config.caching.l3_memcached_host,
                    "port": config.caching.l3_memcached_port
                }
            }

            if config.caching.enabled:
                cache_integration = UnifiedCacheIntegration()
                await cache_integration.initialize(cache_config)
                logger.info("[CACHE] Multi-tier cache system initialized successfully")
            else:
                logger.info("[CACHE] Caching disabled in configuration")
        except Exception as e:
            logger.warning(f"Cache initialization failed, continuing without cache: {e}")

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
        # Shutdown cache system
        try:
            from plexichat.infrastructure.performance.multi_tier_cache_manager import get_cache_manager
            cache_manager = get_cache_manager()
            if hasattr(cache_manager, 'shutdown'):
                await cache_manager.shutdown()
            logger.info("[CACHE] Cache system shutdown completed")
        except Exception as e:
            logger.warning(f"Cache shutdown error: {e}")

        # Shutdown other services
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

# Add production-ready security middleware (highest priority)
@app.middleware("http")
async def security_middleware(request, call_next):
    """Production-ready security middleware optimized for 10K+ req/min."""
    from fastapi.responses import JSONResponse

    # Block dangerous HTTP methods (optimized set lookup)
    dangerous_methods = {"TRACE", "CONNECT", "DEBUG"}
    if request.method in dangerous_methods:
        return JSONResponse(
            status_code=405,
            content={"error": "Method Not Allowed"},
            headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"}
        )

    # Request validation using unified config
    content_length = request.headers.get("content-length")
    max_size_bytes = config.network.max_request_size_mb * 1024 * 1024
    if content_length and int(content_length) > max_size_bytes:
        return JSONResponse(status_code=413, content={"error": "Request Entity Too Large"})

    response = await call_next(request)

    # Security headers based on unified config environment

    if production_mode:
        # Strict production headers
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cache-Control": "no-store, no-cache, must-revalidate, private"
        })
        # Remove server info in production
        response.headers.pop("server", None)
    else:
        # Development headers
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        })

    return response

# Add integrated protection system (DDoS + Rate Limiting + Dynamic Scaling)
try:
    from plexichat.core.middleware.integrated_protection_system import IntegratedProtectionMiddleware

    # Initialize integrated protection middleware using unified config
    rate_limit_config = {
        "enabled": config.network.rate_limit_enabled,
        "requests_per_minute": config.network.rate_limit_requests_per_minute,
        "burst_limit": config.network.rate_limit_burst_limit,
        "ddos_protection": True,
        "dynamic_scaling": True
    }
    protection_middleware = IntegratedProtectionMiddleware(rate_limit_config)

    @app.middleware("http")
    async def integrated_protection_middleware(request, call_next):
        """Integrated protection with DDoS prevention, rate limiting, and dynamic scaling."""
        return await protection_middleware(request, call_next)

    logger.info("🛡️  Integrated Protection System enabled (DDoS + Rate Limiting + Dynamic Scaling)")
except Exception as e:
    logger.warning(f"Integrated protection middleware not available: {e}")

    # Fallback to basic rate limiting using unified config
    try:
        from plexichat.core.middleware.unified_rate_limiter import RateLimitMiddleware

        # Use unified config for rate limiting
        fallback_rate_config = {
            "enabled": config.network.rate_limit_enabled,
            "requests_per_minute": config.network.rate_limit_requests_per_minute,
            "burst_limit": config.network.rate_limit_burst_limit
        }
        rate_limit_middleware = RateLimitMiddleware(fallback_rate_config)

        @app.middleware("http")
        async def fallback_rate_limiting_middleware(request, call_next):
            """Fallback rate limiting middleware."""
            return await rate_limit_middleware(request, call_next)

        logger.info("⚠️  Fallback rate limiting middleware enabled")
    except Exception as e2:
        logger.error(f"No protection middleware available: {e2}")

# Add microsecond performance middleware second
try:
    @app.middleware("http")
    async def microsecond_performance_middleware(request, call_next):
        """Ultra-high performance middleware for microsecond response times."""
        import time
        start_time = time.time_ns()

        response = await call_next(request)

        # Add performance headers (development only for security)
        end_time = time.time_ns()
        duration_us = (end_time - start_time) / 1000.0

        if not production_mode:
            response.headers["X-Response-Time-Microseconds"] = f"{duration_us:.1f}"
            response.headers["X-Performance-Optimized"] = "production_10k_plus"

        return response

    logger.info("[PERF] Microsecond performance middleware added")
except Exception as e:
    logger.warning(f"Microsecond performance middleware error: {e}")

# Add rate limiting middleware (temporarily disabled)
# try:
#     from plexichat.core.middleware.rate_limiting import RateLimitMiddleware
#     app.add_middleware(RateLimitMiddleware)
#     logger.info("[CHECK] Rate limiting middleware added")
# except ImportError as e:
#     logger.warning(f"Rate limiting middleware not available: {e}")
# except Exception as e:
#     logger.warning(f"Rate limiting middleware error: {e}")
logger.info("[CHECK] Rate limiting middleware temporarily disabled")

# Configure CORS using unified config
if production_mode:
    # Production CORS - very restrictive for security
    cors_origins = []  # No cross-origin requests in production
    cors_credentials = False
    cors_methods = ["GET", "POST"]
    cors_headers = ["Content-Type", "Authorization"]
    logger.info("[CORS] Production CORS enabled - restrictive")
else:
    # Development CORS - use config settings
    cors_origins = config.network.cors_origins
    cors_credentials = True
    cors_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    cors_headers = ["*"]
    logger.info(f"[CORS] Development CORS enabled - origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_credentials,
    allow_methods=cors_methods,
    allow_headers=cors_headers,
    max_age=3600
)

# API endpoints are handled by existing routers in interfaces/api/
# No custom endpoints defined in main.py - only system integration

from plexichat.core.app_setup import setup_routers, setup_static_files

setup_routers(app)
templates = setup_static_files(app)

from plexichat.core.error_handlers import not_found_handler, internal_error_handler

app.add_exception_handler(404, not_found_handler)
app.add_exception_handler(500, internal_error_handler)

# Module exports
__all__ = ['app', 'config']

logger.info(f"[PACKAGE] PlexiChat main module initialized (config loaded: {bool(config)})")