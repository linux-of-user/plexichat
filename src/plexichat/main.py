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
from dataclasses import asdict

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
_basic_logger = logging.getLogger(__name__)

# Initialize variables
database_manager = None
UnifiedAuthManager = None

# Try to import core modules with fallbacks
try:
    from plexichat.core.database.manager import database_manager
    _basic_logger.info("Database manager imported successfully")
except ImportError as e:
    _basic_logger.warning(f"Database manager not available: {e}")
    database_manager = None

# Try to import authentication class for type/reference (not initializing yet)
try:
    from plexichat.core.authentication import UnifiedAuthManager  # type: ignore
    _basic_logger.info("Auth manager class imported successfully")
except Exception as e:
    # Not fatal here; we'll initialize the auth manager during startup
    _basic_logger.warning(f"Auth manager class not available: {e}")
    UnifiedAuthManager = None

# Import unified logging system
from plexichat.core.logging import get_logger, get_logging_manager

# Use unified logger for the module
logger = get_logger('plexichat.main')
logger.info("Unified logging system initialized (pre-config)")

# Load configuration system (required)
from plexichat.core.config import get_config
from plexichat.core.config import settings
from plexichat.core.app_setup import setup_routers, setup_static_files
from plexichat.core.plugins.manager import unified_plugin_manager

# Initialize config
config = get_config()

# Apply unified logging configuration now that config is available
try:
    from plexichat.core.logging import setup_module_logging
    
    # Ensure logging manager is referenced to trigger any internal initialization
    _lm = get_logging_manager()
    
    # Apply module logging level if present in config
    level = getattr(getattr(config, "logging", None), "level", "INFO")
    setup_module_logging('plexichat.main', level=level)
    
    # Update logger reference to ensure we have the configured logger
    logger = get_logger('plexichat.main')
    logger.info("Unified logging configured with application config")
except Exception as e:
    logger.warning(f"Failed to apply unified logging configuration: {e}")

# Get production mode from unified config
production_mode = getattr(getattr(config, "system", None), "environment", None) == "production"

logger.info(f"[CONFIG] Unified configuration loaded - Environment: {getattr(getattr(config, 'system', None), 'environment', 'unknown')}")
logger.info(f"[CONFIG] Production mode: {production_mode}")
try:
    logger.info(f"[CONFIG] CORS origins: {config.network.cors_origins}")
    logger.info(f"[CONFIG] Rate limiting: {config.network.rate_limit_enabled}")
    logger.info(f"[CONFIG] SSL enabled: {config.network.ssl_enabled}")
except Exception:
    # If config.network not structured as expected, skip verbose fields
    pass

# Application-level state initialization for performance metrics and flags
performance_metrics: Dict[str, float] = {}
# We'll attach runtime state to the app object later (after app created)

# Application lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown with microsecond optimization."""
    import time
    logger.info("[ROCKET] Starting PlexiChat application with microsecond optimization...")

    # store performance metrics in app state
    app.state.performance_metrics = []
    app.state.protection_middleware_registered = False
    app.state.security_validated = False
    app.state.auth_cache_initialized = False
    app.state.auth_manager = None

    # Startup
    try:
        overall_start = time.perf_counter()

        # Initialize configuration system
        try:
            from plexichat.core.config import get_config
            config = get_config()
            logger.info(f"[CONFIG] Configuration system initialized for environment: {getattr(getattr(config, 'system', None), 'environment', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to initialize configuration system: {e}")
            raise

        # Ensure plugin SDK (plugins_internal.py) is generated before other plugin work
        try:
            from plexichat.core.plugins.sdk_generator import (
                regenerate_plugins_internal_if_needed, 
                validate_plugins_internal,
                get_plugins_internal_stats
            )
            sdk_start = time.perf_counter()
            
            # Generate/validate plugins_internal.py
            ok = regenerate_plugins_internal_if_needed()
            
            # Validate the generated file
            if ok:
                validation_ok = validate_plugins_internal()
                if not validation_ok:
                    logger.error("[SDK] plugins_internal.py validation failed")
                    ok = False
            
            sdk_end = time.perf_counter()
            sdk_duration = (sdk_end - sdk_start) * 1000.0
            app.state.performance_metrics.append({"operation": "sdk_generation_check", "duration_ms": sdk_duration})
            
            if ok:
                logger.info(f"[SDK] plugins_internal SDK generation/validation completed ({sdk_duration:.1f}ms)")
                # Log SDK stats for debugging
                try:
                    stats = get_plugins_internal_stats()
                    logger.debug(f"[SDK] Generated file stats: {stats}")
                except Exception as stats_e:
                    logger.debug(f"[SDK] Could not get stats: {stats_e}")
            else:
                logger.warning("[SDK] plugins_internal SDK generation failed or returned invalid result")
                
        except ImportError as e:
            logger.error(f"[SDK] SDK generator module not available: {e}")
        except Exception as e:
            logger.warning(f"[SDK] Could not run SDK regeneration check: {e}")

        # Initialize cache system using unified config
        try:
            from plexichat.core.caching.unified_cache_integration import UnifiedCacheIntegration

            cache_start = time.perf_counter()

            # Get cache configuration from unified config
            cache_config = {
                "enabled": getattr(getattr(config, "caching", None), "enabled", False),
                "l1_max_size": getattr(getattr(config, "caching", None), "l1_max_items", None),
                "l1_max_memory_mb": getattr(getattr(config, "caching", None), "l1_memory_size_mb", None),
                "default_ttl_seconds": getattr(getattr(config, "caching", None), "default_ttl_seconds", None),
                "compression_threshold": getattr(getattr(config, "caching", None), "compression_threshold_bytes", None),
                "strategy": "cache_aside",
                "warming_enabled": getattr(getattr(config, "caching", None), "warming_enabled", False),
                "warming_patterns": ["user_profiles", "conversations", "message_stats"],
                "redis": {
                    "enabled": getattr(getattr(config, "caching", None), "l2_redis_enabled", False),
                    "host": getattr(getattr(config, "caching", None), "l2_redis_host", None),
                    "port": getattr(getattr(config, "caching", None), "l2_redis_port", None),
                    "db": getattr(getattr(config, "caching", None), "l2_redis_db", None),
                    "password": getattr(getattr(config, "caching", None), "l2_redis_password", None),
                    "max_connections": 50
                },
                "memcached": {
                    "enabled": getattr(getattr(config, "caching", None), "l3_memcached_enabled", False),
                    "host": getattr(getattr(config, "caching", None), "l3_memcached_host", None),
                    "port": getattr(getattr(config, "caching", None), "l3_memcached_port", None)
                }
            }

            if cache_config.get("enabled"):
                cache_integration = UnifiedCacheIntegration()
                await cache_integration.initialize(cache_config)
                cache_end = time.perf_counter()
                cache_duration = (cache_end - cache_start) * 1000.0
                app.state.performance_metrics.append({"operation": "cache_init", "duration_ms": cache_duration})
                logger.info(f"[CACHE] Multi-tier cache system initialized successfully ({cache_duration:.1f}ms)")
            else:
                logger.info("[CACHE] Caching disabled in configuration")
        except Exception as e:
            logger.warning(f"Cache initialization failed, continuing without cache: {e}")

        # Initialize database if available
        if database_manager:
            try:
                db_start = time.perf_counter()
                logger.info("Initializing database...")
                await database_manager.initialize()
                db_end = time.perf_counter()
                db_duration = (db_end - db_start) * 1000.0
                app.state.performance_metrics.append({"operation": "database_init", "duration_ms": db_duration})
                logger.info(f"[DB] Database initialized ({db_duration:.1f}ms)")
            except Exception as e:
                logger.error(f"[DB] Database initialization failed: {e}")
                # continue or raise depending on criticality; here we raise as DB is core
                raise

        # Validate security system components early during startup
        try:
            from plexichat.core.security.security_manager import get_security_system
            ss = get_security_system()
            # Basic validation of security system capabilities
            required_methods = [
                "validate_file_upload",
                "verify_token",
                "revoke_token",
                "validate_filename",
            ]
            missing = []
            for m in required_methods:
                if not hasattr(ss, m):
                    missing.append(m)
            if missing:
                logger.error(f"[SECURITY] Security system missing required methods: {missing}")
                # Mark but continue - depending on policy this could be fatal. We log and continue.
                app.state.security_validated = False
            else:
                logger.info("[SECURITY] Security system validation passed")
                app.state.security_validated = True
        except Exception as e:
            logger.warning(f"[SECURITY] Could not validate security system: {e}")
            app.state.security_validated = False

        # Initialize UnifiedAuthManager (ensure authentication initialized and attached to app state)
        try:
            from plexichat.core.authentication import initialize_auth_manager, get_auth_manager
            auth_start = time.perf_counter()
            
            # Try to initialize the auth manager with proper error handling
            auth_manager = None
            try:
                # First try async initialization
                auth_manager = await initialize_auth_manager()
                logger.debug("[AUTH] Used async auth manager initialization")
            except TypeError:
                # Fallback to synchronous initialization
                try:
                    auth_manager = initialize_auth_manager()
                    logger.debug("[AUTH] Used sync auth manager initialization")
                except Exception as sync_e:
                    logger.warning(f"[AUTH] Sync initialization failed: {sync_e}")
            except Exception as async_e:
                logger.warning(f"[AUTH] Async initialization failed: {async_e}")
                # Try synchronous as fallback
                try:
                    auth_manager = initialize_auth_manager()
                    logger.debug("[AUTH] Used sync auth manager initialization as fallback")
                except Exception as sync_fallback_e:
                    logger.error(f"[AUTH] Both async and sync initialization failed: {sync_fallback_e}")
            
            # Validate the auth manager
            if auth_manager:
                # Test basic functionality
                try:
                    status = auth_manager.get_security_status()
                    logger.debug(f"[AUTH] Auth manager status: {status}")
                except Exception as status_e:
                    logger.warning(f"[AUTH] Could not get auth manager status: {status_e}")
                
                app.state.auth_manager = auth_manager
                auth_end = time.perf_counter()
                auth_duration = (auth_end - auth_start) * 1000.0
                app.state.performance_metrics.append({"operation": "auth_manager_init", "duration_ms": auth_duration})
                logger.info(f"[AUTH] UnifiedAuthManager initialized successfully ({auth_duration:.1f}ms)")
            else:
                logger.error("[AUTH] Failed to initialize UnifiedAuthManager - auth_manager is None")
                app.state.auth_manager = None
                
        except ImportError as e:
            logger.error(f"[AUTH] Authentication module not available: {e}")
            app.state.auth_manager = None
        except Exception as e:
            logger.error(f"[AUTH] Failed to initialize UnifiedAuthManager: {e}")
            app.state.auth_manager = None

        # Initialize authentication cache system to speed up token verification
        try:
            from plexichat.core.performance.auth_cache import initialize_auth_cache
            auth_cache_start = time.perf_counter()
            await initialize_auth_cache()
            auth_cache_end = time.perf_counter()
            auth_cache_duration = (auth_cache_end - auth_cache_start) * 1000.0
            app.state.performance_metrics.append({"operation": "auth_cache_init", "duration_ms": auth_cache_duration})
            app.state.auth_cache_initialized = True
            logger.info(f"[AUTH_CACHE] Authentication cache initialized ({auth_cache_duration:.1f}ms)")
            # Ensure auth manager picks up cache if it wasn't available at construction time
            try:
                if getattr(app.state, "auth_manager", None) and getattr(app.state.auth_manager, "auth_cache", None) is None:
                    try:
                        # Try to attach cache to the auth manager if available via accessor
                        from plexichat.core.performance.auth_cache import get_auth_cache
                        ac = get_auth_cache()
                        if ac:
                            app.state.auth_manager.auth_cache = ac  # type: ignore
                            logger.info("[AUTH] Attached auth cache to UnifiedAuthManager")
                    except Exception:
                        # Non-fatal: continue
                        pass
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"[AUTH_CACHE] Authentication cache initialization failed: {e}")
            app.state.auth_cache_initialized = False

        # Initialize plugin manager (after SDK generation and auth manager)
        try:
            plugin_start = time.perf_counter()
            logger.info("[PLUGINS] Initializing plugin manager...")
            
            # Ensure plugins_internal.py is available before initializing plugins
            try:
                import plexichat.plugins_internal
                logger.debug("[PLUGINS] plugins_internal module is available")
            except ImportError as import_e:
                logger.warning(f"[PLUGINS] plugins_internal not available: {import_e}")
                # Try to regenerate it one more time
                try:
                    from plexichat.core.plugins.sdk_generator import generate_plugins_internal
                    if generate_plugins_internal():
                        logger.info("[PLUGINS] Successfully regenerated plugins_internal.py")
                    else:
                        logger.error("[PLUGINS] Failed to regenerate plugins_internal.py")
                except Exception as regen_e:
                    logger.error(f"[PLUGINS] Could not regenerate plugins_internal: {regen_e}")
            
            # Initialize the plugin manager
            await unified_plugin_manager.initialize()
            
            plugin_end = time.perf_counter()
            plugin_duration = (plugin_end - plugin_start) * 1000.0
            app.state.performance_metrics.append({"operation": "plugin_manager_init", "duration_ms": plugin_duration})
            logger.info(f"[PLUGINS] Plugin manager initialized successfully ({plugin_duration:.1f}ms)")
            
        except Exception as e:
            logger.error(f"[PLUGINS] Plugin manager initialization failed: {e}")
            # Don't raise here - continue without plugins if needed
            logger.warning("[PLUGINS] Continuing without plugin manager")

        # Initialize microsecond optimizer
        try:
            from plexichat.core.performance.microsecond_optimizer import start_microsecond_optimization
            perf_start = time.perf_counter()
            await start_microsecond_optimization()
            perf_end = time.perf_counter()
            perf_duration = (perf_end - perf_start) * 1000.0
            app.state.performance_metrics.append({"operation": "microsecond_optimizer_start", "duration_ms": perf_duration})
            logger.info(f"[PERF] Microsecond optimization started ({perf_duration:.1f}ms)")
        except ImportError as e:
            logger.warning(f"Microsecond optimizer not available: {e}")
        except Exception as e:
            logger.warning(f"Microsecond optimizer failed to start: {e}")

        overall_end = time.perf_counter()
        overall_duration = (overall_end - overall_start) * 1000.0
        app.state.performance_metrics.append({"operation": "startup_total", "duration_ms": overall_duration})
        logger.info("[CHECK] PlexiChat application started successfully with microsecond optimization")
        # Log a brief summary of key startup metrics
        try:
            metrics_summary = {m["operation"]: m["duration_ms"] for m in app.state.performance_metrics}
            logger.info(f"[METRICS] Startup performance summary: {metrics_summary}")
        except Exception:
            pass

    except Exception as e:
        logger.error(f"[X] Failed to start application: {e}")
        raise

    yield

    # Shutdown
    logger.info("[SHUTDOWN] Shutting down PlexiChat application...")
    try:
        # Shutdown cache system
        try:
            from plexichat.core.performance.multi_tier_cache_manager import get_cache_manager
            cache_manager = get_cache_manager()
            if hasattr(cache_manager, 'shutdown'):
                await cache_manager.shutdown()
            logger.info("[CACHE] Cache system shutdown completed")
        except Exception as e:
            logger.warning(f"Cache shutdown error: {e}")

        # Shutdown authentication cache
        try:
            from plexichat.core.performance.auth_cache import shutdown_auth_cache
            if app.state.auth_cache_initialized:
                await shutdown_auth_cache()
                logger.info("[AUTH_CACHE] Authentication cache shut down")
        except Exception as e:
            logger.warning(f"[AUTH_CACHE] Shutdown error: {e}")

        # Shutdown UnifiedAuthManager properly
        try:
            from plexichat.core.authentication import shutdown_auth_manager
            # Attempt to shut down global auth manager instance if present
            if app.state.auth_manager:
                try:
                    await shutdown_auth_manager()
                    logger.info("[AUTH] UnifiedAuthManager shut down successfully")
                except TypeError:
                    # fallback if shutdown_auth_manager is synchronous
                    try:
                        shutdown_auth_manager()
                        logger.info("[AUTH] UnifiedAuthManager shut down (sync fallback)")
                    except Exception as sync_e:
                        logger.warning(f"[AUTH] Sync shutdown failed: {sync_e}")
                except Exception as async_e:
                    logger.warning(f"[AUTH] Async shutdown failed: {async_e}")
                    # Try sync shutdown as fallback
                    try:
                        shutdown_auth_manager()
                        logger.info("[AUTH] UnifiedAuthManager shut down (sync fallback after async failure)")
                    except Exception as sync_fallback_e:
                        logger.warning(f"[AUTH] Both async and sync shutdown failed: {sync_fallback_e}")
            else:
                logger.debug("[AUTH] No auth manager to shut down")
        except ImportError as e:
            logger.debug(f"[AUTH] Auth manager shutdown not available: {e}")
        except Exception as e:
            logger.warning(f"[AUTH] Error shutting down UnifiedAuthManager: {e}")

        # Shutdown other services
        # Stop microsecond optimizer
        try:
            from plexichat.core.performance.microsecond_optimizer import stop_microsecond_optimization
            await stop_microsecond_optimization()
            logger.info("[SHUTDOWN] Microsecond optimization stopped")
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"[PERF] Error stopping microsecond optimizer: {e}")

        # Shutdown plugin manager
        try:
            if hasattr(unified_plugin_manager, 'shutdown'):
                await unified_plugin_manager.shutdown()
                logger.info("[PLUGINS] Plugin manager shut down")
        except Exception as e:
            logger.warning(f"[PLUGINS] Error shutting down plugin manager: {e}")

        # Cleanup resources
        if database_manager:
            logger.info("[DB] Closing database connections...")
            try:
                await database_manager.cleanup()
                logger.info("[DB] Database cleanup completed")
            except Exception as e:
                logger.warning(f"[DB] Error during database cleanup: {e}")

        # Ensure logs flushed for unified logging manager if available
        try:
            logging_manager = get_logging_manager()
            if hasattr(logging_manager, 'flush_logs'):
                logging_manager.flush_logs()
                logger.info("[LOGS] Flushed logs via unified logging manager")
        except Exception as e:
            logger.debug(f"[LOGS] Could not flush logs: {e}")

        logger.info("[CHECK] PlexiChat application shutdown complete")
    except Exception as e:
        logger.error(f"[X] Error during shutdown: {e}")

# Create FastAPI application with microsecond optimization
app = FastAPI(
    title=settings.app_name,
    description="Government-Level Secure Communication Platform - Microsecond Optimized",
    version=settings.version,  # Use version from config
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    # Optimize for performance
    generate_unique_id_function=lambda route: f"{route.tags[0] if route.tags else 'default'}-{route.name}",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1}  # Reduce swagger overhead
)

# Attach a simple runtime metrics store
app.state.runtime_metrics = {"requests_processed": 0, "startup_time_ms": None}
# WAF middleware temporarily disabled for testing
logger.info("[WAF] Web Application Firewall middleware temporarily disabled for testing")

# Setup routers and static files
setup_routers(app)
setup_static_files(app)

# Import the SecurityMiddleware and ensure proper integration
try:
    from plexichat.interfaces.web.middleware.security_middleware import SecurityMiddleware

    app.add_middleware(SecurityMiddleware)
    logger.info("[CHECK] Security middleware (CSRF, etc.) added.")
except ImportError as e:
    logger.warning(f"Security middleware not available: {e}")
except Exception as e:
    logger.warning(f"Error adding security middleware: {e}")

# Add production-ready security middleware (highest priority)
@app.middleware("http")
async def security_middleware(request, call_next):
    """Production-ready security middleware optimized for 10K+ req/min."""
    from fastapi.responses import JSONResponse

    # Helper to produce error responses using centralized error codes when available
    def _make_error_response(default_status: int, default_content: Dict[str, Any]):
        try:
            from plexichat.core.errors.error_codes import make_error_response, ErrorCode
            # map generic scenarios to ErrorCode when possible
            # For our two common cases below use pre-defined enums if present
            return make_error_response(default_status, default_content)
        except Exception:
            # Fallback to simple JSONResponse
            return JSONResponse(status_code=default_status, content=default_content)

    # Block dangerous HTTP methods (optimized set lookup)
    dangerous_methods = {"TRACE", "CONNECT", "DEBUG"}
    if request.method in dangerous_methods:
        return _make_error_response(
            405,
            {"error": "Method Not Allowed", "detail": "This HTTP method is not permitted"}
        )

    # Request validation using unified config
    content_length = request.headers.get("content-length")
    max_size_bytes = getattr(getattr(config, "network", None), "max_request_size_mb", 4) * 1024 * 1024
    if content_length:
        try:
            if int(content_length) > max_size_bytes:
                return _make_error_response(413, {"error": "Request Entity Too Large"})
        except Exception:
            # If header malformed, reject as bad request
            return _make_error_response(400, {"error": "Bad Request", "detail": "Invalid Content-Length header"})

    # Enforce additional security checks via security system if validated
    try:
        from plexichat.core.security.security_manager import get_security_system
        ss = get_security_system()
        if ss and hasattr(ss, "inspect_request"):
            # allow security manager to short-circuit requests (e.g., block malicious payloads)
            inspect_result = ss.inspect_request(request)
            if inspect_result is not None and getattr(inspect_result, "blocked", False):
                return _make_error_response(403, {"error": "Forbidden", "detail": "Blocked by security policy"})
    except Exception:
        # If security system not available or inspection fails, continue with basic checks
        pass

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
        # Header manipulation disabled to avoid MutableHeaders compatibility issues
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
        "enabled": getattr(getattr(config, "network", None), "rate_limit_enabled", False),
        "requests_per_minute": getattr(getattr(config, "network", None), "rate_limit_requests_per_minute", 6000),
        "burst_limit": getattr(getattr(config, "network", None), "rate_limit_burst_limit", 1000),
        "ddos_protection": True,
        "dynamic_scaling": True
    }
    protection_middleware = IntegratedProtectionMiddleware(rate_limit_config)

    @app.middleware("http")
    async def integrated_protection_middleware(request, call_next):
        """Integrated protection with DDoS prevention, rate limiting, and dynamic scaling."""
        # Mark that we registered a protection middleware via decorated handler
        app.state.protection_middleware_registered = True
        return await protection_middleware(request, call_next)

    logger.info("  Integrated Protection System enabled (DDoS + Rate Limiting + Dynamic Scaling)")
except Exception as e:
    logger.warning(f"Integrated protection middleware not available: {e}")

    # Fallback to basic rate limiting using unified config
    try:
        from plexichat.core.middleware.unified_rate_limiter import RateLimitMiddleware

        # Use unified config for rate limiting
        fallback_rate_config = {
            "enabled": getattr(getattr(config, "network", None), "rate_limit_enabled", False),
            "requests_per_minute": getattr(getattr(config, "network", None), "rate_limit_requests_per_minute", 6000),
            "burst_limit": getattr(getattr(config, "network", None), "rate_limit_burst_limit", 1000)
        }
        rate_limit_middleware = RateLimitMiddleware(fallback_rate_config)

        @app.middleware("http")
        async def fallback_rate_limiting_middleware(request, call_next):
            """Fallback rate limiting middleware."""
            # Mark we registered a protection-like middleware
            app.state.protection_middleware_registered = True
            return await rate_limit_middleware(request, call_next)

        logger.info("  Fallback rate limiting middleware enabled")
    except Exception as e2:
        logger.error(f"No protection middleware available: {e2}")

# Add microsecond performance middleware second (kept lightweight and near the edge)
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

        # Track long-running requests for alerting
        try:
            if duration_us > 50000:  # 50ms threshold in microseconds
                logger.warning(f"[PERF] Slow request detected: {duration_us/1000.0:.2f}ms")
        except Exception:
            pass

        return response

    logger.info("[PERF] Microsecond performance middleware added")
except Exception as e:
    logger.warning(f"Microsecond performance middleware error: {e}")

# Attempt to add IntegratedProtectionMiddleware via add_middleware only if not already registered
try:
    from plexichat.core.middleware.integrated_protection_system import IntegratedProtectionMiddleware as _IPS
    if not getattr(app.state, "protection_middleware_registered", False):
        try:
            app.add_middleware(_IPS, rate_limit_config=asdict(config.network.rate_limiting) if hasattr(config.network, "rate_limiting") else {})
            app.state.protection_middleware_registered = True
            logger.info("[CHECK] Integrated protection middleware added via add_middleware")
        except Exception as e:
            logger.warning(f"Integrated protection middleware add_middleware failed: {e}")
    else:
        logger.info("[CHECK] Integrated protection middleware already registered via decorated handler")
except ImportError as e:
    logger.warning(f"Integrated protection middleware not available: {e}")
except Exception as e:
    logger.warning(f"Integrated protection middleware error: {e}")

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
    cors_origins = getattr(getattr(config, "network", None), "cors_origins", [])
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

from plexichat.core.errors import not_found_handler, internal_error_handler

app.add_exception_handler(404, not_found_handler)
app.add_exception_handler(500, internal_error_handler)

# Module exports
__all__ = ['app', 'config']

# Save startup time metric if available
try:
    # Attempt to set startup_time_ms from lifecycle metrics if present
    if hasattr(app.state, "performance_metrics"):
        total = 0.0
        for m in app.state.performance_metrics:
            if m.get("operation") == "startup_total":
                total = m.get("duration_ms", 0.0)
                break
        app.state.runtime_metrics["startup_time_ms"] = total
except Exception:
    pass

logger.info(f"[PACKAGE] PlexiChat main module initialized (config loaded: {bool(config)})")
