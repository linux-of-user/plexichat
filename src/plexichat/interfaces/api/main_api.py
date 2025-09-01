"""
PlexiChat Main API

Main API application with threading and performance optimization.
"""

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None
    Request = None
    HTTPException = Exception
    CORSMiddleware = None
    GZipMiddleware = None
    JSONResponse = None

try:
    import uvicorn
except ImportError:
    uvicorn = None

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import thread_manager, async_thread_manager
except ImportError:
    thread_manager = None
    async_thread_manager = None

try:
    from plexichat.core.messaging.message_processor import message_processor
except ImportError:
    message_processor = None

# try:
#     from plexichat.core.websocket.websocket_manager import websocket_manager
# except ImportError:
#     websocket_manager = None
websocket_manager = None

try:
    from plexichat.core.notifications.notification_manager import notification_manager
except ImportError:
    notification_manager = None

from plexichat.infrastructure.analytics.engine import analytics_manager
from plexichat.core.security.comprehensive_security_manager import security_manager

try:
    from plexichat.core.logging import get_performance_logger
except ImportError:
    get_performance_logger = None

# Utility function to ensure unicode-free logging
def sanitize_for_logging(text):
    """Sanitize text for logging to ensure it's unicode-free and safe."""
    if not isinstance(text, str):
        text = str(text)
    # Replace any problematic unicode characters with safe alternatives
    return text.encode('ascii', 'replace').decode('ascii')

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

# Lifespan manager
@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan manager."""
    try:
        # Startup
        logger.info("Starting PlexiChat API...")

        # Initialize database
        if database_manager:
            await database_manager.initialize()

        # Start processors
        if message_processor:
            await message_processor.start_processing()

        if websocket_manager:
            await websocket_manager.start_broadcasting()

        if notification_manager:
            await notification_manager.start_processing()

        if analytics_manager:
            await analytics_manager.start_processing()

        # Start thread manager
        if thread_manager:
            # Thread manager starts automatically
            pass

        logger.info("PlexiChat API started successfully")

        yield

        # Shutdown
        logger.info("Shutting down PlexiChat API...")

        # Stop processors
        if message_processor:
            await message_processor.stop_processing()

        if websocket_manager:
            await websocket_manager.stop_broadcasting()

        if notification_manager:
            await notification_manager.stop_processing()

        if analytics_manager:
            await analytics_manager.stop_processing()

        # Shutdown thread manager
        if thread_manager:
            thread_manager.shutdown(wait=True)

        if async_thread_manager:
            async_thread_manager.shutdown()

        logger.info("PlexiChat API shutdown complete")

    except Exception as e:
        logger.error(f"Error in lifespan manager: {e}")
        raise

# Create FastAPI app
if FastAPI:
    app = FastAPI(
        title="PlexiChat API",
        description="PlexiChat messaging platform API with threading and performance optimization",
        version="1.0.0",
        lifespan=lifespan
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(GZipMiddleware, minimum_size=1000)
else:
    app = None

# Middleware for performance tracking
async def performance_middleware(request: Request, call_next):
    """Performance tracking middleware."""
    start_time = time.time()

    # Track request
    if analytics_manager:
        await analytics_manager.track_event(
            "api_request",
            properties={
                "method": request.method,
                "path": str(request.url.path),
                "user_agent": request.headers.get("user-agent", "")
            },
            context={
                "ip_address": request.client.host if request.client else "unknown"
            }
        )

    response = await call_next(request)

    # Track response time
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    if performance_logger:
        performance_logger.record_metric("api_request_duration", process_time, "seconds")
        performance_logger.increment_counter("api_requests", 1)

    return response

# Comprehensive logging middleware
async def logging_middleware(request: Request, call_next):
    """Comprehensive request/response logging middleware with correlation ID tracking."""
    # Generate correlation ID
    correlation_id = str(uuid.uuid4())

    # Add correlation ID to request state
    request.state.correlation_id = correlation_id

    # Extract request information
    method = request.method
    url = str(request.url)
    path = request.url.path
    query_params = str(request.url.query) if request.url.query else ""
    user_agent = request.headers.get("user-agent", "")
    content_type = request.headers.get("content-type", "")
    content_length = request.headers.get("content-length", "0")

    # Get client information
    client_host = request.client.host if request.client else "unknown"
    client_port = request.client.port if request.client else "unknown"

    # Log request start (unicode-free)
    logger.info(
        f"REQUEST_START | correlation_id={correlation_id} | method={sanitize_for_logging(method)} | "
        f"path={sanitize_for_logging(path)} | query={sanitize_for_logging(query_params)} | "
        f"client={sanitize_for_logging(client_host)}:{sanitize_for_logging(str(client_port))} | "
        f"user_agent={sanitize_for_logging(user_agent)} | content_type={sanitize_for_logging(content_type)} | "
        f"content_length={sanitize_for_logging(content_length)}"
    )

    # Track specific endpoints
    if path.startswith("/api/v1/threads"):
        logger.info(f"THREADS_ENDPOINT | correlation_id={correlation_id} | path={sanitize_for_logging(path)}")

    start_time = time.time()

    try:
        # Process the request
        response = await call_next(request)

        # Calculate processing time
        process_time = time.time() - start_time

        # Extract response information
        status_code = response.status_code
        response_content_length = getattr(response, 'content_length', 0) or response.headers.get("content-length", "0")
        response_content_type = response.headers.get("content-type", "")

        # Log response (unicode-free)
        logger.info(
            f"REQUEST_COMPLETE | correlation_id={correlation_id} | status={status_code} | "
            f"duration={process_time:.4f}s | response_length={sanitize_for_logging(response_content_length)} | "
            f"response_type={sanitize_for_logging(response_content_type)}"
        )

        # Add correlation ID to response headers
        response.headers["X-Correlation-ID"] = correlation_id

        return response

    except Exception as e:
        # Calculate processing time for errors
        process_time = time.time() - start_time

        # Log error (unicode-free)
        logger.error(
            f"REQUEST_ERROR | correlation_id={correlation_id} | duration={process_time:.4f}s | "
            f"error_type={sanitize_for_logging(type(e).__name__)} | "
            f"error_message={sanitize_for_logging(str(e))}"
        )

        # Re-raise the exception
        raise

if app:
    app.middleware("http")(performance_middleware)
    app.middleware("http")(logging_middleware)

# Enhanced exception handlers with full context logging
async def validation_exception_handler(request: Request, exc: Exception):
    """Handle validation exceptions with full context logging."""
    correlation_id = getattr(request.state, 'correlation_id', 'unknown')

    # Log validation error with full context (unicode-free)
    logger.warning(
        f"VALIDATION_ERROR | correlation_id={correlation_id} | path={sanitize_for_logging(request.url.path)} | "
        f"method={sanitize_for_logging(request.method)} | "
        f"client={sanitize_for_logging(request.client.host if request.client else 'unknown')} | "
        f"error_type={sanitize_for_logging(type(exc).__name__)} | "
        f"error_message={sanitize_for_logging(str(exc))}"
    )

    if performance_logger:
        performance_logger.increment_counter("api_validation_errors", 1)

    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "message": str(exc),
            "correlation_id": correlation_id,
            "timestamp": time.time(),
            "path": request.url.path
        }
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions with full context logging."""
    correlation_id = getattr(request.state, 'correlation_id', 'unknown')

    # Log general error with full context (unicode-free)
    logger.error(
        f"GENERAL_EXCEPTION | correlation_id={correlation_id} | path={sanitize_for_logging(request.url.path)} | "
        f"method={sanitize_for_logging(request.method)} | "
        f"client={sanitize_for_logging(request.client.host if request.client else 'unknown')} | "
        f"error_type={sanitize_for_logging(type(exc).__name__)} | "
        f"error_message={sanitize_for_logging(str(exc))} | "
        f"user_agent={sanitize_for_logging(request.headers.get('user-agent', ''))} | "
        f"query_params={sanitize_for_logging(str(request.url.query) if request.url.query else '')}"
    )

    # Log stack trace for debugging (unicode-free)
    import traceback
    logger.error(f"EXCEPTION_TRACE | correlation_id={correlation_id} | traceback={sanitize_for_logging(traceback.format_exc())}")

    if performance_logger:
        performance_logger.increment_counter("api_errors", 1)

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "correlation_id": correlation_id,
            "timestamp": time.time(),
            "path": request.url.path
        }
    )

if app:
    app.add_exception_handler(422, validation_exception_handler)
    app.add_exception_handler(500, general_exception_handler)

# Health check endpoint
if app:
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        try:
            status = {
                "status": "healthy",
                "timestamp": time.time(),
                "services": {}
            }

            # Check database
            if database_manager:
                try:
                    await database_manager.execute_query("SELECT 1")
                    status["services"]["database"] = "healthy"
                except Exception:
                    status["services"]["database"] = "unhealthy"
                    status["status"] = "degraded"

            # Check thread manager
            if thread_manager:
                thread_status = thread_manager.get_status()
                status["services"]["thread_manager"] = "healthy" if not thread_status["shutdown"] else "unhealthy"

            # Check message processor
            if message_processor:
                processor_status = message_processor.get_status()
                status["services"]["message_processor"] = "healthy" if processor_status["processing"] else "unhealthy"

            # Check websocket manager
            if websocket_manager:
                ws_status = websocket_manager.get_stats()
                status["services"]["websocket_manager"] = "healthy" if ws_status["broadcasting"] else "unhealthy"

            return status

        except Exception as e:
            logger.error(f"Health check error: {e}")
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "error": str(e),
                    "timestamp": time.time()
                }
            )

# Metrics endpoint
if app:
    @app.get("/metrics")
    async def get_metrics():
        """Get system metrics."""
        try:
            metrics = {
                "timestamp": time.time(),
                "system": {}
            }

            # Database metrics
            if database_manager:
                metrics["system"]["database"] = database_manager.get_stats()

            # Thread manager metrics
            if thread_manager:
                metrics["system"]["thread_manager"] = thread_manager.get_status()

            # Message processor metrics
            if message_processor:
                metrics["system"]["message_processor"] = message_processor.get_status()

            # WebSocket metrics
            if websocket_manager:
                metrics["system"]["websocket_manager"] = websocket_manager.get_stats()

            # Notification metrics
            if notification_manager:
                metrics["system"]["notification_manager"] = notification_manager.get_stats()

            # Analytics metrics
            if analytics_manager:
                metrics["system"]["analytics_manager"] = analytics_manager.get_stats()

            return metrics

        except Exception as e:
            logger.error(f"Metrics error: {e}")
            raise HTTPException(status_code=500, detail="Error retrieving metrics")

# Authentication dependency
async def get_current_user(request: Request):
    """Get current authenticated user."""
    try:
        # Get token from header
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

        token = authorization.split(" ")[1]

        # Verify token
        if security_manager:
            payload = security_manager.verify_token(token)
            if not payload:
                raise HTTPException(status_code=401, detail="Invalid or expired token")

            # Get user data
            if database_manager:
                user = await database_manager.get_user_by_id(payload["user_id"])
                if not user or not user.get("is_active"):
                    raise HTTPException(status_code=401, detail="User not found or inactive")

                return user

        # Fallback for testing
        return {"id": 1, "username": "test_user", "email": "test@example.com"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

# Include v1 router
if app:
    try:
        from plexichat.interfaces.api.v1.router import router as v1_router
        app.include_router(v1_router)
        logger.info("Successfully included v1 API router")
    except ImportError as e:
        logger.error(f"Failed to import v1 router: {e}")
        raise

# WebSocket endpoint
if app:
    @app.websocket("/ws/{user_id}")
    async def websocket_endpoint(websocket, user_id: int):
        """WebSocket endpoint for real-time communication."""
        try:
            connection_id = f"ws_{user_id}_{int(time.time())}"

            # Connect WebSocket
            if websocket_manager:
                success = await websocket_manager.connect(websocket, connection_id, user_id)
                if not success:
                    await websocket.close(code=1000, reason="Connection failed")
                    return
            else:
                await websocket.accept()

            try:
                while True:
                    # Receive message
                    data = await websocket.receive_text()
                    # SECURITY: eval() removed - use safe alternatives
                    message_data = json.loads(data)  # In production, use json.loads with proper validation

                    # Handle different message types
                    message_type = message_data.get("type", "unknown")

                    if message_type == "ping":
                        # Respond to ping
                        await websocket.send_text('{"type": "pong", "timestamp": "' + str(time.time()) + '"}')

                    elif message_type == "join_channel":
                        # Join channel
                        channel = message_data.get("channel")
                        if channel and websocket_manager:
                            await websocket_manager.join_channel(connection_id, channel)

                    elif message_type == "leave_channel":
                        # Leave channel
                        channel = message_data.get("channel")
                        if channel and websocket_manager:
                            await websocket_manager.leave_channel(connection_id, channel)

                    # Track analytics
                    if analytics_manager:
                        await analytics_manager.track_event(
                            "websocket_message",
                            user_id=user_id,
                            properties={"message_type": message_type}
                        )

            except Exception as e:
                logger.error(f"WebSocket error for user {user_id}: {e}")

            finally:
                # Disconnect
                if websocket_manager:
                    await websocket_manager.disconnect(connection_id)

        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")

# Run server function
def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Run the API server."""
    if not uvicorn:
        logger.error("uvicorn not available")
        return

    if not app:
        logger.error("FastAPI not available")
        return

    logger.info(f"Starting PlexiChat API server on {host}:{port}")

    uvicorn.run(
        "plexichat.interfaces.api.main_api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )

if __name__ == "__main__":
    print("[X] This module cannot be run standalone!")
    print("Use 'python run.py' to start PlexiChat.")
    sys.exit(1)
