"""FastAPI error handlers using base error creation for consistency."""
from fastapi import Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from .base import create_error_response, PlexiChatErrorCode

async def not_found_handler(request: Request, exc: FastAPIHTTPException):
    """404 handler: use base for JSON, preserve HTML for user-friendliness."""
    if request.headers.get("accept") == "application/json":
        details = {"path": str(request.url.path)}
        error_response = create_error_response(
            PlexiChatErrorCode.FILE_NOT_FOUND.value, 
            details=details
        )
        return JSONResponse(status_code=404, content=error_response.to_dict())
    else:
        # Preserve HTML response as-is for non-JSON requests
        return HTMLResponse(
            status_code=404,
            content=f"<h1>404 Not Found</h1><p>The requested path {request.url.path} was not found.</p>"
        )

async def internal_error_handler(request: Request, exc: Exception):
    """500 handler: use base for JSON, preserve simple HTML."""
    if request.headers.get("accept") == "application/json":
        error_response = create_error_response(PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR.value)
        return JSONResponse(status_code=500, content=error_response.to_dict())
    else:
        # Preserve simple HTML for internal errors
        return HTMLResponse(
            status_code=500,
            content="<h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p>"
        )

# Integration with FastAPI app would be in main app file, e.g.:
# app.add_exception_handler(HTTPException, not_found_handler)
# app.add_exception_handler(Exception, internal_error_handler)

# No direct duplications removed; inline simplifications using base
# Preserve HTML responses for 404/500 (non-breaking)
# Expected reduction: ~10 lines through simplifications
# Ensure FastAPI integration unchanged externally