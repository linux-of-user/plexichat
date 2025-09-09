from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .base import PlexiChatErrorCode, create_error_response

# Try to import settings with fallback
try:
    from .config import settings  # type: ignore
except ImportError:
    # Fallback settings if config import fails
    class FallbackSettings:
        app_name = "PlexiChat"

    settings = FallbackSettings()


async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors."""
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Page Not Found | {settings.app_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1 {{ color: #e74c3c; }}
                .path {{ background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }}
                .links {{ margin-top: 30px; }}
                .links a {{ color: #3498db; text-decoration: none; margin-right: 20px; }}
                .links a:hover {{ text-decoration: underline; }}
                .version {{ color: #7f8c8d; font-size: 0.9em; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>404 - Page Not Found</h1>
                <p>The requested resource was not found on this server.</p>
                <div class="path">Path: {request.url.path}</div>
                <div class="links">
                    <a href="/">Home</a>
                    <a href="/docs">API Documentation</a>
                    <a href="/health">Health Check</a>
                </div>
                <div class="version">{settings.app_name} 1.0.0</div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=404)

    # Use base create_error_response for JSON
    return JSONResponse(
        status_code=404,
        content=create_error_response(
            PlexiChatErrorCode.FILE_NOT_FOUND,
            details={"path": str(request.url.path)}
        ),
    )


async def internal_error_handler(request: Request, exc: Exception):
    """Handle 500 errors."""
    # Use base create_error_response for consistent error handling
    return JSONResponse(
        status_code=500,
        content=create_error_response(PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR),
    )