import asyncio
import logging
from typing import Any, Callable, Dict

from flask import g, jsonify, request

from .manager_auth import auth_manager
from .exceptions_auth import AuthenticationError, AuthorizationError


from fastapi import HTTPException

"""
PlexiChat Authentication Middleware

Middleware for web frameworks to handle authentication automatically.
"""

logger = logging.getLogger(__name__)


class AuthenticationMiddleware:
    """
    Authentication middleware for web applications.

    Automatically handles token extraction, validation, and context injection.
    """

    def __init__(self, app: Callable, config: Dict[str, Any] = None):
        self.app = app
        self.config = config or {}

        # Configuration
        self.token_header = self.config.get("token_header", "Authorization")
        self.token_prefix = self.config.get("token_prefix", "Bearer ")
        self.exclude_paths = set(self.config.get("exclude_paths", []))
        self.require_auth_by_default = self.config.get("require_auth_by_default", False)
        self.default_security_level = self.config.get("default_security_level", "BASIC")

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable):
        """ASGI middleware entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if path should be excluded
        path = scope.get("path", "")
        if path in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        # Extract token from headers
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(self.token_header.lower().encode(), b"").decode()

        token = None
        if auth_header.startswith(self.token_prefix):
            token = auth_header[len(self.token_prefix) :]

        # Validate token if present
        auth_context = None
        if token:
            try:
                auth_context = await auth_manager.require_authentication(
                    token, self.default_security_level
                )
            except (AuthenticationError, AuthorizationError) as e:
                if self.require_auth_by_default:
                    await self._send_auth_error(send, str(e))
                    return
        elif self.require_auth_by_default:
            await self._send_auth_error(send, "Authentication required")
            return

        # Add auth context to scope
        scope["auth_context"] = auth_context
        scope["authenticated"] = auth_context is not None

        await self.app(scope, receive, send)

    async def _send_auth_error(self, send: Callable, message: str):
        """Send authentication error response."""
        response_body = f'{{"error": "{message}"}}'.encode()

        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(response_body)).encode()],
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": response_body,
            }
        )


class FlaskAuthMiddleware:
    """Authentication middleware for Flask applications."""

    def __init__(self, app, config: Dict[str, Any] = None):
        self.app = app
        self.config = config or {}

        # Register before_request handler
        app.before_request(self.before_request)

    def before_request(self):
        """Flask before_request handler."""
        # Check if path should be excluded
        if request.path in self.config.get("exclude_paths", []):
            return

        # Extract token
        auth_header = request.headers.get("Authorization", "")
        token = None

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        # Validate token
        g.auth_context = None
        g.authenticated = False

        if token:
            try:
                loop = asyncio.get_event_loop()
                g.auth_context = loop.run_until_complete(
                    auth_manager.require_authentication(token, "BASIC")
                )
                g.authenticated = True
            except (AuthenticationError, AuthorizationError):
                if self.config.get("require_auth_by_default", False):
                    return jsonify({"error": "Authentication failed"}), 401


class FastAPIAuthMiddleware:
    """Authentication middleware for FastAPI applications."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    async def __call__(self, request, call_next):
        """FastAPI middleware handler."""
        # Check if path should be excluded
        if request.url.path in self.config.get("exclude_paths", []):
            return await call_next(request)

        # Extract token
        auth_header = request.headers.get("authorization", "")
        token = None

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        # Validate token
        auth_context = None
        if token:
            try:
                auth_context = await auth_manager.require_authentication(token, "BASIC")
            except (AuthenticationError, AuthorizationError):
                if self.config.get("require_auth_by_default", False):
                    raise HTTPException(status_code=401, detail="Authentication failed")

        # Add to request state
        request.state.auth_context = auth_context
        request.state.authenticated = auth_context is not None

        return await call_next(request)
