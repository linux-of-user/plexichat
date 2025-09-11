# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Login Router

Enhanced login interface with comprehensive authentication and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.core.logging import get_performance_logger, timer
    from plexichat.core.performance.optimization_engine import (
        PerformanceOptimizationEngine,
    )
    from plexichat.infrastructure.utils.performance import async_track_performance
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Authentication imports - use unified FastAPI auth adapter
from plexichat.core.auth.fastapi_adapter import get_current_user

# Use Unified Auth Manager for authentication operations
from plexichat.core.authentication import AuthResult, get_auth_manager

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        JWT_SECRET = "mock-secret"
        JWT_ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30
    settings = MockSettings()

# Model imports

# Unified logging
from plexichat.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/login", tags=["login"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Pydantic models
class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]

class LoginService:
    """Service class for login operations using the UnifiedAuthManager and EXISTING database abstraction layer."""

    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        # Use global auth manager
        self.auth_manager = get_auth_manager()

    @async_track_performance("user_authentication") if async_track_performance else (lambda f: f)
    async def authenticate_user(self, username: str, password: str, ip_address: str | None = None, user_agent: str | None = None) -> AuthResult | None:
        """
        Authenticate user using UnifiedAuthManager.
        Returns AuthResult on success/failure.
        """
        try:
            # Delegate authentication to the unified auth manager which integrates with the SecuritySystem
            auth_result: AuthResult = await self.auth_manager.authenticate_user(username, password, ip_address=ip_address, user_agent=user_agent)

            # If authentication succeeded, return the AuthResult directly
            if auth_result and getattr(auth_result, "success", False):
                # Optionally update last login in the database if available
                try:
                    if self.db_manager and auth_result.user_id:
                        await self.update_last_login(int(auth_result.user_id))
                except Exception as e:
                    # Log but don't fail authentication because of last-login update issues
                    logger.debug(f"Failed to update last login for user {auth_result.user_id}: {e}")

                return auth_result

            return auth_result

        except Exception as e:
            logger.error(f"Error authenticating user via UnifiedAuthManager: {e}")
            return None

    @async_track_performance("last_login_update") if async_track_performance else (lambda f: f)
    async def update_last_login(self, user_id: int):
        """Update user's last login timestamp in the database if available."""
        if self.db_manager:
            try:
                query = "UPDATE users SET last_login = :last_login WHERE id = :id"
                params = {"last_login": datetime.now(), "id": user_id}

                await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error updating last login: {e}")

# Initialize service
login_service = LoginService()

@router.get("/")
async def login_page(request: Request):
    """Display login page with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Login page accessed from {client_ip}")

    # Performance tracking
    if performance_logger:
        performance_logger.increment_counter("login_page_requests", 1)

    # Generate login page HTML
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Login</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                width: 100%;
                max-width: 400px;
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #333;
                margin: 0 0 10px 0;
            }
            .login-header p {
                color: #666;
                margin: 0;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 5px;
                color: #333;
                font-weight: bold;
            }
            .form-group input {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                box-sizing: border-box;
            }
            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 5px rgba(102, 126, 234, 0.3);
            }
            .login-button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            .login-button:hover {
                transform: translateY(-2px);
            }
            .error-message {
                background: #f8d7da;
                color: #721c24;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 20px;
                display: none;
            }
            .footer {
                text-align: center;
                margin-top: 20px;
                color: #666;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>PlexiChat</h1>
                <p>Sign in to your account</p>
            </div>

            <div id="error-message" class="error-message"></div>

            <form id="login-form" method="post" action="/login/authenticate">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="login-button">Sign In</button>
            </form>

            <div class="footer">
                <p>&copy; 2024 PlexiChat. All rights reserved.</p>
            </div>
        </div>

        <script>
            document.getElementById('login-form').addEventListener('submit', async function(e) {
                e.preventDefault();

                const formData = new FormData(this);
                const errorDiv = document.getElementById('error-message');

                try {
                    const response = await fetch('/login/authenticate', {
                        method: 'POST',
                        body: formData
                    });

                    if (response.ok) {
                        const data = await response.json();
                        localStorage.setItem('access_token', data.access_token);
                        window.location.href = '/web/dashboard';
                    } else {
                        const error = await response.json();
                        errorDiv.textContent = error.detail || 'Login failed';
                        errorDiv.style.display = 'block';
                    }
                } catch (error) {
                    errorDiv.textContent = 'Network error. Please try again.';
                    errorDiv.style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)

@router.post("/")
async def authenticate(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Authenticate user and return access token with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Login attempt for user '{username}' from {client_ip}")

    # Performance tracking
    if performance_logger:
        performance_logger.increment_counter("login_attempts", 1)

    try:
        # Authenticate user using unified auth manager via service
        auth_result = await login_service.authenticate_user(username, password, ip_address=client_ip, user_agent=request.headers.get("user-agent", ""))

        if not auth_result or not getattr(auth_result, "success", False):
            # Performance tracking for failed login
            if performance_logger:
                performance_logger.increment_counter("login_failures", 1)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )

        # Use the token returned by the UnifiedAuthManager if present, otherwise create one
        access_token_expires = timedelta(minutes=getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30))

        access_token = getattr(auth_result, "token", None)
        if not access_token:
            try:
                # Create a token using the auth manager directly
                access_token = login_service.auth_manager.create_access_token(
                    str(auth_result.user_id),
                    getattr(auth_result, "permissions", set()),
                    expires_delta=access_token_expires
                )
            except Exception as e:
                logger.error(f"Failed to create access token: {e}")
                access_token = ""

        # Performance tracking for successful login
        if performance_logger:
            performance_logger.increment_counter("login_successes", 1)

        # Attempt to resolve user profile information (username, email) from DB if available
        user_info = {
            "id": auth_result.user_id,
            "username": None,
            "email": None,
            "is_active": True
        }
        try:
            if database_manager and auth_result.user_id:
                query = "SELECT username, email, is_active FROM users WHERE id = :id"
                params = {"id": int(auth_result.user_id)}
                result = await database_manager.execute_query(query, params)
                if result and len(result) > 0:
                    row = result[0]
                    user_info["username"] = row[0]
                    user_info["email"] = row[1]
                    user_info["is_active"] = bool(row[2])
        except Exception as e:
            logger.debug(f"Could not fetch user profile from DB: {e}")

        # Fallback username if not resolved
        if not user_info["username"]:
            # Try to extract from security context if available
            sec_ctx = getattr(auth_result, "security_context", None)
            uname = None
            if sec_ctx:
                uname = getattr(sec_ctx, "username", None)
            user_info["username"] = uname or str(auth_result.user_id)

        logger.info(f"User '{user_info.get('username')}' logged in successfully")

        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=int(access_token_expires.total_seconds()),
            user=user_info
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user)
):
    """Logout user (token invalidation would be handled by client)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"User '{current_user.get('username')}' logged out from {client_ip}")

    # Performance tracking
    if performance_logger:
        performance_logger.increment_counter("logout_requests", 1)

    return {"message": "Successfully logged out"}

@router.get("/status")
async def login_status(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user)
):
    """Check current login status."""
    client_ip = request.client.host if request.client else "unknown"

    # Log the status check
    logger.info(f"Login status check from {client_ip}")

    # Performance tracking
    if performance_logger:
        performance_logger.increment_counter("login_status_checks", 1)

    return {
        "logged_in": True,
        "user": {
            "id": current_user.get("id"),
            "username": current_user.get("username"),
            "is_admin": current_user.get("is_admin", False)
        }
    }
