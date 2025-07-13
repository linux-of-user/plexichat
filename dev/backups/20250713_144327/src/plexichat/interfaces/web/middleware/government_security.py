import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Response

from starlette.middleware.base import BaseHTTPMiddleware


from datetime import datetime



from datetime import datetime

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from plexichat.core.security.government_auth import government_auth

"""
Government-Level Security Middleware
Protects all endpoints except /docs with ultra-secure authentication.
"""

logger = logging.getLogger(__name__)


class GovernmentSecurityMiddleware(BaseHTTPMiddleware):
    """Government-level security middleware."""

    def __init__(self, app):
        super().__init__(app)
        self.auth_system = government_auth

        # Public paths that don't require authentication
        self.public_paths = {
            '/docs',
            '/redoc',
            '/openapi.json',
            '/favicon.ico',
            '/static',
            '/api/docs'
        }

        # Login paths
        self.login_paths = {
            '/login',
            '/api/auth/login',
            '/api/auth/2fa'
        }

        logger.info("Government security middleware initialized")

    async def dispatch(self, request: Request, call_next):
        """Main security dispatch."""
        start_time = time.time()
        path = str(request.url.path)

        try:
            # Check if path is public
            if self._is_public_path(path):
                response = await call_next(request)
                self._add_security_headers(response)
                return response

            # Check if path is login-related
            if self._is_login_path(path):
                response = await self._handle_login_request(request, call_next)
                self._add_security_headers(response)
                return response

            # All other paths require authentication
            auth_result = await self._authenticate_request(request)

            if not auth_result['authenticated']:
                return self._create_auth_required_response(request, auth_result)

            # Add user info to request state
            request.state.user = auth_result['user']
            request.state.session_token = auth_result['session_token']

            # Process request
            response = await call_next(request)

            # Add security headers
            self._add_security_headers(response)

            # Log access
            await self._log_access(request, response, time.time() - start_time)

            return response

        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={'error': 'Internal security error'}
            )

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public."""
        return any(path.startswith(public_path) for public_path in self.public_paths)

    def _is_login_path(self, path: str) -> bool:
        """Check if path is login-related."""
        return any(path.startswith(login_path) for login_path in self.login_paths)

    async def _handle_login_request(self, request: Request, call_next):
        """Handle login requests."""
        if request.method == "POST":
            # Process login attempt
            try:
                body = await request.body()
                if body:
                    data = json.loads(body.decode())
                    username = data.get('username')
                    password = data.get('password')
                    totp_code = data.get('totp_code')

                    if username and password:
                        auth_result = self.auth_system.authenticate(username, password, totp_code)

                        if auth_result['success']:
                            # Create response with session cookie
                            response_data = {
                                'success': True,
                                'message': 'Login successful',
                                'must_change_password': auth_result.get('must_change_password', False),
                                'requires_2fa': auth_result.get('requires_2fa', False)
                            }

                            response = JSONResponse(content=response_data)

                            # Set secure session cookie
                            response.set_cookie(
                                key="session_token",
                                value=auth_result['session_token'],
                                httponly=True,
                                secure=True,
                                samesite="strict",
                                max_age=3600  # 1 hour
                            )

                            return response
                        else:
                            return JSONResponse(
                                status_code=401,
                                content={
                                    'success': False,
                                    'error': auth_result['error'],
                                    'requires_2fa': auth_result.get('requires_2fa', False)
                                }
                            )
            except Exception as e:
                logger.error(f"Login processing error: {e}")
                return JSONResponse(
                    status_code=400,
                    content={'error': 'Invalid login request'}
                )

        # For GET requests or other methods, proceed normally
        return await call_next(request)

    async def _authenticate_request(self, request: Request) -> Dict[str, Any]:
        """Authenticate request using session token."""
        # Check for session token in cookie
        session_token = request.cookies.get('session_token')

        # Also check Authorization header as fallback
        if not session_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                session_token = auth_header[7:]

        if not session_token:
            return {
                'authenticated': False,
                'reason': 'No session token provided'
            }

        # Validate session
        session_data = self.auth_system.validate_session(session_token)

        if not session_data:
            return {
                'authenticated': False,
                'reason': 'Invalid or expired session'
            }

        return {
            'authenticated': True,
            'user': session_data['username'],
            'session_token': session_token,
            'session_data': session_data
        }

    def _create_auth_required_response(self, request: Request, auth_result: Dict[str, Any]):
        """Create authentication required response."""
        path = str(request.url.path)

        # For API requests, return JSON
        if path.startswith('/api/'):
            return JSONResponse(
                status_code=401,
                content={
                    'error': 'Authentication required',
                    'reason': auth_result['reason'],
                    'login_url': '/login'
                }
            )

        # For web requests, return login page or redirect
        if request.headers.get('accept', '').startswith('text/html'):
            return self._create_login_page()
        else:
            return RedirectResponse(url='/login', status_code=302)

    def _create_login_page(self) -> HTMLResponse:
        """Create government-level login page."""
        login_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PlexiChat - Secure Access</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }

        .login-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 3rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            max-width: 400px;
            width: 90%;
        }

        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .logo p {
            opacity: 0.8;
            font-size: 0.9rem;
        }

        .security-notice {
            background: rgba(255, 193, 7, 0.2);
            border: 1px solid rgba(255, 193, 7, 0.5);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 2rem;
            text-align: center;
        }

        .security-notice h3 {
            color: #ffc107;
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: none;
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            font-size: 1rem;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .form-group input::placeholder {
            color: rgba(255, 255, 255, 0.7);
        }

        .form-group input:focus {
            outline: none;
            background: rgba(255, 255, 255, 0.3);
            border-color: white;
        }

        .login-btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }

        .login-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .error-message {
            background: rgba(220, 53, 69, 0.2);
            border: 1px solid rgba(220, 53, 69, 0.5);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            color: #ff6b6b;
            text-align: center;
            display: none;
        }

        .footer {
            text-align: center;
            margin-top: 2rem;
            opacity: 0.7;
            font-size: 0.8rem;
        }

        .footer a {
            color: white;
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1> PlexiChat</h1>
            <p>Secure Communication Platform</p>
        </div>

        <div class="security-notice">
            <h3> GOVERNMENT-LEVEL SECURITY</h3>
            <p>This system is protected by advanced security measures. Unauthorized access is prohibited.</p>
        </div>

        <form id="loginForm">
            <div class="error-message" id="errorMessage"></div>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required>
            </div>

            <div class="form-group" id="totpGroup" style="display: none;">
                <label for="totp">2FA Code</label>
                <input type="text" id="totp" name="totp" placeholder="Enter 6-digit code" maxlength="6">
            </div>

            <button type="submit" class="login-btn" id="loginBtn">
                 Secure Login
            </button>
        </form>

        <div class="footer">
            <p><a href="/docs"> Documentation</a> | System Time: <span id="currentTime"></span></p>
        </div>
    </div>

    <script>
        // Update current time
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = now.toLocaleTimeString();
        }
        updateTime();
        setInterval(updateTime, 1000);

        // Handle login form
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const totp = document.getElementById('totp').value;
            const errorDiv = document.getElementById('errorMessage');
            const loginBtn = document.getElementById('loginBtn');
            const totpGroup = document.getElementById('totpGroup');

            // Disable button and show loading
            loginBtn.disabled = true;
            loginBtn.textContent = ' Authenticating...';
            errorDiv.style.display = 'none';

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        totp_code: totp || null
                    })
                });

                const result = await response.json();

                if (result.success) {
                    if (result.must_change_password) {
                        window.location.href = '/admin/change-password';
                    } else {
                        window.location.href = '/admin';
                    }
                } else {
                    if (result.requires_2fa) {
                        totpGroup.style.display = 'block';
                        document.getElementById('totp').focus();
                        errorDiv.textContent = '2FA code required';
                    } else {
                        errorDiv.textContent = result.error || 'Login failed';
                    }
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.style.display = 'block';
            }

            // Re-enable button
            loginBtn.disabled = false;
            loginBtn.textContent = ' Secure Login';
        });

        // Auto-focus username field
        document.getElementById('username').focus();
    </script>
</body>
</html>
        """

        return HTMLResponse(content=login_html)

    def _add_security_headers(self, response: Response):
        """Add comprehensive security headers."""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-Security-Level': 'Government-Grade'
        }

        for header, value in security_headers.items():
            response.headers[header] = value

    async def _log_access(self, request: Request, response: Response, duration: float):
        """Log access attempt."""
        access_log = {
            'timestamp': from datetime import datetime
datetime.utcnow().isoformat(),
            'method': request.method,
            'path': str(request.url.path),
            'client_ip': request.client.host if request.client else 'unknown',
            'user_agent': request.headers.get('user-agent', 'Unknown'),
            'status_code': response.status_code,
            'duration': duration,
            'user': getattr(request.state, 'user', None)
        }

        logger.info(f"Access: {json.dumps(access_log)}")


# Global middleware instance
government_security_middleware = GovernmentSecurityMiddleware
