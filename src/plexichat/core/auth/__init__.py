"""PlexiChat Auth"""

import logging
from typing import Any, Dict, Optional

try:
    from plexichat.core_system.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

def import_auth_modules():
    """Import auth modules with error handling."""
    try:
        from .auth_core import auth_core, hash_password, verify_password, create_access_token
        from .manager_auth import auth_manager
        logger.info("Auth modules imported")
    except ImportError as e:
        logger.warning(f"Could not import auth modules: {e}")

import_auth_modules()

__all__ = [
    "auth_core",
    "auth_manager",
    "hash_password",
    "verify_password",
    "create_access_token",
]

__version__ = "1.0.0"
    from .middleware_auth import AuthenticationMiddleware, FastAPIAuthMiddleware, FlaskAuthMiddleware
except ImportError:
    AuthenticationMiddleware = FastAPIAuthMiddleware = FlaskAuthMiddleware = None

try:
    from .validators_auth import PasswordValidator, TokenValidator, BiometricValidator
except ImportError:
    PasswordValidator = TokenValidator = BiometricValidator = None

try:
    from .exceptions_auth import (
        AuthenticationError, AuthorizationError, MFAError, TokenError, SessionError, PasswordError, BiometricError, DeviceError, OAuthError, RateLimitError, AccountLockError
    )
except ImportError:
    AuthenticationError = AuthorizationError = MFAError = TokenError = None
    SessionError = PasswordError = BiometricError = DeviceError = None
    OAuthError = RateLimitError = AccountLockError = None

__all__ = [
    # Core authentication management
    "AuthManager", "auth_manager",
    "TokenManager", "token_manager",
    "SessionManager", "session_manager",
    "PasswordManager", "password_manager",
    "MFAManager", "mfa_manager",
    "BiometricManager", "biometric_manager",
    "OAuthManager", "oauth_manager",
    "DeviceManager", "device_manager",
    "AuthAuditManager", "auth_audit_manager",
    # Middleware
    "AuthenticationMiddleware", "FastAPIAuthMiddleware", "FlaskAuthMiddleware",
    # Validators
    "PasswordValidator", "TokenValidator", "BiometricValidator",
    # Decorators
    "require_auth", "require_admin", "require_mfa", "require_level", "optional_auth",
    # Exceptions
    "AuthenticationError", "AuthorizationError", "MFAError", "TokenError", "SessionError", "PasswordError", "BiometricError", "DeviceError", "OAuthError", "RateLimitError", "AccountLockError"
]
