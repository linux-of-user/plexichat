from typing import Optional
# Unified Authentication API for PlexiChat

try:
    from .decorators_auth import *
except ImportError:
    pass

try:
    from .manager_audit import AuthAuditManager, auth_audit_manager
except ImportError:
    AuthAuditManager = auth_audit_manager = None

try:
    from .manager_auth import AuthManager, auth_manager
except ImportError:
    AuthManager = auth_manager = None

try:
    from .manager_biometric import BiometricManager, biometric_manager
except ImportError:
    BiometricManager = biometric_manager = None

try:
    from .manager_device import DeviceManager, device_manager
except ImportError:
    DeviceManager = device_manager = None

try:
    from .manager_mfa import MFAManager, mfa_manager
except ImportError:
    MFAManager = mfa_manager = None

try:
    from .manager_oauth import OAuthManager, oauth_manager
except ImportError:
    OAuthManager = oauth_manager = None

try:
    from .manager_password import PasswordManager, password_manager
except ImportError:
    PasswordManager = password_manager = None

try:
    from .manager_session import SessionManager, session_manager
except ImportError:
    SessionManager = session_manager = None

try:
    from .manager_token import TokenManager, token_manager
except ImportError:
    TokenManager = token_manager = None

# Optionally import authentication utilities
try:
    from plexichat.infrastructure.utils.auth import require_admin, require_auth, require_level, require_mfa, optional_auth
except ImportError:
    require_admin = require_auth = require_level = require_mfa = optional_auth = None

try:
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
