from typing import Any, Dict, Optional


"""
PlexiChat Authentication Exceptions

Custom exception classes for authentication and authorization errors.
"""


class AuthenticationError(Exception):
    """Base authentication error."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "AUTH_ERROR"
        self.details = details or {}


class AuthorizationError(Exception):
    """Authorization/permission error."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        required_level: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "AUTHZ_ERROR"
        self.required_level = required_level


class MFAError(Exception):
    """Multi-factor authentication error."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        available_methods: Optional[list] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "MFA_ERROR"
        self.available_methods = available_methods or []


class TokenError(Exception):
    """Token-related error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        token_type: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "TOKEN_ERROR"
        self.token_type = token_type


class SessionError(Exception):
    """Session-related error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "SESSION_ERROR"
        self.session_id = session_id


class PasswordError(Exception):
    """Password-related error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        requirements: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "PASSWORD_ERROR"
        self.requirements = requirements or {}


class BiometricError(Exception):
    """Biometric authentication error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        biometric_type: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "BIOMETRIC_ERROR"
        self.biometric_type = biometric_type


class DeviceError(Exception):
    """Device-related error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        device_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "DEVICE_ERROR"
        self.device_id = device_id


class OAuthError(Exception):
    """OAuth-related error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "OAUTH_ERROR"
        self.provider = provider


class RateLimitError(Exception):
    """Rate limiting error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        retry_after: Optional[int] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "RATE_LIMIT_ERROR"
        self.retry_after = retry_after


class AccountLockError(Exception):
    """Account locked error."""
        def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        locked_until: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "ACCOUNT_LOCKED"
        self.locked_until = locked_until
