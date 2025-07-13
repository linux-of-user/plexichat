"""
PlexiChat Security Exceptions

Unified exception classes for all security-related errors.
Consolidates exceptions from various security modules.
"""

from typing import Any, Dict, Optional


class SecurityError(Exception):
    """Base class for all security-related exceptions."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(SecurityError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", 
                 error_code: str = "AUTH_FAILED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class AuthorizationError(SecurityError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Authorization failed", 
                 error_code: str = "AUTHZ_FAILED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class MFAError(SecurityError):
    """Raised when multi-factor authentication fails."""
    
    def __init__(self, message: str = "Multi-factor authentication failed", 
                 error_code: str = "MFA_FAILED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class TokenError(SecurityError):
    """Raised when token validation or processing fails."""
    
    def __init__(self, message: str = "Token error", 
                 error_code: str = "TOKEN_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class SessionError(SecurityError):
    """Raised when session management fails."""
    
    def __init__(self, message: str = "Session error", 
                 error_code: str = "SESSION_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class PasswordError(SecurityError):
    """Raised when password validation or processing fails."""
    
    def __init__(self, message: str = "Password error", 
                 error_code: str = "PASSWORD_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class BiometricError(SecurityError):
    """Raised when biometric authentication fails."""
    
    def __init__(self, message: str = "Biometric authentication failed", 
                 error_code: str = "BIOMETRIC_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class DeviceError(SecurityError):
    """Raised when device registration or validation fails."""
    
    def __init__(self, message: str = "Device error", 
                 error_code: str = "DEVICE_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class OAuthError(SecurityError):
    """Raised when OAuth authentication fails."""
    
    def __init__(self, message: str = "OAuth authentication failed", 
                 error_code: str = "OAUTH_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class RateLimitError(SecurityError):
    """Raised when rate limits are exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", 
                 error_code: str = "RATE_LIMIT_EXCEEDED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class AccountLockError(SecurityError):
    """Raised when account is locked due to security violations."""
    
    def __init__(self, message: str = "Account is locked", 
                 error_code: str = "ACCOUNT_LOCKED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class DDoSError(SecurityError):
    """Raised when DDoS attack is detected."""
    
    def __init__(self, message: str = "DDoS attack detected", 
                 error_code: str = "DDOS_DETECTED", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class ValidationError(SecurityError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Input validation failed", 
                 error_code: str = "VALIDATION_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class EncryptionError(SecurityError):
    """Raised when encryption/decryption operations fail."""
    
    def __init__(self, message: str = "Encryption error", 
                 error_code: str = "ENCRYPTION_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class KeyManagementError(SecurityError):
    """Raised when key management operations fail."""
    
    def __init__(self, message: str = "Key management error", 
                 error_code: str = "KEY_MANAGEMENT_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class CertificateError(SecurityError):
    """Raised when SSL/TLS certificate operations fail."""
    
    def __init__(self, message: str = "Certificate error", 
                 error_code: str = "CERTIFICATE_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class PenetrationTestError(SecurityError):
    """Raised when penetration testing encounters errors."""
    
    def __init__(self, message: str = "Penetration test error", 
                 error_code: str = "PENTEST_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class VulnerabilityError(SecurityError):
    """Raised when vulnerability scanning encounters errors."""
    
    def __init__(self, message: str = "Vulnerability scan error", 
                 error_code: str = "VULNERABILITY_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


class MonitoringError(SecurityError):
    """Raised when security monitoring encounters errors."""
    
    def __init__(self, message: str = "Security monitoring error", 
                 error_code: str = "MONITORING_ERROR", 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(message, error_code, details)


# Exception mapping for backward compatibility
EXCEPTION_MAP = {
    'AUTH_FAILED': AuthenticationError,
    'AUTHZ_FAILED': AuthorizationError,
    'MFA_FAILED': MFAError,
    'TOKEN_ERROR': TokenError,
    'SESSION_ERROR': SessionError,
    'PASSWORD_ERROR': PasswordError,
    'BIOMETRIC_ERROR': BiometricError,
    'DEVICE_ERROR': DeviceError,
    'OAUTH_ERROR': OAuthError,
    'RATE_LIMIT_EXCEEDED': RateLimitError,
    'ACCOUNT_LOCKED': AccountLockError,
    'DDOS_DETECTED': DDoSError,
    'VALIDATION_ERROR': ValidationError,
    'ENCRYPTION_ERROR': EncryptionError,
    'KEY_MANAGEMENT_ERROR': KeyManagementError,
    'CERTIFICATE_ERROR': CertificateError,
    'PENTEST_ERROR': PenetrationTestError,
    'VULNERABILITY_ERROR': VulnerabilityError,
    'MONITORING_ERROR': MonitoringError,
}


def get_exception_class(error_code: str) -> type:
    """Get exception class by error code."""
    return EXCEPTION_MAP.get(error_code, SecurityError)


def create_exception(error_code: str, message: str, 
                    details: Optional[Dict[str, Any]] = None) -> SecurityError:
    """Create exception instance by error code."""
    exception_class = get_exception_class(error_code)
    return exception_class(message, error_code, details)
