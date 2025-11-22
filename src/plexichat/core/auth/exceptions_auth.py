"""
Auth Exception Classes
========================

Custom exceptions for authentication and authorization errors.
"""

class AuthenticationError(Exception):
    """Base authentication error."""
    pass

class InvalidCredentialsError(AuthenticationError):
    """Invalid username or password."""
    pass

class TokenExpiredError(AuthenticationError):
    """JWT token has expired."""
    pass

class InsufficientPermissionsError(AuthenticationError):
    """User lacks required permissions."""
    pass
