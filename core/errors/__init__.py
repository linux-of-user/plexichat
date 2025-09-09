"""Core errors module with shared base functionality and fallback implementations."""
__version__ = "0.0.0"
__all__ = [
    "ErrorSeverity",
    "ErrorCategory",
    "PlexiChatErrorCode",
    "PlexiChatException",
    "ErrorResponse",
    "create_error_response",
    "handle_exception",
    "log_error",
    "ErrorManager",
    "BaseAPIException",
    "AuthenticationError",
    "ValidationError",
    "DatabaseError",
    "get_error_manager",
]

class ErrorManager:
    def __init__(self):
        pass

class ErrorSeverity:
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

class ErrorCategory:
    AUTH = 1
    VALIDATION = 2
    DATABASE = 3
    SYSTEM = 4

class BaseAPIException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

class AuthenticationError(BaseAPIException):
    def __init__(self):
        super().__init__("Authentication failed")

class ValidationError(BaseAPIException):
    def __init__(self):
        super().__init__("Validation failed")

class DatabaseError(BaseAPIException):
    def __init__(self):
        super().__init__("Database error")

def get_error_manager(*args, **kwargs):
    pass

def create_error_response(*args, **kwargs):
    pass

def handle_exception(*args, **kwargs):
    pass

def log_error(*args, **kwargs):
    pass