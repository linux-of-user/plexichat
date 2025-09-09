"""Core security module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["SecurityManager", "security_manager", "authenticate_user", "validate_token"]

class SecurityManager:
    def __init__(self):
        pass

security_manager = None

def authenticate_user(*args, **kwargs):
    pass

def validate_token(*args, **kwargs):
    pass