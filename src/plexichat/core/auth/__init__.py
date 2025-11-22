
from typing import Optional
from plexichat.core.auth.services.authentication import AuthenticationService
from plexichat.core.database.manager import database_manager
from plexichat.core.security.audit import get_audit_system

_auth_manager: Optional[AuthenticationService] = None

async def initialize_auth_manager() -> AuthenticationService:
    """Initialize the global authentication manager."""
    global _auth_manager
    if _auth_manager is None:
        # Ensure dependencies are ready
        audit_system = get_audit_system()
        # Create instance
        _auth_manager = AuthenticationService(
            db_manager=database_manager,
            audit_service=audit_system
        )
    return _auth_manager

def get_auth_manager() -> AuthenticationService:
    """Get the global authentication manager instance."""
    global _auth_manager
    if _auth_manager is None:
        # Fallback for sync context or if not initialized
        # Note: This might fail if DB is not ready, but it's a best effort for sync access
        audit_system = get_audit_system()
        _auth_manager = AuthenticationService(
            db_manager=database_manager,
            audit_service=audit_system
        )
    return _auth_manager

__all__ = [
    "AuthenticationService",
    "initialize_auth_manager",
    "get_auth_manager",
]
