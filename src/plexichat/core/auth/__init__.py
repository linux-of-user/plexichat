"""
PlexiChat Core Authentication System - SINGLE SOURCE OF TRUTH

Consolidates ALL authentication components into a unified system.
"""
import logging

from typing import Any, Dict, Optional

# Import unified authentication system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_auth import (
        UnifiedAuthManager,
        unified_auth_manager,
        AuthenticationMethod,
        SecurityLevel,
        AuthSession,
        AuthResult,
    )
    # Backward compatibility aliases
    AuthManager = UnifiedAuthManager
    auth_manager = unified_auth_manager
except ImportError:
    # Fallback definitions
    class UnifiedAuthManager:
        pass
    unified_auth_manager = UnifiedAuthManager()
    AuthManager = UnifiedAuthManager
    auth_manager = unified_auth_manager

    class AuthenticationMethod:
        PASSWORD = "password"
        MFA_TOTP = "mfa_totp"

    class SecurityLevel:
        BASIC = 1
        GOVERNMENT = 6

    class AuthSession:
        pass

    class AuthResult:
        pass

# Import legacy components for backward compatibility
try:
    from .audit_manager import AuthAuditManager, auth_audit_manager
except ImportError:
    AuthAuditManager = auth_audit_manager = None

try:
    from .biometric_manager import BiometricManager, biometric_manager
except ImportError:
    BiometricManager = biometric_manager = None

try:
    from .device_manager import DeviceManager, device_manager
except ImportError:
    DeviceManager = device_manager = None

try:
    from .mfa_manager import Advanced2FASystem as MFAManager, tfa_system as mfa_manager
except ImportError:
    MFAManager = mfa_manager = None

try:
    from .token_manager import TokenManager, token_manager
except ImportError:
    TokenManager = token_manager = None
# Import authentication exceptions
try:
    from ..exceptions import (
        AuthenticationError,
        AuthorizationError,
    )
except ImportError:
    # Fallback if exceptions module doesn't exist
    class AuthenticationError(Exception):
        pass
    class AuthorizationError(Exception):
        pass

# Additional auth-specific exceptions
class AccountLockError(AuthenticationError):
    pass
class BiometricError(AuthenticationError):
    pass
class DeviceError(AuthenticationError):
    pass
class MFAError(AuthenticationError):
    pass
class OAuthError(AuthenticationError):
    pass
class PasswordError(AuthenticationError):
    pass
class RateLimitError(AuthenticationError):
    pass
class SessionError(AuthenticationError):
    pass
class TokenError(AuthenticationError):
    pass


__version__ = "3.0.0"
__all__ = [
    # Unified authentication system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedAuthManager",
    "unified_auth_manager",
    "AuthManager",  # Backward compatibility
    "auth_manager", # Backward compatibility
    "AuthenticationMethod",
    "SecurityLevel",
    "AuthSession",
    "AuthResult",

    # Legacy components (for backward compatibility)
    "TokenManager",
    "token_manager",
    "MFAManager",
    "mfa_manager",
    "BiometricManager",
    "biometric_manager",
    "DeviceManager",
    "device_manager",
    "AuthAuditManager",
    "auth_audit_manager",

    # Exceptions
    "AuthenticationError",
    "AuthorizationError",
    "MFAError",
    "TokenError",
    "SessionError",
    "PasswordError",
    "BiometricError",
    "DeviceError",
    "OAuthError",
    "RateLimitError",
    "AccountLockError"
]

# Authentication system constants
AUTH_SYSTEM_VERSION = "3.0.0"
SUPPORTED_AUTH_METHODS = [
    "password", "totp", "sms", "email", "biometric",
    "hardware_key", "zero_knowledge", "oauth2"
]
SUPPORTED_BIOMETRIC_TYPES = ["fingerprint", "face", "voice", "iris"]
SUPPORTED_OAUTH_PROVIDERS = ["google", "microsoft", "github", "facebook", "apple"]

# Default authentication configuration
DEFAULT_AUTH_CONFIG = {
    "security_level": "GOVERNMENT",
    "password_policy": {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "prevent_common_passwords": True,
        "prevent_personal_info": True,
        "password_history": 12,
        "max_age_days": 90
    },
    "session_management": {
        "session_timeout_minutes": 30,
        "max_concurrent_sessions": 3,
        "secure_cookies": True,
        "httponly_cookies": True,
        "samesite_strict": True,
        "session_rotation": True
    },
    "multi_factor_auth": {
        "enabled": True,
        "required_for_admin": True,
        "totp_enabled": True,
        "sms_enabled": True,
        "email_enabled": True,
        "backup_codes": 10,
        "remember_device_days": 30
    },
    "biometric_auth": {
        "enabled": True,
        "fingerprint_enabled": True,
        "face_recognition_enabled": True,
        "voice_recognition_enabled": False,
        "quality_threshold": 0.8,
        "max_templates_per_user": 5
    },
    "brute_force_protection": {
        "enabled": True,
        "max_attempts": 5,
        "lockout_duration_minutes": 15,
        "progressive_delays": True,
        "ip_based_limiting": True,
        "account_based_limiting": True
    },
    "token_management": {
        "access_token_lifetime_minutes": 15,
        "refresh_token_lifetime_days": 30,
        "jwt_algorithm": "RS256",
        "token_rotation": True,
        "blacklist_on_logout": True
    },
    "oauth_integration": {
        "enabled": True,
        "auto_registration": False,
        "link_existing_accounts": True,
        "require_email_verification": True,
        "providers": {}
    },
    "device_management": {
        "enabled": True,
        "device_fingerprinting": True,
        "trusted_devices": True,
        "device_registration_required": False,
        "max_devices_per_user": 10
    },
    "audit_logging": {
        "enabled": True,
        "log_all_attempts": True,
        "log_successful_logins": True,
        "log_failed_attempts": True,
        "log_password_changes": True,
        "log_mfa_events": True,
        "retention_days": 365
    },
    "risk_assessment": {
        "enabled": True,
        "ip_reputation_check": True,
        "device_reputation_check": True,
        "behavioral_analysis": True,
        "geolocation_check": True,
        "time_based_analysis": True
    }
}

# Authentication security levels
SECURITY_LEVELS = {
    "BASIC": {
        "level": 1,
        "required_methods": ["password"],
        "session_timeout": 60,
        "features": ["basic_auth", "session_management"]
    },
    "ENHANCED": {
        "level": 2,
        "required_methods": ["password", "totp"],
        "session_timeout": 30,
        "features": ["basic_auth", "2fa", "session_management", "device_tracking"]
    },
    "GOVERNMENT": {
        "level": 3,
        "required_methods": ["password", "totp", "biometric"],
        "session_timeout": 15,
        "features": [
            "basic_auth", "2fa", "biometric_auth", "session_management",
            "device_tracking", "audit_logging", "risk_assessment"
        ]
    },
    "MILITARY": {
        "level": 4,
        "required_methods": ["password", "totp", "biometric", "hardware_key"],
        "session_timeout": 10,
        "features": [
            "basic_auth", "2fa", "biometric_auth", "hardware_keys",
            "session_management", "device_tracking", "audit_logging",
            "risk_assessment", "zero_knowledge_auth"
        ]
    },
    "ZERO_KNOWLEDGE": {
        "level": 5,
        "required_methods": ["zero_knowledge", "biometric", "hardware_key"],
        "session_timeout": 5,
        "features": [
            "zero_knowledge_auth", "biometric_auth", "hardware_keys",
            "quantum_resistant", "session_management", "device_tracking",
            "audit_logging", "risk_assessment", "end_to_end_encryption"
        ]
    }
}

# Password strength requirements by security level
PASSWORD_REQUIREMENTS = {
    "BASIC": {
        "min_length": 8,
        "require_uppercase": False,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": False
    },
    "ENHANCED": {
        "min_length": 10,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True
    },
    "GOVERNMENT": {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "prevent_common_passwords": True,
        "prevent_personal_info": True
    },
    "MILITARY": {
        "min_length": 16,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "prevent_common_passwords": True,
        "prevent_personal_info": True,
        "require_special_chars": True
    },
    "ZERO_KNOWLEDGE": {
        "min_length": 20,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "prevent_common_passwords": True,
        "prevent_personal_info": True,
        "require_special_chars": True,
        "entropy_threshold": 80
    }
}

# MFA method configurations
MFA_METHODS = {
    "totp": {
        "name": "Time-based One-Time Password",
        "description": "Authenticator app (Google Authenticator, Authy, etc.)",
        "setup_required": True,
        "backup_codes": True,
        "security_level": 2
    },
    "sms": {
        "name": "SMS Verification",
        "description": "Text message to registered phone number",
        "setup_required": True,
        "backup_codes": False,
        "security_level": 1
    },
    "email": {
        "name": "Email Verification",
        "description": "Verification code sent to email",
        "setup_required": False,
        "backup_codes": False,
        "security_level": 1
    },
    "hardware_key": {
        "name": "Hardware Security Key",
        "description": "FIDO2/WebAuthn compatible security key",
        "setup_required": True,
        "backup_codes": True,
        "security_level": 4
    },
    "biometric": {
        "name": "Biometric Authentication",
        "description": "Fingerprint, face, or voice recognition",
        "setup_required": True,
        "backup_codes": True,
        "security_level": 3
    }
}

# OAuth provider configurations
OAUTH_PROVIDERS = {
    "google": {
        "name": "Google",
        "authorization_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scopes": ["openid", "email", "profile"],
        "client_id_required": True,
        "client_secret_required": True
    },
    "microsoft": {
        "name": "Microsoft",
        "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": ["openid", "email", "profile"],
        "client_id_required": True,
        "client_secret_required": True
    },
    "github": {
        "name": "GitHub",
        "authorization_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": ["user:email"],
        "client_id_required": True,
        "client_secret_required": True
    }
}

# Risk assessment thresholds
RISK_THRESHOLDS = {
    "low_risk": {
        "score_threshold": 0.3,
        "additional_auth_required": False,
        "session_timeout_multiplier": 1.0
    },
    "medium_risk": {
        "score_threshold": 0.6,
        "additional_auth_required": True,
        "session_timeout_multiplier": 0.5
    },
    "high_risk": {
        "score_threshold": 0.8,
        "additional_auth_required": True,
        "session_timeout_multiplier": 0.25,
        "from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_approval": True
    },
    "critical_risk": {
        "score_threshold": 1.0,
        "additional_auth_required": True,
        "session_timeout_multiplier": 0.1,
        "from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin_approval": True,
        "block_access": True
    }
}

async def initialize_auth_system(config: Optional[dict] = None) -> bool:
    """
    Initialize the unified authentication system.

    Args:
        config: Optional configuration dictionary

    Returns:
        bool: True if initialization successful
    """
    try:
        # Merge with default configuration
        system_config = DEFAULT_AUTH_CONFIG.copy()
        if config:
            system_config.update(config)

        # Initialize core components
        await auth_manager.initialize(system_config)
        await token_manager.initialize(system_config)
        await session_manager.initialize(system_config)
        await password_manager.initialize(system_config)
        # mfa_manager (Advanced2FASystem) doesn't have initialize method
        # await mfa_manager.initialize(system_config)
        await biometric_manager.initialize(system_config)
        await oauth_manager.initialize(system_config)
        await device_manager.initialize(system_config)
        await auth_audit_manager.initialize(system_config)

        return True

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f" Failed to initialize authentication system: {e}")
        return False

async def shutdown_auth_system():
    """Gracefully shutdown the authentication system."""
    try:
        # Shutdown components in reverse order
        await auth_audit_manager.shutdown()
        await device_manager.shutdown()
        await oauth_manager.shutdown()
        await biometric_manager.shutdown()
        # mfa_manager (Advanced2FASystem) doesn't have shutdown method
        # await mfa_manager.shutdown()
        await password_manager.shutdown()
        await session_manager.shutdown()
        await token_manager.shutdown()
        await auth_manager.shutdown()

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f" Error during authentication system shutdown: {e}")

# Convenience functions for common operations
async def authenticate_user(username: str, password: str, mfa_code: Optional[str] = None) -> dict:
    """Authenticate user with username/password and optional MFA."""
    # Import the request class locally to avoid circular imports
    # Create authentication request
    request = AuthenticationRequest(
        username=username,
        password=password,
        mfa_code=mfa_code or "",
        ip_address="127.0.0.1",  # Default for convenience function
        user_agent="PlexiChat-Internal",  # Default for convenience function
        device_info={}  # Default for convenience function
    )

    # Use the imported auth_manager instance
    manager = globals()['auth_manager']  # Get the auth_manager from module globals
    response = await manager.authenticate(request)

    # Convert response to dict for backward compatibility
    if hasattr(response, '__dict__'):
        result = response.__dict__.copy()
        # Convert any non-serializable objects to strings
        for key, value in result.items():
            if hasattr(value, '__dict__'):
                result[key] = value.__dict__
        return result
    # Ensure we always return a dict
    return {"success": False, "error": "Invalid response format"}

async def create_session(user_id: str, device_info: Optional[dict] = None) -> str:
    """Create authenticated session for user."""
    return await session_manager.create_session(user_id, device_info or {})

async def validate_token(token: str) -> Any:
    """Validate JWT access token."""
    result = await token_manager.validate_token(token)
    # Convert TokenValidationResult to dict if needed
    if hasattr(result, '__dict__'):
        return result.__dict__
    # Ensure we always return a dict
    if isinstance(result, dict):
        return result
    return {"valid": False, "error": "Invalid token format"}

async def require_authentication(token: str, required_level: str = "BASIC") -> dict:
    """Require authentication with minimum security level."""
    return await auth_manager.require_authentication(token, required_level)

def get_password_requirements(security_level: str = "GOVERNMENT") -> dict:
    """Get password requirements for security level."""
    return PASSWORD_REQUIREMENTS.get(security_level, PASSWORD_REQUIREMENTS["GOVERNMENT"])

def get_supported_mfa_methods() -> list:
    """Get list of supported MFA methods."""
    return list(MFA_METHODS.keys())

def get_oauth_providers() -> list:
    """Get list of configured OAuth providers."""
    return list(OAUTH_PROVIDERS.keys())
