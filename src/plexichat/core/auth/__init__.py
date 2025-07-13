    from .manager_auth import AuthManager, auth_manager
    from .manager_token import TokenManager, token_manager
    from .manager_session import SessionManager, session_manager
    from .manager_password import PasswordManager, password_manager
    from .manager_mfa import MFAManager, mfa_manager
    from .manager_biometric import BiometricManager, biometric_manager
    from .manager_oauth import OAuthManager, oauth_manager
    from .manager_device import DeviceManager, device_manager
    from .manager_audit import AuthAuditManager, auth_audit_manager
    from .decorators_auth import (
    from .middleware_auth import (
    from .validators_auth import BiometricValidator, PasswordValidator, TokenValidator
    from .exceptions_auth import (
        import logging
        import logging

        from plexichat.infrastructure.utils.auth import require_admin,

"""
PlexiChat Core Authentication System - Unified Authentication Management

Consolidates all authentication components into a single, comprehensive module
with government-level security, 2FA, biometric support, and advanced features.

This unified system replaces and consolidates:
- src/plexichat/app/auth/
- src/plexichat/core/auth/ (if exists)
- Authentication components from security modules

Features:
- Multi-factor authentication (2FA/MFA) with TOTP, SMS, email
- Biometric authentication support (fingerprint, face, voice)
- Zero-knowledge authentication protocols
- Hardware security key support (FIDO2/WebAuthn)
- Government-level security with quantum-resistant algorithms
- JWT token management with refresh tokens
- Session management with security levels
- Brute force protection and account lockout
- Password policies and strength validation
- OAuth2/OpenID Connect integration
- Single Sign-On (SSO) support
- Device fingerprinting and trusted devices
- Risk-based authentication
- Audit logging and compliance reporting
"""

# Import existing authentication components (consolidated)
# Note: Removed duplicate authentication systems - now using unified core system
# Removed: features/security/advanced_auth.py (CONSOLIDATED)
# Removed: features/security/core/government_auth.py (CONSOLIDATED)
# Removed: features/security/core/advanced_authentication.py (CONSOLIDATED)
# Removed: features/security/login_manager.py (CONSOLIDATED)

# Import new unified components
try:
except ImportError:
    AuthManager = auth_manager = None

try:
except ImportError:
    TokenManager = token_manager = None

try:
except ImportError:
    SessionManager = session_manager = None

try:
except ImportError:
    PasswordManager = password_manager = None

try:
except ImportError:
    MFAManager = mfa_manager = None

try:
except ImportError:
    BiometricManager = biometric_manager = None

try:
except ImportError:
    OAuthManager = oauth_manager = None

try:
except ImportError:
    DeviceManager = device_manager = None

try:
except ImportError:
    AuthAuditManager = auth_audit_manager = None

# Import authentication utilities
try:
        optional_auth,
        require_auth,
        require_level,
        require_mfa,
    )
except ImportError:
    require_auth = from plexichat.infrastructure.utils.auth import require_admin = require_mfa = require_level = optional_auth = None

try:
        AuthenticationMiddleware,
        FastAPIAuthMiddleware,
        FlaskAuthMiddleware,
    )
except ImportError:
    AuthenticationMiddleware = FlaskAuthMiddleware = FastAPIAuthMiddleware = None

try:
except ImportError:
    PasswordValidator = TokenValidator = BiometricValidator = None

try:
        AccountLockError,
        AuthenticationError,
        AuthorizationError,
        BiometricError,
        DeviceError,
        MFAError,
        OAuthError,
        PasswordError,
        RateLimitError,
        SessionError,
        TokenError,
    )
except ImportError:
    AuthenticationError = AuthorizationError = MFAError = TokenError = None
    SessionError = PasswordError = BiometricError = DeviceError = None
    OAuthError = RateLimitError = AccountLockError = None

__version__ = "3.0.0"
__all__ = [
    # Core authentication management
    "AuthManager",
    "auth_manager",
    
    # Token management
    "TokenManager",
    "token_manager",
    
    # Session management
    "SessionManager", 
    "session_manager",
    
    # Password management
    "PasswordManager",
    "password_manager",
    
    # Multi-factor authentication
    "MFAManager",
    "mfa_manager",
    
    # Biometric authentication
    "BiometricManager",
    "biometric_manager",
    
    # OAuth management
    "OAuthManager",
    "oauth_manager",
    
    # Device management
    "DeviceManager",
    "device_manager",
    
    # Audit management
    "AuthAuditManager",
    "auth_audit_manager",
    
    # Legacy components (now consolidated into unified system)
    # Note: These are now provided by the unified auth system above
    
    # Middleware
    "AuthenticationMiddleware",
    "FlaskAuthMiddleware",
    "FastAPIAuthMiddleware",

    # Validators
    "PasswordValidator",
    "TokenValidator",
    "BiometricValidator",

    # Decorators
    "require_auth",
    "from plexichat.infrastructure.utils.auth import require_admin",
    "require_mfa",
    "require_level",
    "optional_auth",

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
        "from plexichat.infrastructure.utils.auth import require_admin_approval": True
    },
    "critical_risk": {
        "score_threshold": 1.0,
        "additional_auth_required": True,
        "session_timeout_multiplier": 0.1,
        "from plexichat.infrastructure.utils.auth import require_admin_approval": True,
        "block_access": True
    }
}

async def initialize_auth_system(config: dict = None) -> bool:
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
        await mfa_manager.initialize(system_config)
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
        await mfa_manager.shutdown()
        await password_manager.shutdown()
        await session_manager.shutdown()
        await token_manager.shutdown()
        await auth_manager.shutdown()
        
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f" Error during authentication system shutdown: {e}")

# Convenience functions for common operations
async def authenticate_user(username: str, password: str, mfa_code: str = None) -> dict:
    """Authenticate user with username/password and optional MFA."""
    return await auth_manager.authenticate(username, password, mfa_code)

async def create_session(user_id: str, device_info: dict = None) -> str:
    """Create authenticated session for user."""
    return await session_manager.create_session(user_id, device_info)

async def validate_token(token: str) -> dict:
    """Validate JWT access token."""
    return await token_manager.validate_token(token)

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
