"""
PlexiChat Core Authentication Manager

Central authentication manager that coordinates all authentication
operations and provides a unified interface for the system.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .audit_manager import AuthAuditManager
from .biometric_manager import BiometricManager
from .device_manager import DeviceManager
from .exceptions import AuthenticationError, AuthorizationError
from .mfa_manager import MFAManager
from .password_manager import PasswordManager
from .session_manager import SessionManager
from .token_manager import TokenManager

# Note: Removed import from deleted advanced_authentication.py - functionality now in unified system

logger = logging.getLogger(__name__)


class AuthenticationResult(Enum):
    """Authentication result types."""
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    MFA_REQUIRED = "mfa_required"
    PASSWORD_EXPIRED = "password_expired"
    ACCOUNT_DISABLED = "account_disabled"
    DEVICE_NOT_TRUSTED = "device_not_trusted"
    RISK_TOO_HIGH = "risk_too_high"
    RATE_LIMITED = "rate_limited"


@dataclass
class AuthenticationRequest:
    """Authentication request data."""
    username: str
    password: Optional[str] = None
    mfa_code: Optional[str] = None
    mfa_method: Optional[str] = None
    device_info: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    remember_device: bool = False
    security_level: str = "GOVERNMENT"
    
    # OAuth specific
    oauth_provider: Optional[str] = None
    oauth_code: Optional[str] = None
    oauth_state: Optional[str] = None
    
    # Biometric specific
    biometric_data: Optional[bytes] = None
    biometric_type: Optional[str] = None
    
    # Hardware key specific
    hardware_key_response: Optional[Dict[str, Any]] = None


@dataclass
class AuthenticationResponse:
    """Authentication response data."""
    result: AuthenticationResult
    success: bool
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    
    # Additional requirements
    mfa_required: bool = False
    mfa_methods: List[str] = field(default_factory=list)
    password_change_required: bool = False
    device_registration_required: bool = False
    
    # Error information
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    retry_after: Optional[int] = None
    
    # Security information
    security_level: Optional[str] = None
    risk_score: Optional[float] = None
    trusted_device: bool = False
    
    # Audit information
    audit_id: Optional[str] = None


class AuthManager:
    """
    Central authentication manager.
    
    Coordinates all authentication operations including:
    - User authentication with multiple methods
    - Multi-factor authentication
    - Biometric authentication
    - OAuth integration
    - Session management
    - Token management
    - Risk assessment
    - Audit logging
    """
    
    def __init__(self):
        # Core components
        self.token_manager = TokenManager()
        self.session_manager = SessionManager()
        self.password_manager = PasswordManager()
        self.mfa_manager = MFAManager()
        self.biometric_manager = BiometricManager()
        self.device_manager = DeviceManager()
        self.audit_manager = AuthAuditManager()
        
        # Advanced authentication system
        self.advanced_auth = AdvancedAuthenticationSystem()
        
        # Configuration
        self.config = {}
        self.security_levels = {}
        self.password_requirements = {}
        
        # Rate limiting
        self.rate_limits = {}
        self.failed_attempts = {}
        
        # Risk assessment
        self.risk_factors = {}
        
        self.initialized = False
    
    async def initialize(self, config: Dict[str, Any]):
        """Initialize the authentication manager."""
        if self.initialized:
            return
        
        try:
            self.config = config
            
            # Initialize components
            await self.token_manager.initialize(config.get("token_management", {}))
            await self.session_manager.initialize(config.get("session_management", {}))
            await self.password_manager.initialize(config.get("password_policy", {}))
            await self.mfa_manager.initialize(config.get("multi_factor_auth", {}))
            await self.biometric_manager.initialize(config.get("biometric_auth", {}))
            await self.device_manager.initialize(config.get("device_management", {}))
            await self.audit_manager.initialize(config.get("audit_logging", {}))
            
            # Initialize advanced authentication
            await self.advanced_auth.initialize(config)
            
            # Load security configurations
            self.security_levels = config.get("security_levels", {})
            self.password_requirements = config.get("password_requirements", {})
            
            self.initialized = True
            logger.info("✅ Authentication Manager initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Authentication Manager: {e}")
            raise
    
    async def authenticate(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """
        Authenticate user with comprehensive security checks.
        
        Args:
            request: Authentication request data
            
        Returns:
            AuthenticationResponse: Complete authentication result
        """
        audit_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            # Log authentication attempt
            await self.audit_manager.log_auth_attempt(
                audit_id=audit_id,
                username=request.username,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
                auth_method="password",
                device_info=request.device_info
            )
            
            # Check rate limiting
            if await self._is_rate_limited(request):
                return AuthenticationResponse(
                    result=AuthenticationResult.RATE_LIMITED,
                    success=False,
                    error_message="Too many authentication attempts",
                    retry_after=await self._get_retry_after(request),
                    audit_id=audit_id
                )
            
            # Check if account is locked
            if await self._is_account_locked(request.username):
                return AuthenticationResponse(
                    result=AuthenticationResult.ACCOUNT_LOCKED,
                    success=False,
                    error_message="Account is temporarily locked",
                    audit_id=audit_id
                )
            
            # Perform risk assessment
            risk_score = await self._assess_risk(request)
            
            # Primary authentication
            auth_result = await self._authenticate_primary(request)
            if not auth_result.success:
                await self._record_failed_attempt(request)
                return auth_result
            
            user_id = auth_result.user_id
            
            # Check if MFA is required
            mfa_required = await self._is_mfa_required(user_id, request.security_level, risk_score)
            
            if mfa_required and not request.mfa_code:
                available_methods = await self.mfa_manager.get_user_methods(user_id)
                return AuthenticationResponse(
                    result=AuthenticationResult.MFA_REQUIRED,
                    success=False,
                    user_id=user_id,
                    mfa_required=True,
                    mfa_methods=available_methods,
                    audit_id=audit_id
                )
            
            # Verify MFA if provided
            if request.mfa_code:
                mfa_result = await self.mfa_manager.verify_code(
                    user_id=user_id,
                    code=request.mfa_code,
                    method=request.mfa_method
                )
                
                if not mfa_result.success:
                    await self._record_failed_attempt(request)
                    return AuthenticationResponse(
                        result=AuthenticationResult.INVALID_CREDENTIALS,
                        success=False,
                        error_message="Invalid MFA code",
                        audit_id=audit_id
                    )
            
            # Check device trust
            device_trusted = await self.device_manager.is_device_trusted(
                user_id=user_id,
                device_info=request.device_info
            )
            
            # Register device if requested
            if request.remember_device and not device_trusted:
                await self.device_manager.register_device(
                    user_id=user_id,
                    device_info=request.device_info
                )
                device_trusted = True
            
            # Create session
            session_id = await self.session_manager.create_session(
                user_id=user_id,
                device_info=request.device_info,
                security_level=request.security_level,
                risk_score=risk_score
            )
            
            # Create tokens
            access_token = await self.token_manager.create_access_token(
                user_id=user_id,
                session_id=session_id,
                security_level=request.security_level
            )
            
            refresh_token = await self.token_manager.create_refresh_token(
                user_id=user_id,
                session_id=session_id
            )
            
            # Clear failed attempts
            await self._clear_failed_attempts(request.username)
            
            # Log successful authentication
            await self.audit_manager.log_auth_success(
                audit_id=audit_id,
                user_id=user_id,
                session_id=session_id,
                security_level=request.security_level,
                mfa_used=bool(request.mfa_code),
                device_trusted=device_trusted,
                risk_score=risk_score,
                duration=time.time() - start_time
            )
            
            return AuthenticationResponse(
                result=AuthenticationResult.SUCCESS,
                success=True,
                user_id=user_id,
                session_id=session_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=await self.token_manager.get_token_expiry(access_token),
                security_level=request.security_level,
                risk_score=risk_score,
                trusted_device=device_trusted,
                audit_id=audit_id
            )
            
        except Exception as e:
            logger.error(f"❌ Authentication error: {e}")
            
            await self.audit_manager.log_auth_error(
                audit_id=audit_id,
                username=request.username,
                error=str(e),
                duration=time.time() - start_time
            )
            
            return AuthenticationResponse(
                result=AuthenticationResult.INVALID_CREDENTIALS,
                success=False,
                error_message="Authentication failed",
                audit_id=audit_id
            )
    
    async def validate_session(self, session_id: str) -> Dict[str, Any]:
        """Validate an active session."""
        return await self.session_manager.validate_session(session_id)
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate an access token."""
        return await self.token_manager.validate_token(token)
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh an access token."""
        return await self.token_manager.refresh_token(refresh_token)
    
    async def logout(self, session_id: str = None, token: str = None) -> bool:
        """Logout user and invalidate session/token."""
        try:
            if session_id:
                await self.session_manager.invalidate_session(session_id)
            
            if token:
                await self.token_manager.blacklist_token(token)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Logout error: {e}")
            return False
    
    async def require_authentication(self, token: str, required_level: str = "BASIC") -> Dict[str, Any]:
        """Require authentication with minimum security level."""
        try:
            # Validate token
            token_data = await self.validate_token(token)
            if not token_data.get("valid"):
                raise AuthenticationError("Invalid token")
            
            # Check security level
            current_level = token_data.get("security_level", "BASIC")
            if not await self._meets_security_level(current_level, required_level):
                raise AuthorizationError(f"Insufficient security level: {current_level} < {required_level}")
            
            # Validate session
            session_id = token_data.get("session_id")
            if session_id:
                session_data = await self.validate_session(session_id)
                if not session_data.get("valid"):
                    raise AuthenticationError("Invalid session")
            
            return {
                "authenticated": True,
                "user_id": token_data.get("user_id"),
                "session_id": session_id,
                "security_level": current_level,
                "expires_at": token_data.get("expires_at")
            }
            
        except Exception as e:
            logger.error(f"❌ Authentication requirement failed: {e}")
            raise
    
    async def shutdown(self):
        """Gracefully shutdown the authentication manager."""
        try:
            # Shutdown components
            await self.audit_manager.shutdown()
            await self.device_manager.shutdown()
            await self.biometric_manager.shutdown()
            await self.mfa_manager.shutdown()
            await self.password_manager.shutdown()
            await self.session_manager.shutdown()
            await self.token_manager.shutdown()
            await self.advanced_auth.shutdown()
            
            logger.info("✅ Authentication Manager shutdown complete")
            
        except Exception as e:
            logger.error(f"❌ Error during Authentication Manager shutdown: {e}")
    
    # Private helper methods
    async def _authenticate_primary(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """Perform primary authentication."""
        if request.oauth_provider:
            return await self._authenticate_oauth(request)
        elif request.biometric_data:
            return await self._authenticate_biometric(request)
        elif request.hardware_key_response:
            return await self._authenticate_hardware_key(request)
        else:
            return await self._authenticate_password(request)
    
    async def _authenticate_password(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """Authenticate with username/password."""
        try:
            result = await self.password_manager.verify_password(
                username=request.username,
                password=request.password
            )
            
            if result.success:
                return AuthenticationResponse(
                    result=AuthenticationResult.SUCCESS,
                    success=True,
                    user_id=result.user_id,
                    password_change_required=result.password_expired
                )
            else:
                return AuthenticationResponse(
                    result=AuthenticationResult.INVALID_CREDENTIALS,
                    success=False,
                    error_message="Invalid username or password"
                )
                
        except Exception as e:
            logger.error(f"❌ Password authentication error: {e}")
            return AuthenticationResponse(
                result=AuthenticationResult.INVALID_CREDENTIALS,
                success=False,
                error_message="Authentication failed"
            )
    
    async def _authenticate_oauth(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """Authenticate with OAuth provider."""
        # OAuth authentication logic here
    
    async def _authenticate_biometric(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """Authenticate with biometric data."""
        # Biometric authentication logic here
    
    async def _authenticate_hardware_key(self, request: AuthenticationRequest) -> AuthenticationResponse:
        """Authenticate with hardware security key."""
        # Hardware key authentication logic here
    
    async def _is_rate_limited(self, request: AuthenticationRequest) -> bool:
        """Check if request is rate limited."""
        # Rate limiting logic here
        return False
    
    async def _get_retry_after(self, request: AuthenticationRequest) -> int:
        """Get retry after seconds for rate limited request."""
        return 60
    
    async def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked."""
        # Account locking logic here
        return False
    
    async def _assess_risk(self, request: AuthenticationRequest) -> float:
        """Assess authentication risk."""
        # Risk assessment logic here
        return 0.1
    
    async def _is_mfa_required(self, user_id: str, security_level: str, risk_score: float) -> bool:
        """Check if MFA is required."""
        # MFA requirement logic here
        return self.config.get("multi_factor_auth", {}).get("enabled", True)
    
    async def _meets_security_level(self, current: str, required: str) -> bool:
        """Check if current security level meets requirement."""
        levels = {"BASIC": 1, "ENHANCED": 2, "GOVERNMENT": 3, "MILITARY": 4, "ZERO_KNOWLEDGE": 5}
        return levels.get(current, 0) >= levels.get(required, 0)
    
    async def _record_failed_attempt(self, request: AuthenticationRequest):
        """Record failed authentication attempt."""
        # Failed attempt recording logic here
    
    async def _clear_failed_attempts(self, username: str):
        """Clear failed attempts for user."""
        # Clear failed attempts logic here


# Global instance
auth_manager = AuthManager()
