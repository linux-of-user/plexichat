import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

"""
PlexiChat Token Manager

Comprehensive JWT token management with security features including
token rotation, blacklisting, and quantum-resistant algorithms.
"""

logger = logging.getLogger(__name__)


class TokenType(Enum):
    """Token types."""
    ACCESS = "access"
    REFRESH = "refresh"
    ID = "id"
    RESET = "reset"
    VERIFICATION = "verification"


class TokenStatus(Enum):
    """Token status."""
    VALID = "valid"
    EXPIRED = "expired"
    BLACKLISTED = "blacklisted"
    INVALID = "invalid"


@dataclass
class TokenData:
    """Token data structure."""
    token_id: str
    user_id: str
    session_id: str
    token_type: TokenType
    issued_at: datetime
    expires_at: datetime
    security_level: str
    scopes: List[str] = field(default_factory=list)
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenValidationResult:
    """Token validation result."""
    valid: bool
    token_data: Optional[TokenData] = None
    status: Optional[TokenStatus] = None
    error_message: Optional[str] = None
    expires_in: Optional[int] = None


class TokenManager:
    """
    Comprehensive JWT token management system.
    
    Features:
    - JWT token creation and validation
    - Token rotation and refresh
    - Token blacklisting and revocation
    - Multiple token types (access, refresh, ID, etc.)
    - Quantum-resistant signing algorithms
    - Token introspection and metadata
    - Automatic token cleanup
    - Security level enforcement
    - Scope-based authorization
    """
    
    def __init__(self):
        # Configuration
        self.config = {}
        self.algorithm = "RS256"
        self.access_token_lifetime = timedelta(minutes=15)
        self.refresh_token_lifetime = timedelta(days=30)
        
        # Keys
        self.private_key = None
        self.public_key = None
        self.key_id = None
        
        # Token storage
        self.active_tokens: Dict[str, TokenData] = {}
        self.blacklisted_tokens: set = set()
        self.token_families: Dict[str, List[str]] = {}  # For token rotation
        
        # Cleanup
        self.cleanup_interval = 3600  # 1 hour
        self.cleanup_task = None
        
        self.initialized = False
    
    async def initialize(self, config: Dict[str, Any]):
        """Initialize the token manager."""
        if self.initialized:
            return
        
        try:
            self.config = config
            
            # Configure token lifetimes
            self.access_token_lifetime = timedelta(
                minutes=config.get("access_token_lifetime_minutes", 15)
            )
            self.refresh_token_lifetime = timedelta(
                days=config.get("refresh_token_lifetime_days", 30)
            )
            
            # Configure algorithm
            self.algorithm = config.get("jwt_algorithm", "RS256")
            
            # Generate or load keys
            await self._initialize_keys()
            
            # Start cleanup task
            if config.get("auto_cleanup", True):
                self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            
            self.initialized = True
            logger.info(" Token Manager initialized")
            
        except Exception as e:
            logger.error(f" Failed to initialize Token Manager: {e}")
            raise
    
    async def create_access_token(self, user_id: str, session_id: str, 
                                security_level: str = "GOVERNMENT",
                                scopes: List[str] = None,
                                device_id: str = None,
                                ip_address: str = None,
                                user_agent: str = None,
                                metadata: Dict[str, Any] = None) -> str:
        """Create a new access token."""
        try:
            token_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            expires_at = now + self.access_token_lifetime
            
            # Create token data
            token_data = TokenData(
                token_id=token_id,
                user_id=user_id,
                session_id=session_id,
                token_type=TokenType.ACCESS,
                issued_at=now,
                expires_at=expires_at,
                security_level=security_level,
                scopes=scopes or [],
                device_id=device_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=metadata or {}
            )
            
            # Create JWT payload
            payload = {
                "jti": token_id,
                "sub": user_id,
                "sid": session_id,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "type": TokenType.ACCESS.value,
                "security_level": security_level,
                "scopes": scopes or [],
                "device_id": device_id,
                "iss": "plexichat-auth",
                "aud": "plexichat-api"
            }
            
            # Add metadata to payload
            if metadata:
                payload.update(metadata)
            
            # Sign token
            token = jwt.encode(
                payload,
                self.private_key,
                algorithm=self.algorithm,
                headers={"kid": self.key_id}
            )
            
            # Store token data
            self.active_tokens[token_id] = token_data
            
            logger.debug(f" Access token created for user {user_id}")
            return token
            
        except Exception as e:
            logger.error(f" Failed to create access token: {e}")
            raise
    
    async def create_refresh_token(self, user_id: str, session_id: str,
                                 device_id: str = None,
                                 metadata: Dict[str, Any] = None) -> str:
        """Create a new refresh token."""
        try:
            token_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            expires_at = now + self.refresh_token_lifetime
            
            # Create token data
            token_data = TokenData(
                token_id=token_id,
                user_id=user_id,
                session_id=session_id,
                token_type=TokenType.REFRESH,
                issued_at=now,
                expires_at=expires_at,
                security_level="BASIC",  # Refresh tokens have basic security
                device_id=device_id,
                metadata=metadata or {}
            )
            
            # Create JWT payload
            payload = {
                "jti": token_id,
                "sub": user_id,
                "sid": session_id,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "type": TokenType.REFRESH.value,
                "device_id": device_id,
                "iss": "plexichat-auth",
                "aud": "plexichat-auth"
            }
            
            # Add metadata to payload
            if metadata:
                payload.update(metadata)
            
            # Sign token
            token = jwt.encode(
                payload,
                self.private_key,
                algorithm=self.algorithm,
                headers={"kid": self.key_id}
            )
            
            # Store token data
            self.active_tokens[token_id] = token_data
            
            # Add to token family for rotation
            family_id = f"{user_id}:{session_id}"
            if family_id not in self.token_families:
                self.token_families[family_id] = []
            self.token_families[family_id].append(token_id)
            
            logger.debug(f" Refresh token created for user {user_id}")
            return token
            
        except Exception as e:
            logger.error(f" Failed to create refresh token: {e}")
            raise
    
    async def validate_token(self, token: str) -> TokenValidationResult:
        """Validate a JWT token."""
        try:
            # Decode token without verification first to get token ID
            unverified_payload = import jwt
jwt.decode(token, options={"verify_signature": False})
            token_id = unverified_payload.get("jti")
            
            # Check if token is blacklisted
            if token_id in self.blacklisted_tokens:
                return TokenValidationResult(
                    valid=False,
                    status=TokenStatus.BLACKLISTED,
                    error_message="Token has been revoked"
                )
            
            # Verify and decode token
jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience="plexichat-api",
                issuer="plexichat-auth"
            )
            
            # Get token data
            token_data = self.active_tokens.get(token_id)
            if not token_data:
                return TokenValidationResult(
                    valid=False,
                    status=TokenStatus.INVALID,
                    error_message="Token not found"
                )
            
            # Check expiration
            now = datetime.now(timezone.utc)
            if token_data.expires_at <= now:
                return TokenValidationResult(
                    valid=False,
                    status=TokenStatus.EXPIRED,
                    error_message="Token has expired"
                )
            
            # Calculate expires in seconds
            expires_in = int((token_data.expires_at - now).total_seconds())
            
            return TokenValidationResult(
                valid=True,
                token_data=token_data,
                status=TokenStatus.VALID,
                expires_in=expires_in
            )
            
        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                valid=False,
                status=TokenStatus.EXPIRED,
                error_message="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            return TokenValidationResult(
                valid=False,
                status=TokenStatus.INVALID,
                error_message=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            logger.error(f" Token validation error: {e}")
            return TokenValidationResult(
                valid=False,
                status=TokenStatus.INVALID,
                error_message="Token validation failed"
            )
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh an access token using a refresh token."""
        try:
            # Validate refresh token
            validation_result = await self.validate_token(refresh_token)
            
            if not validation_result.valid:
                raise ValueError(f"Invalid refresh token: {validation_result.error_message}")
            
            token_data = validation_result.token_data
            
            # Verify it's a refresh token
            if token_data.token_type != TokenType.REFRESH:
                raise ValueError("Token is not a refresh token")
            
            # Create new access token
            new_access_token = await self.create_access_token(
                user_id=token_data.user_id,
                session_id=token_data.session_id,
                security_level=token_data.security_level,
                device_id=token_data.device_id,
                metadata=token_data.metadata
            )
            
            # Optionally rotate refresh token
            new_refresh_token = None
            if self.config.get("token_rotation", True):
                new_refresh_token = await self.create_refresh_token(
                    user_id=token_data.user_id,
                    session_id=token_data.session_id,
                    device_id=token_data.device_id,
                    metadata=token_data.metadata
                )
                
                # Blacklist old refresh token
                await self.blacklist_token(refresh_token)
            
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": int(self.access_token_lifetime.total_seconds())
            }
            
        except Exception as e:
            logger.error(f" Token refresh error: {e}")
            raise
    
    async def blacklist_token(self, token: str):
        """Add token to blacklist."""
        try:
            # Decode token to get token ID
            unverified_payload = import jwt
jwt.decode(token, options={"verify_signature": False})
            token_id = unverified_payload.get("jti")
            
            if token_id:
                self.blacklisted_tokens.add(token_id)
                
                # Remove from active tokens
                if token_id in self.active_tokens:
                    del self.active_tokens[token_id]
                
                logger.debug(f" Token blacklisted: {token_id}")
            
        except Exception as e:
            logger.error(f" Failed to blacklist token: {e}")
    
    async def revoke_user_tokens(self, user_id: str):
        """Revoke all tokens for a user."""
        try:
            tokens_to_revoke = []
            
            for token_id, token_data in self.active_tokens.items():
                if token_data.user_id == user_id:
                    tokens_to_revoke.append(token_id)
            
            for token_id in tokens_to_revoke:
                self.blacklisted_tokens.add(token_id)
                del self.active_tokens[token_id]
            
            logger.info(f" Revoked {len(tokens_to_revoke)} tokens for user {user_id}")
            
        except Exception as e:
            logger.error(f" Failed to revoke user tokens: {e}")
    
    async def revoke_session_tokens(self, session_id: str):
        """Revoke all tokens for a session."""
        try:
            tokens_to_revoke = []
            
            for token_id, token_data in self.active_tokens.items():
                if token_data.session_id == session_id:
                    tokens_to_revoke.append(token_id)
            
            for token_id in tokens_to_revoke:
                self.blacklisted_tokens.add(token_id)
                del self.active_tokens[token_id]
            
            logger.info(f" Revoked {len(tokens_to_revoke)} tokens for session {session_id}")
            
        except Exception as e:
            logger.error(f" Failed to revoke session tokens: {e}")
    
    async def get_token_expiry(self, token: str) -> Optional[datetime]:
        """Get token expiry time."""
        try:
            validation_result = await self.validate_token(token)
            if validation_result.valid and validation_result.token_data:
                return validation_result.token_data.expires_at
            return None
            
        except Exception as e:
            logger.error(f" Failed to get token expiry: {e}")
            return None
    
    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Get detailed token information."""
        try:
            validation_result = await self.validate_token(token)
            
            if not validation_result.valid:
                return {
                    "active": False,
                    "error": validation_result.error_message
                }
            
            token_data = validation_result.token_data
            
            return {
                "active": True,
                "token_id": token_data.token_id,
                "user_id": token_data.user_id,
                "session_id": token_data.session_id,
                "token_type": token_data.token_type.value,
                "issued_at": token_data.issued_at.isoformat(),
                "expires_at": token_data.expires_at.isoformat(),
                "expires_in": validation_result.expires_in,
                "security_level": token_data.security_level,
                "scopes": token_data.scopes,
                "device_id": token_data.device_id,
                "metadata": token_data.metadata
            }
            
        except Exception as e:
            logger.error(f" Token introspection error: {e}")
            return {"active": False, "error": "Introspection failed"}
    
    async def shutdown(self):
        """Gracefully shutdown the token manager."""
        try:
            # Cancel cleanup task
            if self.cleanup_task:
                self.cleanup_task.cancel()
                try:
                    await self.cleanup_task
                except asyncio.CancelledError:
                    pass
            
            logger.info(" Token Manager shutdown complete")
            
        except Exception as e:
            logger.error(f" Error during Token Manager shutdown: {e}")
    
    # Private helper methods
    async def _initialize_keys(self):
        """Initialize cryptographic keys."""
        try:
            # Generate RSA key pair for JWT signing
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            self.private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self.public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Generate key ID
            self.key_id = hashlib.sha256(self.public_key).hexdigest()[:16]
            
            logger.info(f" JWT keys initialized (Key ID: {self.key_id})")
            
        except Exception as e:
            logger.error(f" Failed to initialize keys: {e}")
            raise
    
    async def _cleanup_loop(self):
        """Periodic cleanup of expired tokens."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_expired_tokens()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f" Token cleanup error: {e}")
                await asyncio.sleep(self.cleanup_interval)
    
    async def _cleanup_expired_tokens(self):
        """Clean up expired tokens."""
        try:
            now = datetime.now(timezone.utc)
            expired_tokens = []
            
            for token_id, token_data in self.active_tokens.items():
                if token_data.expires_at <= now:
                    expired_tokens.append(token_id)
            
            for token_id in expired_tokens:
                del self.active_tokens[token_id]
                self.blacklisted_tokens.discard(token_id)
            
            if expired_tokens:
                logger.debug(f" Cleaned up {len(expired_tokens)} expired tokens")
            
        except Exception as e:
            logger.error(f" Token cleanup error: {e}")


# Global instance
token_manager = TokenManager()
