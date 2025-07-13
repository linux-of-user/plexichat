import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


import jwt

"""
PlexiChat OAuth Provider

Comprehensive OAuth 2.0 and OpenID Connect provider with PKCE support,
JWT tokens, and enterprise-grade security features.
"""

logger = logging.getLogger(__name__)


class GrantType(Enum):
    """OAuth 2.0 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "device_code"
    IMPLICIT = "implicit"  # Deprecated but supported


class TokenType(Enum):
    """Token types."""
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"
    DEVICE_CODE = "device_code"


class ClientType(Enum):
    """OAuth client types."""
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


@dataclass
class OAuthClient:
    """OAuth client registration."""
    client_id: str
    client_secret: Optional[str]
    client_type: ClientType
    redirect_uris: List[str]
    scopes: Set[str]
    grant_types: Set[GrantType]
    name: str
    description: Optional[str] = None
    logo_uri: Optional[str] = None
    contacts: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert client to dictionary."""
        return {
            "client_id": self.client_id,
            "client_type": self.client_type.value,
            "redirect_uris": self.redirect_uris,
            "scopes": list(self.scopes),
            "grant_types": [gt.value for gt in self.grant_types],
            "name": self.name,
            "description": self.description,
            "logo_uri": self.logo_uri,
            "contacts": self.contacts,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active
        }


@dataclass
class AuthorizationCode:
    """Authorization code for OAuth flow."""
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scopes: Set[str]
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))
    used: bool = False
    
    @property
    def is_expired(self) -> bool:
        """Check if code is expired."""
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class AccessToken:
    """Access token."""
    token: str
    client_id: str
    user_id: Optional[str]
    scopes: Set[str]
    token_type: str = "Bearer"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1))
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary."""
        return {
            "access_token": self.token,
            "token_type": self.token_type,
            "expires_in": int((self.expires_at - datetime.now(timezone.utc)).total_seconds()),
            "scope": " ".join(self.scopes)
        }


@dataclass
class RefreshToken:
    """Refresh token."""
    token: str
    client_id: str
    user_id: str
    scopes: Set[str]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=30))
    used: bool = False
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.expires_at


class OAuthProvider:
    """Comprehensive OAuth 2.0 and OpenID Connect provider."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize OAuth provider."""
        self.config = config or {}
        
        # Storage
        self.clients: Dict[str, OAuthClient] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        
        # Configuration
        self.issuer = self.config.get("issuer", "https://plexichat.local")
        self.authorization_endpoint = f"{self.issuer}/oauth/authorize"
        self.token_endpoint = f"{self.issuer}/oauth/token"
        self.userinfo_endpoint = f"{self.issuer}/oauth/userinfo"
        self.jwks_endpoint = f"{self.issuer}/.well-known/jwks.json"
        
        # JWT configuration
        self.jwt_algorithm = "RS256"
        self.jwt_private_key, self.jwt_public_key = self._generate_jwt_keys()
        
        # Supported features
        self.supported_grant_types = [
            GrantType.AUTHORIZATION_CODE,
            GrantType.CLIENT_CREDENTIALS,
            GrantType.REFRESH_TOKEN
        ]
        self.supported_scopes = {
            "openid", "profile", "email", "read", "write", "admin"
        }
        
        logger.info("OAuth Provider initialized")
    
    def _generate_jwt_keys(self) -> Tuple[str, str]:
        """Generate RSA key pair for JWT signing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    async def register_client(self, 
                            name: str,
                            client_type: ClientType,
                            redirect_uris: List[str],
                            scopes: Optional[Set[str]] = None,
                            grant_types: Optional[Set[GrantType]] = None,
                            description: Optional[str] = None) -> OAuthClient:
        """Register a new OAuth client."""
        client_id = self._generate_client_id()
        client_secret = self._generate_client_secret() if client_type == ClientType.CONFIDENTIAL else None
        
        if not scopes:
            scopes = {"read"}
        
        if not grant_types:
            grant_types = {GrantType.AUTHORIZATION_CODE}
        
        # Validate scopes
        invalid_scopes = scopes - self.supported_scopes
        if invalid_scopes:
            raise ValueError(f"Unsupported scopes: {invalid_scopes}")
        
        # Validate grant types
        invalid_grants = grant_types - set(self.supported_grant_types)
        if invalid_grants:
            raise ValueError(f"Unsupported grant types: {invalid_grants}")
        
        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            client_type=client_type,
            redirect_uris=redirect_uris,
            scopes=scopes,
            grant_types=grant_types,
            name=name,
            description=description
        )
        
        self.clients[client_id] = client
        logger.info(f"OAuth client registered: {client_id}")
        
        return client
    
    def _generate_client_id(self) -> str:
        """Generate unique client ID."""
        return f"plexichat_{secrets.token_urlsafe(16)}"
    
    def _generate_client_secret(self) -> str:
        """Generate client secret."""
        return secrets.token_urlsafe(32)
    
    async def create_authorization_code(self,
                                      client_id: str,
                                      user_id: str,
                                      redirect_uri: str,
                                      scopes: Set[str],
                                      code_challenge: Optional[str] = None,
                                      code_challenge_method: Optional[str] = None) -> str:
        """Create authorization code for OAuth flow."""
        client = self.clients.get(client_id)
        if not client:
            raise ValueError("Invalid client_id")
        
        if redirect_uri not in client.redirect_uris:
            raise ValueError("Invalid redirect_uri")
        
        # Validate scopes
        invalid_scopes = scopes - client.scopes
        if invalid_scopes:
            raise ValueError(f"Client not authorized for scopes: {invalid_scopes}")
        
        code = secrets.token_urlsafe(32)
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        
        self.authorization_codes[code] = auth_code
        logger.info(f"Authorization code created for client {client_id}")
        
        return code
    
    async def exchange_authorization_code(self,
                                        client_id: str,
                                        client_secret: Optional[str],
                                        code: str,
                                        redirect_uri: str,
                                        code_verifier: Optional[str] = None) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        # Validate client
        client = self.clients.get(client_id)
        if not client:
            raise ValueError("Invalid client_id")
        
        if client.client_type == ClientType.CONFIDENTIAL:
            if not client_secret or not self._verify_client_secret(client.client_secret, client_secret):
                raise ValueError("Invalid client_secret")
        
        # Validate authorization code
        auth_code = self.authorization_codes.get(code)
        if not auth_code or auth_code.used or auth_code.is_expired:
            raise ValueError("Invalid or expired authorization code")
        
        if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
            raise ValueError("Authorization code mismatch")
        
        # Validate PKCE if used
        if auth_code.code_challenge:
            if not code_verifier:
                raise ValueError("Code verifier required for PKCE")
            
            if not self._verify_pkce(auth_code.code_challenge, auth_code.code_challenge_method, code_verifier):
                raise ValueError("Invalid code verifier")
        
        # Mark code as used
        auth_code.used = True
        
        # Create access token
        access_token = await self._create_access_token(client_id, auth_code.user_id, auth_code.scopes)
        
        # Create refresh token
        refresh_token = await self._create_refresh_token(client_id, auth_code.user_id, auth_code.scopes)
        
        response = access_token.to_dict()
        response["refresh_token"] = refresh_token.token
        
        # Add ID token for OpenID Connect
        if "openid" in auth_code.scopes:
            id_token = await self._create_id_token(client_id, auth_code.user_id, auth_code.scopes)
            response["id_token"] = id_token
        
        logger.info(f"Authorization code exchanged for client {client_id}")
        
        return response
    
    def _verify_client_secret(self, stored_secret: str, provided_secret: str) -> bool:
        """Verify client secret."""
        return secrets.compare_digest(stored_secret, provided_secret)
    
    def _verify_pkce(self, code_challenge: str, method: str, code_verifier: str) -> bool:
        """Verify PKCE code challenge."""
        if method == "S256":
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip('=')
            return secrets.compare_digest(code_challenge, challenge)
        elif method == "plain":
            return secrets.compare_digest(code_challenge, code_verifier)
        else:
            return False

    async def _create_access_token(self, client_id: str, user_id: Optional[str], scopes: Set[str]) -> AccessToken:
        """Create access token."""
        token = secrets.token_urlsafe(32)

        access_token = AccessToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scopes=scopes
        )

        self.access_tokens[token] = access_token
        return access_token

    async def _create_refresh_token(self, client_id: str, user_id: str, scopes: Set[str]) -> RefreshToken:
        """Create refresh token."""
        token = secrets.token_urlsafe(32)

        refresh_token = RefreshToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scopes=scopes
        )

        self.refresh_tokens[token] = refresh_token
        return refresh_token

    async def _create_id_token(self, client_id: str, user_id: str, scopes: Set[str]) -> str:
        """Create OpenID Connect ID token."""
        now = datetime.now(timezone.utc)

        payload = {
            "iss": self.issuer,
            "sub": user_id,
            "aud": client_id,
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "auth_time": int(now.timestamp())
        }

        # Add profile claims if requested
        if "profile" in scopes:
            # These would typically come from user database
            payload.update({
                "name": f"User {user_id}",
                "preferred_username": f"user_{user_id}"
            })

        if "email" in scopes:
            payload["email"] = f"user_{user_id}@plexichat.local"
            payload["email_verified"] = True

        return jwt.encode(payload, self.jwt_private_key, algorithm=self.jwt_algorithm)

    async def refresh_access_token(self, client_id: str, client_secret: Optional[str], refresh_token: str) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        # Validate client
        client = self.clients.get(client_id)
        if not client:
            raise ValueError("Invalid client_id")

        if client.client_type == ClientType.CONFIDENTIAL:
            if not client_secret or not self._verify_client_secret(client.client_secret, client_secret):
                raise ValueError("Invalid client_secret")

        # Validate refresh token
        refresh_token_obj = self.refresh_tokens.get(refresh_token)
        if not refresh_token_obj or refresh_token_obj.used or refresh_token_obj.is_expired:
            raise ValueError("Invalid or expired refresh token")

        if refresh_token_obj.client_id != client_id:
            raise ValueError("Refresh token client mismatch")

        # Mark old refresh token as used
        refresh_token_obj.used = True

        # Create new access token
        access_token = await self._create_access_token(client_id, refresh_token_obj.user_id, refresh_token_obj.scopes)

        # Create new refresh token
        new_refresh_token = await self._create_refresh_token(client_id, refresh_token_obj.user_id, refresh_token_obj.scopes)

        response = access_token.to_dict()
        response["refresh_token"] = new_refresh_token.token

        logger.info(f"Access token refreshed for client {client_id}")

        return response

    async def validate_access_token(self, token: str) -> Optional[AccessToken]:
        """Validate access token."""
        access_token = self.access_tokens.get(token)
        if not access_token or access_token.is_expired:
            return None

        return access_token

    async def revoke_token(self, token: str, client_id: str, client_secret: Optional[str] = None) -> bool:
        """Revoke access or refresh token."""
        # Validate client
        client = self.clients.get(client_id)
        if not client:
            return False

        if client.client_type == ClientType.CONFIDENTIAL:
            if not client_secret or not self._verify_client_secret(client.client_secret, client_secret):
                return False

        # Try to revoke access token
        if token in self.access_tokens:
            del self.access_tokens[token]
            logger.info(f"Access token revoked for client {client_id}")
            return True

        # Try to revoke refresh token
        if token in self.refresh_tokens:
            refresh_token_obj = self.refresh_tokens[token]
            if refresh_token_obj.client_id == client_id:
                del self.refresh_tokens[token]
                logger.info(f"Refresh token revoked for client {client_id}")
                return True

        return False

    async def get_client_credentials_token(self, client_id: str, client_secret: str, scopes: Optional[Set[str]] = None) -> Dict[str, Any]:
        """Get access token using client credentials grant."""
        # Validate client
        client = self.clients.get(client_id)
        if not client or client.client_type != ClientType.CONFIDENTIAL:
            raise ValueError("Invalid client_id or client type")

        if not self._verify_client_secret(client.client_secret, client_secret):
            raise ValueError("Invalid client_secret")

        if GrantType.CLIENT_CREDENTIALS not in client.grant_types:
            raise ValueError("Client not authorized for client_credentials grant")

        # Validate scopes
        if not scopes:
            scopes = client.scopes
        else:
            invalid_scopes = scopes - client.scopes
            if invalid_scopes:
                raise ValueError(f"Client not authorized for scopes: {invalid_scopes}")

        # Create access token (no user context for client credentials)
        access_token = await self._create_access_token(client_id, None, scopes)

        logger.info(f"Client credentials token issued for client {client_id}")

        return access_token.to_dict()

    async def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Get user information for OpenID Connect."""
        token_obj = await self.validate_access_token(access_token)
        if not token_obj or not token_obj.user_id:
            raise ValueError("Invalid access token")

        if "openid" not in token_obj.scopes:
            raise ValueError("OpenID scope required")

        userinfo = {
            "sub": token_obj.user_id
        }

        if "profile" in token_obj.scopes:
            userinfo.update({
                "name": f"User {token_obj.user_id}",
                "preferred_username": f"user_{token_obj.user_id}"
            })

        if "email" in token_obj.scopes:
            userinfo.update({
                "email": f"user_{token_obj.user_id}@plexichat.local",
                "email_verified": True
            })

        return userinfo

    async def get_jwks(self) -> Dict[str, Any]:
        """Get JSON Web Key Set for token verification."""
        # This is a simplified implementation
        # In production, you'd want proper key management
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": self.jwt_algorithm,
                    "kid": "plexichat-key-1",
                    "n": "...",  # Base64url-encoded modulus
                    "e": "AQAB"  # Base64url-encoded exponent
                }
            ]
        }

    async def get_discovery_document(self) -> Dict[str, Any]:
        """Get OpenID Connect discovery document."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_endpoint,
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self.jwt_algorithm],
            "scopes_supported": list(self.supported_scopes),
            "grant_types_supported": [gt.value for gt in self.supported_grant_types],
            "code_challenge_methods_supported": ["S256", "plain"]
        }

    async def list_clients(self) -> List[Dict[str, Any]]:
        """List all registered clients."""
        return [client.to_dict() for client in self.clients.values()]

    async def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get client information."""
        client = self.clients.get(client_id)
        return client.to_dict() if client else None

    async def update_client(self, client_id: str, updates: Dict[str, Any]) -> bool:
        """Update client information."""
        client = self.clients.get(client_id)
        if not client:
            return False

        # Update allowed fields
        if "name" in updates:
            client.name = updates["name"]
        if "description" in updates:
            client.description = updates["description"]
        if "redirect_uris" in updates:
            client.redirect_uris = updates["redirect_uris"]
        if "is_active" in updates:
            client.is_active = updates["is_active"]

        logger.info(f"Client {client_id} updated")
        return True

    async def delete_client(self, client_id: str) -> bool:
        """Delete OAuth client."""
        if client_id in self.clients:
            del self.clients[client_id]

            # Revoke all tokens for this client
            tokens_to_remove = [token for token, token_obj in self.access_tokens.items() if token_obj.client_id == client_id]
            for token in tokens_to_remove:
                del self.access_tokens[token]

            refresh_tokens_to_remove = [token for token, token_obj in self.refresh_tokens.items() if token_obj.client_id == client_id]
            for token in refresh_tokens_to_remove:
                del self.refresh_tokens[token]

            logger.info(f"Client {client_id} deleted")
            return True

        return False

    async def cleanup_expired_tokens(self):
        """Clean up expired tokens and codes."""
        datetime.now(timezone.utc)

        # Clean up expired authorization codes
        expired_codes = [code for code, code_obj in self.authorization_codes.items() if code_obj.is_expired]
        for code in expired_codes:
            del self.authorization_codes[code]

        # Clean up expired access tokens
        expired_access_tokens = [token for token, token_obj in self.access_tokens.items() if token_obj.is_expired]
        for token in expired_access_tokens:
            del self.access_tokens[token]

        # Clean up expired refresh tokens
        expired_refresh_tokens = [token for token, token_obj in self.refresh_tokens.items() if token_obj.is_expired]
        for token in expired_refresh_tokens:
            del self.refresh_tokens[token]

        if expired_codes or expired_access_tokens or expired_refresh_tokens:
            logger.info(f"Cleaned up {len(expired_codes)} codes, {len(expired_access_tokens)} access tokens, {len(expired_refresh_tokens)} refresh tokens")


# Global instance
oauth_provider = OAuthProvider()
