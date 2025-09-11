# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any

import aiofiles

from ..core.logging import get_logger

"""
import time
OAuth Provider for Plugin Marketplace

Provides OAuth 2.0 authentication and authorization for plugin developers
to publish and manage their plugins in the PlexiChat marketplace.
"""

logger = get_logger(__name__)


class OAuthScope(Enum):
    """OAuth scopes for plugin marketplace."""
    PLUGIN_READ = "plugin:read"
    PLUGIN_PUBLISH = "plugin:publish"
    PLUGIN_MANAGE = "plugin:manage"
    PLUGIN_DELETE = "plugin:delete"
    REVIEWS_READ = "reviews:read"
    REVIEWS_WRITE = "reviews:write"
    REVIEWS_MODERATE = "reviews:moderate"
    MARKETPLACE_ADMIN = "marketplace:admin"


class GrantType(Enum):
    """OAuth grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"


@dataclass
class OAuthClient:
    """OAuth client information."""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: list[str]
    scopes: list[OAuthScope]
    grant_types: list[GrantType]
    developer_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True
    is_trusted: bool = False


@dataclass
class AuthorizationCode:
    """Authorization code for OAuth flow."""
    code: str
    client_id: str
    user_id: str
    scopes: list[OAuthScope]
    redirect_uri: str
    expires_at: datetime
    code_challenge: str | None = None
    code_challenge_method: str | None = None


@dataclass
class AccessToken:
    """OAuth access token."""
    token: str
    client_id: str
    user_id: str
    scopes: list[OAuthScope]
    expires_at: datetime
    token_type: str = "Bearer"


@dataclass
class RefreshToken:
    """OAuth refresh token."""
    token: str
    client_id: str
    user_id: str
    scopes: list[OAuthScope]
    expires_at: datetime


class PluginOAuthProvider:
    """OAuth 2.0 provider for plugin marketplace."""
    def __init__(self, config: dict[str, Any] = None):
        self.config = config or self._load_default_config()
        self.data_dir = Path(self.config.get("data_dir", "data/oauth"))

        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Storage
        self.clients: dict[str, OAuthClient] = {}
        self.authorization_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

        # JWT settings
        self.jwt_secret = self.config.get("jwt_secret", secrets.token_urlsafe(32))
        self.jwt_algorithm = "HS256"

        logger.info("Plugin OAuth Provider initialized")

    def _load_default_config(self) -> dict[str, Any]:
        """Load default OAuth configuration."""
        return {
            "data_dir": "data/oauth",
            "access_token_ttl": 3600,  # 1 hour
            "refresh_token_ttl": 2592000,  # 30 days
            "authorization_code_ttl": 600,  # 10 minutes
            "jwt_secret": secrets.token_urlsafe(32),
            "require_pkce": True,
            "supported_scopes": [scope.value for scope in OAuthScope],
            "supported_grant_types": [grant.value for grant in GrantType]
        }

    async def initialize(self) -> bool:
        """Initialize the OAuth provider."""
        try:
            logger.info("Initializing Plugin OAuth Provider...")

            # Load existing data
            await self._load_oauth_data()

            # Create default client if none exist
            if not self.clients:
                await self._create_default_client()

            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_tokens())

            logger.info("Plugin OAuth Provider initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize OAuth Provider: {e}")
            return False

    async def register_client(self, client_name: str, redirect_uris: list[str],
                            scopes: list[str], developer_id: str,
                            grant_types: list[str] | None = None) -> dict[str, Any]:
        """Register a new OAuth client."""
        try:
            # Validate scopes
            valid_scopes = []
            for scope in scopes:
                try:
                    valid_scopes.append(OAuthScope(scope))
                except ValueError:
                    return {"success": False, "error": f"Invalid scope: {scope}"}

            # Validate grant types
            valid_grant_types = []
            for grant_type in (grant_types or ["authorization_code"]):
                try:
                    valid_grant_types.append(GrantType(grant_type))
                except ValueError:
                    return {"success": False, "error": f"Invalid grant type: {grant_type}"}

            # Generate client credentials
            client_id = f"plexichat_plugin_{secrets.token_urlsafe(16)}"
            client_secret = secrets.token_urlsafe(32)

            # Create client
            client = OAuthClient(
                client_id=client_id,
                client_secret=client_secret,
                client_name=client_name,
                redirect_uris=redirect_uris,
                scopes=valid_scopes,
                grant_types=valid_grant_types,
                developer_id=developer_id
            )

            # Store client
            self.clients[client_id] = client
            await self._save_oauth_data()

            logger.info(f"Registered OAuth client: {client_name}")

            return {
                "success": True,
                "client_id": client_id,
                "client_secret": client_secret,
                "message": "Client registered successfully"
            }

        except Exception as e:
            logger.error(f"Failed to register OAuth client: {e}")
            return {"success": False, "error": str(e)}

    async def authorize(self, client_id: str, redirect_uri: str, scopes: list[str],
                    user_id: str, state: str | None = None, code_challenge: str | None = None,
                    code_challenge_method: str | None = None) -> dict[str, Any]:
        """Generate authorization code for OAuth flow."""
        try:
            # Validate client
            if client_id not in self.clients:
                return {"success": False, "error": "Invalid client"}

            client = self.clients[client_id]

            if not client.is_active:
                return {"success": False, "error": "Client is inactive"}

            # Validate redirect URI
            if redirect_uri not in client.redirect_uris:
                return {"success": False, "error": "Invalid redirect URI"}

            # Validate scopes
            requested_scopes = []
            for scope in scopes:
                try:
                    oauth_scope = OAuthScope(scope)
                    if oauth_scope not in client.scopes:
                        return {"success": False, "error": f"Scope not allowed: {scope}"}
                    requested_scopes.append(oauth_scope)
                except ValueError:
                    return {"success": False, "error": f"Invalid scope: {scope}"}

            # Validate PKCE if required
            if self.config["require_pkce"] and not code_challenge:
                return {"success": False, "error": "PKCE code challenge required"}

            # Generate authorization code
            auth_code = secrets.token_urlsafe(32)
            expires_at = datetime.now(UTC) + timedelta(seconds=self.config["authorization_code_ttl"])

            authorization = AuthorizationCode(
                code=auth_code,
                client_id=client_id,
                user_id=user_id,
                scopes=requested_scopes,
                redirect_uri=redirect_uri,
                expires_at=expires_at,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method
            )

            self.authorization_codes[auth_code] = authorization

            # Build redirect URL
            redirect_params = {"code": auth_code}
            if state:
                redirect_params["state"] = state

            query_string = "&".join([f"{k}={v}" for k, v in redirect_params.items()])
            redirect_url = f"{redirect_uri}?{query_string}"

            return {
                "success": True,
                "authorization_code": auth_code,
                "redirect_url": redirect_url,
                "expires_in": self.config["authorization_code_ttl"]
            }

        except Exception as e:
            logger.error(f"Authorization failed: {e}")
            return {"success": False, "error": str(e)}

    async def exchange_code_for_token(self, client_id: str, client_secret: str,
                                    code: str, redirect_uri: str,
                                    code_verifier: str | None = None) -> dict[str, Any]:
        """Exchange authorization code for access token."""
        try:
            # Validate client
            if client_id not in self.clients:
                return {"success": False, "error": "Invalid client"}

            client = self.clients[client_id]

            if client.client_secret != client_secret:
                return {"success": False, "error": "Invalid client secret"}

            # Validate authorization code
            if code not in self.authorization_codes:
                return {"success": False, "error": "Invalid authorization code"}

            authorization = self.authorization_codes[code]

            if authorization.client_id != client_id:
                return {"success": False, "error": "Authorization code mismatch"}

            if authorization.redirect_uri != redirect_uri:
                return {"success": False, "error": "Redirect URI mismatch"}

            if datetime.now(UTC) > authorization.expires_at:
                del self.authorization_codes[code]
                return {"success": False, "error": "Authorization code expired"}

            # Validate PKCE if present
            if authorization.code_challenge:
                if not code_verifier:
                    return {"success": False, "error": "Code verifier required"}

                if authorization.code_challenge_method == "S256":
                    challenge = base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode()).digest()
                    ).decode().rstrip('=')
                else:
                    challenge = code_verifier

                if challenge != authorization.code_challenge:
                    return {"success": False, "error": "Invalid code verifier"}

            # Generate tokens
            access_token = await self._generate_access_token(
                client_id, authorization.user_id, authorization.scopes
            )

            refresh_token = await self._generate_refresh_token(
                client_id, authorization.user_id, authorization.scopes
            )

            # Clean up authorization code
            del self.authorization_codes[code]

            return {
                "success": True,
                "access_token": access_token.token,
                "token_type": access_token.token_type,
                "expires_in": int((access_token.expires_at - datetime.now(UTC)).total_seconds()),
                "refresh_token": refresh_token.token,
                "scope": " ".join([scope.value for scope in authorization.scopes])
            }

        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            return {"success": False, "error": str(e)}

    async def refresh_access_token(self, client_id: str, client_secret: str,
                                refresh_token: str) -> dict[str, Any]:
        """Refresh an access token using refresh token."""
        try:
            # Validate client
            if client_id not in self.clients:
                return {"success": False, "error": "Invalid client"}

            client = self.clients[client_id]

            if client.client_secret != client_secret:
                return {"success": False, "error": "Invalid client secret"}

            # Validate refresh token
            if refresh_token not in self.refresh_tokens:
                return {"success": False, "error": "Invalid refresh token"}

            refresh_token_obj = self.refresh_tokens[refresh_token]

            if refresh_token_obj.client_id != client_id:
                return {"success": False, "error": "Refresh token mismatch"}

            if datetime.now(UTC) > refresh_token_obj.expires_at:
                del self.refresh_tokens[refresh_token]
                return {"success": False, "error": "Refresh token expired"}

            # Generate new access token
            access_token = await self._generate_access_token(
                client_id, refresh_token_obj.user_id, refresh_token_obj.scopes
            )

            return {
                "success": True,
                "access_token": access_token.token,
                "token_type": access_token.token_type,
                "expires_in": int((access_token.expires_at - datetime.now(UTC)).total_seconds()),
                "scope": " ".join([scope.value for scope in refresh_token_obj.scopes])
            }

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return {"success": False, "error": str(e)}

    async def validate_token(self, token: str) -> dict[str, Any] | None:
        """Validate an access token and return token info."""
        try:
            if token not in self.access_tokens:
                return None

            access_token = self.access_tokens[token]

            if datetime.now(UTC) > access_token.expires_at:
                del self.access_tokens[token]
                return None

            return {
                "client_id": access_token.client_id,
                "user_id": access_token.user_id,
                "scopes": [scope.value for scope in access_token.scopes],
                "expires_at": access_token.expires_at.isoformat()
            }

        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None

    async def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """Revoke an access or refresh token."""
        try:
            if token_type == "access_token" and token in self.access_tokens:
                del self.access_tokens[token]
                return True
            elif token_type == "refresh_token" and token in self.refresh_tokens:
                del self.refresh_tokens[token]
                return True

            return False

        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False

    async def _generate_access_token(self, client_id: str, user_id: str,
                                scopes: list[OAuthScope]) -> AccessToken:
        """Generate a new access token."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=self.config["access_token_ttl"])

        access_token = AccessToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scopes=scopes,
            expires_at=expires_at
        )

        self.access_tokens[token] = access_token
        return access_token

    async def _generate_refresh_token(self, client_id: str, user_id: str,
                                    scopes: list[OAuthScope]) -> RefreshToken:
        """Generate a new refresh token."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=self.config["refresh_token_ttl"])

        refresh_token = RefreshToken(
            token=token,
            client_id=client_id,
            user_id=user_id,
            scopes=scopes,
            expires_at=expires_at
        )

        self.refresh_tokens[token] = refresh_token
        return refresh_token

    async def _create_default_client(self):
        """Create a default OAuth client for testing."""
        try:
            await self.register_client(
                client_name="PlexiChat Plugin Developer",
                redirect_uris=["http://localhost:8080/oauth/callback"],
                scopes=[scope.value for scope in OAuthScope],
                developer_id="system",
                grant_types=["authorization_code", "client_credentials"]
            )

            logger.info("Created default OAuth client")

        except Exception as e:
            logger.error(f"Failed to create default client: {e}")

    async def _cleanup_expired_tokens(self):
        """Periodically clean up expired tokens."""
        while True:
            try:
                now = datetime.now(UTC)

                # Clean up expired authorization codes
                expired_codes = [
                    code for code, auth in self.authorization_codes.items()
                    if now > auth.expires_at
                ]
                for code in expired_codes:
                    del self.authorization_codes[code]

                # Clean up expired access tokens
                expired_access = [
                    token for token, access in self.access_tokens.items()
                    if now > access.expires_at
                ]
                for token in expired_access:
                    del self.access_tokens[token]

                # Clean up expired refresh tokens
                expired_refresh = [
                    token for token, refresh in self.refresh_tokens.items()
                    if now > refresh.expires_at
                ]
                for token in expired_refresh:
                    del self.refresh_tokens[token]

                if expired_codes or expired_access or expired_refresh:
                    logger.debug(f"Cleaned up {len(expired_codes)} codes, {len(expired_access)} access tokens, {len(expired_refresh)} refresh tokens")

                # Sleep for 5 minutes
                await asyncio.sleep(300)

            except Exception as e:
                logger.error(f"Token cleanup failed: {e}")
                await asyncio.sleep(60)  # Retry in 1 minute

    async def _load_oauth_data(self):
        """Load OAuth data from storage."""
        try:
            # Load clients
            clients_file = self.data_dir / "clients.json"
            if clients_file.exists():
                async with aiofiles.open(clients_file) as f:
                    clients_data = json.loads(await f.read())

                for client_data in clients_data:
                    client = self._dict_to_client(client_data)
                    self.clients[client.client_id] = client

            logger.info(f"Loaded {len(self.clients)} OAuth clients")

        except Exception as e:
            logger.error(f"Failed to load OAuth data: {e}")

    async def _save_oauth_data(self):
        """Save OAuth data to storage."""
        try:
            # Save clients
            clients_data = [self._client_to_dict(client) for client in self.clients.values()]
            clients_file = self.data_dir / "clients.json"
            async with aiofiles.open(clients_file, 'w') as f:
                await f.write(json.dumps(clients_data, indent=2, default=str))

            logger.debug("OAuth data saved successfully")

        except Exception as e:
            logger.error(f"Failed to save OAuth data: {e}")

    def _client_to_dict(self, client: OAuthClient) -> dict[str, Any]:
        """Convert client to dictionary."""
        return {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "scopes": [scope.value for scope in client.scopes],
            "grant_types": [grant.value for grant in client.grant_types],
            "developer_id": client.developer_id,
            "created_at": client.created_at.isoformat(),
            "is_active": client.is_active,
            "is_trusted": client.is_trusted
        }

    def _dict_to_client(self, data: dict[str, Any]) -> OAuthClient:
        """Convert dictionary to client."""
        return OAuthClient(
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            client_name=data["client_name"],
            redirect_uris=data["redirect_uris"],
            scopes=[OAuthScope(scope) for scope in data["scopes"]],
            grant_types=[GrantType(grant) for grant in data["grant_types"]],
            developer_id=data["developer_id"],
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"],
            is_active=data.get("is_active", True),
            is_trusted=data.get("is_trusted", False)
        )


# Global service instance
_oauth_provider: PluginOAuthProvider | None = None


def get_plugin_oauth_provider() -> PluginOAuthProvider:
    """Get the global OAuth provider instance."""
    global _oauth_provider
    if _oauth_provider is None:
        _oauth_provider = PluginOAuthProvider()
    return _oauth_provider


async def initialize_plugin_oauth() -> bool:
    """Initialize the OAuth provider."""
    provider = get_plugin_oauth_provider()
    if provider and hasattr(provider, "initialize"):
        return await provider.initialize()
    return False
