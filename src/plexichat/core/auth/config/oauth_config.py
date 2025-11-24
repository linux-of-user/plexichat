"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

OAuth2 Configuration Module
"""

import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin


class OAuthProvider(Enum):
    """Supported OAuth2 providers."""

    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    GITLAB = "gitlab"


@dataclass
class OAuth2ProviderConfig:
    """
    Configuration for a single OAuth2 provider.

    Supports standard OAuth2 flows with PKCE and state validation.
    """

    provider: OAuthProvider
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    user_info_url: str
    scope: str
    redirect_uri: str

    # Advanced Security Features
    pkce_required: bool = True
    state_validation: bool = True
    nonce_support: bool = False

    # Provider-specific settings
    additional_scopes: List[str] = field(default_factory=list)
    custom_parameters: Dict[str, str] = field(default_factory=dict)

    # Rate limiting
    requests_per_minute: int = 60
    burst_limit: int = 10

    # Token settings
    access_token_lifetime: int = 3600  # 1 hour
    refresh_token_lifetime: int = 2592000  # 30 days

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.client_id or not self.client_secret:
            raise ValueError(f"Client ID and secret required for {self.provider.value}")

        if not self.authorization_url or not self.token_url:
            raise ValueError(
                f"Authorization and token URLs required for {self.provider.value}"
            )

    def get_authorization_url(
        self, state: Optional[str] = None, pkce_challenge: Optional[str] = None
    ) -> str:
        """Generate OAuth2 authorization URL."""
        from urllib.parse import urlencode

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "response_type": "code",
        }

        if self.state_validation:
            params["state"] = state or secrets.token_urlsafe(32)

        if self.pkce_required and pkce_challenge:
            params["code_challenge"] = pkce_challenge
            params["code_challenge_method"] = "S256"

        if self.nonce_support:
            params["nonce"] = secrets.token_urlsafe(16)

        # Add custom parameters
        params.update(self.custom_parameters)

        return f"{self.authorization_url}?{urlencode(params)}"

    def get_full_scope(self) -> str:
        """Get complete scope including additional scopes."""
        scopes = [self.scope]
        scopes.extend(self.additional_scopes)
        return " ".join(scopes)


@dataclass
class OAuth2Config:
    """
    Master OAuth2 configuration for all providers.

    Features:
    - Multiple provider support
    - PKCE and state validation
    - Rate limiting and security
    - Token management
    - Provider-specific customization
    """

    # Provider configurations
    providers: Dict[OAuthProvider, OAuth2ProviderConfig] = field(default_factory=dict)

    # Global settings
    enable_oauth2: bool = True
    default_provider: Optional[OAuthProvider] = None
    allow_multiple_providers: bool = True

    # Security settings
    state_timeout_seconds: int = 600  # 10 minutes
    pkce_required: bool = True
    secure_redirect_only: bool = True

    # Rate limiting
    global_requests_per_minute: int = 100
    global_burst_limit: int = 20

    # Token settings
    default_access_token_lifetime: int = 3600
    default_refresh_token_lifetime: int = 2592000

    # User mapping
    auto_create_users: bool = True
    username_template: str = "{provider}_{id}"
    email_verification_required: bool = False

    def __post_init__(self):
        """Initialize default provider configurations."""
        if not self.providers:
            self._initialize_default_providers()

    def _initialize_default_providers(self):
        """Initialize default OAuth2 provider configurations."""
        # Google OAuth2
        google_config = OAuth2ProviderConfig(
            provider=OAuthProvider.GOOGLE,
            client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
            authorization_url="https://accounts.google.com/o/oauth2/auth",
            token_url="https://oauth2.googleapis.com/token",
            user_info_url="https://www.googleapis.com/oauth2/v2/userinfo",
            scope="openid email profile",
            redirect_uri=os.getenv(
                "OAUTH2_REDIRECT_URI", "http://localhost:8000/auth/oauth2/callback"
            ),
            additional_scopes=["https://www.googleapis.com/auth/userinfo.email"],
        )

        # GitHub OAuth2
        github_config = OAuth2ProviderConfig(
            provider=OAuthProvider.GITHUB,
            client_id=os.getenv("GITHUB_CLIENT_ID", ""),
            client_secret=os.getenv("GITHUB_CLIENT_SECRET", ""),
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_info_url="https://api.github.com/user",
            scope="user:email",
            redirect_uri=os.getenv(
                "OAUTH2_REDIRECT_URI", "http://localhost:8000/auth/oauth2/callback"
            ),
            additional_scopes=["read:user"],
        )

        # Microsoft OAuth2
        microsoft_config = OAuth2ProviderConfig(
            provider=OAuthProvider.MICROSOFT,
            client_id=os.getenv("MICROSOFT_CLIENT_ID", ""),
            client_secret=os.getenv("MICROSOFT_CLIENT_SECRET", ""),
            authorization_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
            user_info_url="https://graph.microsoft.com/v1.0/me",
            scope="openid email profile",
            redirect_uri=os.getenv(
                "OAUTH2_REDIRECT_URI", "http://localhost:8000/auth/oauth2/callback"
            ),
        )

        # Only add providers that have credentials configured
        if google_config.client_id and google_config.client_secret:
            self.providers[OAuthProvider.GOOGLE] = google_config

        if github_config.client_id and github_config.client_secret:
            self.providers[OAuthProvider.GITHUB] = github_config

        if microsoft_config.client_id and microsoft_config.client_secret:
            self.providers[OAuthProvider.MICROSOFT] = microsoft_config

        # Set default provider
        if self.providers and not self.default_provider:
            self.default_provider = next(iter(self.providers.keys()))

    @classmethod
    def from_env(cls) -> "OAuth2Config":
        """Create OAuth2 configuration from environment variables."""
        config = cls()

        # Global settings
        config.enable_oauth2 = os.getenv("OAUTH2_ENABLED", "true").lower() == "true"
        config.allow_multiple_providers = (
            os.getenv("OAUTH2_MULTIPLE_PROVIDERS", "true").lower() == "true"
        )

        # Security settings
        config.pkce_required = (
            os.getenv("OAUTH2_PKCE_REQUIRED", "true").lower() == "true"
        )
        config.secure_redirect_only = (
            os.getenv("OAUTH2_SECURE_REDIRECT", "true").lower() == "true"
        )

        # User settings
        config.auto_create_users = (
            os.getenv("OAUTH2_AUTO_CREATE_USERS", "true").lower() == "true"
        )
        config.email_verification_required = (
            os.getenv("OAUTH2_EMAIL_VERIFICATION", "false").lower() == "true"
        )

        if template := os.getenv("OAUTH2_USERNAME_TEMPLATE"):
            config.username_template = template

        return config

    def get_provider_config(
        self, provider: OAuthProvider
    ) -> Optional[OAuth2ProviderConfig]:
        """Get configuration for a specific provider."""
        return self.providers.get(provider)

    def is_provider_enabled(self, provider: OAuthProvider) -> bool:
        """Check if a provider is enabled and configured."""
        if not self.enable_oauth2:
            return False

        config = self.get_provider_config(provider)
        return config is not None and bool(config.client_id and config.client_secret)

    def get_enabled_providers(self) -> List[OAuthProvider]:
        """Get list of enabled providers."""
        return [
            provider
            for provider in self.providers.keys()
            if self.is_provider_enabled(provider)
        ]

    def validate_redirect_uri(self, redirect_uri: str) -> bool:
        """Validate OAuth2 redirect URI."""
        if not self.secure_redirect_only:
            return True

        # Only allow HTTPS in production
        return redirect_uri.startswith("https://") or redirect_uri.startswith(
            "http://localhost"
        )

    def generate_state_token(self) -> str:
        """Generate a secure state token for OAuth2 flow."""
        return secrets.token_urlsafe(32)

    def generate_pkce_challenge(self) -> tuple[str, str]:
        """Generate PKCE challenge and verifier."""
        import base64
        import hashlib

        verifier = secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )

        return challenge, verifier


# Global OAuth2 configuration instance
_oauth2_config: Optional[OAuth2Config] = None


def get_oauth2_config() -> OAuth2Config:
    """Get the global OAuth2 configuration."""
    global _oauth2_config
    if _oauth2_config is None:
        _oauth2_config = OAuth2Config.from_env()
    return _oauth2_config


def create_oauth2_provider_config(
    provider: OAuthProvider, client_id: str, client_secret: str, **kwargs
) -> OAuth2ProviderConfig:
    """Factory function to create OAuth2 provider configuration."""
    defaults = {
        "redirect_uri": os.getenv(
            "OAUTH2_REDIRECT_URI", "http://localhost:8000/auth/oauth2/callback"
        )
    }

    # Provider-specific defaults
    if provider == OAuthProvider.GOOGLE:
        defaults.update(
            {
                "authorization_url": "https://accounts.google.com/o/oauth2/auth",
                "token_url": "https://oauth2.googleapis.com/token",
                "user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
                "scope": "openid email profile",
            }
        )
    elif provider == OAuthProvider.GITHUB:
        defaults.update(
            {
                "authorization_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "user_info_url": "https://api.github.com/user",
                "scope": "user:email",
            }
        )
    elif provider == OAuthProvider.MICROSOFT:
        defaults.update(
            {
                "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                "user_info_url": "https://graph.microsoft.com/v1.0/me",
                "scope": "openid email profile",
            }
        )

    # Override defaults with provided kwargs
    defaults.update(kwargs)

    return OAuth2ProviderConfig(
        provider=provider, client_id=client_id, client_secret=client_secret, **defaults
    )


__all__ = [
    "OAuth2Config",
    "OAuth2ProviderConfig",
    "OAuthProvider",
    "get_oauth2_config",
    "create_oauth2_provider_config",
]
