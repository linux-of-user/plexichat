"""
OAuth Provider Integration
Support for multiple OAuth providers including Google, GitHub, Discord, Microsoft.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import aiohttp
from urllib.parse import urlencode
import secrets
import hashlib

from app.core.config.settings import settings
from app.logger_config import logger

class OAuthProvider:
    """Base OAuth provider class."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.session = None
        
    async def get_authorization_url(self, state: str = None) -> str:
        """Get authorization URL for OAuth flow."""
        raise NotImplementedError
        
    async def exchange_code_for_token(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        raise NotImplementedError
        
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information using access token."""
        raise NotImplementedError
        
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token."""
        raise NotImplementedError

class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth provider."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        self.scope = "openid email profile"
        
    async def get_authorization_url(self, state: str = None) -> str:
        """Get Google authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "response_type": "code",
            "access_type": "offline",
            "prompt": "consent"
        }
        
        if state:
            params["state"] = state
            
        return f"{self.auth_url}?{urlencode(params)}"
        
    async def exchange_code_for_token(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange code for Google access token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.token_url, data=data) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Token exchange failed: {error_text}")
                    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Google user information."""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as response:
                if response.status == 200:
                    user_data = await response.json()
                    return {
                        "id": user_data.get("id"),
                        "email": user_data.get("email"),
                        "name": user_data.get("name"),
                        "picture": user_data.get("picture"),
                        "verified_email": user_data.get("verified_email", False)
                    }
                else:
                    raise Exception(f"Failed to get user info: {response.status}")

class GitHubOAuthProvider(OAuthProvider):
    """GitHub OAuth provider."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.auth_url = "https://github.com/login/oauth/authorize"
        self.token_url = "https://github.com/login/oauth/access_token"
        self.user_info_url = "https://api.github.com/user"
        self.scope = "user:email"
        
    async def get_authorization_url(self, state: str = None) -> str:
        """Get GitHub authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state or secrets.token_urlsafe(32)
        }
        
        return f"{self.auth_url}?{urlencode(params)}"
        
    async def exchange_code_for_token(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange code for GitHub access token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code
        }
        
        headers = {"Accept": "application/json"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.token_url, data=data, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Token exchange failed: {error_text}")
                    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get GitHub user information."""
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as response:
                if response.status == 200:
                    user_data = await response.json()
                    
                    # Get user email separately
                    email = None
                    async with session.get(f"{self.user_info_url}/emails", headers=headers) as email_response:
                        if email_response.status == 200:
                            emails = await email_response.json()
                            primary_email = next((e for e in emails if e.get("primary")), None)
                            email = primary_email.get("email") if primary_email else None
                    
                    return {
                        "id": str(user_data.get("id")),
                        "email": email or user_data.get("email"),
                        "name": user_data.get("name") or user_data.get("login"),
                        "username": user_data.get("login"),
                        "avatar_url": user_data.get("avatar_url")
                    }
                else:
                    raise Exception(f"Failed to get user info: {response.status}")

class DiscordOAuthProvider(OAuthProvider):
    """Discord OAuth provider."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.auth_url = "https://discord.com/api/oauth2/authorize"
        self.token_url = "https://discord.com/api/oauth2/token"
        self.user_info_url = "https://discord.com/api/users/@me"
        self.scope = "identify email"
        
    async def get_authorization_url(self, state: str = None) -> str:
        """Get Discord authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": self.scope,
            "state": state or secrets.token_urlsafe(32)
        }
        
        return f"{self.auth_url}?{urlencode(params)}"
        
    async def exchange_code_for_token(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange code for Discord access token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.token_url, data=data, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Token exchange failed: {error_text}")
                    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Discord user information."""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as response:
                if response.status == 200:
                    user_data = await response.json()
                    return {
                        "id": user_data.get("id"),
                        "email": user_data.get("email"),
                        "username": user_data.get("username"),
                        "discriminator": user_data.get("discriminator"),
                        "avatar": user_data.get("avatar"),
                        "verified": user_data.get("verified", False)
                    }
                else:
                    raise Exception(f"Failed to get user info: {response.status}")

class MicrosoftOAuthProvider(OAuthProvider):
    """Microsoft OAuth provider."""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.user_info_url = "https://graph.microsoft.com/v1.0/me"
        self.scope = "openid email profile User.Read"
        
    async def get_authorization_url(self, state: str = None) -> str:
        """Get Microsoft authorization URL."""
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state or secrets.token_urlsafe(32)
        }
        
        return f"{self.auth_url}?{urlencode(params)}"
        
    async def exchange_code_for_token(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange code for Microsoft access token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.token_url, data=data) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Token exchange failed: {error_text}")
                    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Microsoft user information."""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(self.user_info_url, headers=headers) as response:
                if response.status == 200:
                    user_data = await response.json()
                    return {
                        "id": user_data.get("id"),
                        "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                        "name": user_data.get("displayName"),
                        "given_name": user_data.get("givenName"),
                        "surname": user_data.get("surname")
                    }
                else:
                    raise Exception(f"Failed to get user info: {response.status}")

class OAuthManager:
    """Manages OAuth providers and authentication flow."""
    
    def __init__(self):
        self.providers: Dict[str, OAuthProvider] = {}
        self.state_store: Dict[str, Dict[str, Any]] = {}
        
    def register_provider(self, name: str, provider: OAuthProvider):
        """Register an OAuth provider."""
        self.providers[name] = provider
        logger.info(f"Registered OAuth provider: {name}")
        
    def get_provider(self, name: str) -> Optional[OAuthProvider]:
        """Get OAuth provider by name."""
        return self.providers.get(name)
        
    def generate_state(self, provider_name: str, user_data: Dict[str, Any] = None) -> str:
        """Generate and store OAuth state."""
        state = secrets.token_urlsafe(32)
        self.state_store[state] = {
            "provider": provider_name,
            "created_at": datetime.utcnow(),
            "user_data": user_data or {}
        }
        return state
        
    def validate_state(self, state: str, provider_name: str) -> bool:
        """Validate OAuth state."""
        stored_state = self.state_store.get(state)
        if not stored_state:
            return False
            
        # Check if state is expired (15 minutes)
        if datetime.utcnow() - stored_state["created_at"] > timedelta(minutes=15):
            del self.state_store[state]
            return False
            
        # Check if provider matches
        if stored_state["provider"] != provider_name:
            return False
            
        return True
        
    def cleanup_expired_states(self):
        """Clean up expired OAuth states."""
        now = datetime.utcnow()
        expired_states = [
            state for state, data in self.state_store.items()
            if now - data["created_at"] > timedelta(minutes=15)
        ]
        
        for state in expired_states:
            del self.state_store[state]
            
    async def initialize_providers(self):
        """Initialize OAuth providers from settings."""
        # Google OAuth
        if hasattr(settings, 'GOOGLE_CLIENT_ID') and settings.GOOGLE_CLIENT_ID:
            google_provider = GoogleOAuthProvider(
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                redirect_uri=f"{settings.BASE_URL}/api/v1/auth/oauth/google/callback"
            )
            self.register_provider("google", google_provider)
            
        # GitHub OAuth
        if hasattr(settings, 'GITHUB_CLIENT_ID') and settings.GITHUB_CLIENT_ID:
            github_provider = GitHubOAuthProvider(
                client_id=settings.GITHUB_CLIENT_ID,
                client_secret=settings.GITHUB_CLIENT_SECRET,
                redirect_uri=f"{settings.BASE_URL}/api/v1/auth/oauth/github/callback"
            )
            self.register_provider("github", github_provider)
            
        # Discord OAuth
        if hasattr(settings, 'DISCORD_CLIENT_ID') and settings.DISCORD_CLIENT_ID:
            discord_provider = DiscordOAuthProvider(
                client_id=settings.DISCORD_CLIENT_ID,
                client_secret=settings.DISCORD_CLIENT_SECRET,
                redirect_uri=f"{settings.BASE_URL}/api/v1/auth/oauth/discord/callback"
            )
            self.register_provider("discord", discord_provider)
            
        # Microsoft OAuth
        if hasattr(settings, 'MICROSOFT_CLIENT_ID') and settings.MICROSOFT_CLIENT_ID:
            microsoft_provider = MicrosoftOAuthProvider(
                client_id=settings.MICROSOFT_CLIENT_ID,
                client_secret=settings.MICROSOFT_CLIENT_SECRET,
                redirect_uri=f"{settings.BASE_URL}/api/v1/auth/oauth/microsoft/callback"
            )
            self.register_provider("microsoft", microsoft_provider)
            
        logger.info(f"Initialized {len(self.providers)} OAuth providers")

# Global OAuth manager instance
oauth_manager = OAuthManager()
