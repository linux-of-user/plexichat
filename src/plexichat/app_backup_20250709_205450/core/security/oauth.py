"""
OAuth 2.0 and OpenID Connect implementation with multiple providers.
Supports Google, GitHub, Discord, Microsoft, and custom OAuth providers.
"""

import asyncio
import json
import secrets
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, parse_qs
from dataclasses import dataclass
from enum import Enum

import httpx
from fastapi import HTTPException, Request
from jose import jwt, JWTError
import bcrypt

from app.core.config.settings import settings
from app.logger_config import logger

class OAuthProvider(str, Enum):
    """Supported OAuth providers."""
    GOOGLE = "google"
    GITHUB = "github"
    DISCORD = "discord"
    MICROSOFT = "microsoft"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    CUSTOM = "custom"

@dataclass
class OAuthConfig:
    """OAuth provider configuration."""
    name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: List[str]
    redirect_uri: str
    additional_params: Dict[str, str] = None

class OAuthManager:
    """OAuth 2.0 manager with support for multiple providers."""
    
    def __init__(self):
        self.providers: Dict[str, OAuthConfig] = {}
        self.state_store: Dict[str, Dict[str, Any]] = {}  # In production, use Redis
        self._load_providers()
    
    def _load_providers(self):
        """Load OAuth provider configurations."""
        # Google OAuth
        if hasattr(settings, 'GOOGLE_CLIENT_ID') and settings.GOOGLE_CLIENT_ID:
            self.providers[OAuthProvider.GOOGLE] = OAuthConfig(
                name="Google",
                client_id=settings.GOOGLE_CLIENT_ID,
                client_secret=settings.GOOGLE_CLIENT_SECRET,
                authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo",
                scopes=["openid", "email", "profile"],
                redirect_uri=f"{settings.BASE_URL}/auth/oauth/google/callback"
            )
        
        # GitHub OAuth
        if hasattr(settings, 'GITHUB_CLIENT_ID') and settings.GITHUB_CLIENT_ID:
            self.providers[OAuthProvider.GITHUB] = OAuthConfig(
                name="GitHub",
                client_id=settings.GITHUB_CLIENT_ID,
                client_secret=settings.GITHUB_CLIENT_SECRET,
                authorize_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                userinfo_url="https://api.github.com/user",
                scopes=["user:email"],
                redirect_uri=f"{settings.BASE_URL}/auth/oauth/github/callback"
            )
        
        # Discord OAuth
        if hasattr(settings, 'DISCORD_CLIENT_ID') and settings.DISCORD_CLIENT_ID:
            self.providers[OAuthProvider.DISCORD] = OAuthConfig(
                name="Discord",
                client_id=settings.DISCORD_CLIENT_ID,
                client_secret=settings.DISCORD_CLIENT_SECRET,
                authorize_url="https://discord.com/api/oauth2/authorize",
                token_url="https://discord.com/api/oauth2/token",
                userinfo_url="https://discord.com/api/users/@me",
                scopes=["identify", "email"],
                redirect_uri=f"{settings.BASE_URL}/auth/oauth/discord/callback"
            )
        
        # Microsoft OAuth
        if hasattr(settings, 'MICROSOFT_CLIENT_ID') and settings.MICROSOFT_CLIENT_ID:
            tenant_id = getattr(settings, 'MICROSOFT_TENANT_ID', 'common')
            self.providers[OAuthProvider.MICROSOFT] = OAuthConfig(
                name="Microsoft",
                client_id=settings.MICROSOFT_CLIENT_ID,
                client_secret=settings.MICROSOFT_CLIENT_SECRET,
                authorize_url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
                token_url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                userinfo_url="https://graph.microsoft.com/v1.0/me",
                scopes=["openid", "email", "profile"],
                redirect_uri=f"{settings.BASE_URL}/auth/oauth/microsoft/callback"
            )
        
        logger.info(f"Loaded {len(self.providers)} OAuth providers: {list(self.providers.keys())}")
    
    def get_authorization_url(self, provider: str, state: Optional[str] = None) -> str:
        """Generate OAuth authorization URL."""
        if provider not in self.providers:
            raise HTTPException(status_code=400, detail=f"Unsupported OAuth provider: {provider}")
        
        config = self.providers[provider]
        
        # Generate state parameter for CSRF protection
        if not state:
            state = secrets.token_urlsafe(32)
        
        # Store state with timestamp for validation
        self.state_store[state] = {
            'provider': provider,
            'timestamp': time.time(),
            'used': False
        }
        
        # Build authorization URL
        params = {
            'client_id': config.client_id,
            'redirect_uri': config.redirect_uri,
            'scope': ' '.join(config.scopes),
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',  # For refresh tokens
            'prompt': 'consent'
        }
        
        # Add provider-specific parameters
        if config.additional_params:
            params.update(config.additional_params)
        
        # Special handling for different providers
        if provider == OAuthProvider.DISCORD:
            params['permissions'] = '0'
        elif provider == OAuthProvider.MICROSOFT:
            params['response_mode'] = 'query'
        
        auth_url = f"{config.authorize_url}?{urlencode(params)}"
        logger.info(f"Generated OAuth URL for {provider}: {auth_url}")
        
        return auth_url
    
    async def exchange_code_for_token(self, provider: str, code: str, state: str) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        if provider not in self.providers:
            raise HTTPException(status_code=400, detail=f"Unsupported OAuth provider: {provider}")
        
        # Validate state parameter
        if not self._validate_state(state, provider):
            raise HTTPException(status_code=400, detail="Invalid or expired state parameter")
        
        config = self.providers[provider]
        
        # Prepare token request
        token_data = {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': config.redirect_uri
        }
        
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # GitHub requires specific Accept header
        if provider == OAuthProvider.GITHUB:
            headers['Accept'] = 'application/json'
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    config.token_url,
                    data=token_data,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                token_response = response.json()
                logger.info(f"Successfully exchanged code for token with {provider}")
                
                return token_response
                
        except httpx.HTTPError as e:
            logger.error(f"Token exchange failed for {provider}: {e}")
            raise HTTPException(status_code=400, detail="Failed to exchange authorization code")
    
    async def get_user_info(self, provider: str, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider."""
        if provider not in self.providers:
            raise HTTPException(status_code=400, detail=f"Unsupported OAuth provider: {provider}")
        
        config = self.providers[provider]
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    config.userinfo_url,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                user_info = response.json()
                
                # Normalize user info across providers
                normalized_info = self._normalize_user_info(provider, user_info)
                
                logger.info(f"Retrieved user info from {provider} for user: {normalized_info.get('email', 'unknown')}")
                
                return normalized_info
                
        except httpx.HTTPError as e:
            logger.error(f"Failed to get user info from {provider}: {e}")
            raise HTTPException(status_code=400, detail="Failed to retrieve user information")
    
    def _validate_state(self, state: str, provider: str) -> bool:
        """Validate OAuth state parameter."""
        if state not in self.state_store:
            logger.warning(f"Invalid state parameter: {state}")
            return False
        
        state_data = self.state_store[state]
        
        # Check if already used
        if state_data['used']:
            logger.warning(f"State parameter already used: {state}")
            return False
        
        # Check if expired (5 minutes)
        if time.time() - state_data['timestamp'] > 300:
            logger.warning(f"Expired state parameter: {state}")
            del self.state_store[state]
            return False
        
        # Check provider match
        if state_data['provider'] != provider:
            logger.warning(f"Provider mismatch for state: {state}")
            return False
        
        # Mark as used
        state_data['used'] = True
        
        return True
    
    def _normalize_user_info(self, provider: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize user information across different OAuth providers."""
        normalized = {
            'provider': provider,
            'provider_id': None,
            'email': None,
            'username': None,
            'display_name': None,
            'avatar_url': None,
            'verified': False,
            'raw_data': user_info
        }
        
        if provider == OAuthProvider.GOOGLE:
            normalized.update({
                'provider_id': user_info.get('id'),
                'email': user_info.get('email'),
                'username': user_info.get('email', '').split('@')[0],
                'display_name': user_info.get('name'),
                'avatar_url': user_info.get('picture'),
                'verified': user_info.get('verified_email', False)
            })
        
        elif provider == OAuthProvider.GITHUB:
            normalized.update({
                'provider_id': str(user_info.get('id')),
                'email': user_info.get('email'),
                'username': user_info.get('login'),
                'display_name': user_info.get('name') or user_info.get('login'),
                'avatar_url': user_info.get('avatar_url'),
                'verified': True  # GitHub emails are verified
            })
        
        elif provider == OAuthProvider.DISCORD:
            normalized.update({
                'provider_id': user_info.get('id'),
                'email': user_info.get('email'),
                'username': user_info.get('username'),
                'display_name': user_info.get('global_name') or user_info.get('username'),
                'avatar_url': f"https://cdn.discordapp.com/avatars/{user_info.get('id')}/{user_info.get('avatar')}.png" if user_info.get('avatar') else None,
                'verified': user_info.get('verified', False)
            })
        
        elif provider == OAuthProvider.MICROSOFT:
            normalized.update({
                'provider_id': user_info.get('id'),
                'email': user_info.get('mail') or user_info.get('userPrincipalName'),
                'username': user_info.get('userPrincipalName', '').split('@')[0],
                'display_name': user_info.get('displayName'),
                'avatar_url': None,  # Microsoft Graph doesn't provide avatar URL directly
                'verified': True  # Microsoft emails are verified
            })
        
        return normalized
    
    def get_available_providers(self) -> List[Dict[str, str]]:
        """Get list of available OAuth providers."""
        return [
            {
                'id': provider_id,
                'name': config.name,
                'authorize_url': self.get_authorization_url(provider_id)
            }
            for provider_id, config in self.providers.items()
        ]
    
    async def refresh_token(self, provider: str, refresh_token: str) -> Dict[str, Any]:
        """Refresh OAuth access token."""
        if provider not in self.providers:
            raise HTTPException(status_code=400, detail=f"Unsupported OAuth provider: {provider}")
        
        config = self.providers[provider]
        
        token_data = {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    config.token_url,
                    data=token_data,
                    headers={'Accept': 'application/json'},
                    timeout=30.0
                )
                response.raise_for_status()
                
                return response.json()
                
        except httpx.HTTPError as e:
            logger.error(f"Token refresh failed for {provider}: {e}")
            raise HTTPException(status_code=400, detail="Failed to refresh token")
    
    def cleanup_expired_states(self):
        """Clean up expired state parameters."""
        current_time = time.time()
        expired_states = [
            state for state, data in self.state_store.items()
            if current_time - data['timestamp'] > 300
        ]
        
        for state in expired_states:
            del self.state_store[state]
        
        if expired_states:
            logger.info(f"Cleaned up {len(expired_states)} expired OAuth states")

# Global OAuth manager instance
oauth_manager = OAuthManager()

# Cleanup task for expired states
async def cleanup_oauth_states():
    """Background task to cleanup expired OAuth states."""
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            oauth_manager.cleanup_expired_states()
        except Exception as e:
            logger.error(f"OAuth cleanup task error: {e}")

# Start cleanup task
asyncio.create_task(cleanup_oauth_states())
