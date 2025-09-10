
"""
PlexiChat Push Notification Service

Handles sending push notifications to mobile devices and browsers.
Supports Firebase Cloud Messaging (FCM), Apple Push Notification Service (APNS), and web push.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class PushConfig:
    """Push notification service configuration."""

    fcm_server_key: Optional[str] = None
    fcm_project_id: Optional[str] = None
    apns_key_id: Optional[str] = None
    apns_team_id: Optional[str] = None
    apns_bundle_id: Optional[str] = None
    apns_private_key: Optional[str] = None
    vapid_private_key: Optional[str] = None
    vapid_email: Optional[str] = None


@dataclass
class PushToken:
    """Push notification token for a device."""

    token: str
    platform: str  # 'ios', 'android', 'web'
    user_id: int
    device_id: str
    subscribed_at: datetime
    last_used: Optional[datetime] = None


@dataclass
class PushMessage:
    """Push notification message."""

    title: str
    body: str
    data: Optional[Dict[str, Any]] = None
    badge: Optional[int] = None
    sound: Optional[str] = None
    icon: Optional[str] = None
    image: Optional[str] = None
    click_action: Optional[str] = None
    ttl: int = 86400  # 24 hours


class PushService:
    """Push notification service supporting multiple platforms."""

    def __init__(self, config: PushConfig):
        self.config = config
        self.tokens: Dict[str, PushToken] = {}  # token -> PushToken
        self.user_tokens: Dict[int, List[str]] = {}  # user_id -> [tokens]

        # Initialize platform clients
        self.fcm_available = bool(config.fcm_server_key)
        self.apns_available = bool(config.apns_key_id and config.apns_private_key)
        self.web_push_available = bool(config.vapid_private_key)

        if self.fcm_available:
            self._init_fcm()
        if self.apns_available:
            self._init_apns()
        if self.web_push_available:
            self._init_web_push()

    def _init_fcm(self):
        """Initialize Firebase Cloud Messaging client."""
        try:
            import firebase_admin
            from firebase_admin import credentials, messaging

            if not firebase_admin._apps:
                cred = credentials.Certificate(
                    {
                        "type": "service_account",
                        "project_id": self.config.fcm_project_id,
                        "private_key": self.config.fcm_server_key.replace("\\n", "\n"),
                        "client_email": f"firebase-adminsdk-@firebaseapp.com",
                    }
                )
                firebase_admin.initialize_app(cred)

            self.fcm_client = messaging
            logger.info("FCM client initialized")
        except ImportError:
            logger.warning("Firebase Admin SDK not available")
            self.fcm_available = False
        except Exception as e:
            logger.error(f"Failed to initialize FCM: {e}")
            self.fcm_available = False

    def _init_apns(self):
        """Initialize Apple Push Notification Service client."""
        try:
            import base64

            import apns2
            from cryptography.hazmat.primitives import serialization

            # Decode private key
            private_key_data = base64.b64decode(self.config.apns_private_key)
            private_key = serialization.load_pem_private_key(
                private_key_data, password=None
            )

            self.apns_client = apns2.APNSClient(
                credentials=(
                    self.config.apns_team_id,
                    self.config.apns_key_id,
                    private_key,
                ),
                use_sandbox=False,
                bundle_id=self.config.apns_bundle_id,
            )
            logger.info("APNS client initialized")
        except ImportError:
            logger.warning("APNS2 library not available")
            self.apns_available = False
        except Exception as e:
            logger.error(f"Failed to initialize APNS: {e}")
            self.apns_available = False

    def _init_web_push(self):
        """Initialize web push client."""
        try:
            from pywebpush import webpush

            self.webpush_client = webpush
            self.vapid_claims = {
                "sub": f"mailto:{self.config.vapid_email}",
                "aud": "https://fcm.googleapis.com",
                "exp": None,
            }
            logger.info("Web push client initialized")
        except ImportError:
            logger.warning("PyWebPush library not available")
            self.web_push_available = False
        except Exception as e:
            logger.error(f"Failed to initialize web push: {e}")
            self.web_push_available = False

    def register_token(self, token: str, platform: str, user_id: int, device_id: str):
        """Register a push notification token for a user."""
        push_token = PushToken(
            token=token,
            platform=platform.lower(),
            user_id=user_id,
            device_id=device_id,
            subscribed_at=datetime.now(),
        )

        self.tokens[token] = push_token

        if user_id not in self.user_tokens:
            self.user_tokens[user_id] = []
        if token not in self.user_tokens[user_id]:
            self.user_tokens[user_id].append(token)

        logger.info(f"Registered push token for user {user_id} on {platform}")

    def unregister_token(self, token: str):
        """Unregister a push notification token."""
        if token in self.tokens:
            push_token = self.tokens[token]
            user_id = push_token.user_id

            # Remove from user tokens
            if user_id in self.user_tokens:
                self.user_tokens[user_id].remove(token)
                if not self.user_tokens[user_id]:
                    del self.user_tokens[user_id]

            # Remove token
            del self.tokens[token]

            logger.info(f"Unregistered push token for user {user_id}")

    def get_user_tokens(self, user_id: int) -> List[PushToken]:
        """Get all push tokens for a user."""
        tokens = []
        if user_id in self.user_tokens:
            for token in self.user_tokens[user_id]:
                if token in self.tokens:
                    tokens.append(self.tokens[token])
        return tokens

    async def send_to_user(self, user_id: int, message: PushMessage) -> Dict[str, bool]:
        """
        Send push notification to all devices of a user.

        Returns:
            Dict mapping tokens to success status
        """
        tokens = self.get_user_tokens(user_id)
        if not tokens:
            logger.warning(f"No push tokens found for user {user_id}")
            return {}

        results = {}

        # Group tokens by platform
        platform_tokens = {}
        for token in tokens:
            if token.platform not in platform_tokens:
                platform_tokens[token.platform] = []
            platform_tokens[token.platform].append(token)

        # Send to each platform
        for platform, token_list in platform_tokens.items():
            if platform == "android":
                platform_results = await self._send_fcm(token_list, message)
            elif platform == "ios":
                platform_results = await self._send_apns(token_list, message)
            elif platform == "web":
                platform_results = await self._send_web_push(token_list, message)
            else:
                logger.warning(f"Unsupported platform: {platform}")
                platform_results = {token.token: False for token in token_list}

            results.update(platform_results)

        return results

    async def _send_fcm(
        self, tokens: List[PushToken], message: PushMessage
    ) -> Dict[str, bool]:
        """Send push notification via Firebase Cloud Messaging."""
        if not self.fcm_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            # Create FCM message
            fcm_message = messaging.Message(
                notification=messaging.Notification(
                    title=message.title, body=message.body, image=message.image
                ),
                data=message.data or {},
                android=messaging.AndroidConfig(
                    ttl=message.ttl * 1000,  # Convert to milliseconds
                    priority=(
                        "high"
                        if message.data and message.data.get("priority") == "high"
                        else "normal"
                    ),
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            badge=message.badge,
                            sound=message.sound or "default",
                            alert=messaging.ApsAlert(
                                title=message.title, body=message.body
                            ),
                        )
                    )
                ),
            )

            # Send to multiple tokens
            token_strings