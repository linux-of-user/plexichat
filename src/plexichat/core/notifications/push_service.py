"""
PlexiChat Push Notification Service

Handles sending push notifications to mobile devices and browsers.
Supports Firebase Cloud Messaging (FCM), Apple Push Notification Service (APNS), and web push.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PushConfig:
    """Push notification service configuration."""

    fcm_server_key: str | None = None
    fcm_project_id: str | None = None
    apns_key_id: str | None = None
    apns_team_id: str | None = None
    apns_bundle_id: str | None = None
    apns_private_key: str | None = None
    vapid_private_key: str | None = None
    vapid_email: str | None = None


@dataclass
class PushToken:
    """Push notification token for a device."""

    token: str
    platform: str  # 'ios', 'android', 'web'
    user_id: int
    device_id: str
    subscribed_at: datetime
    last_used: datetime | None = None


@dataclass
class PushMessage:
    """Push notification message."""

    title: str
    body: str
    data: dict[str, Any] | None = None
    badge: int | None = None
    sound: str | None = None
    icon: str | None = None
    image: str | None = None
    click_action: str | None = None
    ttl: int = 86400  # 24 hours


class PushService:
    """Push notification service supporting multiple platforms."""

    def __init__(self, config: PushConfig) -> None:
        self.config: PushConfig = config
        self.tokens: dict[str, PushToken] = {}  # token -> PushToken
        self.user_tokens: dict[int, list[str]] = {}  # user_id -> [tokens]

        # Initialize platform clients
        self.fcm_available: bool = bool(config.fcm_server_key)
        self.apns_available: bool = bool(config.apns_key_id and config.apns_private_key)
        self.web_push_available: bool = bool(config.vapid_private_key)

        if self.fcm_available:
            self._init_fcm()
        if self.apns_available:
            self._init_apns()
        if self.web_push_available:
            self._init_web_push()

    def _init_fcm(self) -> None:
        """Initialize Firebase Cloud Messaging client."""
        try:
            import firebase_admin
            from firebase_admin import credentials, messaging

            if not firebase_admin._apps:
                cred = credentials.Certificate(
                    {
                        "type": "service_account",
                        "project_id": self.config.fcm_project_id,
                        "private_key": self.config.fcm_server_key.replace("\\n", "\n"),  # type: ignore
                        "client_email": f"firebase-adminsdk-@{self.config.fcm_project_id}.iam.gserviceaccount.com",
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

    def _init_apns(self) -> None:
        """Initialize Apple Push Notification Service client."""
        try:
            import base64

            import apns2
            from cryptography.hazmat.primitives import serialization

            # Decode private key
            private_key_data = base64.b64decode(self.config.apns_private_key)  # type: ignore
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

    def _init_web_push(self) -> None:
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

    def register_token(
        self, token: str, platform: str, user_id: int, device_id: str
    ) -> None:
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

    def unregister_token(self, token: str) -> None:
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

    def get_user_tokens(self, user_id: int) -> list[PushToken]:
        """Get all push tokens for a user."""
        tokens = []
        if user_id in self.user_tokens:
            for token in self.user_tokens[user_id]:
                if token in self.tokens:
                    tokens.append(self.tokens[token])
        return tokens

    async def send_to_user(self, user_id: int, message: PushMessage) -> dict[str, bool]:
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
        self, tokens: list[PushToken], message: PushMessage
    ) -> dict[str, bool]:
        """Send push notification via Firebase Cloud Messaging."""
        if not self.fcm_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            # Import required modules
            from firebase_admin import messaging

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
            token_strings = [token.token for token in tokens]
            response = messaging.send_multicast(
                messaging.MulticastMessage(
                    tokens=token_strings,
                    notification=fcm_message.notification,
                    data=fcm_message.data,
                    android=fcm_message.android,
                    apns=fcm_message.apns,
                )
            )

            # Process results
            for i, resp in enumerate(response.responses):
                token_string = token_strings[i]
                if resp.success:
                    results[token_string] = True
                    logger.info(
                        f"FCM message sent successfully to token {token_string[:10]}..."
                    )
                else:
                    results[token_string] = False
                    logger.error(
                        f"FCM failed for token {token_string[:10]}...: {resp.exception}"
                    )

        except Exception as e:
            logger.error(f"FCM send failed: {e}")
            for token in tokens:
                results[token.token] = False

        return results

    async def _send_apns(
        self, tokens: list[PushToken], message: PushMessage
    ) -> dict[str, bool]:
        """Send push notification via Apple Push Notification Service."""
        if not self.apns_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            import apns2

            # Create APNS payload
            payload = apns2.Payload(
                alert=apns2.PayloadAlert(title=message.title, body=message.body),
                badge=message.badge,
                sound=message.sound or "default",
                custom=message.data or {},
            )

            # Send to each token
            for token in tokens:
                try:
                    request = apns2.APNSRequest(
                        device_token=token.token,
                        message=payload,
                        priority=apns2.PRIORITY_HIGH,
                    )

                    response = self.apns_client.send_notification(request)

                    if response.is_successful:
                        results[token.token] = True
                        logger.info(
                            f"APNS message sent successfully to token {token.token[:10]}..."
                        )
                    else:
                        results[token.token] = False
                        logger.error(
                            f"APNS failed for token {token.token[:10]}...: {response.description}"
                        )

                except Exception as e:
                    results[token.token] = False
                    logger.error(
                        f"APNS send failed for token {token.token[:10]}...: {e}"
                    )

        except Exception as e:
            logger.error(f"APNS send failed: {e}")
            for token in tokens:
                results[token.token] = False

        return results

    async def _send_web_push(
        self, tokens: list[PushToken], message: PushMessage
    ) -> dict[str, bool]:
        """Send web push notification."""
        if not self.web_push_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            # Create web push payload
            payload_data = {
                "title": message.title,
                "body": message.body,
                "icon": message.icon,
                "image": message.image,
                "data": message.data or {},
            }
            payload = json.dumps(payload_data)

            # Send to each token
            for token in tokens:
                try:
                    # Parse subscription info from token
                    subscription_info = json.loads(token.token)

                    response = self.webpush_client(
                        subscription_info=subscription_info,
                        data=payload,
                        vapid_private_key=self.config.vapid_private_key,
                        vapid_claims=self.vapid_claims,
                        ttl=message.ttl,
                    )

                    if response.status_code < 400:
                        results[token.token] = True
                        logger.info(
                            f"Web push sent successfully to token {token.token[:10]}..."
                        )
                    else:
                        results[token.token] = False
                        logger.error(
                            f"Web push failed for token {token.token[:10]}...: {response.reason}"
                        )

                except Exception as e:
                    results[token.token] = False
                    logger.error(
                        f"Web push send failed for token {token.token[:10]}...: {e}"
                    )

        except Exception as e:
            logger.error(f"Web push send failed: {e}")
            for token in tokens:
                results[token.token] = False

        return results

    async def send_bulk_notifications(
        self, user_messages: list[tuple[int, PushMessage]]
    ) -> dict[int, dict[str, bool]]:
        """
        Send push notifications to multiple users concurrently.

        Args:
            user_messages: List of (user_id, PushMessage) tuples

        Returns:
            Dict mapping user_id to token results
        """
        tasks = []
        user_ids = []

        for user_id, message in user_messages:
            task = self.send_to_user(user_id, message)
            tasks.append(task)
            user_ids.append(user_id)

        results = await asyncio.gather(*tasks, return_exceptions=False)

        return dict(zip(user_ids, results, strict=False))


# Module-level functions for backward compatibility
async def send_push_notification(
    push_service: PushService,
    user_id: int,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Send push notification (backward compatibility function)."""
    message = PushMessage(title=title, body=body, data=data)
    return await push_service.send_to_user(user_id, message)
