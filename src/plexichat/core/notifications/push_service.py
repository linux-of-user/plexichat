"""
PlexiChat Push Notification Service

Handles sending push notifications to mobile devices and browsers.
Supports Firebase Cloud Messaging (FCM), Apple Push Notification Service (APNS), and web push.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime

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
            from firebase_admin import messaging, credentials
            import firebase_admin

            if not firebase_admin._apps:
                cred = credentials.Certificate({
                    "type": "service_account",
                    "project_id": self.config.fcm_project_id,
                    "private_key": self.config.fcm_server_key.replace('\\n', '\n'),
                    "client_email": f"firebase-adminsdk-@firebaseapp.com",
                })
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
            import apns2
            from cryptography.hazmat.primitives import serialization
            import base64

            # Decode private key
            private_key_data = base64.b64decode(self.config.apns_private_key)
            private_key = serialization.load_pem_private_key(private_key_data, password=None)

            self.apns_client = apns2.APNSClient(
                credentials=(self.config.apns_team_id, self.config.apns_key_id, private_key),
                use_sandbox=False,
                bundle_id=self.config.apns_bundle_id
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
                "exp": None
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
            subscribed_at=datetime.now()
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
            if platform == 'android':
                platform_results = await self._send_fcm(token_list, message)
            elif platform == 'ios':
                platform_results = await self._send_apns(token_list, message)
            elif platform == 'web':
                platform_results = await self._send_web_push(token_list, message)
            else:
                logger.warning(f"Unsupported platform: {platform}")
                platform_results = {token.token: False for token in token_list}

            results.update(platform_results)

        return results

    async def _send_fcm(self, tokens: List[PushToken], message: PushMessage) -> Dict[str, bool]:
        """Send push notification via Firebase Cloud Messaging."""
        if not self.fcm_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            # Create FCM message
            fcm_message = messaging.Message(
                notification=messaging.Notification(
                    title=message.title,
                    body=message.body,
                    image=message.image
                ),
                data=message.data or {},
                android=messaging.AndroidConfig(
                    ttl=message.ttl * 1000,  # Convert to milliseconds
                    priority='high' if message.data and message.data.get('priority') == 'high' else 'normal'
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            badge=message.badge,
                            sound=message.sound or 'default',
                            alert=messaging.ApsAlert(
                                title=message.title,
                                body=message.body
                            )
                        )
                    )
                )
            )

            # Send to multiple tokens
            token_strings = [token.token for token in tokens]
            batch_response = self.fcm_client.send_multicast(fcm_message, token_strings)

            # Process responses
            for i, response in enumerate(batch_response.responses):
                token = token_strings[i]
                if response.success:
                    results[token] = True
                    logger.debug(f"FCM message sent successfully to {token}")
                else:
                    results[token] = False
                    logger.error(f"FCM message failed for {token}: {response.exception}")

        except Exception as e:
            logger.error(f"FCM send error: {e}")
            results = {token.token: False for token in tokens}

        return results

    async def _send_apns(self, tokens: List[PushToken], message: PushMessage) -> Dict[str, bool]:
        """Send push notification via Apple Push Notification Service."""
        if not self.apns_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            import apns2

            for token in tokens:
                try:
                    # Create APNS payload
                    payload = {
                        "aps": {
                            "alert": {
                                "title": message.title,
                                "body": message.body
                            },
                            "badge": message.badge,
                            "sound": message.sound or "default"
                        }
                    }

                    if message.data:
                        payload.update(message.data)

                    # Send notification
                    notification = apns2.Notification(
                        token=token.token,
                        payload=json.dumps(payload)
                    )

                    result = self.apns_client.send_notification(notification)
                    results[token.token] = result == 'Success'

                    if result == 'Success':
                        logger.debug(f"APNS message sent successfully to {token.token}")
                    else:
                        logger.error(f"APNS message failed for {token.token}: {result}")

                except Exception as e:
                    logger.error(f"APNS send error for {token.token}: {e}")
                    results[token.token] = False

        except Exception as e:
            logger.error(f"APNS general error: {e}")
            results = {token.token: False for token in tokens}

        return results

    async def _send_web_push(self, tokens: List[PushToken], message: PushMessage) -> Dict[str, bool]:
        """Send push notification via web push."""
        if not self.web_push_available:
            return {token.token: False for token in tokens}

        results = {}

        try:
            for token in tokens:
                try:
                    # Web push subscription data would be stored with the token
                    # For now, assume token contains subscription info
                    subscription_info = json.loads(token.token)

                    # Send web push
                    result = self.webpush_client(
                        subscription_info=subscription_info,
                        data=json.dumps({
                            "title": message.title,
                            "body": message.body,
                            "icon": message.icon,
                            "badge": message.badge,
                            "data": message.data
                        }),
                        vapid_private_key=self.config.vapid_private_key,
                        vapid_claims=self.vapid_claims
                    )

                    results[token.token] = True
                    logger.debug(f"Web push sent successfully to {token.token}")

                except Exception as e:
                    logger.error(f"Web push error for {token.token}: {e}")
                    results[token.token] = False

        except Exception as e:
            logger.error(f"Web push general error: {e}")
            results = {token.token: False for token in tokens}

        return results

    async def send_bulk_push(self, notifications: List[Dict[str, Any]]) -> Dict[str, Dict[str, bool]]:
        """
        Send bulk push notifications.

        Args:
            notifications: List of notification data with keys:
                - user_id: int
                - title: str
                - body: str
                - data: dict (optional)

        Returns:
            Dict mapping user_ids to token results
        """
        results = {}

        # Send notifications concurrently with rate limiting
        semaphore = asyncio.Semaphore(50)  # Limit concurrent sends

        async def send_single_push(notification_data: Dict[str, Any]):
            async with semaphore:
                user_id = notification_data['user_id']
                message = PushMessage(
                    title=notification_data['title'],
                    body=notification_data['body'],
                    data=notification_data.get('data')
                )
                return user_id, await self.send_to_user(user_id, message)

        tasks = [send_single_push(data) for data in notifications]
        send_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in send_results:
            if isinstance(result, Exception):
                logger.error(f"Bulk push error: {result}")
            else:
                user_id, token_results = result
                results[str(user_id)] = token_results

        return results

# Global push service instance
_push_service: Optional[PushService] = None

def get_push_service() -> Optional[PushService]:
    """Get the global push service instance."""
    return _push_service

def initialize_push_service(config: PushConfig) -> PushService:
    """Initialize the global push service."""
    global _push_service
    _push_service = PushService(config)
    return _push_service

async def send_push_notification(user_id: int, title: str, body: str,
                               data: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """Send push notification using global service."""
    service = get_push_service()
    if not service:
        logger.warning("Push service not initialized")
        return {}

    message = PushMessage(title=title, body=body, data=data)
    return await service.send_to_user(user_id, message)