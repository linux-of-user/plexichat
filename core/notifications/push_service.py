from .base_sender import NotificationSender
import firebase_admin
from firebase_admin import messaging
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Initialize Firebase if not already
if not firebase_admin._apps:
    firebase_admin.initialize_app()

class PushNotificationSender(NotificationSender):
    """
    Push notification sender using FCM with multi-platform support.
    """

    def __init__(self):
        super().__init__()

    def _get_platform_client(self, platform: str) -> None:
        """
        Determine platform and return appropriate message configuration.
        """
        # For simplicity, use FCM for both Android/iOS; extend for APNS if needed
        pass  # FCM handles both

    async def _send_via_platform(self, rendered_content: str, device_token: str, notification_data: Dict[str, Any]) -> bool:
        """
        Send push notification via FCM, supporting TTL and multi-platform.
        """
        try:
            ttl = notification_data.get('ttl', 3600)
            message = messaging.Message(
                notification=messaging.Notification(
                    title=notification_data.get('title', 'Notification'),
                    body=rendered_content,
                ),
                token=device_token,
                android=messaging.AndroidConfig(
                    ttl=ttl,
                    priority='high',
                ),
                apns=messaging.APNSConfig(
                    apns_expiration=ttl,
                    headers={'apns-priority': '10'},
                ) if 'ios' in device_token else None,
            )
            
            response = messaging.send(message)
            logger.info(f"Push sent to {device_token}: {response}")
            return True
        except Exception as e:
            logger.error(f"FCM send failed for {device_token}: {e}")
            raise

    async def send_push(self, template_name: str, context: Dict[str, Any], device_token: str, title: str = "Notification", ttl: Optional[int] = 3600) -> bool:
        """
        Public method for sending push notification.
        """
        notification_data = {
            "template": template_name,
            "context": context,
            "device_token": device_token,
            "title": title,
            "ttl": ttl
        }
        return await self.send_notification(notification_data)