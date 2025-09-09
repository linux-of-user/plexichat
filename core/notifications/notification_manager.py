import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from queue import PriorityQueue
from typing import Any, Dict, List, Optional

from .base_sender import NotificationSender
from .email_service import EmailNotificationSender
from .push_service import PushNotificationSender

logger = logging.getLogger(__name__)


class NotificationPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3


@dataclass
class QueuedNotification:
    priority: int
    data: Dict[str, Any]
    notification_id: str


class NotificationManager(NotificationSender):
    """
    Manages notification queue and processing using sender instances.
    """

    def __init__(
        self,
        email_sender: Optional[EmailNotificationSender] = None,
        push_sender: Optional[PushNotificationSender] = None,
    ):
        super().__init__()
        self.email_sender = email_sender or EmailNotificationSender(
            smtp_server="localhost",
            smtp_port=587,
            username="user",
            password="pass",
            from_email="noreply@plexichat.com",
        )
        self.push_sender = push_sender or PushNotificationSender()
        self.queue = PriorityQueue()
        self.max_workers = 5
        self.is_processing = False

    def queue_notification(
        self,
        notification_data: Dict[str, Any],
        priority: NotificationPriority = NotificationPriority.NORMAL,
        notification_id: str = "",
    ) -> None:
        """
        Queue a notification for processing.
        """
        if not notification_id:
            notification_id = f"notif_{id(notification_data)}"
        queued = QueuedNotification(priority.value, notification_data, notification_id)
        self.queue.put(queued)
        logger.info(f"Queued notification {notification_id} with priority {priority}")
        if not self.is_processing:
            asyncio.create_task(self._process_queue())

    async def _process_queue(self) -> None:
        """
        Process the notification queue asynchronously.
        """
        self.is_processing = True
        while not self.queue.empty():
            try:
                queued = self.queue.get_nowait()
                await self._handle_notification(queued.data, queued.notification_id)
                self.queue.task_done()
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
                await asyncio.sleep(1)  # Backoff
        self.is_processing = False

    async def _handle_notification(
        self, data: Dict[str, Any], notification_id: str
    ) -> None:
        """
        Handle a single notification based on type.
        """
        notification_type = data.get("type", "email")
        try:
            if notification_type == "email":
                success = await self.email_sender.send_notification(data)
            elif notification_type == "push":
                success = await self.push_sender.send_notification(data)
            else:
                logger.error(f"Unknown notification type: {notification_type}")
                success = False

            if success:
                logger.info(f"Processed {notification_id} successfully")
            else:
                logger.warning(f"Failed to process {notification_id}, will retry")
                # Retry logic: re-queue with reduced priority or max retries
                if data.get("retry_count", 0) < 3:
                    data["retry_count"] = data.get("retry_count", 0) + 1
                    self.queue_notification(
                        data, NotificationPriority.LOW, notification_id
                    )
        except Exception as e:
            logger.error(f"Error handling {notification_id}: {e}")

    async def send_notification(self, notification_data: Dict[str, Any]) -> bool:
        """
        Override to route through queue.
        """
        self.queue_notification(notification_data)
        return True  # Queued successfully
