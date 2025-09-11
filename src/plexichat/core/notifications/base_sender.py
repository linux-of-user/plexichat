from abc import ABC, abstractmethod
import asyncio
import logging
import os
from typing import Any

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class NotificationSender(ABC):
    """
    Abstract base class for notification senders, handling shared rendering and sending logic.
    """

    def __init__(self, templates_dir: str = "templates") -> None:
        self.templates_dir: str = os.path.join(os.path.dirname(__file__), templates_dir)
        self.env: Environment = Environment(loader=FileSystemLoader(self.templates_dir))
        self.max_retries: int = 3
        self.retry_delay: float = 1.0  # seconds

    async def _render_template(
        self, template_name: str, context: dict[str, Any]
    ) -> str:
        """Render a template with the given context."""
        try:
            template = self.env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            raise

    async def _send_notification(self, notification_data: dict[str, Any]) -> bool:
        """Generic sending method with error handling and retries."""
        rendered_content = await self._render_template(
            notification_data["template"], notification_data["context"]
        )
        recipient = notification_data["recipient"]
        for attempt in range(self.max_retries):
            try:
                success = await self._send_via_platform(
                    rendered_content, recipient, notification_data
                )
                if success:
                    logger.info(f"Notification sent successfully to {recipient}")
                    return True
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {recipient}: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                else:
                    logger.error(f"All retries failed for {recipient}: {e}")
                    raise
        return False

    @abstractmethod
    async def _send_via_platform(
        self, rendered_content: str, recipient: str, notification_data: dict[str, Any]
    ) -> bool:
        """Abstract method to be overridden by subclasses for platform-specific sending."""
        raise NotImplementedError

    async def send_notification(self, notification_data: dict[str, Any]) -> bool:
        """Public method to send a notification."""
        return await self._send_notification(notification_data)
