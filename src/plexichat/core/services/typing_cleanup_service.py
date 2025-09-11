"""
Typing Cleanup Service

Background service for cleaning up expired typing indicators.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from plexichat.core.config import get_config
from plexichat.core.services.typing_service import typing_service
from plexichat.infrastructure.services.background_tasks import (
    TaskPriority,
    submit_scheduled_task,
)

logger = logging.getLogger(__name__)


class TypingCleanupService:
    """Service for managing background cleanup of expired typing states."""

    def __init__(self):
        self.cleanup_interval = get_config(
            "typing.cleanup_interval_seconds", 30
        )  # seconds
        self.max_cleanup_age = (
            get_config("typing.max_typing_history_days", 7) * 24 * 60 * 60
        )  # Convert days to seconds
        self.running = False
        self.cleanup_task_id: Optional[str] = None

    async def start(self) -> None:
        """Start the cleanup service."""
        if self.running:
            return

        self.running = True
        logger.info("Starting typing cleanup service")

        # Schedule initial cleanup
        await self._schedule_next_cleanup()

    async def stop(self) -> None:
        """Stop the cleanup service."""
        if not self.running:
            return

        self.running = False

        # Cancel any pending cleanup task
        if self.cleanup_task_id:
            # Note: In a real implementation, you'd cancel the task
            # For now, just mark as stopped
            pass

        logger.info("Stopped typing cleanup service")

    async def _schedule_next_cleanup(self) -> None:
        """Schedule the next cleanup task."""
        if not self.running:
            return

        try:
            # Schedule cleanup to run in cleanup_interval seconds
            next_run = datetime.now(timezone.utc) + timedelta(
                seconds=self.cleanup_interval
            )

            self.cleanup_task_id = await submit_scheduled_task(
                self._run_cleanup,
                next_run,
                name="typing_cleanup",
                priority=TaskPriority.LOW,
            )

            logger.debug(f"Scheduled next typing cleanup for {next_run}")

        except Exception as e:
            logger.error(f"Failed to schedule typing cleanup: {e}")
            # Retry after a shorter interval
            await asyncio.sleep(10)
            if self.running:
                await self._schedule_next_cleanup()

    async def _run_cleanup(self) -> Dict[str, Any]:
        """Run the actual cleanup operation."""
        try:
            logger.debug("Running typing cleanup")

            # Run cleanup
            cleaned_count = await typing_service.cleanup_expired_states()

            # Record metrics
            await self._record_cleanup_metrics(cleaned_count)

            # Schedule next cleanup
            if self.running:
                await self._schedule_next_cleanup()

            return {
                "success": True,
                "cleaned_count": cleaned_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Typing cleanup failed: {e}")

            # Still schedule next cleanup even if this one failed
            if self.running:
                await self._schedule_next_cleanup()

            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def _record_cleanup_metrics(self, cleaned_count: int) -> None:
        """Record cleanup metrics for monitoring."""
        try:
            # This would integrate with your metrics system
            # For now, just log the metrics
            logger.info(
                f"Typing cleanup completed: {cleaned_count} expired states removed"
            )

            # You could store this in the typing_metrics table
            # await self._store_metrics("cleanup", cleaned_count, ...)

        except Exception as e:
            logger.error(f"Failed to record cleanup metrics: {e}")

    async def force_cleanup(self) -> Dict[str, Any]:
        """Force an immediate cleanup (for admin purposes)."""
        try:
            logger.info("Forcing immediate typing cleanup")

            cleaned_count = await typing_service.cleanup_expired_states()

            return {
                "success": True,
                "cleaned_count": cleaned_count,
                "forced": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Forced typing cleanup failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "forced": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def get_status(self) -> Dict[str, Any]:
        """Get the current status of the cleanup service."""
        return {
            "running": self.running,
            "cleanup_interval": self.cleanup_interval,
            "max_cleanup_age": self.max_cleanup_age,
            "next_cleanup_task_id": self.cleanup_task_id,
            "last_cleanup_result": getattr(self, "_last_result", None),
        }

    async def update_config(self, config: Dict[str, Any]) -> bool:
        """Update cleanup service configuration."""
        try:
            if "cleanup_interval" in config:
                self.cleanup_interval = max(
                    10, min(300, config["cleanup_interval"])
                )  # 10s to 5min

            if "max_cleanup_age" in config:
                self.max_cleanup_age = max(
                    60, min(3600, config["max_cleanup_age"])
                )  # 1min to 1hour

            logger.info(
                f"Updated typing cleanup config: interval={self.cleanup_interval}s, max_age={self.max_cleanup_age}s"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to update cleanup config: {e}")
            return False


# Global cleanup service instance
typing_cleanup_service = TypingCleanupService()


async def start_typing_cleanup() -> None:
    """Start the typing cleanup service."""
    await typing_cleanup_service.start()


async def stop_typing_cleanup() -> None:
    """Stop the typing cleanup service."""
    await typing_cleanup_service.stop()


async def force_typing_cleanup() -> Dict[str, Any]:
    """Force an immediate cleanup."""
    return await typing_cleanup_service.force_cleanup()


async def get_typing_cleanup_status() -> Dict[str, Any]:
    """Get cleanup service status."""
    return await typing_cleanup_service.get_status()


async def update_typing_cleanup_config(config: Dict[str, Any]) -> bool:
    """Update cleanup service configuration."""
    return await typing_cleanup_service.update_config(config)
