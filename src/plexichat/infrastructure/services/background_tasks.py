# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from sqlmodel import select


from plexichat.app.db import get_session
from plexichat.app.logger_config import logger
from plexichat.app.models.message import Message
from plexichat.app.models.moderation import (
    ModerationLog,
    ModerationStatus,
    UserModerationStatus,
, Optional)

"""
Background task service for PlexiChat.
Handles disappearing messages, expired moderation actions, and cleanup tasks.
"""


class BackgroundTaskService:
    """Service for managing background tasks and cleanup operations."""

    def __init__(self):
        self.running = False
        self.tasks = []

    async def start(self):
        """Start all background tasks."""
        if self.running:
            return

        self.running = True
        logger.info("Starting background task service")

        # Start individual tasks
        self.tasks = [
            asyncio.create_task(self._cleanup_expired_messages()),
            asyncio.create_task(self._cleanup_expired_moderation()),
            asyncio.create_task(self._cleanup_old_logs()),
            asyncio.create_task(self._update_user_activity()),
        ]

        # Wait for all tasks to complete (they run indefinitely)
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def stop(self):
        """Stop all background tasks."""
        if not self.running:
            return

        self.running = False
        logger.info("Stopping background task service")

        # Cancel all tasks
        for task in self.tasks:
            task.cancel()

        # Wait for tasks to finish cancellation
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()

    async def _cleanup_expired_messages(self):
        """Clean up expired/disappearing messages."""
        while self.running:
            try:
                async with get_session() as session:
                    now = datetime.now(timezone.utc)

                    # Find expired messages
                    statement = select(Message).where(
                        (Message.expires_at.is_not(None))
                        & (Message.expires_at <= now)
                        & (not Message.is_deleted)
                    )

                    expired_messages = session.exec(statement).all()

                    for message in expired_messages:
                        # Mark message as deleted
                        message.is_deleted = True
                        message.content = "[Message expired]"
                        message.attached_files = []
                        message.embedded_files = []

                        logger.debug(f"Expired message {message.id}")

                    if expired_messages:
                        session.commit()
                        logger.info(
                            f"Cleaned up {len(expired_messages)} expired messages"
                        )

                # Sleep for 1 minute before next check
                await asyncio.sleep(60)

            except Exception as e:
                logger.error(f"Error in expired message cleanup: {e}")
                await asyncio.sleep(60)

    async def _cleanup_expired_moderation(self):
        """Clean up expired moderation actions."""
        while self.running:
            try:
                async with get_session() as session:
                    now = datetime.now(timezone.utc)

                    # Find expired moderation logs
                    statement = select(ModerationLog).where(
                        (ModerationLog.expires_at.is_not(None))
                        & (ModerationLog.expires_at <= now)
                        & (ModerationLog.status == ModerationStatus.ACTIVE)
                    )

                    expired_logs = session.exec(statement).all()

                    for log in expired_logs:
                        log.status = ModerationStatus.EXPIRED
                        log.resolved_at = now

                        # Update user moderation status
                        if log.target_user_id:
                            user_status = session.exec(
                                select(UserModerationStatus).where(
                                    UserModerationStatus.user_id == log.target_user_id
                                )
                            ).first()

                            if user_status:
                                # Check and clear expired restrictions
                                if (
                                    user_status.is_muted
                                    and user_status.mute_expires_at
                                    and user_status.mute_expires_at <= now
                                ):
                                    user_status.is_muted = False
                                    user_status.mute_expires_at = None
                                    user_status.mute_reason = None

                                if (
                                    user_status.is_banned
                                    and user_status.ban_expires_at
                                    and user_status.ban_expires_at <= now
                                ):
                                    user_status.is_banned = False
                                    user_status.ban_expires_at = None
                                    user_status.ban_reason = None

                                if (
                                    user_status.is_timed_out
                                    and user_status.timeout_expires_at
                                    and user_status.timeout_expires_at <= now
                                ):
                                    user_status.is_timed_out = False
                                    user_status.timeout_expires_at = None
                                    user_status.timeout_reason = None

                                user_status.updated_at = now

                        logger.debug(f"Expired moderation action {log.id}")

                    if expired_logs:
                        session.commit()
                        logger.info(
                            f"Cleaned up {len(expired_logs)} expired moderation actions"
                        )

                # Sleep for 5 minutes before next check
                await asyncio.sleep(300)

            except Exception as e:
                logger.error(f"Error in expired moderation cleanup: {e}")
                await asyncio.sleep(300)

    async def _cleanup_old_logs(self):
        """Clean up old log entries to prevent database bloat."""
        while self.running:
            try:
                async with get_session() as session:
                    # Clean up old moderation logs (older than 1 year)
                    cutoff_date = datetime.now(timezone.utc) - timedelta(days=365)

                    statement = select(ModerationLog).where(
                        (ModerationLog.created_at < cutoff_date)
                        & (
                            ModerationLog.status.in_(
                                [ModerationStatus.EXPIRED, ModerationStatus.REVOKED]
                            )
                        )
                    )

                    old_logs = session.exec(statement).all()

                    for log in old_logs:
                        session.delete(log)

                    if old_logs:
                        session.commit()
                        logger.info(f"Cleaned up {len(old_logs)} old moderation logs")

                # Sleep for 24 hours before next cleanup
                await asyncio.sleep(86400)

            except Exception as e:
                logger.error(f"Error in old log cleanup: {e}")
                await asyncio.sleep(86400)

    async def _update_user_activity(self):
        """Update user activity metrics and statistics."""
        while self.running:
            try:
                async with get_session():
                    # This could include updating user statistics, calculating metrics, etc.
                    # For now, we'll just log that the task is running
                    logger.debug("User activity update task running")

                # Sleep for 1 hour before next update
                await asyncio.sleep(3600)

            except Exception as e:
                logger.error(f"Error in user activity update: {e}")
                await asyncio.sleep(3600)

    async def cleanup_user_data(self, user_id: int) -> Dict[str, int]:
        """Clean up all data for a deleted user."""
        try:
            async with get_session() as session:
                cleanup_stats = {
                    "messages_deleted": 0,
                    "moderation_logs_anonymized": 0,
                    "files_deleted": 0,
                }

                # Anonymize messages (don't delete to preserve conversation context)
                statement = select(Message).where(
                    (Message.sender_id == user_id) | (Message.author_id == user_id)
                )
                user_messages = session.exec(statement).all()

                for message in user_messages:
                    message.content = "[Message from deleted user]"
                    message.sender_id = None
                    message.author_id = None
                    message.attached_files = []
                    message.embedded_files = []
                    cleanup_stats["messages_deleted"] += 1

                # Anonymize moderation logs
                statement = select(ModerationLog).where(
                    (ModerationLog.target_user_id == user_id)
                    | (ModerationLog.moderator_id == user_id)
                )
                moderation_logs = session.exec(statement).all()

                for log in moderation_logs:
                    if log.target_user_id == user_id: Optional[log.target_user_id] = None
                    if log.moderator_id == user_id: Optional[log.moderator_id] = None
                    cleanup_stats["moderation_logs_anonymized"] += 1

                session.commit()

                logger.info(
                    f"Cleaned up data for deleted user {user_id}: {cleanup_stats}"
                )
                return cleanup_stats

        except Exception as e:
            logger.error(f"Error cleaning up user data: {e}")
            return {"error": str(e)}

    async def force_expire_message(self, message_id: int) -> bool:
        """Force expire a specific message."""
        try:
            async with get_session() as session:
                message = session.get(Message, message_id)
                if not message:
                    return False

                message.is_deleted = True
                message.content = "[Message expired by moderator]"
                message.attached_files = []
                message.embedded_files = []
                message.expires_at = datetime.now(timezone.utc)

                session.commit()

                logger.info(f"Force expired message {message_id}")
                return True

        except Exception as e:
            logger.error(f"Error force expiring message: {e}")
            return False

    async def get_cleanup_statistics(self) -> Dict[str, Any]:
        """Get statistics about cleanup operations."""
        try:
            async with get_session() as session:
                now = datetime.now(timezone.utc)

                # Count expired messages in last 24 hours
                yesterday = now - timedelta(days=1)
                expired_messages = session.exec(
                    select(Message).where(
                        (Message.expires_at.is_not(None))
                        & (Message.expires_at >= yesterday)
                        & (Message.expires_at <= now)
                        & (Message.is_deleted)
                    )
                ).all()

                # Count expired moderation actions in last 24 hours
                expired_moderation = session.exec(
                    select(ModerationLog).where(
                        (ModerationLog.expires_at.is_not(None))
                        & (ModerationLog.expires_at >= yesterday)
                        & (ModerationLog.expires_at <= now)
                        & (ModerationLog.status == ModerationStatus.EXPIRED)
                    )
                ).all()

                # Count pending disappearing messages
                pending_messages = session.exec(
                    select(Message).where(
                        (Message.expires_at.is_not(None))
                        & (Message.expires_at > now)
                        & (not Message.is_deleted)
                    )
                ).all()

                return {
                    "expired_messages_24h": len(expired_messages),
                    "expired_moderation_24h": len(expired_moderation),
                    "pending_disappearing_messages": len(pending_messages),
                    "service_running": self.running,
                    "active_tasks": len(self.tasks),
                }

        except Exception as e:
            logger.error(f"Error getting cleanup statistics: {e}")
            return {"error": str(e)}


# Global instance
background_task_service = BackgroundTaskService()
