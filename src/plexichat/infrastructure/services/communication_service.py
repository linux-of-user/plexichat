# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
import logging
from pathlib import Path
from typing import Any
import uuid

import yaml


# Placeholder imports for dependencies
def get_ai_manager():
    return None


def get_logger(name):
    return logging.getLogger(name)


class BaseService:
    def __init__(self, name):
        self.name = name
        self.logger = logging.getLogger(name)

    async def start(self):
        pass

    async def stop(self):
        pass

    async def get_health_status(self):
        return {}


logger = get_logger(__name__)


class MessageType(Enum):
    """Message types for advanced communication."""

    TEXT = "text"
    VOICE = "voice"
    IMAGE = "image"
    FILE = "file"
    SYSTEM = "system"
    REACTION = "reaction"
    THREAD_REPLY = "thread_reply"
    TRANSLATION = "translation"


class ReactionType(Enum):
    """Available reaction types."""

    LIKE = "like"
    LOVE = "love"
    LAUGH = "laugh"
    WOW = "wow"
    SAD = "sad"
    ANGRY = "angry"
    CELEBRATE = "celebrate"
    THUMBS_DOWN = "thumbs_down"


class NotificationPriority(Enum):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class ThreadStatus(Enum):
    """Thread status types."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


@dataclass
class VoiceMessage:
    """Voice message data structure."""

    message_id: str
    user_id: str
    chat_id: str
    file_path: str
    duration: float  # in seconds
    transcript: str | None = None
    waveform_data: list[float] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_transcribed: bool = False


@dataclass
class MessageReaction:
    """Message reaction data structure."""

    reaction_id: str
    message_id: str
    user_id: str
    reaction_type: ReactionType
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class MessageThread:
    """Message thread data structure."""

    thread_id: str
    parent_message_id: str
    chat_id: str
    title: str | None = None
    status: ThreadStatus = ThreadStatus.ACTIVE
    participants: set[str] = field(default_factory=set)
    message_count: int = 0
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    created_by: str | None = None


@dataclass
class TranslationRequest:
    """Translation request data structure."""

    request_id: str
    message_id: str
    user_id: str
    source_language: str
    target_language: str
    original_text: str
    translated_text: str | None = None
    confidence_score: float | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


@dataclass
class SmartNotification:
    """Smart notification data structure."""

    notification_id: str
    user_id: str
    message_id: str
    chat_id: str
    priority: NotificationPriority
    title: str
    content: str
    ai_summary: str | None = None
    action_required: bool = False
    read: bool = False
    delivered: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    scheduled_for: datetime | None = None
    expires_at: datetime | None = None


class CommunicationService(BaseService):
    """Advanced communication service with enhanced features."""

    def __init__(self, config_path: Path | None = None):
        super().__init__("communication")

        # Configuration management
        self.config_path = config_path or Path("config/communication.yaml")

        # Storage for communication data
        self.voice_messages: dict[str, VoiceMessage] = {}
        self.message_reactions: dict[str, list[MessageReaction]] = {}
        self.message_threads: dict[str, MessageThread] = {}
        self.translations: dict[str, TranslationRequest] = {}
        self.notifications: dict[str, list[SmartNotification]] = {}

        # AI manager for smart features
        self.ai_manager = None

        # Load configuration from file or use defaults
        self.config = self._load_configuration()

        # Configuration-derived properties
        self.voice_storage_path = Path(self.config["voice_messages"]["storage_path"])
        self.max_voice_duration = self.config["voice_messages"]["max_duration_seconds"]
        self.supported_languages = self.config["translation"]["supported_languages"]

        # Background tasks
        self._cleanup_task = None
        self._notification_task = None

    def _load_configuration(self) -> dict[str, Any]:
        """Load configuration from YAML file or return defaults."""
        try:
            if self.config_path and self.config_path.exists():
                with open(self.config_path, encoding="utf-8") as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        # Merge with defaults to ensure all keys exist
                        default_config = self._get_default_configuration()
                        return self._deep_merge_config(default_config, loaded_config)

            # Return default configuration if file doesn't exist
            logger.info(
                f"Configuration file {self.config_path} not found, using defaults"
            )
            return self._get_default_configuration()

        except Exception as e:
            logger.error(f"Failed to load configuration from {self.config_path}: {e}")
            logger.info("Using default configuration")
            return self._get_default_configuration()

    def _get_default_configuration(self) -> dict[str, Any]:
        """Get default configuration."""
        return {
            "voice_messages": {
                "enabled": True,
                "storage_path": "data/voice_messages",
                "max_duration_seconds": 300,
                "max_file_size_mb": 50,
                "auto_transcription": True,
                "transcription_language": "auto",
                "compression_enabled": True,
                "compression_quality": 0.8,
                "allowed_formats": ["wav", "mp3", "ogg", "m4a"],
                "cleanup_after_days": 90,
            },
            "reactions": {
                "enabled": True,
                "max_reactions_per_message": 50,
                "max_reactions_per_user": 10,
                "custom_reactions_enabled": True,
                "reaction_analytics": True,
                "rate_limit_per_minute": 30,
            },
            "threads": {
                "enabled": True,
                "max_thread_depth": 5,
                "max_participants": 100,
                "auto_archive_after_days": 30,
                "thread_notifications": True,
                "thread_search_enabled": True,
                "max_threads_per_message": 3,
            },
            "translation": {
                "enabled": True,
                "supported_languages": [
                    "en",
                    "es",
                    "fr",
                    "de",
                    "it",
                    "pt",
                    "ru",
                    "zh",
                    "ja",
                    "ko",
                    "ar",
                    "hi",
                    "tr",
                    "pl",
                    "nl",
                ],
                "auto_detect_language": True,
                "translation_provider": "openai",
                "fallback_providers": ["google", "azure"],
                "cache_translations": True,
                "cache_duration_hours": 24,
                "confidence_threshold": 0.7,
                "rate_limit_per_hour": 1000,
                "batch_translation_enabled": True,
            },
            "notifications": {
                "enabled": True,
                "ai_analysis_enabled": True,
                "priority_adjustment": True,
                "smart_scheduling": True,
                "digest_notifications": True,
                "digest_frequency_hours": 4,
                "max_notifications_per_user": 1000,
                "notification_retention_days": 30,
                "push_notifications": True,
                "email_notifications": True,
                "sms_notifications": False,
                "quiet_hours_start": "22:00",
                "quiet_hours_end": "08:00",
                "weekend_quiet_mode": False,
            },
            "ai_features": {
                "enabled": True,
                "sentiment_analysis": True,
                "content_moderation": True,
                "smart_replies": True,
                "message_summarization": True,
                "language_detection": True,
                "spam_detection": True,
                "ai_provider": "openai",
                "fallback_providers": ["anthropic", "google"],
                "confidence_threshold": 0.8,
                "rate_limit_per_hour": 5000,
                "cache_ai_responses": True,
                "cache_duration_hours": 12,
            },
            "security": {
                "message_encryption": True,
                "end_to_end_encryption": True,
                "content_filtering": True,
                "audit_logging": True,
                "rate_limiting": True,
                "ip_whitelisting": False,
                "user_verification": True,
                "message_retention_days": 365,
                "auto_delete_sensitive": True,
                "encryption_algorithm": "AES-256-GCM",
            },
            "performance": {
                "max_concurrent_operations": 1000,
                "cache_size_mb": 512,
                "batch_processing": True,
                "auto_scaling": True,
                "connection_pooling": True,
                "compression_enabled": True,
                "cdn_enabled": False,
                "metrics_collection": True,
                "performance_monitoring": True,
                "resource_limits": {
                    "max_memory_mb": 2048,
                    "max_cpu_percent": 80,
                    "max_disk_mb": 10240,
                },
            },
            "integrations": {
                "webhooks_enabled": True,
                "external_storage": False,
                "third_party_apis": {},
                "plugin_support": True,
                "custom_handlers": True,
                "api_rate_limits": {"requests_per_minute": 1000, "burst_limit": 100},
                "storage_config": {},
                "notification_services": [],
            },
        }

    def _deep_merge_config(
        self, base: dict[str, Any], update: dict[str, Any]
    ) -> dict[str, Any]:
        """Deep merge configuration dictionaries."""
        result = base.copy()

        for key, value in update.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge_config(result[key], value)
            else:
                result[key] = value

        return result

    async def _save_configuration(self) -> bool:
        """Save current configuration to YAML file."""
        try:
            # Ensure config directory exists
            if self.config_path:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)

                # Save configuration to YAML file
                with open(self.config_path, "w", encoding="utf-8") as f:
                    yaml.dump(
                        self.config,
                        f,
                        default_flow_style=False,
                        indent=2,
                        sort_keys=True,
                    )

                logger.info(f"Configuration saved to {self.config_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save configuration to {self.config_path}: {e}")
            return False

    async def start(self):
        """Start the communication service."""
        try:
            await super().start()

            # Initialize AI manager
            self.ai_manager = await get_ai_manager()

            # Create voice storage directory
            self.voice_storage_path.mkdir(parents=True, exist_ok=True)

            # Start background tasks
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            self._notification_task = asyncio.create_task(self._notification_loop())

            logger.info(" Communication service started successfully")

        except Exception as e:
            logger.error(f"Failed to start communication service: {e}")
            self.state = ServiceState.ERROR
            raise

    async def stop(self):
        """Stop the communication service."""
        try:
            # Cancel background tasks
            if self._cleanup_task:
                self._cleanup_task.cancel()
            if self._notification_task:
                self._notification_task.cancel()

            await super().stop()
            logger.info(" Communication service stopped")

        except Exception as e:
            logger.error(f"Error stopping communication service: {e}")

    # Voice Message Methods

    async def create_voice_message(
        self, user_id: str, chat_id: str, audio_data: bytes, duration: float
    ) -> VoiceMessage:
        """Create a new voice message."""
        try:
            if duration > self.max_voice_duration:
                raise ValueError(
                    f"Voice message too long: {duration}s > {self.max_voice_duration}s"
                )

            message_id = str(uuid.uuid4())
            file_path = self.voice_storage_path / f"{message_id}.wav"

            # Save audio file
            with open(file_path, "wb") as f:
                f.write(audio_data)

            # Create voice message
            voice_message = VoiceMessage(
                message_id=message_id,
                user_id=user_id,
                chat_id=chat_id,
                file_path=str(file_path),
                duration=duration,
            )

            self.voice_messages[message_id] = voice_message

            # Start transcription in background
            asyncio.create_task(self._transcribe_voice_message(message_id))

            logger.info(f"Voice message created: {message_id}")
            return voice_message

        except Exception as e:
            logger.error(f"Failed to create voice message: {e}")
            raise

    async def _transcribe_voice_message(self, message_id: str):
        """Transcribe voice message using AI."""
        try:
            voice_message = self.voice_messages.get(message_id)
            if not voice_message or not self.ai_manager:
                return

            # Use AI to transcribe audio
            transcript = await self.ai_manager.transcribe_audio(voice_message.file_path)

            # Update voice message
            voice_message.transcript = transcript
            voice_message.is_transcribed = True

            logger.info(f"Voice message transcribed: {message_id}")

        except Exception as e:
            logger.error(f"Failed to transcribe voice message {message_id}: {e}")

    async def get_voice_message(self, message_id: str) -> VoiceMessage | None:
        """Get voice message by ID."""
        return self.voice_messages.get(message_id)

    # Message Reaction Methods

    async def add_reaction(
        self, message_id: str, user_id: str, reaction_type: ReactionType
    ) -> MessageReaction:
        """Add reaction to a message."""
        try:
            # Check if user already reacted with this type
            existing_reactions = self.message_reactions.get(message_id, [])
            for reaction in existing_reactions:
                if (
                    reaction.user_id == user_id
                    and reaction.reaction_type == reaction_type
                ):
                    raise ValueError("User already reacted with this type")

            # Create reaction
            reaction = MessageReaction(
                reaction_id=str(uuid.uuid4()),
                message_id=message_id,
                user_id=user_id,
                reaction_type=reaction_type,
            )

            if message_id not in self.message_reactions:
                self.message_reactions[message_id] = []

            self.message_reactions[message_id].append(reaction)

            logger.info(f"Reaction added: {reaction.reaction_id}")
            return reaction

        except Exception as e:
            logger.error(f"Failed to add reaction: {e}")
            raise

    async def remove_reaction(
        self, message_id: str, user_id: str, reaction_type: ReactionType
    ) -> bool:
        """Remove reaction from a message."""
        try:
            reactions = self.message_reactions.get(message_id, [])

            for i, reaction in enumerate(reactions):
                if (
                    reaction.user_id == user_id
                    and reaction.reaction_type == reaction_type
                ):
                    reactions.pop(i)
                    logger.info(f"Reaction removed: {reaction.reaction_id}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to remove reaction: {e}")
            return False

    async def get_message_reactions(self, message_id: str) -> list[MessageReaction]:
        """Get all reactions for a message."""
        return self.message_reactions.get(message_id, [])

    # Thread Management Methods

    async def create_thread(
        self,
        parent_message_id: str,
        chat_id: str,
        user_id: str,
        title: str | None = None,
    ) -> MessageThread:
        """Create a new message thread."""
        try:
            thread_id = str(uuid.uuid4())

            thread = MessageThread(
                thread_id=thread_id,
                parent_message_id=parent_message_id,
                chat_id=chat_id,
                title=title,
                created_by=user_id,
            )

            thread.participants.add(user_id)
            self.message_threads[thread_id] = thread

            logger.info(f"Thread created: {thread_id}")
            return thread

        except Exception as e:
            logger.error(f"Failed to create thread: {e}")
            raise

    async def add_thread_participant(self, thread_id: str, user_id: str) -> bool:
        """Add participant to thread."""
        try:
            thread = self.message_threads.get(thread_id)
            if not thread:
                return False

            thread.participants.add(user_id)
            thread.last_activity = datetime.now(UTC)

            logger.info(f"Participant added to thread {thread_id}: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add thread participant: {e}")
            return False

    async def update_thread_status(self, thread_id: str, status: ThreadStatus) -> bool:
        """Update thread status."""
        try:
            thread = self.message_threads.get(thread_id)
            if not thread:
                return False

            thread.status = status
            thread.last_activity = datetime.now(UTC)

            logger.info(f"Thread status updated: {thread_id} -> {status.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to update thread status: {e}")
            return False

    async def get_thread(self, thread_id: str) -> MessageThread | None:
        """Get thread by ID."""
        return self.message_threads.get(thread_id)

    async def get_chat_threads(self, chat_id: str) -> list[MessageThread]:
        """Get all threads for a chat."""
        return [
            thread
            for thread in self.message_threads.values()
            if thread.chat_id == chat_id
        ]

    # Translation Methods

    async def translate_message(
        self,
        message_id: str,
        user_id: str,
        original_text: str,
        target_language: str,
        source_language: str = "auto",
    ) -> TranslationRequest:
        """Translate a message."""
        try:
            if target_language not in self.supported_languages:
                raise ValueError(f"Unsupported target language: {target_language}")

            request_id = str(uuid.uuid4())

            translation_request = TranslationRequest(
                request_id=request_id,
                message_id=message_id,
                user_id=user_id,
                source_language=source_language,
                target_language=target_language,
                original_text=original_text,
            )

            self.translations[request_id] = translation_request

            # Start translation in background
            asyncio.create_task(self._perform_translation(request_id))

            logger.info(f"Translation request created: {request_id}")
            return translation_request

        except Exception as e:
            logger.error(f"Failed to create translation request: {e}")
            raise

    async def _perform_translation(self, request_id: str):
        """Perform translation using AI."""
        try:
            translation_request = self.translations.get(request_id)
            if not translation_request or not self.ai_manager:
                return

            # Use AI to translate text
            translated_text, confidence = await self.ai_manager.translate_text(
                translation_request.original_text,
                translation_request.target_language,
                translation_request.source_language,
            )

            # Update translation request
            translation_request.translated_text = translated_text
            translation_request.confidence_score = confidence
            translation_request.completed_at = datetime.now(UTC)

            logger.info(f"Translation completed: {request_id}")

        except Exception as e:
            logger.error(f"Failed to perform translation {request_id}: {e}")

    async def get_translation(self, request_id: str) -> TranslationRequest | None:
        """Get translation by request ID."""
        return self.translations.get(request_id)

    # Smart Notification Methods

    async def create_smart_notification(
        self,
        user_id: str,
        message_id: str,
        chat_id: str,
        title: str,
        content: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
    ) -> SmartNotification:
        """Create a smart notification with AI analysis."""
        try:
            notification_id = str(uuid.uuid4())

            notification = SmartNotification(
                notification_id=notification_id,
                user_id=user_id,
                message_id=message_id,
                chat_id=chat_id,
                priority=priority,
                title=title,
                content=content,
            )

            if user_id not in self.notifications:
                self.notifications[user_id] = []

            self.notifications[user_id].append(notification)

            # Analyze notification with AI
            asyncio.create_task(self._analyze_notification(notification_id))

            logger.info(f"Smart notification created: {notification_id}")
            return notification

        except Exception as e:
            logger.error(f"Failed to create smart notification: {e}")
            raise

    async def _analyze_notification(self, notification_id: str):
        """Analyze notification with AI for smart prioritization."""
        try:
            # Find notification
            notification = None
            for user_notifications in self.notifications.values():
                for notif in user_notifications:
                    if notif.notification_id == notification_id:
                        notification = notif
                        break
                if notification:
                    break

            if not notification or not self.ai_manager:
                return

            # Use AI to analyze and summarize
            analysis = await self.ai_manager.analyze_message_importance(
                notification.content, notification.chat_id
            )

            # Update notification
            notification.ai_summary = analysis.get("summary")
            notification.action_required = analysis.get("action_required", False)

            # Adjust priority based on AI analysis
            importance_score = analysis.get("importance_score", 0.5)
            if importance_score > 0.8:
                notification.priority = NotificationPriority.URGENT
            elif importance_score > 0.6:
                notification.priority = NotificationPriority.HIGH

            logger.info(f"Notification analyzed: {notification_id}")

        except Exception as e:
            logger.error(f"Failed to analyze notification {notification_id}: {e}")

    async def get_user_notifications(
        self, user_id: str, unread_only: bool = False
    ) -> list[SmartNotification]:
        """Get notifications for a user."""
        notifications = self.notifications.get(user_id, [])

        if unread_only:
            notifications = [n for n in notifications if not n.read]

        # Sort by priority and creation time
        priority_order = {
            NotificationPriority.URGENT: 0,
            NotificationPriority.HIGH: 1,
            NotificationPriority.NORMAL: 2,
            NotificationPriority.LOW: 3,
        }

        return sorted(
            notifications,
            key=lambda n: (priority_order[n.priority], n.created_at),
            reverse=True,
        )

    async def mark_notification_read(self, notification_id: str, user_id: str) -> bool:
        """Mark notification as read."""
        try:
            user_notifications = self.notifications.get(user_id, [])

            for notification in user_notifications:
                if notification.notification_id == notification_id:
                    notification.read = True
                    logger.info(f"Notification marked as read: {notification_id}")
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to mark notification as read: {e}")
            return False

    # Background Tasks

    async def _cleanup_loop(self):
        """Background cleanup task."""
        while self.state == ServiceState.RUNNING:
            try:
                await self._cleanup_old_data()
                await asyncio.sleep(3600)  # Run every hour

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error

    async def _cleanup_old_data(self):
        """Clean up old data."""
        try:
            cutoff_date = datetime.now(UTC) - timedelta(days=30)

            # Clean up old translations
            old_translations = [
                req_id
                for req_id, req in self.translations.items()
                if req.created_at < cutoff_date
            ]

            for req_id in old_translations:
                del self.translations[req_id]

            # Clean up old notifications
            for user_id, notifications in self.notifications.items():
                self.notifications[user_id] = [
                    n
                    for n in notifications
                    if n.created_at >= cutoff_date or not n.read
                ]

            if old_translations:
                logger.info(f"Cleaned up {len(old_translations)} old translations")

        except Exception as e:
            logger.error(f"Data cleanup error: {e}")

    async def _notification_loop(self):
        """Background notification processing task."""
        while self.state == ServiceState.RUNNING:
            try:
                await self._process_scheduled_notifications()
                await asyncio.sleep(60)  # Check every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Notification loop error: {e}")
                await asyncio.sleep(60)

    async def _process_scheduled_notifications(self):
        """Process scheduled notifications."""
        try:
            now = datetime.now(UTC)

            for user_notifications in self.notifications.values():
                for notification in user_notifications:
                    if (
                        notification.scheduled_for
                        and notification.scheduled_for <= now
                        and not notification.delivered
                    ):

                        # Mark as delivered
                        notification.delivered = True

                        # Here you would send the actual notification
                        # (push notification, email, etc.)
                        logger.info(
                            f"Delivered scheduled notification: {notification.notification_id}"
                        )

        except Exception as e:
            logger.error(f"Scheduled notification processing error: {e}")

    # Configuration Management Methods

    async def get_configuration(self) -> dict[str, Any]:
        """Get current service configuration."""
        return self.config.copy()

    async def update_configuration(self, config_updates: dict[str, Any]) -> bool:
        """Update service configuration."""
        try:
            # Deep merge configuration updates
            self.config = self._deep_merge_config(self.config, config_updates)

            # Update derived properties
            self.voice_storage_path = Path(
                self.config["voice_messages"]["storage_path"]
            )
            self.max_voice_duration = self.config["voice_messages"][
                "max_duration_seconds"
            ]
            self.supported_languages = self.config["translation"]["supported_languages"]

            # Recreate voice storage directory if path changed
            self.voice_storage_path.mkdir(parents=True, exist_ok=True)

            # Save configuration to file
            save_success = await self._save_configuration()
            if not save_success:
                logger.warning(
                    "Configuration updated in memory but failed to save to file"
                )

            logger.info("Communication service configuration updated")
            return True

        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False

    async def reset_configuration_section(self, section: str) -> bool:
        """Reset a configuration section to defaults."""
        try:
            default_config = self._get_default_configuration()

            if section in default_config:
                self.config[section] = default_config[section].copy()

                # Update derived properties if needed
                if section == "voice_messages":
                    self.voice_storage_path = Path(
                        self.config["voice_messages"]["storage_path"]
                    )
                    self.max_voice_duration = self.config["voice_messages"][
                        "max_duration_seconds"
                    ]
                    self.voice_storage_path.mkdir(parents=True, exist_ok=True)
                elif section == "translation":
                    self.supported_languages = self.config["translation"][
                        "supported_languages"
                    ]

                # Save configuration to file
                save_success = await self._save_configuration()
                if not save_success:
                    logger.warning(
                        "Configuration reset in memory but failed to save to file"
                    )

                logger.info(f"Configuration section '{section}' reset to defaults")
                return True
            else:
                logger.warning(f"Unknown configuration section: {section}")
                return False

        except Exception as e:
            logger.error(f"Failed to reset configuration section: {e}")
            return False

    async def validate_configuration(self) -> dict[str, list[str]]:
        """Validate current configuration and return any issues."""
        issues = {}

        try:
            # Validate voice messages config
            voice_config = self.config.get("voice_messages", {})
            voice_issues = []

            if voice_config.get("max_duration_seconds", 0) <= 0:
                voice_issues.append("max_duration_seconds must be positive")
            if voice_config.get("max_file_size_mb", 0) <= 0:
                voice_issues.append("max_file_size_mb must be positive")
            if not isinstance(voice_config.get("allowed_formats", []), list):
                voice_issues.append("allowed_formats must be a list")

            if voice_issues:
                issues["voice_messages"] = voice_issues

            # Validate translation config
            translation_config = self.config.get("translation", {})
            translation_issues = []

            if not isinstance(translation_config.get("supported_languages", []), list):
                translation_issues.append("supported_languages must be a list")
            if not (0 <= translation_config.get("confidence_threshold", 0) <= 1):
                translation_issues.append(
                    "confidence_threshold must be between 0 and 1"
                )

            if translation_issues:
                issues["translation"] = translation_issues

            # Validate notifications config
            notifications_config = self.config.get("notifications", {})
            notifications_issues = []

            if notifications_config.get("max_notifications_per_user", 0) <= 0:
                notifications_issues.append(
                    "max_notifications_per_user must be positive"
                )
            if notifications_config.get("notification_retention_days", 0) <= 0:
                notifications_issues.append(
                    "notification_retention_days must be positive"
                )

            if notifications_issues:
                issues["notifications"] = notifications_issues

            return issues

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return {"general": [f"Validation error: {e!s}"]}

    async def get_configuration_schema(self) -> dict[str, Any]:
        """Get configuration schema for UI generation."""
        return {
            "voice_messages": {
                "title": "Voice Messages",
                "description": "Configuration for voice message features",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "title": "Enable Voice Messages",
                        "default": True,
                    },
                    "storage_path": {
                        "type": "string",
                        "title": "Storage Path",
                        "default": "data/voice_messages",
                    },
                    "max_duration_seconds": {
                        "type": "integer",
                        "title": "Max Duration (seconds)",
                        "minimum": 1,
                        "maximum": 3600,
                        "default": 300,
                    },
                    "max_file_size_mb": {
                        "type": "integer",
                        "title": "Max File Size (MB)",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                    },
                    "auto_transcription": {
                        "type": "boolean",
                        "title": "Auto Transcription",
                        "default": True,
                    },
                    "transcription_language": {
                        "type": "string",
                        "title": "Transcription Language",
                        "default": "auto",
                    },
                    "compression_enabled": {
                        "type": "boolean",
                        "title": "Enable Compression",
                        "default": True,
                    },
                    "compression_quality": {
                        "type": "number",
                        "title": "Compression Quality",
                        "minimum": 0.1,
                        "maximum": 1.0,
                        "default": 0.8,
                    },
                    "allowed_formats": {
                        "type": "array",
                        "title": "Allowed Formats",
                        "items": {"type": "string"},
                        "default": ["wav", "mp3", "ogg", "m4a"],
                    },
                    "cleanup_after_days": {
                        "type": "integer",
                        "title": "Cleanup After (days)",
                        "minimum": 1,
                        "default": 90,
                    },
                },
            },
            "reactions": {
                "title": "Message Reactions",
                "description": "Configuration for message reaction features",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "title": "Enable Reactions",
                        "default": True,
                    },
                    "max_reactions_per_message": {
                        "type": "integer",
                        "title": "Max Reactions per Message",
                        "minimum": 1,
                        "default": 50,
                    },
                    "max_reactions_per_user": {
                        "type": "integer",
                        "title": "Max Reactions per User",
                        "minimum": 1,
                        "default": 10,
                    },
                    "custom_reactions_enabled": {
                        "type": "boolean",
                        "title": "Enable Custom Reactions",
                        "default": True,
                    },
                    "reaction_analytics": {
                        "type": "boolean",
                        "title": "Enable Reaction Analytics",
                        "default": True,
                    },
                    "rate_limit_per_minute": {
                        "type": "integer",
                        "title": "Rate Limit (per minute)",
                        "minimum": 1,
                        "default": 30,
                    },
                },
            },
            "threads": {
                "title": "Message Threads",
                "description": "Configuration for message threading features",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "title": "Enable Threads",
                        "default": True,
                    },
                    "max_thread_depth": {
                        "type": "integer",
                        "title": "Max Thread Depth",
                        "minimum": 1,
                        "maximum": 10,
                        "default": 5,
                    },
                    "max_participants": {
                        "type": "integer",
                        "title": "Max Participants",
                        "minimum": 2,
                        "default": 100,
                    },
                    "auto_archive_after_days": {
                        "type": "integer",
                        "title": "Auto Archive After (days)",
                        "minimum": 1,
                        "default": 30,
                    },
                    "thread_notifications": {
                        "type": "boolean",
                        "title": "Thread Notifications",
                        "default": True,
                    },
                    "thread_search_enabled": {
                        "type": "boolean",
                        "title": "Enable Thread Search",
                        "default": True,
                    },
                    "max_threads_per_message": {
                        "type": "integer",
                        "title": "Max Threads per Message",
                        "minimum": 1,
                        "default": 3,
                    },
                },
            },
            "translation": {
                "title": "Message Translation",
                "description": "Configuration for message translation features",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "title": "Enable Translation",
                        "default": True,
                    },
                    "supported_languages": {
                        "type": "array",
                        "title": "Supported Languages",
                        "items": {"type": "string"},
                        "default": ["en", "es", "fr", "de"],
                    },
                    "auto_detect_language": {
                        "type": "boolean",
                        "title": "Auto Detect Language",
                        "default": True,
                    },
                    "translation_provider": {
                        "type": "string",
                        "title": "Translation Provider",
                        "enum": ["openai", "google", "azure", "aws"],
                        "default": "openai",
                    },
                    "fallback_providers": {
                        "type": "array",
                        "title": "Fallback Providers",
                        "items": {"type": "string"},
                        "default": ["google", "azure"],
                    },
                    "cache_translations": {
                        "type": "boolean",
                        "title": "Cache Translations",
                        "default": True,
                    },
                    "cache_duration_hours": {
                        "type": "integer",
                        "title": "Cache Duration (hours)",
                        "minimum": 1,
                        "default": 24,
                    },
                    "confidence_threshold": {
                        "type": "number",
                        "title": "Confidence Threshold",
                        "minimum": 0,
                        "maximum": 1,
                        "default": 0.7,
                    },
                    "rate_limit_per_hour": {
                        "type": "integer",
                        "title": "Rate Limit (per hour)",
                        "minimum": 1,
                        "default": 1000,
                    },
                    "batch_translation_enabled": {
                        "type": "boolean",
                        "title": "Enable Batch Translation",
                        "default": True,
                    },
                },
            },
            "notifications": {
                "title": "Smart Notifications",
                "description": "Configuration for smart notification features",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "title": "Enable Notifications",
                        "default": True,
                    },
                    "ai_analysis_enabled": {
                        "type": "boolean",
                        "title": "Enable AI Analysis",
                        "default": True,
                    },
                    "priority_adjustment": {
                        "type": "boolean",
                        "title": "Priority Adjustment",
                        "default": True,
                    },
                    "smart_scheduling": {
                        "type": "boolean",
                        "title": "Smart Scheduling",
                        "default": True,
                    },
                    "digest_notifications": {
                        "type": "boolean",
                        "title": "Digest Notifications",
                        "default": True,
                    },
                    "digest_frequency_hours": {
                        "type": "integer",
                        "title": "Digest Frequency (hours)",
                        "minimum": 1,
                        "default": 4,
                    },
                    "max_notifications_per_user": {
                        "type": "integer",
                        "title": "Max Notifications per User",
                        "minimum": 1,
                        "default": 1000,
                    },
                    "notification_retention_days": {
                        "type": "integer",
                        "title": "Retention (days)",
                        "minimum": 1,
                        "default": 30,
                    },
                    "push_notifications": {
                        "type": "boolean",
                        "title": "Push Notifications",
                        "default": True,
                    },
                    "email_notifications": {
                        "type": "boolean",
                        "title": "Email Notifications",
                        "default": True,
                    },
                    "sms_notifications": {
                        "type": "boolean",
                        "title": "SMS Notifications",
                        "default": False,
                    },
                    "quiet_hours_start": {
                        "type": "string",
                        "title": "Quiet Hours Start",
                        "pattern": "^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
                        "default": "22:00",
                    },
                    "quiet_hours_end": {
                        "type": "string",
                        "title": "Quiet Hours End",
                        "pattern": "^([01]?[0-9]|2[0-3]):[0-5][0-9]$",
                        "default": "08:00",
                    },
                    "weekend_quiet_mode": {
                        "type": "boolean",
                        "title": "Weekend Quiet Mode",
                        "default": False,
                    },
                },
            },
        }

    async def get_health_status(self) -> dict[str, Any]:
        """Get service health status."""
        base_health = await super().get_health_status()

        communication_health = {
            "voice_messages_count": len(self.voice_messages),
            "active_threads_count": len(
                [
                    t
                    for t in self.message_threads.values()
                    if t.status == ThreadStatus.ACTIVE
                ]
            ),
            "pending_translations": len(
                [t for t in self.translations.values() if t.translated_text is None]
            ),
            "unread_notifications": sum(
                len([n for n in notifications if not n.read])
                for notifications in self.notifications.values()
            ),
            "ai_manager_available": self.ai_manager is not None,
            "voice_storage_path": str(self.voice_storage_path),
            "supported_languages": len(self.supported_languages),
            "configuration_valid": len(await self.validate_configuration()) == 0,
            "features_enabled": {
                "voice_messages": self.config["voice_messages"]["enabled"],
                "reactions": self.config["reactions"]["enabled"],
                "threads": self.config["threads"]["enabled"],
                "translation": self.config["translation"]["enabled"],
                "notifications": self.config["notifications"]["enabled"],
                "ai_features": self.config["ai_features"]["enabled"],
            },
        }

        base_health.update(communication_health)
        return base_health


# Global service instance
_communication_service = None


async def get_communication_service() -> CommunicationService:
    """Get the global communication service instance."""
    global _communication_service

    if _communication_service is None:
        _communication_service = CommunicationService()
        if _communication_service and hasattr(_communication_service, "start"):
            await _communication_service.start()

    return _communication_service


__all__ = [
    "CommunicationService",
    "MessageReaction",
    "MessageThread",
    "MessageType",
    "NotificationPriority",
    "ReactionType",
    "SmartNotification",
    "ThreadStatus",
    "TranslationRequest",
    "VoiceMessage",
    "get_communication_service",
]
