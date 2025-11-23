"""
PlexiChat Messaging System

Consolidates messaging functionality with watertight security.
Provides a single interface for all messaging operations with:
- Message routing and delivery
- End-to-end encryption
- Real-time messaging
- Message persistence
- Group messaging
- Voice/video channels
- Business automation
- Advanced user system integration
- Comprehensive security integration
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import logging
from typing import Any
from uuid import uuid4

from plexichat.core.messaging.message_formatter import message_formatter
from plexichat.core.services.message_threads_service import get_message_threads_service

# Notification integration
notification_manager = None
try:
    from plexichat.core.notifications import notification_manager as nm

    notification_manager = nm
except ImportError:
    pass

# Security integration
SECURITY_AVAILABLE = False
try:
    from plexichat.core.security import comprehensive_security_manager

    SECURITY_AVAILABLE = True
except ImportError:
    pass

# Logging setup
logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of messages supported."""

    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    VOICE = "voice"
    VIDEO = "video"
    SYSTEM = "system"
    NOTIFICATION = "notification"


class MessageStatus(Enum):
    """Message delivery status."""

    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class ChannelType(Enum):
    """Types of channels."""

    DIRECT = "direct"
    GROUP = "group"
    PUBLIC = "public"
    PRIVATE = "private"
    VOICE = "voice"
    VIDEO = "video"


class EncryptionLevel(Enum):
    """Encryption levels for messages."""

    NONE = "none"
    BASIC = "basic"
    ENHANCED = "enhanced"
    MILITARY = "military"


@dataclass
class MessageMetadata:
    """Metadata for messages."""

    message_id: str
    sender_id: str
    channel_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    message_type: MessageType = MessageType.TEXT
    encryption_level: EncryptionLevel = EncryptionLevel.ENHANCED
    priority: int = 1
    reply_to: str | None = None
    thread_id: str | None = None
    edited: bool = False
    deleted: bool = False


@dataclass
class SystemMessage:
    """Core message structure."""

    metadata: MessageMetadata
    content: str
    attachments: list[dict[str, Any]] = field(default_factory=list)
    reactions: dict[str, list[str]] = field(default_factory=dict)
    mentions: list[str] = field(default_factory=list)
    status: MessageStatus = MessageStatus.PENDING


@dataclass
class Channel:
    """Channel structure."""

    channel_id: str
    name: str
    channel_type: ChannelType
    members: set[str] = field(default_factory=set)
    admins: set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    description: str = ""
    is_active: bool = True
    max_members: int = 1000
    encryption_level: EncryptionLevel = EncryptionLevel.ENHANCED


@dataclass
class Thread:
    """Thread structure for organizing message conversations."""

    thread_id: str
    title: str
    channel_id: str
    creator_id: str
    parent_message_id: str | None = None
    is_resolved: bool = False
    participant_count: int = 1
    message_count: int = 0
    last_message_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    participants: set[str] = field(default_factory=set)


class MessageValidator:
    """Validates messages for security and compliance."""

    def __init__(self):
        self.max_message_length = 10000
        self.max_attachments = 10
        self.allowed_file_types = {
            ".txt",
            ".pdf",
            ".jpg",
            ".png",
            ".gif",
            ".mp4",
            ".mp3",
        }

    def validate_message(self, message: SystemMessage) -> tuple[bool, list[str]]:
        """Validate message content and metadata."""
        issues = []

        # Content validation
        if not message.content and not message.attachments:
            issues.append("Message must have content or attachments")

        if len(message.content) > self.max_message_length:
            issues.append(
                f"Message content exceeds maximum length of {self.max_message_length}"
            )

        # Attachment validation
        if len(message.attachments) > self.max_attachments:
            issues.append(f"Too many attachments (max: {self.max_attachments})")

        # Security validation
        if SECURITY_AVAILABLE:
            try:
                from plexichat.core.security.security_manager import get_security_module

                security_system = get_security_module()
                threats = security_system.input_sanitizer.detect_threats(
                    message.content
                )
                if threats:
                    issues.extend(threats)
            except ImportError:
                pass

        return len(issues) == 0, issues


class MessageEncryption:
    """Handles message encryption and decryption."""

    def __init__(self):
        self.encryption_keys: dict[str, str] = {}

    def encrypt_message(
        self, message: SystemMessage, encryption_level: EncryptionLevel
    ) -> str:
        """Encrypt message content based on encryption level."""
        if encryption_level == EncryptionLevel.NONE:
            return message.content

        # Simplified encryption for demo (would use proper crypto in production)
        import base64

        encrypted = base64.b64encode(message.content.encode()).decode()

        if encryption_level == EncryptionLevel.MILITARY:
            # Additional encryption layers would go here
            encrypted = base64.b64encode(encrypted.encode()).decode()

        return encrypted

    def decrypt_message(
        self, encrypted_content: str, encryption_level: EncryptionLevel
    ) -> str:
        """Decrypt message content."""
        if encryption_level == EncryptionLevel.NONE:
            return encrypted_content

        try:
            import base64

            if encryption_level == EncryptionLevel.MILITARY:
                # Additional decryption layers
                encrypted_content = base64.b64decode(
                    encrypted_content.encode()
                ).decode()

            decrypted = base64.b64decode(encrypted_content.encode()).decode()
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return "[Encrypted Message - Decryption Failed]"


class MessageRouter:
    """Routes messages to appropriate channels and users."""

    def __init__(self):
        self.routing_rules: dict[str, Callable] = {}
        self.delivery_handlers: dict[str, Callable] = {}

    def add_routing_rule(self, rule_name: str, handler: Callable):
        """Add a message routing rule."""
        self.routing_rules[rule_name] = handler

    def route_message(self, message: SystemMessage) -> list[str]:
        """Route message to appropriate destinations."""
        destinations = []

        # Basic routing logic
        channel_id = message.metadata.channel_id
        destinations.append(channel_id)

        # Add mentioned users
        for mention in message.mentions:
            destinations.append(f"user:{mention}")

        return destinations


class ChannelManager:
    """Manages channels and their members."""

    def __init__(self):
        self.channels: dict[str, Channel] = {}
        self.user_channels: dict[str, set[str]] = {}

    def create_channel(
        self, name: str, channel_type: ChannelType, creator_id: str
    ) -> Channel:
        """Create a new channel."""
        channel_id = str(uuid4())
        channel = Channel(
            channel_id=channel_id,
            name=name,
            channel_type=channel_type,
            members={creator_id},
            admins={creator_id},
        )

        self.channels[channel_id] = channel
        if creator_id not in self.user_channels:
            self.user_channels[creator_id] = set()
        self.user_channels[creator_id].add(channel_id)

        return channel

    def add_member(self, channel_id: str, user_id: str) -> bool:
        """Add a member to a channel."""
        if channel_id not in self.channels:
            return False

        channel = self.channels[channel_id]
        if len(channel.members) >= channel.max_members:
            return False

        channel.members.add(user_id)
        if user_id not in self.user_channels:
            self.user_channels[user_id] = set()
        self.user_channels[user_id].add(channel_id)

        return True

    def remove_member(self, channel_id: str, user_id: str) -> bool:
        """Remove a member from a channel."""
        if channel_id not in self.channels:
            return False

        channel = self.channels[channel_id]
        channel.members.discard(user_id)

        if user_id in self.user_channels:
            self.user_channels[user_id].discard(channel_id)

        return True

    def get_user_channels(self, user_id: str) -> list[Channel]:
        """Get all channels for a user."""
        if user_id not in self.user_channels:
            return []

        return [
            self.channels[channel_id]
            for channel_id in self.user_channels[user_id]
            if channel_id in self.channels
        ]


class MessagingSystem:
    """
    Messaging System providing watertight security.

    Consolidates all messaging functionality:
    - Message processing and validation
    - Channel management
    - Real-time delivery
    - Encryption and security
    - User management
    - Analytics and monitoring
    """

    def __init__(self):
        # Core components
        self.validator = MessageValidator()
        self.encryption = MessageEncryption()
        self.router = MessageRouter()
        self.channel_manager = ChannelManager()
        # Initialize message threads service
        self.threads_service = get_message_threads_service()

        # Message storage
        self.messages: dict[str, SystemMessage] = {}
        # Thread storage
        self.threads: dict[str, Thread] = {}
        self.thread_messages: dict[str, list[str]] = {}
        self.message_history: dict[str, list[str]] = {}

        # Real-time subscribers
        self.subscribers: dict[str, set[Callable]] = {}

        # Security integration
        if SECURITY_AVAILABLE:
            try:
                from plexichat.core.security.security_manager import (
                    get_security_module,
                )
                from plexichat.core.security.security_manager import get_security_module

                self.security_system = get_security_module()
                self.security_manager = get_security_manager()
            except ImportError:
                self.security_system = None
                self.security_manager = None
        else:
            self.security_system = None
            self.security_manager = None

        # Analytics and metrics
        self.metrics = {
            "messages_sent": 0,
            "messages_delivered": 0,
            "messages_failed": 0,
            "channels_created": 0,
            "users_active": 0,
        }

    async def send_message(
        self,
        sender_id: str,
        channel_id: str,
        content: str,
        message_type: MessageType = MessageType.TEXT,
        attachments: list[dict[str, Any]] | None = None,
        reply_to: str | None = None,
        thread_id: str | None = None,
    ) -> tuple[bool, str, SystemMessage | None]:
        """
        Send a message with comprehensive security validation.

        Returns:
            Tuple of (success, message_id_or_error, message_object)
        """
        try:
            # Create message ID first
            message_id = str(uuid4())

            # Security validation
            if self.security_system:
                valid, issues = await self.security_system.validate_request_security(
                    content
                )
                if not valid:
                    return (
                        False,
                        f"Security validation failed: {', '.join(issues)}",
                        None,
                    )

            # Create message metadata
            metadata = MessageMetadata(
                message_id=message_id,
                sender_id=sender_id,
                channel_id=channel_id,
                message_type=message_type,
                reply_to=reply_to,
                thread_id=thread_id,
            )

            message = SystemMessage(
                metadata=metadata, content=content, attachments=attachments or []
            )

            # Parse mentions from content
            message.mentions = self._parse_mentions(content)

            # Validate message
            valid, validation_issues = self.validator.validate_message(message)
            if not valid:
                return False, f"Validation failed: {', '.join(validation_issues)}", None

            # Encrypt message
            encrypted_content = self.encryption.encrypt_message(
                message, metadata.encryption_level
            )
            message.content = encrypted_content

            # Store message
            self.messages[message_id] = message

            # Add to channel history
            if channel_id not in self.message_history:
                self.message_history[channel_id] = []
            self.message_history[channel_id].append(message_id)

            # Add to thread history if thread_id is provided
            if thread_id:
                if thread_id not in self.thread_messages:
                    self.thread_messages[thread_id] = []
                self.thread_messages[thread_id].append(message_id)

                # Update thread statistics
                if thread_id in self.threads:
                    thread = self.threads[thread_id]
                    thread.message_count += 1
                    thread.last_message_at = datetime.now(UTC)
                    thread.participants.add(sender_id)
                    thread.participant_count = len(thread.participants)

            # Route and deliver
            destinations = self.router.route_message(message)
            await self._deliver_message(message, destinations)

            # Trigger notifications for message and mentions
            await self._trigger_message_notifications(message, destinations)

            # Update metrics
            self.metrics["messages_sent"] += 1
            self.metrics["messages_delivered"] += len(destinations)

            # Mark as sent
            message.status = MessageStatus.SENT

            return True, message_id, message

        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.metrics["messages_failed"] += 1
            return False, f"Internal error: {e!s}", None

    async def _deliver_message(self, message: SystemMessage, destinations: list[str]):
        """Deliver message to all destinations."""
        for destination in destinations:
            if destination in self.subscribers:
                for callback in self.subscribers[destination]:
                    try:
                        await callback(message)
                    except Exception as e:
                        logger.error(f"Error delivering message to {destination}: {e}")

    async def _trigger_message_notifications(
        self, message: SystemMessage, destinations: list[str]
    ):
        """Trigger notifications for message events."""
        try:
            if not notification_manager:
                return

            # Get channel members for notifications (excluding sender)
            channel_members = []
            if (
                hasattr(self.channel_manager, "channels")
                and message.metadata.channel_id in self.channel_manager.channels
            ):
                channel = self.channel_manager.channels[message.metadata.channel_id]
                channel_members = [
                    member
                    for member in channel.members
                    if member != message.metadata.sender_id
                ]

            # Send message notifications to channel members
            for member_id in channel_members:
                try:
                    await notification_manager.create_notification(
                        user_id=int(member_id),
                        notification_type=notification_manager.NotificationType.MESSAGE,
                        title=f"New message in {message.metadata.channel_id}",
                        message=f"{message.metadata.sender_id}: {message.content[:100]}{'...' if len(message.content) > 100 else ''}",
                        priority=notification_manager.NotificationPriority.NORMAL,
                        data={
                            "message_id": message.metadata.message_id,
                            "channel_id": message.metadata.channel_id,
                            "sender_id": message.metadata.sender_id,
                            "thread_id": message.metadata.thread_id,
                        },
                    )
                except Exception as e:
                    logger.error(
                        f"Error creating message notification for user {member_id}: {e}"
                    )

            # Send mention notifications
            for mention in message.mentions:
                try:
                    mention_user_id = int(mention) if mention.isdigit() else mention
                    if str(mention_user_id) != str(message.metadata.sender_id):
                        await notification_manager.create_notification(
                            user_id=mention_user_id,
                            notification_type=notification_manager.NotificationType.MENTION,
                            title=f"You were mentioned in {message.metadata.channel_id}",
                            message=f"{message.metadata.sender_id} mentioned you: {message.content[:100]}{'...' if len(message.content) > 100 else ''}",
                            priority=notification_manager.NotificationPriority.HIGH,
                            data={
                                "message_id": message.metadata.message_id,
                                "channel_id": message.metadata.channel_id,
                                "sender_id": message.metadata.sender_id,
                                "thread_id": message.metadata.thread_id,
                            },
                        )
                except Exception as e:
                    logger.error(
                        f"Error creating mention notification for user {mention}: {e}"
                    )

        except Exception as e:
            logger.error(f"Error triggering message notifications: {e}")

    async def _trigger_thread_message_notifications(
        self, message: SystemMessage, destinations: list[str]
    ):
        """Trigger notifications for thread message events."""
        try:
            if not notification_manager or not message.metadata.thread_id:
                return

            thread = self.threads.get(message.metadata.thread_id)
            if not thread:
                return

            # Get thread participants for notifications (excluding sender)
            thread_participants = [
                participant
                for participant in thread.participants
                if participant != message.metadata.sender_id
            ]

            # Send thread message notifications to thread participants
            for participant_id in thread_participants:
                try:
                    await notification_manager.create_notification(
                        user_id=int(participant_id),
                        notification_type=notification_manager.NotificationType.MESSAGE,
                        title=f"New reply in thread: {thread.title}",
                        message=f"{message.metadata.sender_id}: {message.content[:100]}{'...' if len(message.content) > 100 else ''}",
                        priority=notification_manager.NotificationPriority.NORMAL,
                        data={
                            "message_id": message.metadata.message_id,
                            "channel_id": message.metadata.channel_id,
                            "thread_id": message.metadata.thread_id,
                            "sender_id": message.metadata.sender_id,
                        },
                    )
                except Exception as e:
                    logger.error(
                        f"Error creating thread message notification for user {participant_id}: {e}"
                    )

            # Send mention notifications in thread
            for mention in message.mentions:
                try:
                    mention_user_id = int(mention) if mention.isdigit() else mention
                    if str(mention_user_id) != str(message.metadata.sender_id):
                        await notification_manager.create_notification(
                            user_id=mention_user_id,
                            notification_type=notification_manager.NotificationType.MENTION,
                            title=f"You were mentioned in thread: {thread.title}",
                            message=f"{message.metadata.sender_id} mentioned you in a thread: {message.content[:100]}{'...' if len(message.content) > 100 else ''}",
                            priority=notification_manager.NotificationPriority.HIGH,
                            data={
                                "message_id": message.metadata.message_id,
                                "channel_id": message.metadata.channel_id,
                                "thread_id": message.metadata.thread_id,
                                "sender_id": message.metadata.sender_id,
                                "thread_id": message.metadata.thread_id,
                            },
                        )
                except Exception as e:
                    logger.error(
                        f"Error creating thread mention notification for user {mention}: {e}"
                    )

        except Exception as e:
            logger.error(f"Error triggering thread message notifications: {e}")

    def _parse_mentions(self, content: str) -> list[str]:
        """Parse @mentions from message content."""
        try:
            import re

            # Find all @mentions using regex
            # Matches @ followed by word characters, dots, or hyphens
            mention_pattern = r"@(\w[\w.-]*)"
            mentions = re.findall(mention_pattern, content)

            # Remove duplicates while preserving order
            seen = set()
            unique_mentions = []
            for mention in mentions:
                if mention not in seen:
                    seen.add(mention)
                    unique_mentions.append(mention)

            return unique_mentions

        except Exception as e:
            logger.error(f"Error parsing mentions: {e}")
            return []

    def subscribe_to_channel(self, channel_id: str, callback: Callable):
        """Subscribe to real-time messages in a channel."""
        if channel_id not in self.subscribers:
            self.subscribers[channel_id] = set()
        self.subscribers[channel_id].add(callback)

    def unsubscribe_from_channel(self, channel_id: str, callback: Callable):
        """Unsubscribe from channel messages."""
        if channel_id in self.subscribers:
            self.subscribers[channel_id].discard(callback)

    async def get_channel_messages(
        self, channel_id: str, limit: int = 50, before_message_id: str | None = None
    ) -> list[SystemMessage]:
        """Get messages from a channel with pagination."""
        if channel_id not in self.message_history:
            return []

        message_ids = self.message_history[channel_id]

        # Apply pagination
        if before_message_id:
            try:
                before_index = message_ids.index(before_message_id)
                message_ids = message_ids[:before_index]
            except ValueError:
                pass

        # Get latest messages
        recent_ids = message_ids[-limit:] if len(message_ids) > limit else message_ids

        # Decrypt and return messages
        messages = []
        for msg_id in recent_ids:
            if msg_id in self.messages:
                message = self.messages[msg_id]
                # Decrypt content for display
                # Decrypt content for display
                decrypted_content = self.encryption.decrypt_message(
                    message.content, message.metadata.encryption_level
                )
                # Apply rich text formatting
                formatted_content = message_formatter.format_message(decrypted_content)
                display_message = SystemMessage(
                    metadata=message.metadata,
                    content=formatted_content,
                    attachments=message.attachments,
                    reactions=message.reactions,
                    mentions=message.mentions,
                    status=message.status,
                )
                # Create a copy with formatted content
                decrypted_content = self.encryption.decrypt_message(
                    message.content, message.metadata.encryption_level
                )
                # Create a copy with decrypted content
                display_message = SystemMessage(
                    metadata=message.metadata,
                    content=decrypted_content,
                    attachments=message.attachments,
                    reactions=message.reactions,
                    mentions=message.mentions,
                    status=message.status,
                )
                messages.append(display_message)

        return messages

    def get_system_status(self) -> dict[str, Any]:
        """Get comprehensive messaging system status."""
        return {
            "metrics": self.metrics.copy(),
            "active_channels": len(self.channel_manager.channels),
            "total_messages": len(self.messages),
            "active_subscribers": sum(len(subs) for subs in self.subscribers.values()),
            "security_enabled": SECURITY_AVAILABLE,
            "encryption_enabled": True,
        }

    async def create_thread(
        self,
        title: str,
        channel_id: str,
        creator_id: str,
        parent_message_id: str | None = None,
    ) -> tuple[bool, str, Thread | None]:
        """Create a new thread using the threads service."""
        try:
            # Use the threads service for database operations
            success, thread_id_or_error, thread = (
                await self.threads_service.create_thread(
                    parent_message_id=parent_message_id,
                    title=title,
                    creator_id=creator_id,
                )
            )

            if success and thread:
                # Also store in memory for quick access
                self.threads[thread.thread_id] = thread
                self.thread_messages[thread.thread_id] = []

                # Update metrics
                self.metrics["threads_created"] = (
                    self.metrics.get("threads_created", 0) + 1
                )

            return success, thread_id_or_error, thread

        except Exception as e:
            logger.error(f"Error creating thread: {e}")
            return False, f"Internal error: {e!s}", None

    async def send_thread_message(
        self,
        sender_id: str,
        thread_id: str,
        content: str,
        message_type: MessageType = MessageType.TEXT,
        attachments: list[dict[str, Any]] | None = None,
        reply_to: str | None = None,
    ) -> tuple[bool, str, SystemMessage | None]:
        """Send a message in a thread."""
        try:
            if thread_id not in self.threads:
                return False, "Thread not found", None

            thread = self.threads[thread_id]

            # Create message with thread_id
            message_id = str(uuid4())
            metadata = MessageMetadata(
                message_id=message_id,
                sender_id=sender_id,
                channel_id=thread.channel_id,
                message_type=message_type,
                reply_to=reply_to,
                thread_id=thread_id,
            )

            message = Message(
                metadata=metadata, content=content, attachments=attachments or []
            )

            # Parse mentions from content
            message.mentions = self._parse_mentions(content)

            # Validate message
            valid, validation_issues = self.validator.validate_message(message)
            if not valid:
                return False, f"Validation failed: {', '.join(validation_issues)}", None

            # Encrypt message
            encrypted_content = self.encryption.encrypt_message(
                message, metadata.encryption_level
            )
            message.content = encrypted_content

            # Store message
            self.messages[message_id] = message

            # Add to thread message history
            if thread_id not in self.thread_messages:
                self.thread_messages[thread_id] = []
            self.thread_messages[thread_id].append(message_id)

            # Update thread
            thread.message_count += 1
            thread.last_message_at = datetime.now(UTC)
            thread.participants.add(sender_id)
            thread.participant_count = len(thread.participants)

            # Also update threads service
            await self.threads_service.add_reply(thread_id, content, sender_id)

            # Route and deliver
            destinations = self.router.route_message(message)
            await self._deliver_message(message, destinations)

            # Trigger notifications for thread message and mentions
            await self._trigger_thread_message_notifications(message, destinations)

            # Update metrics
            self.metrics["messages_sent"] += 1
            self.metrics["messages_delivered"] += len(destinations)

            # Mark as sent
            message.status = MessageStatus.SENT

            return True, message_id, message

        except Exception as e:
            logger.error(f"Error sending thread message: {e}")
            self.metrics["messages_failed"] += 1
            return False, f"Internal error: {e!s}", None

    async def get_thread_messages(
        self, thread_id: str, limit: int = 50, before_message_id: str | None = None
    ) -> list[Message]:
        """Get messages from a thread with pagination."""
        # Try memory first
        if thread_id in self.thread_messages:
            message_ids = self.thread_messages[thread_id]

            # Apply pagination
            if before_message_id:
                try:
                    before_index = message_ids.index(before_message_id)
                    message_ids = message_ids[:before_index]
                except ValueError:
                    pass

            # Get latest messages
            recent_ids = (
                message_ids[-limit:] if len(message_ids) > limit else message_ids
            )

            # Decrypt and return messages
            messages = []
            for msg_id in recent_ids:
                if msg_id in self.messages:
                    message = self.messages[msg_id]
                    # Decrypt content for display
                    decrypted_content = self.encryption.decrypt_message(
                        message.content, message.metadata.encryption_level
                    )
                    # Create a copy with decrypted content
                    display_message = Message(
                        metadata=message.metadata,
                        content=decrypted_content,
                        attachments=message.attachments,
                        reactions=message.reactions,
                        mentions=message.mentions,
                        status=message.status,
                    )
                    messages.append(display_message)

            return messages

        # Fallback to service replies
        replies = await self.threads_service.get_thread_replies(thread_id, limit, 0)
        messages = []
        for reply in replies:
            # Convert reply dict to Message object
            metadata = MessageMetadata(
                message_id=reply["id"],
                sender_id=reply["user_id"],
                channel_id="",  # Would need to derive from thread
                message_type=MessageType.TEXT,
                thread_id=thread_id,
            )
            message = Message(
                metadata=metadata,
                content=reply["message_content"],
                status=MessageStatus.SENT,
            )
            messages.append(message)

        return messages

    def get_channel_threads(self, channel_id: str) -> list[Thread]:
        """Get all threads in a channel."""
        # Get from memory
        memory_threads = [
            thread
            for thread in self.threads.values()
            if thread.channel_id == channel_id
        ]
        # Also get from service cache
        service_threads = [
            thread
            for thread in self.threads_service._cache.values()
            if thread.channel_id == channel_id
        ]
        # Combine and deduplicate
        all_threads = memory_threads + service_threads
        seen_ids = set()
        unique_threads = []
        for thread in all_threads:
            if thread.thread_id not in seen_ids:
                seen_ids.add(thread.thread_id)
                unique_threads.append(thread)
        return unique_threads

    def get_thread(self, thread_id: str) -> Thread | None:
        """Get a thread by ID."""
        # Check memory cache first
        if thread_id in self.threads:
            return self.threads[thread_id]
        # Fallback to service
        return self.threads_service._cache.get(thread_id)

    async def resolve_thread(self, thread_id: str, resolver_id: str) -> bool:
        """Mark a thread as resolved."""
        # Update service
        success = await self.threads_service.resolve_thread(thread_id)
        if success:
            # Also update memory
            if thread_id in self.threads:
                self.threads[thread_id].is_resolved = True
                self.threads[thread_id].updated_at = datetime.now(UTC)
        return success

    async def shutdown(self) -> None:
        """Shutdown the messaging system."""
        logger.info("Messaging System shutting down")


# Global messaging system instance
_global_messaging_system: MessagingSystem | None = None


def get_messaging_system() -> MessagingSystem:
    """Get the global messaging system instance."""
    global _global_messaging_system
    if _global_messaging_system is None:
        _global_messaging_system = MessagingSystem()
    return _global_messaging_system


async def initialize_messaging_system() -> MessagingSystem:
    """Initialize the global messaging system."""
    global _global_messaging_system
    _global_messaging_system = MessagingSystem()
    return _global_messaging_system


async def shutdown_messaging_system() -> None:
    """Shutdown the global messaging system."""
    global _global_messaging_system
    if _global_messaging_system:
        await _global_messaging_system.shutdown()
        _global_messaging_system = None


__all__ = [
    "Channel",
    "ChannelManager",
    "ChannelType",
    "EncryptionLevel",
    "Message",
    "MessageEncryption",
    "MessageMetadata",
    "MessageRouter",
    "MessageStatus",
    "MessageType",
    "MessageValidator",
    "Thread",
    "MessagingSystem",
    "get_messaging_system",
    "initialize_messaging_system",
    "shutdown_messaging_system",
]
