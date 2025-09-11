# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlmodel import Session, and_, or_, select

from plexichat.core.database import get_engine
from plexichat.core.logging import get_logger
from plexichat.shared.models import Message, MessageReaction, MessageType

engine = get_engine()
logger = get_logger(__name__)

# Import unified cache integration
try:
    from plexichat.core.caching.unified_cache_integration import (
        cache_get, cache_set, cache_delete, CacheKeyBuilder
    )
    CACHE_AVAILABLE = True
except ImportError:
    # Fallback if cache not available
    async def cache_get(key: str, default=None): return default
    async def cache_set(key: str, value, ttl=None): return True
    async def cache_delete(key: str): return True
    class CacheKeyBuilder:
        @staticmethod
        def message_key(msg_id: str, suffix: str = ""): return f"msg:{msg_id}:{suffix}"
    CACHE_AVAILABLE = False

"""
Enhanced Messaging Service
Comprehensive messaging service with emoji support, replies, reactions, and resilience features.
"""

class ReactionService:
    """Service for handling message reactions."""
    @classmethod
    async def add_reaction(cls, message_id: int, user_id: int, emoji: str, emoji_id: Optional[int] = None) -> bool:
        """Add a reaction to a message."""
        try:
            with Session(engine) as session:
                # Check if reaction already exists
                existing = session.exec(
                    select(MessageReaction).where(
                        and_(
                            MessageReaction.message_id == message_id,
                            MessageReaction.user_id == user_id,
                            or_(
                                MessageReaction.emoji == emoji,
                                MessageReaction.emoji_id == emoji_id
                            )
                        )
                    )
                ).first()

                if existing:
                    return False  # Already reacted

                # Add new reaction
                reaction = MessageReaction(
                    message_id=message_id,
                    user_id=user_id,
                    emoji=emoji,
                    emoji_id=emoji_id,
                    emoji_name=None # EmojiService removed
                )
                session.add(reaction)
                session.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to add reaction: {e}")
            return False

    @classmethod
    async def remove_reaction(cls, message_id: int, user_id: int, emoji: str, emoji_id: Optional[int] = None) -> bool:
        """Remove a reaction from a message."""
        try:
            with Session(engine) as session:
                reaction = session.exec(
                    select(MessageReaction).where(
                        and_(
                            MessageReaction.message_id == message_id,
                            MessageReaction.user_id == user_id,
                            or_(
                                MessageReaction.emoji == emoji,
                                MessageReaction.emoji_id == emoji_id
                            )
                        )
                    )
                ).first()

                if reaction:
                    session.delete(reaction)
                    session.commit()
                    return True
                return False

        except Exception as e:
            logger.error(f"Failed to remove reaction: {e}")
            return False

    @classmethod
    async def get_message_reactions(cls, message_id: int) -> List[Dict[str, Any]]:
        """Get all reactions for a message."""
        try:
            with Session(engine) as session:
                reactions = session.exec(
                    select(MessageReaction).where(MessageReaction.message_id == message_id)
                ).all()

                # Group reactions by emoji
                reaction_groups = {}
                for reaction in reactions:
                    key = reaction.emoji or f"custom_{reaction.emoji_id}"
                    if key not in reaction_groups:
                        reaction_groups[key] = {
                            "emoji": reaction.emoji,
                            "emoji_id": reaction.emoji_id,
                            "emoji_name": reaction.emoji_name,
                            "count": 0,
                            "users": []
                        }
                    reaction_groups[key]["count"] += 1
                    reaction_groups[key]["users"].append(reaction.user_id)

                return list(reaction_groups.values())

        except Exception as e:
            logger.error(f"Failed to get message reactions: {e}")
            return []


class ReplyService:
    """Service for handling message replies."""
    @classmethod
    async def create_reply(cls, original_message_id: int, reply_content: str, sender_id: int, **kwargs) -> Optional[Message]:
        """Create a reply to a message."""
        try:
            with Session(engine) as session:
                # Get original message
                original_message = session.get(Message, original_message_id)
                if not original_message:
                    return None

                # Create reply message
                reply_message = Message(
                    sender_id=sender_id,
                    recipient_id=kwargs.get('recipient_id', original_message.sender_id),
                    channel_id=kwargs.get('channel_id', original_message.channel_id),
                    guild_id=kwargs.get('guild_id', original_message.guild_id),
                    content=reply_content,
                    type=kwargs.get('message_type', MessageType.REPLY),
                    referenced_message_id=original_message_id,
                    message_reference={
                        "message_id": original_message_id,
                        "channel_id": original_message.channel_id,
                        "guild_id": original_message.guild_id
                    }
                )

                session.add(reply_message)
                session.commit()
                session.refresh(reply_message)
                return reply_message

        except Exception as e:
            logger.error(f"Failed to create reply: {e}")
            return None

    @classmethod
    async def get_message_replies(cls, message_id: int, limit: int = 50) -> List[Message]:
        """Get replies to a message."""
        try:
            with Session(engine) as session:
                replies = session.exec(
                    select(Message)
                    .where(Message.referenced_message_id == message_id)
                    .order_by(Message.timestamp)
                    .limit(limit)
                ).all()
                return list(replies)

        except Exception as e:
            logger.error(f"Failed to get message replies: {e}")
            return []


class EnhancedMessagingService:
    """Enhanced messaging service with comprehensive features."""
    def __init__(self):
        self.reaction_service = ReactionService()
        self.reply_service = ReplyService()
        self.message_cache = {}
        self.rate_limits = {}  # Rate limiting storage

    async def send_message(self, sender_id: int, content: str, **kwargs) -> Optional[Message]:
        """Send a message with emoji processing and resilience."""
        try:
            # Check rate limits
            if not await self._check_rate_limit(sender_id):
                raise Exception("Rate limit exceeded")

            with Session(engine) as session:
                message = Message(
                    sender_id=sender_id,
                    recipient_id=kwargs.get('recipient_id'),
                    channel_id=kwargs.get('channel_id'),
                    guild_id=kwargs.get('guild_id'),
                    content=content,
                    type=kwargs.get('message_type', MessageType.DEFAULT),
                    metadata=kwargs.get('metadata', {}),
                    is_system=kwargs.get('is_system', False)
                )

                session.add(message)
                session.commit()
                session.refresh(message)

                # Cache the message
                self.message_cache[message.id] = message

                logger.info(f"Message {message.id} sent by user {sender_id}")
                return message

        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return None

    async def send_reply(self, sender_id: int, original_message_id: int, content: str, **kwargs) -> Optional[Message]:
        """Send a reply to a message."""
        try:
            # Check rate limits
            if not await self._check_rate_limit(sender_id):
                raise Exception("Rate limit exceeded")

            reply = await self.reply_service.create_reply(
                original_message_id=original_message_id,
                reply_content=content,
                sender_id=sender_id,
                **kwargs
            )

            if reply:
                self.message_cache[reply.id] = reply
                logger.info(f"Reply {reply.id} sent by user {sender_id} to message {original_message_id}")

            return reply

        except Exception as e:
            logger.error(f"Failed to send reply: {e}")
            return None

    async def add_reaction(self, message_id: int, user_id: int, emoji: str) -> bool:
        """Add a reaction to a message."""
        try:
            # Check rate limits
            if not await self._check_rate_limit(user_id, action="reaction"):
                return False

            return await self.reaction_service.add_reaction(message_id, user_id, emoji)

        except Exception as e:
            logger.error(f"Failed to add reaction: {e}")
            return False

    async def remove_reaction(self, message_id: int, user_id: int, emoji: str) -> bool:
        """Remove a reaction from a message."""
        return await self.reaction_service.remove_reaction(message_id, user_id, emoji)

    async def get_messages(self, **filters) -> List[Message]:
        """Get messages with filters and caching."""
        try:
            with Session(engine) as session:
                query = select(Message).where(not Message.is_deleted)

                # Apply filters
                if filters.get('channel_id'):
                    query = query.where(Message.channel_id == filters['channel_id'])
                if filters.get('guild_id'):
                    query = query.where(Message.guild_id == filters['guild_id'])
                if filters.get('sender_id'):
                    query = query.where(Message.sender_id == filters['sender_id'])
                if filters.get('recipient_id'):
                    query = query.where(Message.recipient_id == filters['recipient_id'])

                # Ordering and limiting
                query = query.order_by(desc(Message.timestamp))
                if filters.get('limit'):
                    query = query.limit(filters['limit'])

                messages = session.exec(query).all()
                return list(messages)

        except Exception as e:
            logger.error(f"Failed to get messages: {e}")
            return []

    async def get_message_with_context(self, message_id: int) -> Dict[str, Any]:
        """Get a message with its reactions, replies, and context."""
        try:
            with Session(engine) as session:
                message = session.get(Message, message_id)
                if not message:
                    return {}

                # Get reactions
                reactions = await self.reaction_service.get_message_reactions(message_id)

                # Get replies
                replies = await self.reply_service.get_message_replies(message_id)

                # Get referenced message if this is a reply
                referenced_message = None
                if message.referenced_message_id:
                    referenced_message = session.get(Message, message.referenced_message_id)

                return {
                    "message": message,
                    "reactions": reactions,
                    "replies": replies,
                    "referenced_message": referenced_message,
                    "emoji_count": 0, # EmojiService removed
                    "has_emoji": False # EmojiService removed
                }

        except Exception as e:
            logger.error(f"Failed to get message context: {e}")
            return {}

    async def _check_rate_limit(self, user_id: int, action: str = "message") -> bool:
        """Check if user is within rate limits."""
        try:
            now = datetime.now()
            key = f"{user_id}_{action}"

            if key not in self.rate_limits:
                self.rate_limits[key] = []

            # Clean old entries
            self.rate_limits[key] = [
                timestamp for timestamp in self.rate_limits[key]
                if now - timestamp < timedelta(minutes=1)
            ]

            # Check limits (configurable)
            limits = {
                "message": 60,  # 60 messages per minute
                "reaction": 100  # 100 reactions per minute
            }

            if len(self.rate_limits[key]) >= limits.get(action, 60):
                return False

            # Add current timestamp
            self.rate_limits[key].append(now)
            return True

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow on error


    async def search_messages(self, query: str, **filters) -> List[Message]:
        """Search messages using advanced search service."""
        try:
            # Import here to avoid circular imports
            from plexichat.core.search_service import get_search_service, SearchFilter

            search_service = await get_search_service()

            # Convert filters to SearchFilter
            search_filters = SearchFilter(
                query=query,
                user_id=filters.get('sender_id'),
                channel_id=filters.get('channel_id'),
                date_from=filters.get('date_from'),
                date_to=filters.get('date_to'),
                message_type=filters.get('message_type'),
                has_attachments=filters.get('has_attachments'),
                limit=filters.get('limit', 50),
                offset=filters.get('offset', 0)
            )

            # Perform search
            results, _ = await search_service.search_messages(search_filters, filters.get('user_id', 'system'))

            # Convert SearchResult back to Message objects
            messages = []
            with Session(engine) as session:
                for result in results:
                    message = session.get(Message, result.message_id)
                    if message:
                        messages.append(message)

            return messages

        except Exception as e:
            logger.error(f"Failed to search messages: {e}")
            # Fallback to basic search if advanced search fails
            return await self._basic_search_messages(query, **filters)

    async def _basic_search_messages(self, query: str, **filters) -> List[Message]:
        """Fallback basic search implementation."""
        try:
            with Session(engine) as session:
                search_query = select(Message).where(
                    and_(
                        not Message.is_deleted,
                        Message.content.contains(query)
                    )
                )

                # Apply additional filters
                if filters.get('channel_id'):
                    search_query = search_query.where(Message.channel_id == filters['channel_id'])
                if filters.get('guild_id'):
                    search_query = search_query.where(Message.guild_id == filters['guild_id'])
                if filters.get('sender_id'):
                    search_query = search_query.where(Message.sender_id == filters['sender_id'])
                if filters.get('has_emoji'):
                    # This would need a more sophisticated implementation
                    pass

                search_query = search_query.order_by(desc(Message.timestamp))
                if filters.get('limit'):
                    search_query = search_query.limit(filters['limit'])

                messages = session.exec(search_query).all()
                return list(messages)

        except Exception as e:
            logger.error(f"Failed to perform basic search: {e}")
            return []

    async def delete_message(self, message_id: int, user_id: int, force: bool = False) -> bool:
        """Delete a message (soft delete by default)."""
        try:
            with Session(engine) as session:
                message = session.get(Message, message_id)
                if not message:
                    return False

                # Check permissions (message owner or admin)
                if message.sender_id != user_id and not force:
                    return False

                if force:
                    # Hard delete
                    session.delete(message)
                else:
                    # Soft delete
                    message.is_deleted = True
                    message.content = "[Message deleted]"

                session.commit()

                # Remove from cache
                if message_id in self.message_cache:
                    del self.message_cache[message_id]

                logger.info(f"Message {message_id} deleted by user {user_id}")
                return True

        except Exception as e:
            logger.error(f"Failed to delete message: {e}")
            return False

    async def edit_message(self, message_id: int, user_id: int, new_content: str) -> Optional[Message]:
        """Edit a message."""
        try:
            with Session(engine) as session:
                message = session.get(Message, message_id)
                if not message or message.sender_id != user_id:
                    return None

                # Update message
                message.content = new_content
                message.edited_timestamp = datetime.now()
                message.is_edited = True

                session.commit()
                session.refresh(message)

                # Update cache
                self.message_cache[message_id] = message

                logger.info(f"Message {message_id} edited by user {user_id}")
                return message

        except Exception as e:
            logger.error(f"Failed to edit message: {e}")
            return None


# Global service instance
enhanced_messaging_service = EnhancedMessagingService()
