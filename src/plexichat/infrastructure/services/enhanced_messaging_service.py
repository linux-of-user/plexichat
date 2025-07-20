# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import re
import unicodedata
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlmodel import Session, and_, or_, select


from datetime import datetime


from sqlalchemy import desc

from plexichat.app.db import engine
from plexichat.app.logger_config import logger
from plexichat.app.models.guild import Emoji
from plexichat.app.models.message import Message, MessageReaction, MessageType
import time

# Import unified cache integration
try:
    from plexichat.core.caching.unified_cache_integration import ()
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

class EmojiService:
    """Service for handling emoji operations."""

    # Unicode emoji patterns and mappings
    UNICODE_EMOJI_PATTERN = re.compile()
        r'[\U0001F600-\U0001F64F]|'  # emoticons
        r'[\U0001F300-\U0001F5FF]|'  # symbols & pictographs
        r'[\U0001F680-\U0001F6FF]|'  # transport & map symbols
        r'[\U0001F1E0-\U0001F1FF]|'  # flags (iOS)
        r'[\U00002702-\U000027B0]|'  # dingbats
        r'[\U000024C2-\U0001F251]'   # enclosed characters
    )

    # Common emoji shortcodes
    EMOJI_SHORTCODES = {
        ':smile:': '',
        ':grin:': '',
        ':joy:': '',
        ':heart:': '',
        ':thumbsup:': '',
        ':thumbsdown:': '',
        ':fire:': '',
        ':star:': '',
        ':check:': '',
        ':x:': '',
        ':warning:': '',
        ':info:': '',
        ':question:': '',
        ':exclamation:': '',
        ':wave:': '',
        ':clap:': '',
        ':pray:': '',
        ':rocket:': '',
        ':tada:': '',
        ':confetti:': '',
        ':100:': '',
        ':ok:': '',
        ':peace:': '',
        ':love:': '',
        ':kiss:': '',
        ':hug:': '',
        ':thinking:': '',
        ':shrug:': '',
        ':facepalm:': '',
        ':eyes:': '',
        ':brain:': '',
        ':muscle:': '',
        ':coffee:': '',
        ':pizza:': '',
        ':beer:': '',
        ':wine:': '',
        ':cake:': '',
        ':gift:': '',
        ':balloon:': '',
        ':party:': '',
        ':music:': '',
        ':game:': '',
        ':book:': '',
        ':computer:': '',
        ':phone:': '',
        ':camera:': '',
        ':lock:': '',
        ':key:': '',
        ':shield:': '',
        ':sword:': '',
        ':bow:': '',
        ':crown:': '',
        ':gem:': '',
        ':money:': '',
        ':coin:': '',
        ':house:': '',
        ':car:': '',
        ':plane:': '',
        ':ship:': '',
        ':train:': '',
        ':bike:': '',
        ':sun:': '',
        ':moon:': '',
        ':star2:': '',
        ':cloud:': '',
        ':rain:': '',
        ':snow:': '',
        ':lightning:': '',
        ':rainbow:': '',
        ':tree:': '',
        ':flower:': '',
        ':rose:': '',
        ':tulip:': '',
        ':sunflower:': '',
        ':cactus:': '',
        ':palm:': '',
        ':leaves:': '',
        ':herb:': '',
        ':four_leaf_clover:': '',
        ':mushroom:': '',
        ':earth:': '',
        ':globe:': '',
        ':mountain:': '',
        ':volcano:': '',
        ':desert:': '',
        ':beach:': '',
        ':island:': '',
        ':ocean:': '',
        ':droplet:': '',
        ':snowflake:': '',
        ':ice:': '',
        ':crystal:': '',
        ':diamond:': '',
        ':ring:': '',
        ':crown2:': '',
        ':trophy:': '',
        ':medal:': '',
        ':ribbon:': '',
        ':gift2:': '',
        ':balloon2:': '',
        ':confetti2:': '',
        ':fireworks:': '',
        ':sparkler:': '',
        ':sparkles:': ''
    }

    @classmethod
    def process_emoji_shortcodes(cls, text: str) -> str:
        """Convert emoji shortcodes to Unicode emoji."""
        for shortcode, emoji in cls.EMOJI_SHORTCODES.items():
            text = text.replace(shortcode, emoji)
        return text

    @classmethod
    def extract_emojis(cls, text: str) -> List[str]:
        """Extract all emojis from text."""
        return cls.UNICODE_EMOJI_PATTERN.findall(text)

    @classmethod
    def has_emoji(cls, text: str) -> bool:
        """Check if text contains emoji."""
        return bool(cls.UNICODE_EMOJI_PATTERN.search(text))

    @classmethod
    def get_emoji_name(cls, emoji: str) -> str:
        """Get the Unicode name of an emoji."""
        try:
            return unicodedata.name(emoji, f"EMOJI_{ord(emoji):04X}")
        except (ValueError, TypeError):
            return "UNKNOWN_EMOJI"

    @classmethod
    async def get_custom_emojis(cls, guild_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get custom emojis for a guild."""
        with Session(engine) as session:
            query = select(Emoji).where(Emoji.available)
            if guild_id:
                query = query.where(Emoji.guild_id == guild_id)

            emojis = session.exec(query).all()
            return [
                {
                    "id": emoji.id,
                    "name": emoji.name,
                    "animated": emoji.animated,
                    "image": emoji.image,
                    "guild_id": emoji.guild_id
                }
                for emoji in emojis
            ]

    @classmethod
    async def add_custom_emoji(cls, guild_id: int, name: str, image: str,)
                             user_id: int, animated: bool = False) -> Optional[Emoji]:
        """Add a custom emoji to a guild."""
        try:
            with Session(engine) as session:
                emoji = Emoji()
                    guild_id=guild_id,
                    name=name,
                    image=image,
                    user_id=user_id,
                    animated=animated,
                    available=True
                )
                session.add(emoji)
                session.commit()
                session.refresh(emoji)
                return emoji
        except Exception as e:
            logger.error(f"Failed to add custom emoji: {e}")
            return None


class ReactionService:
    """Service for handling message reactions."""

    @classmethod
    async def add_reaction(cls, message_id: int, user_id: int, emoji: str,)
                          emoji_id: Optional[int] = None) -> bool:
        """Add a reaction to a message."""
        try:
            with Session(engine) as session:
                # Check if reaction already exists
                existing = session.exec()
                    select(MessageReaction).where()
                        and_()
                            MessageReaction.message_id == message_id,
                            MessageReaction.user_id == user_id,
                            or_()
                                MessageReaction.emoji == emoji,
                                MessageReaction.emoji_id == emoji_id
                            )
                        )
                    )
                ).first()

                if existing:
                    return False  # Already reacted

                # Add new reaction
                reaction = MessageReaction()
                    message_id=message_id,
                    user_id=user_id,
                    emoji=emoji,
                    emoji_id=emoji_id,
                    emoji_name=EmojiService.get_emoji_name(emoji) if not emoji_id else None
                )
                session.add(reaction)
                session.commit()
                return True

        except Exception as e:
            logger.error(f"Failed to add reaction: {e}")
            return False

    @classmethod
    async def remove_reaction(cls, message_id: int, user_id: int, emoji: str,)
                            emoji_id: Optional[int] = None) -> bool:
        """Remove a reaction from a message."""
        try:
            with Session(engine) as session:
                reaction = session.exec()
                    select(MessageReaction).where()
                        and_()
                            MessageReaction.message_id == message_id,
                            MessageReaction.user_id == user_id,
                            or_()
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
                reactions = session.exec()
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
    async def create_reply(cls, original_message_id: int, reply_content: str,)
                          sender_id: int, **kwargs) -> Optional[Message]:
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
                replies = session.exec()
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
        self.emoji_service = EmojiService()
        self.reaction_service = ReactionService()
        self.reply_service = ReplyService()
        # Using unified cache instead of local cache
        self.rate_limits = {}  # Rate limiting storage

    async def send_message(self, sender_id: int, content: str, **kwargs) -> Optional[Message]:
        """Send a message with emoji processing and resilience."""
        try:
            # Process emoji shortcodes
            processed_content = self.emoji_service.process_emoji_shortcodes(content)

            # Check rate limits
            if not await self._check_rate_limit(sender_id):
                raise Exception("Rate limit exceeded")

            with Session(engine) as session:
                message = Message(
                    sender_id=sender_id,
                    recipient_id=kwargs.get('recipient_id'),
                    channel_id=kwargs.get('channel_id'),
                    guild_id=kwargs.get('guild_id'),
                    content=processed_content,
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

    async def send_reply(self, sender_id: int, original_message_id: int,)
                        content: str, **kwargs) -> Optional[Message]:
        """Send a reply to a message."""
        try:
            # Process emoji shortcodes
            processed_content = self.emoji_service.process_emoji_shortcodes(content)

            # Check rate limits
            if not await self._check_rate_limit(sender_id):
                raise Exception("Rate limit exceeded")

            reply = await self.reply_service.create_reply()
                original_message_id=original_message_id,
                reply_content=processed_content,
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
                    "emoji_count": len(self.emoji_service.extract_emojis(message.content or "")),
                    "has_emoji": self.emoji_service.has_emoji(message.content or "")
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
        """Search messages with text search and emoji filtering."""
        try:
            with Session(engine) as session:
                search_query = select(Message).where()
                    and_()
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
            logger.error(f"Failed to search messages: {e}")
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

                # Process emoji shortcodes
                processed_content = self.emoji_service.process_emoji_shortcodes(new_content)

                # Update message
                message.content = processed_content
                message.from datetime import datetime
edited_timestamp = datetime.now()
datetime.utcnow()
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

    async def get_emoji_statistics(self, **filters) -> Dict[str, Any]:
        """Get emoji usage statistics."""
        try:
            with Session(engine) as session:
                query = select(Message).where(not Message.is_deleted)

                # Apply filters
                if filters.get('channel_id'):
                    query = query.where(Message.channel_id == filters['channel_id'])
                if filters.get('guild_id'):
                    query = query.where(Message.guild_id == filters['guild_id'])
                if filters.get('days'):
since = datetime.now()
datetime.utcnow() - timedelta(days=filters['days'])
                    query = query.where(Message.timestamp >= since)

                messages = session.exec(query).all()

                # Count emojis
                emoji_counts = {}
                total_messages = len(messages)
                messages_with_emoji = 0

                for message in messages:
                    if message.content:
                        emojis = self.emoji_service.extract_emojis(message.content)
                        if emojis:
                            messages_with_emoji += 1
                            for emoji in emojis:
                                emoji_counts[emoji] = emoji_counts.get(emoji, 0) + 1

                # Sort by usage
                top_emojis = sorted(emoji_counts.items(), key=lambda x: x[1], reverse=True)[:20]

                return {
                    "total_messages": total_messages,
                    "messages_with_emoji": messages_with_emoji,
                    "emoji_usage_rate": messages_with_emoji / total_messages if total_messages > 0 else 0,
                    "unique_emojis": len(emoji_counts),
                    "total_emoji_uses": sum(emoji_counts.values()),
                    "top_emojis": [{"emoji": emoji, "count": count} for emoji, count in top_emojis]
                }

        except Exception as e:
            logger.error(f"Failed to get emoji statistics: {e}")
            return {}


# Global service instance
enhanced_messaging_service = EnhancedMessagingService()
