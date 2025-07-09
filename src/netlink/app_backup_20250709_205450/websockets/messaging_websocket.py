"""
Real-time Messaging WebSocket Handler
Handles real-time messaging, reactions, and typing indicators with resilience features.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ValidationError

from netlink.app.services.enhanced_messaging_service import enhanced_messaging_service, EmojiService
from netlink.app.models.user import User
from netlink.app.logger_config import logger


class WebSocketMessage(BaseModel):
    """WebSocket message structure."""
    type: str
    data: Dict[str, Any]
    timestamp: Optional[datetime] = None


class TypingIndicator(BaseModel):
    """Typing indicator data."""
    user_id: int
    channel_id: Optional[int] = None
    guild_id: Optional[int] = None
    started_at: datetime
    expires_at: datetime


class MessagingWebSocketManager:
    """Manager for real-time messaging WebSocket connections."""
    
    def __init__(self):
        # Connection management
        self.active_connections: Dict[int, List[WebSocket]] = {}  # user_id -> websockets
        self.connection_info: Dict[WebSocket, Dict[str, Any]] = {}
        self.channel_subscriptions: Dict[int, Set[WebSocket]] = {}  # channel_id -> websockets
        self.guild_subscriptions: Dict[int, Set[WebSocket]] = {}  # guild_id -> websockets
        
        # Typing indicators
        self.typing_indicators: Dict[str, TypingIndicator] = {}  # key -> indicator
        self.typing_cleanup_task: Optional[asyncio.Task] = None
        
        # Message queue for offline users
        self.offline_message_queue: Dict[int, List[Dict[str, Any]]] = {}
        
        # Rate limiting
        self.rate_limits: Dict[int, List[datetime]] = {}
        
        # Start cleanup task
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start the cleanup task for expired typing indicators."""
        if self.typing_cleanup_task is None or self.typing_cleanup_task.done():
            self.typing_cleanup_task = asyncio.create_task(self._cleanup_typing_indicators())
    
    async def _cleanup_typing_indicators(self):
        """Clean up expired typing indicators."""
        while True:
            try:
                now = datetime.utcnow()
                expired_keys = [
                    key for key, indicator in self.typing_indicators.items()
                    if indicator.expires_at <= now
                ]
                
                for key in expired_keys:
                    indicator = self.typing_indicators.pop(key)
                    await self._broadcast_typing_stop(indicator)
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in typing indicator cleanup: {e}")
                await asyncio.sleep(10)
    
    async def connect(self, websocket: WebSocket, user: User):
        """Connect a user's WebSocket."""
        try:
            await websocket.accept()
            
            # Add to connections
            if user.id not in self.active_connections:
                self.active_connections[user.id] = []
            self.active_connections[user.id].append(websocket)
            
            # Store connection info
            self.connection_info[websocket] = {
                'user_id': user.id,
                'username': user.username,
                'connected_at': datetime.utcnow(),
                'is_admin': user.is_admin,
                'last_activity': datetime.utcnow()
            }
            
            # Send queued messages
            await self._send_queued_messages(user.id, websocket)
            
            # Send connection confirmation
            await self._send_to_websocket(websocket, {
                'type': 'connection_established',
                'data': {
                    'user_id': user.id,
                    'username': user.username,
                    'server_time': datetime.utcnow().isoformat()
                }
            })
            
            logger.info(f"WebSocket connected: user {user.username} ({user.id})")
            
        except Exception as e:
            logger.error(f"Failed to connect WebSocket for user {user.id}: {e}")
            await websocket.close()
    
    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket."""
        try:
            connection_info = self.connection_info.get(websocket)
            if not connection_info:
                return
            
            user_id = connection_info['user_id']
            
            # Remove from connections
            if user_id in self.active_connections:
                self.active_connections[user_id] = [
                    ws for ws in self.active_connections[user_id] if ws != websocket
                ]
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            
            # Remove from subscriptions
            for channel_subs in self.channel_subscriptions.values():
                channel_subs.discard(websocket)
            for guild_subs in self.guild_subscriptions.values():
                guild_subs.discard(websocket)
            
            # Remove connection info
            del self.connection_info[websocket]
            
            # Stop typing indicators
            await self._stop_user_typing(user_id)
            
            logger.info(f"WebSocket disconnected: user {connection_info.get('username')} ({user_id})")
            
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket: {e}")
    
    async def subscribe_to_channel(self, websocket: WebSocket, channel_id: int):
        """Subscribe WebSocket to a channel."""
        if channel_id not in self.channel_subscriptions:
            self.channel_subscriptions[channel_id] = set()
        self.channel_subscriptions[channel_id].add(websocket)
        
        await self._send_to_websocket(websocket, {
            'type': 'channel_subscribed',
            'data': {'channel_id': channel_id}
        })
    
    async def subscribe_to_guild(self, websocket: WebSocket, guild_id: int):
        """Subscribe WebSocket to a guild."""
        if guild_id not in self.guild_subscriptions:
            self.guild_subscriptions[guild_id] = set()
        self.guild_subscriptions[guild_id].add(websocket)
        
        await self._send_to_websocket(websocket, {
            'type': 'guild_subscribed',
            'data': {'guild_id': guild_id}
        })
    
    async def handle_message(self, websocket: WebSocket, message: str):
        """Handle incoming WebSocket message."""
        try:
            connection_info = self.connection_info.get(websocket)
            if not connection_info:
                return
            
            user_id = connection_info['user_id']
            
            # Update last activity
            connection_info['last_activity'] = datetime.utcnow()
            
            # Check rate limit
            if not await self._check_rate_limit(user_id):
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Rate limit exceeded'}
                })
                return
            
            # Parse message
            try:
                ws_message = json.loads(message)
                msg_type = ws_message.get('type')
                msg_data = ws_message.get('data', {})
            except json.JSONDecodeError:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Invalid JSON message'}
                })
                return
            
            # Handle different message types
            if msg_type == 'send_message':
                await self._handle_send_message(websocket, user_id, msg_data)
            elif msg_type == 'send_reply':
                await self._handle_send_reply(websocket, user_id, msg_data)
            elif msg_type == 'add_reaction':
                await self._handle_add_reaction(websocket, user_id, msg_data)
            elif msg_type == 'remove_reaction':
                await self._handle_remove_reaction(websocket, user_id, msg_data)
            elif msg_type == 'typing_start':
                await self._handle_typing_start(websocket, user_id, msg_data)
            elif msg_type == 'typing_stop':
                await self._handle_typing_stop(websocket, user_id, msg_data)
            elif msg_type == 'subscribe_channel':
                await self.subscribe_to_channel(websocket, msg_data.get('channel_id'))
            elif msg_type == 'subscribe_guild':
                await self.subscribe_to_guild(websocket, msg_data.get('guild_id'))
            elif msg_type == 'ping':
                await self._send_to_websocket(websocket, {
                    'type': 'pong',
                    'data': {'timestamp': datetime.utcnow().isoformat()}
                })
            else:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': f'Unknown message type: {msg_type}'}
                })
            
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
            await self._send_to_websocket(websocket, {
                'type': 'error',
                'data': {'message': 'Internal server error'}
            })
    
    async def _handle_send_message(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle send message request."""
        try:
            message = await enhanced_messaging_service.send_message(
                sender_id=user_id,
                content=data.get('content', ''),
                recipient_id=data.get('recipient_id'),
                channel_id=data.get('channel_id'),
                guild_id=data.get('guild_id'),
                metadata=data.get('metadata', {})
            )
            
            if message:
                # Broadcast to relevant subscribers
                await self._broadcast_message(message)
                
                # Send confirmation to sender
                await self._send_to_websocket(websocket, {
                    'type': 'message_sent',
                    'data': {
                        'message_id': message.id,
                        'timestamp': message.timestamp.isoformat()
                    }
                })
            else:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Failed to send message'}
                })
                
        except Exception as e:
            logger.error(f"Error sending message via WebSocket: {e}")
            await self._send_to_websocket(websocket, {
                'type': 'error',
                'data': {'message': 'Failed to send message'}
            })
    
    async def _handle_send_reply(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle send reply request."""
        try:
            reply = await enhanced_messaging_service.send_reply(
                sender_id=user_id,
                original_message_id=data.get('original_message_id'),
                content=data.get('content', ''),
                recipient_id=data.get('recipient_id'),
                channel_id=data.get('channel_id'),
                guild_id=data.get('guild_id')
            )
            
            if reply:
                # Broadcast to relevant subscribers
                await self._broadcast_message(reply)
                
                # Send confirmation to sender
                await self._send_to_websocket(websocket, {
                    'type': 'reply_sent',
                    'data': {
                        'message_id': reply.id,
                        'original_message_id': data.get('original_message_id'),
                        'timestamp': reply.timestamp.isoformat()
                    }
                })
            else:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Failed to send reply'}
                })
                
        except Exception as e:
            logger.error(f"Error sending reply via WebSocket: {e}")
            await self._send_to_websocket(websocket, {
                'type': 'error',
                'data': {'message': 'Failed to send reply'}
            })
    
    async def _handle_add_reaction(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle add reaction request."""
        try:
            success = await enhanced_messaging_service.add_reaction(
                message_id=data.get('message_id'),
                user_id=user_id,
                emoji=data.get('emoji')
            )
            
            if success:
                # Broadcast reaction to relevant subscribers
                await self._broadcast_reaction(
                    message_id=data.get('message_id'),
                    user_id=user_id,
                    emoji=data.get('emoji'),
                    action='add'
                )
                
                await self._send_to_websocket(websocket, {
                    'type': 'reaction_added',
                    'data': {
                        'message_id': data.get('message_id'),
                        'emoji': data.get('emoji')
                    }
                })
            else:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Failed to add reaction'}
                })
                
        except Exception as e:
            logger.error(f"Error adding reaction via WebSocket: {e}")
            await self._send_to_websocket(websocket, {
                'type': 'error',
                'data': {'message': 'Failed to add reaction'}
            })
    
    async def _handle_remove_reaction(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle remove reaction request."""
        try:
            success = await enhanced_messaging_service.remove_reaction(
                message_id=data.get('message_id'),
                user_id=user_id,
                emoji=data.get('emoji')
            )
            
            if success:
                # Broadcast reaction removal to relevant subscribers
                await self._broadcast_reaction(
                    message_id=data.get('message_id'),
                    user_id=user_id,
                    emoji=data.get('emoji'),
                    action='remove'
                )
                
                await self._send_to_websocket(websocket, {
                    'type': 'reaction_removed',
                    'data': {
                        'message_id': data.get('message_id'),
                        'emoji': data.get('emoji')
                    }
                })
            else:
                await self._send_to_websocket(websocket, {
                    'type': 'error',
                    'data': {'message': 'Failed to remove reaction'}
                })
                
        except Exception as e:
            logger.error(f"Error removing reaction via WebSocket: {e}")
            await self._send_to_websocket(websocket, {
                'type': 'error',
                'data': {'message': 'Failed to remove reaction'}
            })

    async def _handle_typing_start(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle typing start indicator."""
        try:
            channel_id = data.get('channel_id')
            guild_id = data.get('guild_id')

            # Create typing indicator
            key = f"{user_id}_{channel_id}_{guild_id}"
            now = datetime.utcnow()

            indicator = TypingIndicator(
                user_id=user_id,
                channel_id=channel_id,
                guild_id=guild_id,
                started_at=now,
                expires_at=now + timedelta(seconds=10)  # 10 second timeout
            )

            self.typing_indicators[key] = indicator

            # Broadcast typing indicator
            await self._broadcast_typing_start(indicator)

        except Exception as e:
            logger.error(f"Error handling typing start: {e}")

    async def _handle_typing_stop(self, websocket: WebSocket, user_id: int, data: Dict[str, Any]):
        """Handle typing stop indicator."""
        try:
            channel_id = data.get('channel_id')
            guild_id = data.get('guild_id')

            key = f"{user_id}_{channel_id}_{guild_id}"
            if key in self.typing_indicators:
                indicator = self.typing_indicators.pop(key)
                await self._broadcast_typing_stop(indicator)

        except Exception as e:
            logger.error(f"Error handling typing stop: {e}")

    async def _stop_user_typing(self, user_id: int):
        """Stop all typing indicators for a user."""
        try:
            keys_to_remove = [
                key for key in self.typing_indicators.keys()
                if key.startswith(f"{user_id}_")
            ]

            for key in keys_to_remove:
                indicator = self.typing_indicators.pop(key)
                await self._broadcast_typing_stop(indicator)

        except Exception as e:
            logger.error(f"Error stopping user typing: {e}")

    async def _broadcast_message(self, message):
        """Broadcast a message to relevant subscribers."""
        try:
            message_data = {
                'type': 'new_message',
                'data': {
                    'id': message.id,
                    'sender_id': message.sender_id,
                    'recipient_id': message.recipient_id,
                    'channel_id': message.channel_id,
                    'guild_id': message.guild_id,
                    'content': message.content,
                    'message_type': message.type.value if hasattr(message.type, 'value') else str(message.type),
                    'timestamp': message.timestamp.isoformat(),
                    'referenced_message_id': message.referenced_message_id,
                    'emoji_count': len(EmojiService.extract_emojis(message.content or "")),
                    'has_emoji': EmojiService.has_emoji(message.content or "")
                }
            }

            # Determine who should receive this message
            target_websockets = set()

            # Channel subscribers
            if message.channel_id and message.channel_id in self.channel_subscriptions:
                target_websockets.update(self.channel_subscriptions[message.channel_id])

            # Guild subscribers
            if message.guild_id and message.guild_id in self.guild_subscriptions:
                target_websockets.update(self.guild_subscriptions[message.guild_id])

            # Direct message participants
            if message.recipient_id:
                if message.sender_id in self.active_connections:
                    target_websockets.update(self.active_connections[message.sender_id])
                if message.recipient_id in self.active_connections:
                    target_websockets.update(self.active_connections[message.recipient_id])

            # Send to all target websockets
            for websocket in target_websockets:
                await self._send_to_websocket(websocket, message_data)

            # Queue for offline users
            if message.recipient_id and message.recipient_id not in self.active_connections:
                await self._queue_message_for_user(message.recipient_id, message_data)

        except Exception as e:
            logger.error(f"Error broadcasting message: {e}")

    async def _broadcast_reaction(self, message_id: int, user_id: int, emoji: str, action: str):
        """Broadcast a reaction update."""
        try:
            reaction_data = {
                'type': f'reaction_{action}',
                'data': {
                    'message_id': message_id,
                    'user_id': user_id,
                    'emoji': emoji,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }

            # Broadcast to all connected users (could be optimized to specific channels/guilds)
            for websockets in self.active_connections.values():
                for websocket in websockets:
                    await self._send_to_websocket(websocket, reaction_data)

        except Exception as e:
            logger.error(f"Error broadcasting reaction: {e}")

    async def _broadcast_typing_start(self, indicator: TypingIndicator):
        """Broadcast typing start indicator."""
        try:
            typing_data = {
                'type': 'typing_start',
                'data': {
                    'user_id': indicator.user_id,
                    'channel_id': indicator.channel_id,
                    'guild_id': indicator.guild_id,
                    'timestamp': indicator.started_at.isoformat()
                }
            }

            # Broadcast to channel/guild subscribers
            target_websockets = set()

            if indicator.channel_id and indicator.channel_id in self.channel_subscriptions:
                target_websockets.update(self.channel_subscriptions[indicator.channel_id])

            if indicator.guild_id and indicator.guild_id in self.guild_subscriptions:
                target_websockets.update(self.guild_subscriptions[indicator.guild_id])

            # Don't send to the typing user themselves
            user_websockets = self.active_connections.get(indicator.user_id, [])
            target_websockets = target_websockets - set(user_websockets)

            for websocket in target_websockets:
                await self._send_to_websocket(websocket, typing_data)

        except Exception as e:
            logger.error(f"Error broadcasting typing start: {e}")

    async def _broadcast_typing_stop(self, indicator: TypingIndicator):
        """Broadcast typing stop indicator."""
        try:
            typing_data = {
                'type': 'typing_stop',
                'data': {
                    'user_id': indicator.user_id,
                    'channel_id': indicator.channel_id,
                    'guild_id': indicator.guild_id,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }

            # Broadcast to channel/guild subscribers
            target_websockets = set()

            if indicator.channel_id and indicator.channel_id in self.channel_subscriptions:
                target_websockets.update(self.channel_subscriptions[indicator.channel_id])

            if indicator.guild_id and indicator.guild_id in self.guild_subscriptions:
                target_websockets.update(self.guild_subscriptions[indicator.guild_id])

            # Don't send to the typing user themselves
            user_websockets = self.active_connections.get(indicator.user_id, [])
            target_websockets = target_websockets - set(user_websockets)

            for websocket in target_websockets:
                await self._send_to_websocket(websocket, typing_data)

        except Exception as e:
            logger.error(f"Error broadcasting typing stop: {e}")

    async def _send_to_websocket(self, websocket: WebSocket, data: Dict[str, Any]):
        """Send data to a specific WebSocket."""
        try:
            await websocket.send_text(json.dumps(data))
        except Exception as e:
            logger.error(f"Error sending to WebSocket: {e}")
            # Connection might be closed, remove it
            await self.disconnect(websocket)

    async def _queue_message_for_user(self, user_id: int, message_data: Dict[str, Any]):
        """Queue a message for an offline user."""
        try:
            if user_id not in self.offline_message_queue:
                self.offline_message_queue[user_id] = []

            # Limit queue size
            if len(self.offline_message_queue[user_id]) >= 100:
                self.offline_message_queue[user_id].pop(0)

            self.offline_message_queue[user_id].append(message_data)

        except Exception as e:
            logger.error(f"Error queuing message for user {user_id}: {e}")

    async def _send_queued_messages(self, user_id: int, websocket: WebSocket):
        """Send queued messages to a newly connected user."""
        try:
            if user_id in self.offline_message_queue:
                messages = self.offline_message_queue.pop(user_id)

                for message_data in messages:
                    message_data['type'] = 'queued_message'
                    await self._send_to_websocket(websocket, message_data)

                if messages:
                    logger.info(f"Sent {len(messages)} queued messages to user {user_id}")

        except Exception as e:
            logger.error(f"Error sending queued messages to user {user_id}: {e}")

    async def _check_rate_limit(self, user_id: int) -> bool:
        """Check WebSocket rate limit for user."""
        try:
            now = datetime.utcnow()

            if user_id not in self.rate_limits:
                self.rate_limits[user_id] = []

            # Clean old entries (1 minute window)
            self.rate_limits[user_id] = [
                timestamp for timestamp in self.rate_limits[user_id]
                if now - timestamp < timedelta(minutes=1)
            ]

            # Check limit (120 messages per minute)
            if len(self.rate_limits[user_id]) >= 120:
                return False

            # Add current timestamp
            self.rate_limits[user_id].append(now)
            return True

        except Exception as e:
            logger.error(f"Rate limit check failed for user {user_id}: {e}")
            return True  # Allow on error

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics."""
        try:
            total_connections = sum(len(websockets) for websockets in self.active_connections.values())
            active_users = len(self.active_connections)
            typing_users = len(self.typing_indicators)
            queued_messages = sum(len(messages) for messages in self.offline_message_queue.values())

            return {
                'total_connections': total_connections,
                'active_users': active_users,
                'typing_users': typing_users,
                'queued_messages': queued_messages,
                'channel_subscriptions': len(self.channel_subscriptions),
                'guild_subscriptions': len(self.guild_subscriptions)
            }

        except Exception as e:
            logger.error(f"Error getting connection stats: {e}")
            return {}


# Global WebSocket manager instance
messaging_websocket_manager = MessagingWebSocketManager()
