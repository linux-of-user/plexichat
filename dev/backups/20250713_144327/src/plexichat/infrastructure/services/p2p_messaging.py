import asyncio
import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet


from plexichat.core.logging import logger

"""
Peer-to-peer messaging service with database fallback.
Enables messaging when database is unavailable using server as proxy.
"""


@dataclass
class P2PMessage:
    """Peer-to-peer message structure."""

    id: str
    sender_id: int
    recipient_id: int
    content: str
    timestamp: datetime
    message_type: str = "text"
    encrypted: bool = True
    signature: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "P2PMessage":
        """Create from dictionary."""
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class PeerConnection:
    """Peer connection information."""

    peer_id: int
    connection_id: str
    websocket: Any
    last_seen: datetime
    is_online: bool = True
    message_queue: List[P2PMessage] = None

    def __post_init__(self):
        if self.message_queue is None:
            self.message_queue = []


class MessageCache:
    """Secure message cache for offline storage."""

    def __init__(self):
        self.cache: Dict[str, P2PMessage] = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.max_cache_size = 10000
        self.cache_file = "data/p2p_message_cache.json"

    def add_message(self, message: P2PMessage) -> bool:
        """Add message to cache."""
        try:
            if len(self.cache) >= self.max_cache_size:
                self._cleanup_old_messages()

            self.cache[message.id] = message
            self._save_to_disk()

            logger.info(f" Cached P2P message {message.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cache message: {e}")
            return False

    def get_messages_for_user(self, user_id: int) -> List[P2PMessage]:
        """Get cached messages for a user."""
        return [
            msg
            for msg in self.cache.values()
            if msg.recipient_id == user_id or msg.sender_id == user_id
        ]

    def remove_message(self, message_id: str) -> bool:
        """Remove message from cache."""
        if message_id in self.cache:
            del self.cache[message_id]
            self._save_to_disk()
            return True
        return False

    def get_pending_database_sync(self) -> List[P2PMessage]:
        """Get messages pending database synchronization."""
        return list(self.cache.values())

    def clear_synced_messages(self, message_ids: List[str]):
        """Clear messages that have been synced to database."""
        for msg_id in message_ids:
            self.cache.pop(msg_id, None)
        self._save_to_disk()

    def _cleanup_old_messages(self):
        """Remove oldest messages when cache is full."""
        sorted_messages = sorted(self.cache.items(), key=lambda x: x[1].timestamp)

        # Remove oldest 20%
        remove_count = len(sorted_messages) // 5
        for i in range(remove_count):
            del self.cache[sorted_messages[i][0]]

    def _save_to_disk(self):
        """Save cache to encrypted file."""
        try:
            cache_data = {msg_id: msg.to_dict() for msg_id, msg in self.cache.items()}

            json_data = json.dumps(cache_data).encode()
            encrypted_data = self.cipher.encrypt(json_data)

            with open(self.cache_file, "wb") as f:
                f.write(encrypted_data)

        except Exception as e:
            logger.error(f"Failed to save cache to disk: {e}")

    def _load_from_disk(self):
        """Load cache from encrypted file."""
        try:
            with open(self.cache_file, "rb") as f:
                encrypted_data = f.read()

            json_data = self.cipher.decrypt(encrypted_data)
            cache_data = json.loads(json_data.decode())

            self.cache = {
                msg_id: P2PMessage.from_dict(msg_data)
                for msg_id, msg_data in cache_data.items()
            }

            logger.info(f" Loaded {len(self.cache)} cached messages")

        except FileNotFoundError:
            logger.info("No existing cache file found")
        except Exception as e:
            logger.error(f"Failed to load cache from disk: {e}")


class P2PMessagingService:
    """Peer-to-peer messaging service with database fallback."""

    def __init__(self):
        self.peers: Dict[int, PeerConnection] = {}
        self.message_cache = MessageCache()
        self.database_available = True
        self.sync_interval = 30  # seconds
        self.message_encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.message_encryption_key)

        # Load cached messages
        self.message_cache._load_from_disk()

        # Start background tasks
        asyncio.create_task(self._periodic_database_sync())
        asyncio.create_task(self._peer_health_check())

    async def connect_peer(self, user_id: int, websocket: Any) -> str:
        """Connect a peer to the P2P network."""
        try:
            connection_id = f"p2p_{user_id}_{secrets.token_urlsafe(8)}"

            peer_connection = PeerConnection(
                peer_id=user_id,
                connection_id=connection_id,
                websocket=websocket,
                last_seen=datetime.now(timezone.utc),
            )

            self.peers[user_id] = peer_connection

            # Send queued messages
            await self._send_queued_messages(user_id)

            logger.info(f" Peer {user_id} connected to P2P network")

            return connection_id

        except Exception as e:
            logger.error(f"Failed to connect peer {user_id}: {e}")
            raise

    async def disconnect_peer(self, user_id: int):
        """Disconnect a peer from the P2P network."""
        if user_id in self.peers:
            del self.peers[user_id]
            logger.info(f" Peer {user_id} disconnected from P2P network")

    async def send_message(
        self,
        sender_id: int,
        recipient_id: int,
        content: str,
        message_type: str = "text",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> P2PMessage:
        """Send a peer-to-peer message."""
        try:
            # Create message
            message = P2PMessage(
                id=f"p2p_{secrets.token_urlsafe(16)}",
                sender_id=sender_id,
                recipient_id=recipient_id,
                content=content,
                timestamp=datetime.now(timezone.utc),
                message_type=message_type,
                metadata=metadata or {},
            )

            # Encrypt content
            if message.encrypted:
                message.content = self._encrypt_content(content)

            # Add signature
            message.signature = self._sign_message(message)

            # Try to send directly to peer
            if recipient_id in self.peers and self.peers[recipient_id].is_online:
                success = await self._send_direct_message(message)
                if success:
                    logger.info(f" Sent P2P message directly to peer {recipient_id}")
                else:
                    # Queue for later delivery
                    self.peers[recipient_id].message_queue.append(message)
                    logger.info(f" Queued P2P message for peer {recipient_id}")
            else:
                # Peer offline, cache message
                self.message_cache.add_message(message)
                logger.info(f" Cached P2P message for offline peer {recipient_id}")

            # Try to save to database if available
            if self.database_available:
                await self._save_to_database(message)
            else:
                # Cache for later database sync
                self.message_cache.add_message(message)
                logger.info(f" Cached message for database sync: {message.id}")

            return message

        except Exception as e:
            logger.error(f"Failed to send P2P message: {e}")
            raise

    async def get_messages(
        self, user_id: int, other_user_id: Optional[int] = None, limit: int = 50
    ) -> List[P2PMessage]:
        """Get messages for a user (from cache and database)."""
        try:
            messages = []

            # Get from cache
            cached_messages = self.message_cache.get_messages_for_user(user_id)
            if other_user_id:
                cached_messages = [
                    msg
                    for msg in cached_messages
                    if (msg.sender_id == other_user_id and msg.recipient_id == user_id)
                    or (msg.sender_id == user_id and msg.recipient_id == other_user_id)
                ]

            messages.extend(cached_messages)

            # Get from database if available
            if self.database_available:
                db_messages = await self._get_from_database(
                    user_id, other_user_id, limit
                )
                messages.extend(db_messages)

            # Sort by timestamp and limit
            messages.sort(key=lambda x: x.timestamp, reverse=True)
            return messages[:limit]

        except Exception as e:
            logger.error(f"Failed to get messages for user {user_id}: {e}")
            return []

    async def _send_direct_message(self, message: P2PMessage) -> bool:
        """Send message directly to connected peer."""
        try:
            recipient = self.peers.get(message.recipient_id)
            if not recipient or not recipient.is_online:
                return False

            message_data = {"type": "p2p_message", "message": message.to_dict()}

            await recipient.websocket.send_text(json.dumps(message_data))
            return True

        except Exception as e:
            logger.error(f"Failed to send direct message: {e}")
            return False

    async def _send_queued_messages(self, user_id: int):
        """Send queued messages to newly connected peer."""
        try:
            peer = self.peers.get(user_id)
            if not peer:
                return

            # Send queued messages
            for message in peer.message_queue[:]:
                success = await self._send_direct_message(message)
                if success:
                    peer.message_queue.remove(message)

            # Send cached messages for this user
            cached_messages = self.message_cache.get_messages_for_user(user_id)
            for message in cached_messages:
                if message.recipient_id == user_id:
                    await self._send_direct_message(message)

        except Exception as e:
            logger.error(f"Failed to send queued messages to {user_id}: {e}")

    async def _periodic_database_sync(self):
        """Periodically sync cached messages to database."""
        while True:
            try:
                await asyncio.sleep(self.sync_interval)

                if self.database_available:
                    pending_messages = self.message_cache.get_pending_database_sync()

                    if pending_messages:
                        logger.info(
                            f" Syncing {len(pending_messages)} messages to database"
                        )

                        synced_ids = []
                        for message in pending_messages:
                            success = await self._save_to_database(message)
                            if success:
                                synced_ids.append(message.id)

                        # Clear synced messages from cache
                        self.message_cache.clear_synced_messages(synced_ids)

                        logger.info(f" Synced {len(synced_ids)} messages to database")

            except Exception as e:
                logger.error(f"Database sync error: {e}")

    async def _peer_health_check(self):
        """Check peer connection health."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute

                current_time = datetime.now(timezone.utc)
                offline_peers = []

                for user_id, peer in self.peers.items():
                    # Check if peer is still responsive
                    time_since_last_seen = (
                        current_time - peer.last_seen
                    ).total_seconds()

                    if time_since_last_seen > 300:  # 5 minutes
                        peer.is_online = False
                        offline_peers.append(user_id)

                # Clean up offline peers
                for user_id in offline_peers:
                    await self.disconnect_peer(user_id)

                if offline_peers:
                    logger.info(f" Cleaned up {len(offline_peers)} offline peers")

            except Exception as e:
                logger.error(f"Peer health check error: {e}")

    def _encrypt_content(self, content: str) -> str:
        """Encrypt message content."""
        try:
            encrypted_bytes = self.cipher.encrypt(content.encode())
            return base64.b64encode(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt content: {e}")
            return content

    def _decrypt_content(self, encrypted_content: str) -> str:
        """Decrypt message content."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_content.encode())
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt content: {e}")
            return encrypted_content

    def _sign_message(self, message: P2PMessage) -> str:
        """Create message signature for integrity verification."""
        try:
            message_data = f"{message.id}{message.sender_id}{message.recipient_id}{message.content}{message.timestamp.isoformat()}"
            signature = hashlib.sha256(message_data.encode()).hexdigest()
            return signature
        except Exception as e:
            logger.error(f"Failed to sign message: {e}")
            return ""

    def _verify_signature(self, message: P2PMessage) -> bool:
        """Verify message signature."""
        try:
            expected_signature = self._sign_message(message)
            return message.signature == expected_signature
        except Exception as e:
            logger.error(f"Failed to verify signature: {e}")
            return False

    async def _save_to_database(self, message: P2PMessage) -> bool:
        """Save message to database (placeholder)."""
        try:
            # In production, this would save to actual database
            logger.debug(f" Saved message {message.id} to database")
            return True
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")
            self.database_available = False
            return False

    async def _get_from_database(
        self, user_id: int, other_user_id: Optional[int], limit: int
    ) -> List[P2PMessage]:
        """Get messages from database (placeholder)."""
        try:
            # In production, this would query actual database
            return []
        except Exception as e:
            logger.error(f"Failed to get from database: {e}")
            self.database_available = False
            return []

    def set_database_status(self, available: bool):
        """Set database availability status."""
        self.database_available = available
        if available:
            logger.info(" Database connection restored")
        else:
            logger.warning(" Database unavailable, using P2P mode")

    def get_network_status(self) -> Dict[str, Any]:
        """Get P2P network status."""
        return {
            "connected_peers": len(self.peers),
            "online_peers": sum(1 for p in self.peers.values() if p.is_online),
            "cached_messages": len(self.message_cache.cache),
            "database_available": self.database_available,
            "total_queued_messages": sum(
                len(p.message_queue) for p in self.peers.values()
            ),
        }


# Global service instance
p2p_messaging_service = P2PMessagingService()
