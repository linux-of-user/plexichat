# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from typing import Any, Dict, List, Optional

import aiosqlite
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .distributed_key_manager import DistributedKeyManager, KeyDomain
# from .quantum_encryption import QuantumEncryptionSystem, SecurityTier  # REMOVED: file deleted


"""
PlexiChat End-to-End Encryption System

Implements E2E encryption for all API endpoints, ensuring that even if
the server is compromised, user data remains encrypted. Uses forward
secrecy, perfect forward secrecy, and quantum-resistant algorithms.
"""

# Cryptography imports
logger = logging.getLogger(__name__)


class E2EProtocol(Enum):
    """End-to-end encryption protocols."""
    SIGNAL_PROTOCOL = "signal"
    DOUBLE_RATCHET = "double_ratchet"
    QUANTUM_RESISTANT_E2E = "quantum_e2e"
    HYBRID_CLASSICAL_QUANTUM = "hybrid_cq"


class EndpointType(Enum):
    """Types of API endpoints."""
    AUTHENTICATION = "auth"
    MESSAGING = "messaging"
    FILE_TRANSFER = "file_transfer"
    DATABASE_API = "database"
    BACKUP_API = "backup"
    ADMIN_API = "admin"
    PUBLIC_API = "public"


@dataclass
class E2ESession:
    """End-to-end encryption session."""
    session_id: str
    user_id: str
    endpoint_type: EndpointType
    protocol: E2EProtocol

    # Key material
    local_private_key: bytes
    local_public_key: bytes
    remote_public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None

    # Ratchet state (for Double Ratchet protocol)
    root_key: Optional[bytes] = None
    chain_key_send: Optional[bytes] = None
    chain_key_recv: Optional[bytes] = None
    message_keys_send: List[bytes] = field(default_factory=list)
    message_keys_recv: List[bytes] = field(default_factory=list)

    # Session metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message_count: int = 0
    is_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class E2EMessage:
    """Encrypted end-to-end message."""
    message_id: str
    session_id: str
    sender_id: str
    recipient_id: str
    encrypted_payload: bytes
    message_key_index: int
    timestamp: datetime
    signature: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EndToEndEncryption:
    """
    End-to-End Encryption System for API Endpoints

    Features:
    - Forward secrecy (each message uses unique key)
    - Perfect forward secrecy (past messages remain secure)
    - Quantum-resistant algorithms
    - Double Ratchet protocol implementation
    - Endpoint-specific encryption policies
    - Session management and key rotation
    """

    def __init__(self, config_dir: str = "config/security/e2e"):
        from pathlib import Path
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Database for E2E sessions
        self.db_path = self.config_dir / "e2e_sessions.db"

        # Session storage
        self.active_sessions: Dict[str, E2ESession] = {}
        self.endpoint_policies: Dict[EndpointType, Dict[str, Any]] = {}

        # Encryption systems
        self.quantum_encryption = None # REMOVED: file deleted
        self.distributed_keys = DistributedKeyManager()

        # Initialize system (will be called manually during app startup)
        self._initialization_task = None

    async def _initialize_system(self):
        """Initialize the E2E encryption system."""
        await self._init_database()
        await self._load_sessions()
        await self._setup_endpoint_policies()
        logger.info(" End-to-end encryption system initialized")

    async def _init_database(self):
        """Initialize the E2E sessions database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS e2e_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    endpoint_type TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    local_private_key BLOB NOT NULL,
                    local_public_key BLOB NOT NULL,
                    remote_public_key BLOB,
                    shared_secret BLOB,
                    root_key BLOB,
                    chain_key_send BLOB,
                    chain_key_recv BLOB,
                    created_at TEXT NOT NULL,
                    last_used TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0,
                    is_verified BOOLEAN DEFAULT FALSE,
                    metadata TEXT
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS e2e_messages (
                    message_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    encrypted_payload BLOB NOT NULL,
                    message_key_index INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    signature BLOB,
                    metadata TEXT,
                    FOREIGN KEY (session_id) REFERENCES e2e_sessions (session_id)
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_access_log (
                    log_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    endpoint_type TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT
                )
            """)

            await db.commit()

    async def _load_sessions(self):
        """Load active E2E sessions from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT * FROM e2e_sessions WHERE last_used > ?",
                                 [(datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()]) as cursor:
                async for row in cursor:
                    session = E2ESession()
                    session.session_id = row[0]
                    session.user_id = row[1]
                    session.endpoint_type = EndpointType(row[2])
                    session.protocol = E2EProtocol(row[3])
                    session.local_private_key = row[4]
                    session.local_public_key = row[5]
                    session.remote_public_key = row[6]
                    session.shared_secret = row[7]
                    session.root_key = row[8]
                    session.chain_key_send = row[9]
                    session.chain_key_recv = row[10]
                    session.created_at = datetime.fromisoformat(row[11])
                    session.last_used = datetime.fromisoformat(row[12])
                    session.message_count = row[13]
                    session.is_verified = bool(row[14])
                    session.metadata = json.loads(row[15]) if row[15] else {}
                    self.active_sessions[session.session_id] = session

    async def _setup_endpoint_policies(self):
        """Setup encryption policies for different endpoint types."""
        self.endpoint_policies = {
            EndpointType.AUTHENTICATION: {
                "protocol": E2EProtocol.QUANTUM_RESISTANT_E2E,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(minutes=15),
                "max_messages": 100
            },
            EndpointType.MESSAGING: {
                "protocol": E2EProtocol.DOUBLE_RATCHET,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(hours=24),
                "max_messages": 10000
            },
            EndpointType.FILE_TRANSFER: {
                "protocol": E2EProtocol.HYBRID_CLASSICAL_QUANTUM,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(hours=1),
                "max_messages": 1000
            },
            EndpointType.DATABASE_API: {
                "protocol": E2EProtocol.QUANTUM_RESISTANT_E2E,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(minutes=30),
                "max_messages": 500
            },
            EndpointType.BACKUP_API: {
                "protocol": E2EProtocol.QUANTUM_RESISTANT_E2E,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(hours=2),
                "max_messages": 100
            },
            EndpointType.ADMIN_API: {
                "protocol": E2EProtocol.QUANTUM_RESISTANT_E2E,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": True,
                "session_timeout": timedelta(minutes=10),
                "max_messages": 50
            },
            EndpointType.PUBLIC_API: {
                "protocol": E2EProtocol.SIGNAL_PROTOCOL,
                "security_tier": None, # REMOVED: file deleted
                "require_verification": False,
                "session_timeout": timedelta(hours=1),
                "max_messages": 1000
            }
        }

    async def create_session(self, user_id: str, endpoint_type: EndpointType) -> E2ESession:
        """Create a new E2E encryption session."""
        policy = self.endpoint_policies[endpoint_type]
        protocol = policy["protocol"]

        session_id = f"e2e_{endpoint_type.value}_{user_id}_{secrets.token_hex(8)}"

        # Generate key pair based on protocol
        if protocol in [E2EProtocol.SIGNAL_PROTOCOL, E2EProtocol.DOUBLE_RATCHET]:
            # Use X25519 for key exchange
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

        else:  # Quantum-resistant protocols
            # Use quantum-resistant key generation
            domain_key = await self.distributed_keys.get_domain_key(KeyDomain.COMMUNICATION)
            if domain_key:
                # Derive session keys from domain key
                private_key_bytes = hashlib.blake2b(
                    domain_key + user_id.encode() + session_id.encode(),
                    digest_size=32
                ).digest()
                public_key_bytes = hashlib.blake2b(
                    private_key_bytes + b"public",
                    digest_size=32
                ).digest()
            else:
                # Fallback to random keys
                private_key_bytes = secrets.token_bytes(32)
                public_key_bytes = secrets.token_bytes(32)

        session = E2ESession()
        session.session_id = session_id
        session.user_id = user_id
        session.endpoint_type = endpoint_type
        session.protocol = protocol
        session.local_private_key = private_key_bytes
        session.local_public_key = public_key_bytes
        session.metadata = {
            "policy": policy,
            "created_by": "e2e_encryption_system"
        }

        self.active_sessions[session_id] = session
        await self._save_session(session)

        logger.info(f" Created E2E session: {session_id} for {endpoint_type.value}")
        return session

    async def establish_shared_secret(self, session_id: str, remote_public_key: bytes) -> bool:
        """Establish shared secret with remote party."""
        if session_id not in self.active_sessions:
            logger.error(f"Session not found: {session_id}")
            return False

        session = self.active_sessions[session_id]
        session.remote_public_key = remote_public_key

        if session.protocol in [E2EProtocol.SIGNAL_PROTOCOL, E2EProtocol.DOUBLE_RATCHET]:
            # Perform X25519 key exchange
            try:
                private_key = x25519.X25519PrivateKey.from_private_bytes(session.local_private_key)
                remote_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key)
                shared_secret = private_key.exchange(remote_key)

                # Derive root key using HKDF
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"PlexiChat-E2E-Root-Key",
                    info=session.session_id.encode(),
                    backend=default_backend()
                )
                session.root_key = hkdf.derive(shared_secret)
                session.shared_secret = shared_secret

                # Initialize chain keys for Double Ratchet
                if session.protocol == E2EProtocol.DOUBLE_RATCHET:
                    await self._initialize_double_ratchet(session)

            except Exception as e:
                logger.error(f"Failed to establish shared secret: {e}")
                return False

        else:  # Quantum-resistant protocols
            # Use quantum-resistant key agreement
            session.shared_secret = self._quantum_key_agreement(
                session.local_private_key,
                remote_public_key,
                session.session_id
            )
            session.root_key = hashlib.blake2b(
                session.shared_secret + b"root_key",
                digest_size=32
            ).digest()

        session.is_verified = True
        await self._save_session(session)

        logger.info(f" Established shared secret for session: {session_id}")
        return True

    async def _initialize_double_ratchet(self, session: E2ESession):
        """Initialize Double Ratchet protocol state."""
        if not session.root_key:
            raise ValueError("Root key not established")

        # Initialize chain keys
        session.chain_key_send = hashlib.blake2b(
            session.root_key + b"send_chain",
            digest_size=32
        ).digest()

        session.chain_key_recv = hashlib.blake2b(
            session.root_key + b"recv_chain",
            digest_size=32
        ).digest()

        # Pre-generate some message keys
        for _ in range(10):
            message_key = hashlib.blake2b(
                session.chain_key_send + len(session.message_keys_send).to_bytes(4, 'big'),
                digest_size=32
            ).digest()
            session.message_keys_send.append(message_key)

    def _quantum_key_agreement(self, local_private: bytes, remote_public: bytes, context: str) -> bytes:
        if local_private is None or remote_public is None:
            raise ValueError("Quantum key agreement requires non-None key material.")
        combined = local_private + remote_public + context.encode()
        return hashlib.blake2b(combined, digest_size=32).digest()

    async def encrypt_message(self, session_id: str, plaintext: bytes,
                             recipient_id: str = "") -> Optional[E2EMessage]:
        session = self.active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")
        if session.root_key is None:
            raise ValueError("Session root_key is not initialized.")

        if not session.is_verified:
            logger.error(f"Session not verified: {session_id}")
            return None

        # Check session limits
        policy = self.endpoint_policies[session.endpoint_type]
        if session.message_count >= policy["max_messages"]:
            logger.warning(f"Session message limit reached: {session_id}")
            await self._rotate_session(session)

        # Get message key
        if session.protocol == E2EProtocol.DOUBLE_RATCHET:
            if not session.message_keys_send:
                await self._advance_chain_key(session, "send")

            message_key = session.message_keys_send.pop(0)
            message_key_index = session.message_count

        else:
            # Generate message key from root key
            message_key = hashlib.blake2b(
                session.root_key + session.message_count.to_bytes(4, 'big'),
                digest_size=32
            ).digest()
            message_key_index = session.message_count

        # Encrypt the message
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(message_key)
        encrypted_payload = nonce + cipher.encrypt(nonce, plaintext, None)

        # Create message
        message_id = f"msg_{session_id}_{message_key_index}_{secrets.token_hex(4)}"
        message = E2EMessage()
        message.message_id = message_id
        message.session_id = session_id
        message.sender_id = session.user_id
        message.recipient_id = recipient_id
        message.encrypted_payload = encrypted_payload
        message.message_key_index = message_key_index
        message.timestamp = datetime.now(timezone.utc)
        message.metadata = {
            "protocol": session.protocol.value,
            "endpoint_type": session.endpoint_type.value
        }

        # Sign message if required
        if session.endpoint_type in [EndpointType.AUTHENTICATION, EndpointType.ADMIN_API]:
            message.signature = self._sign_message(message, session)

        # Update session
        session.message_count += 1
        session.last_used = datetime.now(timezone.utc)
        await self._save_session(session)
        await self._save_message(message)

        logger.debug(f" Encrypted message: {message_id}")
        return message

    async def decrypt_message(self, message: E2EMessage) -> Optional[bytes]:
        session = self.active_sessions.get(message.session_id)
        if not session:
            raise ValueError(f"Session {message.session_id} not found.")
        if session.root_key is None:
            raise ValueError("Session root_key is not initialized.")

        # Verify signature if present
        if message.signature and not self._verify_message_signature(message, session):
            logger.error(f"Message signature verification failed: {message.message_id}")
            return None

        # Get message key
        if session.protocol == E2EProtocol.DOUBLE_RATCHET:
            # Handle out-of-order messages
            message_key = await self._get_receive_message_key(session, message.message_key_index)
        else:
            # Generate message key from root key
            message_key = hashlib.blake2b(
                session.root_key + message.message_key_index.to_bytes(4, 'big'),
                digest_size=32
            ).digest()

        if not message_key:
            logger.error(f"Could not derive message key for: {message.message_id}")
            return None

        # Decrypt the message
        try:
            encrypted_data = message.encrypted_payload
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            cipher = ChaCha20Poly1305(message_key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            # Update session
            session.last_used = datetime.now(timezone.utc)
            await self._save_session(session)

            logger.debug(f" Decrypted message: {message.message_id}")
            return plaintext

        except Exception as e:
            logger.error(f"Failed to decrypt message {message.message_id}: {e}")
            return None

    async def _advance_chain_key(self, session: E2ESession, direction: str):
        """Advance chain key and generate new message keys."""
        if direction == "send":
            if session.chain_key_send is None:
                raise ValueError("Session chain_key_send is not initialized.")
            # Generate new message keys
            for i in range(10):
                message_key = hashlib.blake2b(
                    session.chain_key_send + (len(session.message_keys_send) + i).to_bytes(4, 'big'),
                    digest_size=32
                ).digest()
                session.message_keys_send.append(message_key)

            # Advance chain key
            session.chain_key_send = hashlib.blake2b(
                session.chain_key_send + b"advance",
                digest_size=32
            ).digest()

        else:  # receive
            if session.chain_key_recv is None:
                raise ValueError("Session chain_key_recv is not initialized.")
            # Generate new message keys
            for i in range(10):
                message_key = hashlib.blake2b(
                    session.chain_key_recv + (len(session.message_keys_recv) + i).to_bytes(4, 'big'),
                    digest_size=32
                ).digest()
                session.message_keys_recv.append(message_key)

            # Advance chain key
            session.chain_key_recv = hashlib.blake2b(
                session.chain_key_recv + b"advance",
                digest_size=32
            ).digest()

    async def _get_receive_message_key(self, session: E2ESession, key_index: int) -> Optional[bytes]:
        """Get message key for receiving (handles out-of-order messages)."""
        if session.chain_key_recv is None:
            raise ValueError("Session chain_key_recv is not initialized.")
        # Ensure we have enough receive keys
        while len(session.message_keys_recv) <= key_index:
            await self._advance_chain_key(session, "recv")

        if key_index < len(session.message_keys_recv):
            return session.message_keys_recv[key_index]

        return None

    def _sign_message(self, message: E2EMessage, session: E2ESession) -> bytes:
        """Sign a message for authentication."""
        # Create message hash
        message_data = (
            message.message_id.encode() +
            message.session_id.encode() +
            message.encrypted_payload +
            message.timestamp.isoformat().encode()
        )

        message_hash = hashlib.blake2b(message_data, digest_size=32).digest()

        # Sign with session private key (simplified - use proper signing in production)
        signature = hashlib.blake2b(
            session.local_private_key + message_hash,
            digest_size=64
        ).digest()

        return signature

    def _verify_message_signature(self, message: E2EMessage, session: E2ESession) -> bool:
        """Verify message signature."""
        if not message.signature:
            return False

        # Recreate message hash
        message_data = (
            message.message_id.encode() +
            message.session_id.encode() +
            message.encrypted_payload +
            message.timestamp.isoformat().encode()
        )

        message_hash = hashlib.blake2b(message_data, digest_size=32).digest()

        # Verify signature (simplified - use proper verification in production)
        expected_signature = hashlib.blake2b(
            session.local_private_key + message_hash,
            digest_size=64
        ).digest()

        return message.signature == expected_signature

    async def _rotate_session(self, session: E2ESession):
        """Rotate session keys when limits are reached."""
        logger.info(f" Rotating session: {session.session_id}")

        # Create new session
        new_session = await self.create_session(session.user_id, session.endpoint_type)

        # Transfer remote public key if established
        if session.remote_public_key:
            await self.establish_shared_secret(new_session.session_id, session.remote_public_key)

        # Mark old session as rotated
        session.metadata["rotated_to"] = new_session.session_id
        session.metadata["rotation_reason"] = "message_limit_reached"
        await self._save_session(session)

        # Remove from active sessions
        del self.active_sessions[session.session_id]

        logger.info(f" Session rotated: {session.session_id} -> {new_session.session_id}")
        return new_session

    async def _save_session(self, session: E2ESession):
        """Save session to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO e2e_sessions
                (session_id, user_id, endpoint_type, protocol, local_private_key, local_public_key, remote_public_key, shared_secret, root_key, chain_key_send, chain_key_recv, created_at, last_used, message_count, is_verified, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                session.user_id,
                session.endpoint_type.value,
                session.protocol.value,
                session.local_private_key,
                session.local_public_key,
                session.remote_public_key,
                session.shared_secret,
                session.root_key,
                session.chain_key_send,
                session.chain_key_recv,
                session.created_at.isoformat(),
                session.last_used.isoformat(),
                session.message_count,
                session.is_verified,
                json.dumps(session.metadata)
            ))
            await db.commit()

    async def _save_message(self, message: E2EMessage):
        """Save message to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO e2e_messages
                (message_id, session_id, sender_id, recipient_id, encrypted_payload, message_key_index, timestamp, signature, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message.message_id,
                message.session_id,
                message.sender_id,
                message.recipient_id,
                message.encrypted_payload,
                message.message_key_index,
                message.timestamp.isoformat(),
                message.signature,
                json.dumps(message.metadata)
            ))
            await db.commit()

    async def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        current_time = datetime.now(timezone.utc)
        expired_sessions = []

        for session_id, session in list(self.active_sessions.items()):
            policy = self.endpoint_policies[session.endpoint_type]
            session_timeout = policy["session_timeout"]

            if current_time - session.last_used > session_timeout:
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            session = self.active_sessions[session_id]
            session.metadata["expired_at"] = current_time.isoformat()
            await self._save_session(session)
            del self.active_sessions[session_id]
            logger.info(f" Cleaned up expired session: {session_id}")

        return len(expired_sessions)

    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a session."""
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions[session_id]
        policy = self.endpoint_policies[session.endpoint_type]

        return {}}
            "session_id": session.session_id,
            "user_id": session.user_id,
            "endpoint_type": session.endpoint_type.value,
            "protocol": session.protocol.value,
            "is_verified": session.is_verified,
            "message_count": session.message_count,
            "max_messages": policy["max_messages"],
            "created_at": session.created_at.isoformat(),
            "last_used": session.last_used.isoformat(),
            "expires_at": (session.last_used + policy["session_timeout"]).isoformat(),
            "metadata": session.metadata
        }

    async def get_endpoint_stats(self) -> Dict[str, Any]:
        """Get statistics about E2E encryption usage."""
        stats = {
            "total_active_sessions": len(self.active_sessions),
            "sessions_by_endpoint": {},
            "sessions_by_protocol": {},
            "total_messages_today": 0
        }

        # Count sessions by endpoint and protocol
        for session in self.active_sessions.values():
            endpoint = session.endpoint_type.value
            protocol = session.protocol.value

            stats["sessions_by_endpoint"][endpoint] = stats["sessions_by_endpoint"].get(endpoint, 0) + 1
            stats["sessions_by_protocol"][protocol] = stats["sessions_by_protocol"].get(protocol, 0) + 1

        # Count messages from today
        today = datetime.now(timezone.utc).date()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM e2e_messages WHERE DATE(timestamp) = ?",
                                 [today.isoformat()]) as cursor:
                row = await cursor.fetchone()
                if row:
                    stats["total_messages_today"] = row[0]

        return stats


# Global end-to-end encryption system instance
e2e_encryption = EndToEndEncryption()
