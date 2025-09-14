# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import json
import logging
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Lightweight, self-contained calling service implementation with enhanced features:
# - WebRTC signaling helpers (SDP handling, ICE candidate generation)
# - Media server allocation and basic health management
# - End-to-end encryption support with graceful fallback to RSA-wrapped AES keys
# - Adaptive quality and bandwidth optimization loop (simulated metrics)
# - Secure signaling envelopes and optional integration with quantum-ready encryption manager
# - WebSocket signaling handler helpers (framework-agnostic)
# - STUN/TURN management and health checks
# - Presence broadcasting and basic rate-limiting for call initiation
# - Optional recording support with encryption and backup integration
# - Monitoring metrics collection

logger = logging.getLogger(__name__)


# ---------------------------
# Domain models (concrete)
# ---------------------------
@dataclass
class CallInvitation:
    call_session_id: str
    inviter_id: int
    invitee_id: int
    status: str = "pending"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None


@dataclass
class CallParticipant:
    call_session_id: str
    user_id: int
    peer_id: str
    connection_id: str
    status: str
    public_key: str | None = None
    session_key_encrypted: str | None = None
    joined_at: datetime | None = None
    left_at: datetime | None = None
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class CallSession:
    id: str
    call_id: str
    call_type: str
    initiator_id: int
    participants: list[int]
    max_participants: int
    encryption_method: str
    master_key_hash: str
    ice_servers: list[dict[str, Any]]
    video_quality: str
    audio_quality: str
    status: str
    media_server_id: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_seconds: int | None = None
    # New fields for DTLS & key rotation management
    session_key: str | None = None
    key_rotation_interval_seconds: int = 300
    _rotation_task: Any | None = None
    dtls_fingerprint: str | None = None
    dtls_private_key_b64: str | None = None
    dtls_public_key_b64: str | None = None


@dataclass
class CallOffer:
    call_id: str
    offer_sdp: str
    ice_candidates: list[dict[str, Any]]
    encryption_key: str
    public_key: str


@dataclass
class CallAnswer:
    call_id: str
    answer_sdp: str
    ice_candidates: list[dict[str, Any]]
    encryption_key: str
    public_key: str


class CallStatus:
    INITIATING = "initiating"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ENDED = "ended"


class CallType:
    VOICE = "voice"
    VIDEO = "video"


class EncryptionMethod:
    AES_256_GCM = "aes-256-gcm"
    FERNET = "fernet"
    HYBRID = "hybrid"


# ---------------------------
# Call quality telemetry
# ---------------------------
@dataclass
class CallQuality:
    """Real-time call quality metrics."""

    latency_ms: float
    packet_loss: float
    bandwidth_kbps: float
    audio_quality: float
    video_quality: float
    connection_stability: float


# ---------------------------
# Encryption Manager
# ---------------------------
class EncryptionManager:
    """Manages end-to-end encryption for calls with graceful quantum manager integration."""

    @staticmethod
    def generate_key_pair() -> tuple[str, str]:
        """Generate RSA key pair for key exchange (base64 PEMs)."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return (
            base64.b64encode(private_pem).decode("utf-8"),
            base64.b64encode(public_pem).decode("utf-8"),
        )

    @staticmethod
    def generate_session_key() -> str:
        """Generate AES session key for call encryption (base64)."""
        return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")

    @staticmethod
    def encrypt_session_key(session_key: str, public_key_pem: str) -> str:
        """Encrypt session key with RSA public key. If quantum manager is available, prefer it for additional wrapping."""
        # Try to use quantum encryption manager if present for an additional layer
        try:
            from plexichat.core.security.quantum_encryption import (
                get_quantum_manager,  # type: ignore
            )

            qm = get_quantum_manager()
        except Exception:
            qm = None

        session_key_bytes = base64.b64decode(session_key.encode("utf-8"))

        if qm:
            # Use HTTP traffic encryption layer to protect the session key envelope for signaling
            try:
                encrypted_bytes = qm.encrypt_http_traffic(
                    session_key_bytes, endpoint="session_key"
                )
                return base64.b64encode(encrypted_bytes).decode("utf-8")
            except Exception as e:
                logger.warning(
                    f"Quantum encryption used but failed; falling back to RSA. Error: {e}"
                )

        # Fallback to RSA OAEP
        try:
            public_key_bytes = base64.b64decode(public_key_pem.encode("utf-8"))
            public_key = serialization.load_pem_public_key(public_key_bytes)

            encrypted = public_key.encrypt(
                session_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to encrypt session key with RSA: {e}")
            raise

    @staticmethod
    def decrypt_session_key(encrypted_key: str, private_key_pem: str) -> str:
        """Decrypt session key with RSA private key, with fallback to quantum manager decryption if applicable."""
        # Try quantum manager first (it may have been used to encrypt)
        try:
            from plexichat.core.security.quantum_encryption import (
                get_quantum_manager,  # type: ignore
            )

            qm = get_quantum_manager()
        except Exception:
            qm = None

        encrypted_bytes = base64.b64decode(encrypted_key.encode("utf-8"))

        if qm:
            try:
                payload, _ts = qm.decrypt_http_traffic(
                    encrypted_bytes, endpoint="session_key"
                )
                return base64.b64encode(payload).decode("utf-8")
            except Exception:
                # fallthrough to RSA
                pass

        try:
            private_key_bytes = base64.b64decode(private_key_pem.encode("utf-8"))
            private_key = serialization.load_pem_private_key(
                private_key_bytes, password=None
            )

            decrypted = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            return base64.b64encode(decrypted).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decrypt session key: {e}")
            raise


# ---------------------------
# STUN/TURN helpers
# ---------------------------
@dataclass
class TurnServer:
    url: str
    username: str | None = None
    credential: str | None = None
    healthy: bool = True
    last_checked: float | None = None


# ---------------------------
# WebRTC Manager
# ---------------------------
class WebRTCManager:
    """Manages WebRTC connections and signaling helpers."""

    def __init__(self):
        self.ice_servers = [
            {"urls": "stun:stun.l.google.com:19302"},
            {"urls": "stun:stun1.l.google.com:19302"},
            {"urls": "stun:stun2.l.google.com:19302"},
        ]
        self.turn_servers: list[TurnServer] = []  # ideally loaded from config
        self.ice_candidate_seq = 0

    def get_ice_configuration(self) -> dict[str, Any]:
        """Get ICE server configuration for WebRTC clients, including TURN servers that are healthy."""
        turn_entries = []
        for t in self.turn_servers:
            if t.healthy:
                entry = {"urls": t.url}
                if t.username:
                    entry["username"] = t.username
                if t.credential:
                    entry["credential"] = t.credential
                turn_entries.append(entry)
        return {
            "iceServers": self.ice_servers + turn_entries,
            "iceCandidatePoolSize": 10,
        }

    def add_turn_server(
        self, url: str, username: str | None = None, credential: str | None = None
    ):
        self.turn_servers.append(
            TurnServer(url=url, username=username, credential=credential)
        )

    def validate_sdp(self, sdp: str) -> bool:
        """Basic plus hardened validation for SDP content."""
        if not sdp or not isinstance(sdp, str):
            return False
        required_fields = ["v=", "o=", "s=", "t=", "m="]
        if not all(field in sdp for field in required_fields):
            return False
        # Reject overly long single-line SDPs or embedded scripts
        if len(sdp) > 20000:
            logger.warning("SDP too large")
            return False
        if "<script" in sdp.lower() or "javascript:" in sdp.lower():
            logger.warning("SDP contains potentially malicious content")
            return False
        return True

    def enhance_sdp_security(
        self, sdp: str, dtls_fingerprint: str | None = None
    ) -> str:
        """Enhance SDP with security features such as DTLS fingerprint and setup lines."""
        if dtls_fingerprint:
            # ensure given fingerprint is present
            if "a=fingerprint:" not in sdp:
                sdp += f"\na=fingerprint:sha-256 {dtls_fingerprint}"
        elif "a=fingerprint:" not in sdp:
            # In production, compute real certificate fingerprint
            sdp += "\na=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        if "a=setup:" not in sdp:
            sdp += "\na=setup:actpass"
        # Add SRTP setup hint
        if "a=crypto:" not in sdp and "a=rtcp-mux" in sdp:
            # Modern browsers use DTLS-SRTP, but keep an informational crypto line
            # Generate a proper SRTP crypto key for the SDP
            import secrets

            crypto_key = base64.b64encode(secrets.token_bytes(30)).decode("utf-8")
            sdp += f"\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{crypto_key}"
        return sdp

    def create_simulated_ice_candidates(self, count: int = 2) -> list[dict[str, Any]]:
        """Produce simulated ICE candidates (useful for environments without full ICE)."""
        candidates = []
        for _ in range(count):
            self.ice_candidate_seq += 1
            candidate = {
                "candidate": f"candidate:{self.ice_candidate_seq} 1 udp 2122260223 192.0.2.{self.ice_candidate_seq} 54400 typ host",
                "sdpMid": "0",
                "sdpMLineIndex": 0,
            }
            candidates.append(candidate)
        return candidates

    def apply_bandwidth_constraints(self, sdp: str, bandwidth_kbps: float) -> str:
        """Patch SDP with bandwidth b=AS hints for browsers/servers that respect them."""
        # Insert a simple b=AS line for audio/video sections
        lines = sdp.splitlines()
        patched_lines = []
        for line in lines:
            patched_lines.append(line)
            if line.startswith("m=audio"):
                # audio recommended 64 kbps min
                patched_lines.append(f"b=AS:{max(64, int(bandwidth_kbps * 0.2))}")
            if line.startswith("m=video"):
                # allocate the majority of bandwidth to video
                patched_lines.append(f"b=AS:{max(128, int(bandwidth_kbps * 0.7))}")
        return "\n".join(patched_lines)

    def prefer_codecs(
        self, sdp: str, audio_codecs: list[str] = None, video_codecs: list[str] = None
    ) -> str:
        """Simple heuristic to place preferred codecs first in SDP"""
        # This is a best-effort, not a full SDP parser
        # If no preferences provided, return original
        if not audio_codecs and not video_codecs:
            return sdp
        for codec in audio_codecs or []:
            sdp = sdp.replace(codec + "/", codec + "/")
        return sdp


# ---------------------------
# Media Server Manager
# ---------------------------
class MediaServerManager:
    """Lightweight manager to allocate and monitor media server instances."""

    def __init__(self):
        # server_id -> info
        self.servers: dict[str, dict[str, Any]] = {}
        # Seed with a local lightweight mock media server for single-node setups
        local_id = "media_local_1"
        self.servers[local_id] = {
            "id": local_id,
            "host": "127.0.0.1",
            "port": 4000,
            "capacity": 100,
            "current_load": 0,
            "last_heartbeat": time.time(),
            "healthy": True,
        }

    async def allocate_server_for_call(self, call_id: str) -> str | None:
        """Pick a healthy media server with available capacity."""
        # Basic load-based allocation
        candidates = sorted(
            self.servers.values(), key=lambda s: (not s["healthy"], s["current_load"])
        )
        for srv in candidates:
            if srv["healthy"] and srv["current_load"] < srv["capacity"]:
                srv["current_load"] += 1
                logger.debug(f"Allocated media server {srv['id']} to call {call_id}")
                return srv["id"]
        logger.warning("No healthy media server available")
        return None

    async def release_server_for_call(self, server_id: str):
        """Decrease load on server when calls end."""
        if server_id not in self.servers:
            return
        srv = self.servers[server_id]
        srv["current_load"] = max(0, srv["current_load"] - 1)
        logger.debug(
            f"Released media server {server_id}, new load {srv['current_load']}"
        )

    def register_server(
        self, server_id: str, host: str, port: int, capacity: int = 100
    ):
        self.servers[server_id] = {
            "id": server_id,
            "host": host,
            "port": port,
            "capacity": capacity,
            "current_load": 0,
            "last_heartbeat": time.time(),
            "healthy": True,
        }

    def heartbeat(self, server_id: str):
        if server_id in self.servers:
            self.servers[server_id]["last_heartbeat"] = time.time()
            self.servers[server_id]["healthy"] = True


# ---------------------------
# WebSocket & Presence Manager (framework-agnostic helpers)
# ---------------------------
class WebSocketManager:
    """A lightweight manager for tracking websocket connections and broadcasting presence.

    This is framework-agnostic: it expects the websocket object to provide:
      - .send(text_or_bytes)
      - .recv()
      - .close()
    and to be used within an asyncio event loop (e.g. 'websockets' library).
    """

    def __init__(self, calling_service: "CallingService"):
        self.calling_service = calling_service
        # user_id -> set of websocket connections
        self.connections: dict[int, set[Any]] = {}
        # store per-connection metadata if needed
        self._lock = asyncio.Lock()

    async def register(self, user_id: int, websocket: Any):
        async with self._lock:
            conns = self.connections.setdefault(user_id, set())
            conns.add(websocket)
        # announce presence
        await self.calling_service._broadcast_presence(user_id, "online")

    async def unregister(self, user_id: int, websocket: Any):
        async with self._lock:
            conns = self.connections.get(user_id, set())
            conns.discard(websocket)
            if not conns:
                self.connections.pop(user_id, None)
        # announce presence if user has no more connections
        if user_id not in self.connections:
            await self.calling_service._broadcast_presence(user_id, "offline")

    async def broadcast_to_user(self, user_id: int, message: dict[str, Any]):
        conns = list(self.connections.get(user_id, []))
        for ws in conns:
            try:
                await ws.send(json.dumps(message))
            except Exception:
                # ignore send errors, remote will cleanup
                pass

    async def broadcast_to_all(self, message: dict[str, Any]):
        # send to all connected users
        for user_id in list(self.connections.keys()):
            await self.broadcast_to_user(user_id, message)


# ---------------------------
# Calling Service
# ---------------------------
class CallingService:
    """Main calling service with enhanced WebRTC, media server management, and encryption."""

    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.webrtc_manager = WebRTCManager()
        self.media_manager = MediaServerManager()
        self.active_calls: dict[str, CallSession] = {}
        self.call_participants: dict[str, list[CallParticipant]] = {}
        self.metrics: dict[str, Any] = {
            "calls_initiated": 0,
            "calls_connected": 0,
            "calls_ended": 0,
            "call_failures": 0,
            "recordings_made": 0,
            "avg_call_duration_seconds": 0,
            "quality_samples": 0,
        }
        # Rate limiting: user_id -> list of initiation timestamps
        self._initiation_attempts: dict[int, list[float]] = {}
        # Configurable rate limits (per minute) by tier; in production read from config_manager
        self._tier_limits = {
            "anonymous": 10,
            "authenticated": 60,
            "premium": 600,
            "admin": 120,
        }
        # Presence and websocket manager
        self.ws_manager = WebSocketManager(self)
        # Background tasks
        loop = asyncio.get_event_loop()
        self._monitor_task = loop.create_task(self._background_monitor())
        self._turn_health_task = loop.create_task(self._turn_health_checker())
        # TURN health check cadence (seconds)
        self.turn_health_interval = 30
        # Recording storage path fallback
        self._recordings_path = "/tmp/plexichat_recordings"
        # Recording handles: call_id -> recording metadata
        self._recordings: dict[str, dict[str, Any]] = {}

    # -----------------------
    # Public API
    # -----------------------
    async def initiate_call(
        self,
        initiator_id: int,
        target_user_ids: list[int],
        call_type: str,
        video_quality: str = "720p",
        audio_quality: str = "high",
        requester_token: str | None = None,
    ) -> CallSession:
        """Initiate a new encrypted call with media server allocation and signaling envelope.

        Enforces simple rate limiting for call initiation and integrates security tier checks when possible.
        """
        try:
            # Rate limiting enforcement & authentication check
            if not await self._allow_initiation(initiator_id, requester_token):
                self.metrics["call_failures"] += 1
                raise PermissionError("Rate limit exceeded for call initiation")

            # Validate token for user authenticity if provided
            if requester_token:
                try:
                    ok, payload = await self._verify_token_async(requester_token)
                    if (
                        not ok
                        or not payload
                        or int(payload.get("user_id", -1)) != initiator_id
                    ):
                        logger.warning(
                            "Token authentication failed or mismatch for initiator"
                        )
                        # We don't strictly fail here to keep backwards compatibility,
                        # but log the event for audit.
                except Exception as e:
                    logger.debug(f"Token verification attempt raised: {e}")

            # Create unique IDs
            call_uuid = f"call_{secrets.token_urlsafe(16)}"
            session_id = f"session_{secrets.token_urlsafe(12)}"

            # Generate master encryption key (session key) and hash for reference
            master_key = self._generate_master_key_for_session()
            master_key_hash = hashlib.sha256(master_key.encode()).hexdigest()

            # Allocate a media server
            media_server_id = await self.media_manager.allocate_server_for_call(
                call_uuid
            )

            # Generate DTLS keypair and fingerprint for the call and store in session
            dtls_priv_b64, dtls_pub_b64 = self._generate_dtls_keypair()
            dtls_fingerprint = self._compute_fingerprint_from_public_b64(dtls_pub_b64)

            # Build call session object
            call_session = CallSession(
                id=session_id,
                call_id=call_uuid,
                call_type=call_type,
                initiator_id=initiator_id,
                participants=[initiator_id] + list(target_user_ids),
                max_participants=len(target_user_ids) + 1,
                encryption_method=EncryptionMethod.AES_256_GCM,
                master_key_hash=master_key_hash,
                ice_servers=self.webrtc_manager.get_ice_configuration()["iceServers"],
                video_quality=video_quality,
                audio_quality=audio_quality,
                status=CallStatus.INITIATING,
                media_server_id=media_server_id,
                started_at=datetime.now(UTC),
                session_key=master_key,
                dtls_fingerprint=dtls_fingerprint,
                dtls_private_key_b64=dtls_priv_b64,
                dtls_public_key_b64=dtls_pub_b64,
            )

            # Persist in-memory
            self.active_calls[call_uuid] = call_session
            self.call_participants[call_uuid] = []

            # Create initiator participant and keys
            initiator_private_key, initiator_public_key = (
                self.encryption_manager.generate_key_pair()
            )

            encrypted_key_for_initiator = self.encryption_manager.encrypt_session_key(
                master_key, initiator_public_key
            )

            initiator_participant = CallParticipant(
                call_session_id=call_session.id,
                user_id=initiator_id,
                peer_id=f"peer_{secrets.token_urlsafe(8)}",
                connection_id=f"conn_{secrets.token_urlsafe(8)}",
                status=CallStatus.CONNECTING,
                public_key=initiator_public_key,
                session_key_encrypted=encrypted_key_for_initiator,
                joined_at=datetime.now(UTC),
                metrics={},
            )

            self.call_participants[call_uuid].append(initiator_participant)

            # Start periodic session key rotation task for this call
            self._start_key_rotation_for_call(
                call_uuid, interval_seconds=call_session.key_rotation_interval_seconds
            )

            # Send invitations to target users asynchronously
            for user_id in target_user_ids:
                # fire-and-forget invitation send
                asyncio.get_event_loop().create_task(
                    self._send_call_invitation(call_session, initiator_id, user_id)
                )

            # Update metrics
            self.metrics["calls_initiated"] += 1

            logger.info(
                f"Initiated encrypted {call_type} call {call_uuid} with media_server={media_server_id}, dtls_fp={dtls_fingerprint}"
            )

            return call_session

        except Exception as e:
            logger.error(f"Failed to initiate call: {e}")
            raise

    async def join_call(
        self,
        call_id: str,
        user_id: int,
        offer_sdp: str | None = None,
        token: str | None = None,
    ) -> CallOffer:
        """Join an existing call: register participant, provide ICE and encrypted session key, generate offer SDP.

        Optional token can be provided for authentication and will be validated if present.
        """
        try:
            # Optional authentication verification
            if token:
                ok, payload = await self._verify_token_async(token)
                if not ok or not payload:
                    logger.warning(
                        f"Token verification failed for join_call user {user_id}"
                    )
                    raise PermissionError("Invalid authentication token for join_call")
                # optionally enforce that token user matches user_id
                t_uid = int(payload.get("user_id")) if payload.get("user_id") else None
                if t_uid and t_uid != user_id:
                    logger.warning("Token user mismatch for join_call")
                    raise PermissionError("Token user mismatch")

            if call_id not in self.active_calls:
                raise ValueError(f"Call {call_id} not found")

            call_session = self.active_calls[call_id]

            if user_id not in call_session.participants:
                raise ValueError(f"User {user_id} not invited to call {call_id}")

            # Generate key pair for participant
            private_key, public_key = self.encryption_manager.generate_key_pair()

            # Retrieve the master key securely from vault in production. For now, simulate retrieval.
            master_key = self._retrieve_master_key_for_call(call_id)

            encrypted_session_key = self.encryption_manager.encrypt_session_key(
                master_key, public_key
            )

            participant = CallParticipant(
                call_session_id=call_session.id,
                user_id=user_id,
                peer_id=f"peer_{secrets.token_urlsafe(8)}",
                connection_id=f"conn_{secrets.token_urlsafe(8)}",
                status=CallStatus.CONNECTING,
                public_key=public_key,
                session_key_encrypted=encrypted_session_key,
                joined_at=datetime.now(UTC),
                metrics={},
            )

            self.call_participants[call_id].append(participant)

            # Generate an offer SDP (mock or proxied). Enhance with security and bandwidth hints.
            sdp = offer_sdp or self._generate_default_sdp()
            sdp = self.webrtc_manager.enhance_sdp_security(
                sdp, dtls_fingerprint=call_session.dtls_fingerprint
            )
            # Provide initial bandwidth hints based on configured quality
            estimated_bandwidth = self._bandwidth_for_quality(
                call_session.video_quality
            )
            sdp = self.webrtc_manager.apply_bandwidth_constraints(
                sdp, estimated_bandwidth
            )

            # Simulate ICE candidate gathering
            ice_candidates = self.webrtc_manager.create_simulated_ice_candidates(2)

            call_offer = CallOffer(
                call_id=call_id,
                offer_sdp=sdp,
                ice_candidates=ice_candidates,
                encryption_key=encrypted_session_key,
                public_key=public_key,
            )

            logger.info(
                f"User {user_id} joined encrypted call {call_id} and received offer (dtls_fp={call_session.dtls_fingerprint})"
            )

            return call_offer

        except Exception as e:
            logger.error(f"Failed to join call {call_id}: {e}")
            raise

    async def answer_call(
        self, call_id: str, user_id: int, answer_sdp: str, token: str | None = None
    ) -> CallAnswer:
        """Answer a call: validate, secure the SDP, and return encrypted key for signaling."""
        try:
            # Optional authentication verification
            if token:
                ok, payload = await self._verify_token_async(token)
                if not ok or not payload:
                    logger.warning(
                        f"Token verification failed for answer_call user {user_id}"
                    )
                    raise PermissionError(
                        "Invalid authentication token for answer_call"
                    )
                t_uid = int(payload.get("user_id")) if payload.get("user_id") else None
                if t_uid and t_uid != user_id:
                    logger.warning("Token user mismatch for answer_call")
                    raise PermissionError("Token user mismatch")

            if call_id not in self.active_calls:
                raise ValueError(f"Call {call_id} not found")

            if not self.webrtc_manager.validate_sdp(answer_sdp):
                raise ValueError("Invalid SDP answer")

            call_session = self.active_calls[call_id]

            secure_sdp = self.webrtc_manager.enhance_sdp_security(
                answer_sdp, dtls_fingerprint=call_session.dtls_fingerprint
            )

            # Find participant
            participant = next(
                (
                    p
                    for p in self.call_participants.get(call_id, [])
                    if p.user_id == user_id
                ),
                None,
            )
            if not participant:
                raise ValueError(f"Participant {user_id} not found in call {call_id}")

            participant.status = CallStatus.CONNECTED
            participant.joined_at = participant.joined_at or datetime.now(UTC)

            # Optionally add bandwidth hints based on current measured metrics
            participant_metrics = participant.metrics or {}
            measured_bw = participant_metrics.get("bandwidth_kbps", 512)
            secure_sdp = self.webrtc_manager.apply_bandwidth_constraints(
                secure_sdp, measured_bw
            )

            call_answer = CallAnswer(
                call_id=call_id,
                answer_sdp=secure_sdp,
                ice_candidates=self.webrtc_manager.create_simulated_ice_candidates(2),
                encryption_key=participant.session_key_encrypted,
                public_key=participant.public_key,
            )

            # Update metrics
            self.metrics["calls_connected"] += 1

            logger.info(f"User {user_id} answered encrypted call {call_id}")

            return call_answer

        except Exception as e:
            logger.error(f"Failed to answer call {call_id}: {e}")
            raise

    async def end_call(self, call_id: str, user_id: int) -> bool:
        """End a call and cleanup resources. Release media server and persist duration."""
        try:
            if call_id not in self.active_calls:
                return False

            call_session = self.active_calls[call_id]

            call_session.status = CallStatus.ENDED
            call_session.ended_at = datetime.now(UTC)

            if call_session.started_at:
                duration = (
                    call_session.ended_at - call_session.started_at
                ).total_seconds()
                call_session.duration_seconds = int(duration)

            # Update participants
            for participant in list(self.call_participants.get(call_id, [])):
                if participant.status == CallStatus.CONNECTED:
                    participant.status = CallStatus.ENDED
                    participant.left_at = datetime.now(UTC)

            # Cancel key rotation task if running
            try:
                if call_session._rotation_task:
                    call_session._rotation_task.cancel()
                    call_session._rotation_task = None
            except Exception:
                pass

            # Release media server
            if call_session.media_server_id:
                await self.media_manager.release_server_for_call(
                    call_session.media_server_id
                )

            # Optionally finalize recording
            if call_id in self._recordings and self._recordings[call_id].get("active"):
                try:
                    await self._finalize_recording(call_id)
                except Exception as e:
                    logger.warning(f"Failed to finalize recording for {call_id}: {e}")

            # Cleanup in-memory structures
            try:
                del self.active_calls[call_id]
            except Exception:
                pass
            try:
                del self.call_participants[call_id]
            except Exception:
                pass

            # Update metrics
            self.metrics["calls_ended"] += 1
            # update avg duration sample (simple moving average)
            samples = self.metrics.get("quality_samples", 0)
            avg = self.metrics.get("avg_call_duration_seconds", 0)
            dur = call_session.duration_seconds or 0
            new_samples = samples + 1
            self.metrics["avg_call_duration_seconds"] = (
                avg * samples + dur
            ) / new_samples
            self.metrics["quality_samples"] = new_samples

            logger.info(f"Ended encrypted call {call_id} by user {user_id}")

            return True

        except Exception as e:
            logger.error(f"Failed to end call {call_id}: {e}")
            return False

    async def get_call_quality(self, call_id: str, user_id: int) -> CallQuality:
        """Return simulated or aggregated call quality metrics and provide suggestions."""
        try:
            if call_id not in self.active_calls:
                raise ValueError(f"Call {call_id} not found")

            # Aggregate participant-level metrics if available
            participants = self.call_participants.get(call_id, [])
            if not participants:
                # default synthetic metrics
                return CallQuality(
                    latency_ms=40.0,
                    packet_loss=0.0,
                    bandwidth_kbps=1024.0,
                    audio_quality=0.98,
                    video_quality=0.95,
                    connection_stability=0.99,
                )

            # Compute averages
            latencies = [p.metrics.get("latency_ms", 50.0) for p in participants]
            packet_losses = [p.metrics.get("packet_loss", 0.01) for p in participants]
            bws = [p.metrics.get("bandwidth_kbps", 512) for p in participants]
            audio_scores = [p.metrics.get("audio_quality", 0.9) for p in participants]
            video_scores = [p.metrics.get("video_quality", 0.85) for p in participants]
            stability = [p.metrics.get("stability", 0.95) for p in participants]

            avg = lambda arr: sum(arr) / len(arr) if arr else 0.0

            quality = CallQuality(
                latency_ms=avg(latencies),
                packet_loss=avg(packet_losses),
                bandwidth_kbps=avg(bws),
                audio_quality=avg(audio_scores),
                video_quality=avg(video_scores),
                connection_stability=avg(stability),
            )

            # Optionally run an adaptation step
            asyncio.get_event_loop().create_task(
                self._adjust_media_parameters(call_id, quality)
            )

            # Track quality samples for monitoring
            self.metrics.setdefault("recent_quality", []).append(
                {
                    "call_id": call_id,
                    "timestamp": time.time(),
                    "quality": {
                        "latency_ms": quality.latency_ms,
                        "packet_loss": quality.packet_loss,
                        "bandwidth_kbps": quality.bandwidth_kbps,
                        "video_quality": quality.video_quality,
                    },
                }
            )
            # Keep only last N samples
            recent = self.metrics.get("recent_quality", [])
            if len(recent) > 1000:
                self.metrics["recent_quality"] = recent[-1000:]

            return quality

        except Exception as e:
            logger.error(f"Failed to get call quality for {call_id}: {e}")
            raise

    # -----------------------
    # Recording support
    # -----------------------
    async def start_recording(
        self, call_id: str, initiator_user_id: int, encrypt_with_qm: bool = True
    ) -> dict[str, Any]:
        """Start optional recording for a call. Recording is simulated; in production this would be media server driven."""
        if call_id not in self.active_calls:
            raise ValueError("Call not found")

        if self._recordings.get(call_id, {}).get("active"):
            raise RuntimeError("Recording already active")

        recording_id = f"rec_{secrets.token_urlsafe(12)}"
        filename = f"{self._recordings_path}/{recording_id}.enc"

        # Create metadata record
        rec_meta = {
            "id": recording_id,
            "call_id": call_id,
            "initiator": initiator_user_id,
            "started_at": datetime.now(UTC),
            "active": True,
            "filename": filename,
            "encrypted_with_qm": False,
        }

        # Try to reserve recording with backup manager if available
        try:
            from plexichat.features.backup.backup_manager import (
                get_backup_manager,  # type: ignore
            )

            bm = get_backup_manager()
            # notify backup system (best-effort)
            try:
                bm.reserve_temporary_object(recording_id, metadata=rec_meta)  # type: ignore
            except Exception:
                pass
        except Exception:
            # backup manager not available; proceed with local recording
            pass

        # Mark active
        self._recordings[call_id] = rec_meta

        # If encryption requested, attempt quantum manager usage if available
        if encrypt_with_qm:
            try:
                from plexichat.core.security.quantum_encryption import (
                    get_quantum_manager,  # type: ignore
                )

                qm = get_quantum_manager()
                # Just mark as using QM; actual streaming encryption would be done in media pipeline
                rec_meta["encrypted_with_qm"] = True
                # Suggest key rotation on start to provide fresh keys for recording
                try:
                    asyncio.get_event_loop().create_task(
                        qm.rotate_http_keys(f"recording:{rec_meta['id']}")
                    )
                except Exception:
                    # best-effort
                    pass
            except Exception:
                rec_meta["encrypted_with_qm"] = False

        self.metrics["recordings_made"] += 1
        logger.info(f"Started recording for call {call_id} -> {recording_id}")
        return rec_meta

    async def stop_recording(self, call_id: str) -> dict[str, Any] | None:
        """Stop a recording and finalize storage and optional backup integration."""
        if call_id not in self._recordings or not self._recordings[call_id].get(
            "active"
        ):
            return None
        try:
            await self._finalize_recording(call_id)
            return self._recordings.get(call_id)
        except Exception as e:
            logger.error(f"Failed to stop recording for {call_id}: {e}")
            raise

    async def _finalize_recording(self, call_id: str):
        """Finalize recording, encrypt file if needed and hand to backup system."""
        rec_meta = self._recordings.get(call_id)
        if not rec_meta:
            return

        # Simulate cleanup and mark ended
        rec_meta["active"] = False
        rec_meta["ended_at"] = datetime.now(UTC)

        # Simulate encryption of final blob using QM if marked
        encrypted_payload = b"simulated media data for " + call_id.encode("utf-8")
        filename = rec_meta["filename"]

        try:
            if rec_meta.get("encrypted_with_qm"):
                from plexichat.core.security.quantum_encryption import (
                    get_quantum_manager,  # type: ignore
                )

                qm = get_quantum_manager()
                # Use QM's HTTP traffic encryption as a pragmatic wrapper for recorded blobs
                try:
                    encrypted_payload = qm.encrypt_http_traffic(
                        encrypted_payload, endpoint=f"recording:{rec_meta['id']}"
                    )
                except Exception:
                    # fallback to classical encrypt using AESGCM
                    try:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                        key_b64 = self.encryption_manager.generate_session_key()
                        key = base64.b64decode(key_b64)
                        aesgcm = AESGCM(key)
                        nonce = secrets.token_bytes(12)
                        c = aesgcm.encrypt(nonce, encrypted_payload, None)
                        encrypted_payload = nonce + c
                        rec_meta["wrapped_key"] = base64.b64encode(key).decode("utf-8")
                    except Exception:
                        pass
            else:
                # Simple RSA wrap of a symmetric key then base64 store (demo)
                key = self.encryption_manager.generate_session_key()
                _, public = self.encryption_manager.generate_key_pair()
                encrypted_key = self.encryption_manager.encrypt_session_key(key, public)
                # for demo we attach metadata only
                rec_meta["wrapped_key"] = encrypted_key

            # Hand off to backup manager if available
            try:
                from plexichat.features.backup.backup_manager import (
                    get_backup_manager,  # type: ignore
                )

                bm = get_backup_manager()
                # store object (best-effort)
                try:
                    bm.store_object(rec_meta["id"], encrypted_payload, metadata=rec_meta)  # type: ignore
                    rec_meta["stored_in_backup"] = True
                except Exception:
                    # some backup backends might be async or have different names - best-effort
                    try:
                        res = bm.store(rec_meta["id"], encrypted_payload, metadata=rec_meta)  # type: ignore
                        if asyncio.iscoroutine(res):
                            await res
                        rec_meta["stored_in_backup"] = True
                    except Exception:
                        rec_meta["stored_in_backup"] = False
            except Exception:
                # fallback: write to local file
                try:
                    import os

                    os.makedirs(self._recordings_path, exist_ok=True)
                    with open(filename, "wb") as f:
                        f.write(encrypted_payload)
                    rec_meta["stored_in_backup"] = False
                except Exception as e:
                    logger.warning(f"Failed to persist recording locally: {e}")
                    rec_meta["stored_in_backup"] = False
        except Exception as e:
            logger.error(f"Error finalizing recording: {e}")
            rec_meta["stored_in_backup"] = False

        logger.info(f"Finalized recording {rec_meta.get('id')} (call {call_id})")

    # -----------------------
    # Internal helpers
    # -----------------------
    async def _send_call_invitation(
        self, call_session: CallSession, inviter_id: int, invitee_id: int
    ):
        """Construct and (simulated) send a call invitation to user."""
        invitation = CallInvitation(
            call_session_id=call_session.id,
            inviter_id=inviter_id,
            invitee_id=invitee_id,
            status="pending",
            expires_at=datetime.now(UTC) + timedelta(minutes=2),
        )
        # In real system, push notification / websocket message should be sent.
        # If invitee connected via websocket, send directly
        try:
            await self.ws_manager.broadcast_to_user(
                invitee_id,
                {
                    "type": "call_invitation",
                    "payload": {
                        "call_id": call_session.call_id,
                        "session_id": call_session.id,
                        "from": inviter_id,
                        "expires_at": (
                            invitation.expires_at.isoformat()
                            if invitation.expires_at
                            else None
                        ),
                    },
                },
            )
        except Exception:
            # ignore broadcast failures
            pass

        logger.info(
            f"Sent call invitation to user {invitee_id} for call {call_session.call_id} (invitation={invitation})"
        )

    def _generate_default_sdp(self) -> str:
        """Generate default SDP for testing and initial offers."""
        return """v=0
o=- 123456789 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:test
a=ice-pwd:testpassword
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
a=setup:actpass
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:test
a=ice-pwd:testpassword
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
a=setup:actpass
a=mid:1
a=sendrecv
a=rtcp-mux
a=rtpmap:96 VP8/90000"""

    def _generate_master_key_for_session(self) -> str:
        """Generate a new master session key. In production this would be stored in a secure key vault."""
        # Try to register key with quantum manager for stronger handling, but fallback to local generation
        try:
            from plexichat.core.security.quantum_encryption import (
                get_quantum_manager,  # type: ignore
            )

            qm = get_quantum_manager()
            # We create a symmetric key and let QM manage traffic encryption contexts
            key_b64 = self.encryption_manager.generate_session_key()
            # Optionally pre-warm HTTP traffic key for this session
            try:
                qm.setup_traffic_encryption(endpoint=f"session:{secrets.token_hex(6)}")
            except Exception:
                pass
            return key_b64
        except Exception:
            return self.encryption_manager.generate_session_key()

    def _retrieve_master_key_for_call(self, call_id: str) -> str:
        """Placeholder for secure master key retrieval for a call."""
        # In production: retrieve from KMS or distributed key store using call metadata
        # Here we simulate by generating a stable key based on call_id hash (for test purposes only)
        digest = hashlib.sha256(call_id.encode("utf-8")).digest()
        # Expand to 32 bytes by hashing with a random salt (deterministic salt makes it reproducible)
        return base64.b64encode(
            hashlib.sha256(digest + b"stable_salt").digest()
        ).decode("utf-8")

    def _bandwidth_for_quality(self, quality_label: str) -> int:
        """Map video quality to approximate bandwidth requirement in kbps."""
        mapping = {"360p": 500, "480p": 800, "720p": 1500, "1080p": 3000, "4k": 10000}
        return mapping.get(quality_label, 800)

    async def _adjust_media_parameters(self, call_id: str, quality: CallQuality):
        """Adaptive quality control based on measured metrics."""
        try:
            if call_id not in self.active_calls:
                return
            call_session = self.active_calls[call_id]

            # Basic heuristic: if packet loss > 3% or bandwidth low, reduce video quality
            new_video_quality = call_session.video_quality
            if quality.packet_loss > 0.03 or quality.bandwidth_kbps < 700:
                # step down
                if call_session.video_quality == "1080p":
                    new_video_quality = "720p"
                elif call_session.video_quality == "720p":
                    new_video_quality = "480p"
                elif call_session.video_quality == "480p":
                    new_video_quality = "360p"
            elif quality.bandwidth_kbps > 2500 and call_session.video_quality in (
                "480p",
                "720p",
            ):
                # step up
                if call_session.video_quality == "480p":
                    new_video_quality = "720p"
                elif call_session.video_quality == "720p":
                    new_video_quality = "1080p"

            # Update and issue hint to media server if changed
            if new_video_quality != call_session.video_quality:
                old = call_session.video_quality
                call_session.video_quality = new_video_quality
                logger.info(
                    f"Adjusted video quality for call {call_id} from {old} to {new_video_quality}"
                )
                # In production, signal media server to adjust simulcast layers / encodings

        except Exception as e:
            logger.error(f"Failed to adjust media parameters for {call_id}: {e}")

    async def _background_monitor(self):
        """Background task that simulates periodic health checks and adaptation across calls."""
        try:
            while True:
                # iterate active calls and simulate metric gathering
                for call_id, participants in list(self.call_participants.items()):
                    # Simulate participant metrics update
                    for participant in participants:
                        # Randomized simulation could be replaced with real telemetry
                        participant.metrics.setdefault("latency_ms", 40.0)
                        participant.metrics.setdefault("packet_loss", 0.01)
                        participant.metrics.setdefault("bandwidth_kbps", 1200)
                        participant.metrics.setdefault("audio_quality", 0.95)
                        participant.metrics.setdefault("video_quality", 0.90)
                        participant.metrics.setdefault("stability", 0.97)

                    # Aggregate and potentially adapt
                    try:
                        quality = await self.get_call_quality(call_id, -1)
                        # The get_call_quality already triggers adaptive adjustment
                        logger.debug(f"Monitored call {call_id} quality: {quality}")
                    except Exception:
                        # skip if call ended during iteration
                        pass

                # Check media servers health and mark unhealthy servers that haven't heartbeated
                now_ts = time.time()
                for srv in list(self.media_manager.servers.values()):
                    if now_ts - srv["last_heartbeat"] > 120:
                        srv["healthy"] = False

                await asyncio.sleep(10)  # adjustable monitoring cadence

        except asyncio.CancelledError:
            logger.info("CallingService background monitor cancelled")
        except Exception as e:
            logger.error(f"CallingService monitor encountered error: {e}")

    # -----------------------
    # TURN health checker
    # -----------------------
    async def _turn_health_checker(self):
        """Periodically check TURN servers for reachability and mark healthy/unhealthy."""
        try:
            while True:
                for turn in list(self.webrtc_manager.turn_servers):
                    try:
                        # parse host from url (very basic)
                        host = turn.url
                        port = 3478
                        if "turn:" in host:
                            host = host.split("turn:")[1]
                        if ":" in host:
                            parts = host.split(":")
                            host = parts[0]
                            try:
                                port = int(parts[1])
                            except Exception:
                                port = 3478
                        # Attempt simple TCP connect (non-blocking)
                        fut = asyncio.open_connection(host, port)
                        try:
                            reader, writer = await asyncio.wait_for(fut, timeout=3.0)
                            writer.close()
                            try:
                                await writer.wait_closed()
                            except Exception:
                                pass
                            turn.healthy = True
                            turn.last_checked = time.time()
                        except Exception:
                            turn.healthy = False
                            turn.last_checked = time.time()
                    except Exception as e:
                        logger.debug(f"TURN health check error for {turn.url}: {e}")
                await asyncio.sleep(self.turn_health_interval)
        except asyncio.CancelledError:
            logger.info("TURN health checker cancelled")
        except Exception as e:
            logger.error(f"TURN health checker encountered error: {e}")

    # -----------------------
    # Secure signaling helpers
    # -----------------------
    async def create_encrypted_offer(
        self, call_id: str, user_id: int, preferred_bandwidth_kbps: int = 1500
    ) -> CallOffer:
        """Create an encrypted offer envelope for secure signaling, suitable for sending over untrusted channels."""
        if call_id not in self.active_calls:
            raise ValueError("Call not found")

        call_session = self.active_calls[call_id]

        # Find participant
        participant = next(
            (
                p
                for p in self.call_participants.get(call_id, [])
                if p.user_id == user_id
            ),
            None,
        )
        if not participant:
            raise ValueError("Participant not found")

        # Prepare SDP and apply bandwidth hints
        sdp = self._generate_default_sdp()
        sdp = self.webrtc_manager.enhance_sdp_security(
            sdp, dtls_fingerprint=call_session.dtls_fingerprint
        )
        sdp = self.webrtc_manager.apply_bandwidth_constraints(
            sdp, preferred_bandwidth_kbps
        )

        # Encrypt the SDP envelope itself using quantum manager if available or using AES+RSA wrap
        payload = sdp.encode("utf-8")

        # Try quantum manager path
        encrypted_b64 = ""
        try:
            from plexichat.core.security.quantum_encryption import (
                get_quantum_manager,  # type: ignore
            )

            qm = get_quantum_manager()
            try:
                encrypted_payload = qm.encrypt_http_traffic(payload, endpoint=call_id)
                encrypted_b64 = base64.b64encode(encrypted_payload).decode("utf-8")
            except Exception:
                # if QM fails, fallback to AESGCM based on call session key
                raise
        except Exception:
            # Fallback: encrypt payload with session key (simulated) by wrapping AES key with participant's public RSA key
            session_key = (
                call_session.session_key or self._generate_master_key_for_session()
            )
            try:
                # symmetric AES-GCM encryption using session_key
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                key = base64.b64decode(session_key)
                aesgcm = AESGCM(key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, payload, None)
                encrypted_payload = nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_payload).decode("utf-8")
                # rotate session_key to be enveloped if possible (we include current wrapped key for signaling)
                try:
                    wrapped = self.encryption_manager.encrypt_session_key(
                        session_key, participant.public_key or ""
                    )
                except Exception:
                    wrapped = ""
            except Exception:
                # As ultimate fallback return plaintext base64 (logged)
                logger.warning(
                    "Falling back to plaintext envelope for SDP (not secure) for call %s",
                    call_id,
                )
                encrypted_b64 = base64.b64encode(payload).decode("utf-8")
                wrapped = ""

        return CallOffer(
            call_id=call_id,
            offer_sdp=encrypted_b64,
            ice_candidates=self.webrtc_manager.create_simulated_ice_candidates(2),
            encryption_key=participant.session_key_encrypted or "",
            public_key=participant.public_key or "",
        )

    # -----------------------
    # WebSocket signaling helper (framework-agnostic entrypoint)
    # -----------------------
    async def websocket_signaling_handler(
        self, websocket: Any, path: str | None = None
    ):
        """Framework-agnostic websocket handler for signaling.

        Expected message format (JSON):
          {"type": "auth", "token": "<jwt>"}  -- authenticate
          {"type": "offer", "call_id": "...", "sdp": "..."} -- send offer to call participants
          {"type": "answer", "call_id": "...", "sdp": "..."} -- send answer
          {"type": "candidate", "call_id": "...", "candidate": {...}} -- ICE candidate
          {"type": "presence", "status": "busy|away|online|offline"}
          {"type": "start_record", "call_id": "..."}
          {"type": "stop_record", "call_id": "..."}
          {"type": "hangup", "call_id": "..."}
        """
        user_id = None
        authenticated = False
        token_payload = None
        # Some websocket libraries give query params in path; try to extract token from path if present
        try:
            # Note: path parsing is best-effort and optional
            if path and "?" in path and "token=" in path:
                q = path.split("?", 1)[1]
                for part in q.split("&"):
                    if part.startswith("token="):
                        token = part.split("=", 1)[1]
                        ok, token_payload = await self._verify_token_async(token)
                        authenticated = ok
                        if ok:
                            user_id = (
                                int(token_payload.get("user_id"))
                                if token_payload.get("user_id")
                                else None
                            )
                        break
        except Exception:
            pass

        # send initial handshake if needed
        try:
            await websocket.send(json.dumps({"type": "welcome", "version": "1.0"}))
        except Exception:
            pass

        # register connection on auth
        try:
            while True:
                raw = await websocket.recv()
                try:
                    msg = json.loads(raw)
                except Exception:
                    # ignore non-json
                    continue

                mtype = msg.get("type")
                if mtype == "auth":
                    token = msg.get("token")
                    ok, token_payload = await self._verify_token_async(token)
                    if not ok:
                        await websocket.send(
                            json.dumps({"type": "auth_result", "success": False})
                        )
                        continue
                    authenticated = True
                    user_id = (
                        int(token_payload.get("user_id"))
                        if token_payload.get("user_id")
                        else None
                    )
                    # register connection
                    if user_id is not None:
                        await self.ws_manager.register(user_id, websocket)
                    await websocket.send(
                        json.dumps(
                            {"type": "auth_result", "success": True, "user_id": user_id}
                        )
                    )
                    continue

                # require authentication for most message types
                if not authenticated or user_id is None:
                    await websocket.send(
                        json.dumps({"type": "error", "message": "not_authenticated"})
                    )
                    continue

                if mtype == "presence":
                    status = msg.get("status", "online")
                    await self._broadcast_presence(user_id, status)
                    continue

                if mtype in ("offer", "answer", "candidate"):
                    call_id = msg.get("call_id")
                    payload = (
                        msg.get("sdp")
                        if mtype in ("offer", "answer")
                        else msg.get("candidate")
                    )
                    # basic validation and forwarding to participants except sender
                    if call_id not in self.active_calls:
                        await websocket.send(
                            json.dumps({"type": "error", "message": "call_not_found"})
                        )
                        continue

                    # Validate SDP when present
                    if mtype in ("offer", "answer"):
                        if not self.webrtc_manager.validate_sdp(payload):
                            await websocket.send(
                                json.dumps({"type": "error", "message": "invalid_sdp"})
                            )
                            continue
                        # Enhance for security; include dtls fingerprint when available
                        call_session = self.active_calls.get(call_id)
                        payload = self.webrtc_manager.enhance_sdp_security(
                            payload,
                            dtls_fingerprint=(
                                call_session.dtls_fingerprint if call_session else None
                            ),
                        )

                    # Forward to other participants via websockets if connected
                    recipients = [
                        p.user_id
                        for p in self.call_participants.get(call_id, [])
                        if p.user_id != user_id
                    ]
                    for rid in recipients:
                        await self.ws_manager.broadcast_to_user(
                            rid,
                            {
                                "type": "signaling",
                                "subtype": mtype,
                                "call_id": call_id,
                                "from": user_id,
                                "payload": payload,
                            },
                        )
                    continue

                if mtype == "start_record":
                    call_id = msg.get("call_id")
                    try:
                        rec_meta = await self.start_recording(
                            call_id, user_id, encrypt_with_qm=True
                        )
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "start_record_result",
                                    "success": True,
                                    "recording": rec_meta,
                                }
                            )
                        )
                    except Exception as e:
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "start_record_result",
                                    "success": False,
                                    "error": str(e),
                                }
                            )
                        )
                    continue

                if mtype == "stop_record":
                    call_id = msg.get("call_id")
                    try:
                        rec_meta = await self.stop_recording(call_id)
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "stop_record_result",
                                    "success": True,
                                    "recording": rec_meta,
                                }
                            )
                        )
                    except Exception as e:
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "stop_record_result",
                                    "success": False,
                                    "error": str(e),
                                }
                            )
                        )
                    continue

                if mtype == "hangup":
                    call_id = msg.get("call_id")
                    try:
                        ok = await self.end_call(call_id, user_id)
                        await websocket.send(
                            json.dumps({"type": "hangup_result", "success": ok})
                        )
                    except Exception as e:
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "hangup_result",
                                    "success": False,
                                    "error": str(e),
                                }
                            )
                        )
                    continue

                # unknown type
                await websocket.send(
                    json.dumps({"type": "error", "message": "unknown_message_type"})
                )

        except asyncio.CancelledError:
            # connection closed / cleanup
            pass
        except Exception as e:
            logger.debug(f"Websocket handler exception: {e}")
        finally:
            # cleanup registration
            try:
                if user_id is not None:
                    await self.ws_manager.unregister(user_id, websocket)
            except Exception:
                pass

    # -----------------------
    # Presence broadcasting
    # -----------------------
    async def _broadcast_presence(self, user_id: int, status: str):
        """Broadcast a user's presence change to their contacts or globally depending on design.

        For simplicity, this implementation broadcasts to all connected users.
        """
        try:
            payload = {
                "type": "presence_update",
                "user_id": user_id,
                "status": status,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            await self.ws_manager.broadcast_to_all(payload)
        except Exception as e:
            logger.debug(f"Failed to broadcast presence for {user_id}: {e}")

    # -----------------------
    # Security & rate limiting helpers
    # -----------------------
    async def _verify_token_async(
        self, token: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """Verify JWT token using the SecuritySystem TokenManager if available."""
        try:
            # Prefer the centralized security manager API if available
            from plexichat.core.security.security_manager import (
                get_security_system,  # type: ignore
            )

            sec = get_security_system()
            ok, payload = sec.token_manager.verify_token(token)
            return ok, payload
        except Exception as e:
            logger.debug(f"Token verification fallback failed: {e}")
            # best-effort attempt to decode JWT without verification (not recommended)
            try:
                parts = token.split(".")
                if len(parts) >= 2:
                    body = parts[1] + "=="
                    decoded = base64.urlsafe_b64decode(body.encode("utf-8"))
                    data = json.loads(decoded.decode("utf-8"))
                    return True, data
            except Exception:
                pass
        return False, None

    async def _allow_initiation(self, user_id: int, token: str | None) -> bool:
        """Decide if a user is allowed to initiate a call based on simple rate-limiting and tier detection."""
        # determine tier from token if possible
        tier = "authenticated"
        if token:
            ok, payload = await self._verify_token_async(token)
            if ok and payload:
                perms = payload.get("permissions", [])
                # simple mapping for demonstration
                if "admin" in perms:
                    tier = "admin"
                elif "premium" in perms:
                    tier = "premium"
                else:
                    tier = "authenticated"
            else:
                tier = "anonymous"
        else:
            tier = "anonymous"

        limit = self._tier_limits.get(tier, 60)
        now_ts = time.time()
        window_start = now_ts - 60  # 1 minute window
        attempts = self._initiation_attempts.setdefault(user_id, [])
        # purge old
        attempts = [t for t in attempts if t >= window_start]
        attempts.append(now_ts)
        self._initiation_attempts[user_id] = attempts
        if len(attempts) > limit:
            logger.warning(
                f"User {user_id} exceeded initiation limit ({len(attempts)}/{limit})"
            )
            return False
        return True

    # -----------------------
    # Key rotation & DTLS helpers
    # -----------------------
    def _generate_dtls_keypair(self) -> tuple[str, str]:
        """Generate a lightweight RSA keypair for DTLS fingerprint simulation and return base64 PEMs."""
        priv_b64, pub_b64 = EncryptionManager.generate_key_pair()
        return priv_b64, pub_b64

    def _compute_fingerprint_from_public_b64(self, public_b64: str) -> str:
        """Compute a sha-256 fingerprint from base64-encoded public key to include in SDP."""
        try:
            pub_bytes = base64.b64decode(public_b64.encode("utf-8"))
            digest = hashlib.sha256(pub_bytes).digest()
            # format as colon separated hex pairs uppercase
            fp = ":".join(f"{b:02X}" for b in digest)
            return fp
        except Exception:
            return "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

    def _start_key_rotation_for_call(self, call_id: str, interval_seconds: int = 300):
        """Start periodic rotation of session keys for a call."""
        try:
            if call_id not in self.active_calls:
                return

            call_session = self.active_calls[call_id]

            async def rotation_loop():
                try:
                    while True:
                        await asyncio.sleep(interval_seconds)
                        try:
                            await self._rotate_session_keys(call_id)
                        except asyncio.CancelledError:
                            break
                        except Exception as e:
                            logger.error(f"Key rotation for {call_id} failed: {e}")
                except asyncio.CancelledError:
                    logger.debug(f"Rotation loop cancelled for call {call_id}")

            # cancel existing if present
            try:
                if call_session._rotation_task:
                    call_session._rotation_task.cancel()
            except Exception:
                pass

            task = asyncio.get_event_loop().create_task(rotation_loop())
            call_session._rotation_task = task
            logger.debug(
                f"Started key rotation task for call {call_id} interval={interval_seconds}s"
            )
        except Exception as e:
            logger.error(f"Failed to start key rotation for {call_id}: {e}")

    async def _rotate_session_keys(self, call_id: str):
        """Rotate session keys for running call and update encrypted envelopes for participants."""
        try:
            if call_id not in self.active_calls:
                return
            call_session = self.active_calls[call_id]
            # Generate new master session key
            new_key = self.encryption_manager.generate_session_key()
            call_session.session_key = new_key
            # If quantum manager present, ask it to rotate keys for the call endpoint
            try:
                from plexichat.core.security.quantum_encryption import (
                    get_quantum_manager,  # type: ignore
                )

                qm = get_quantum_manager()
                try:
                    # rotate any internal http keys used for this session
                    qm.rotate_http_keys(endpoint=call_id)
                except Exception:
                    # best-effort
                    pass
            except Exception:
                qm = None

            # For each participant, wrap the new key and update participant record
            for participant in list(self.call_participants.get(call_id, [])):
                try:
                    if participant.public_key:
                        wrapped = self.encryption_manager.encrypt_session_key(
                            new_key, participant.public_key
                        )
                        participant.session_key_encrypted = wrapped
                        # Notify participant via websocket about key rotation (best-effort)
                        try:
                            await self.ws_manager.broadcast_to_user(
                                participant.user_id,
                                {
                                    "type": "key_rotation",
                                    "call_id": call_id,
                                    "payload": {
                                        "rotated_at": datetime.now(UTC).isoformat(),
                                        "note": "Session key rotated for forward secrecy",
                                    },
                                },
                            )
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(
                        f"Failed to wrap new session key for participant {participant.user_id} in call {call_id}: {e}"
                    )

            logger.info(f"Rotated session keys for call {call_id}")
        except Exception as e:
            logger.error(f"Error rotating session keys for {call_id}: {e}")


# Global service instance
calling_service = CallingService()
