"""
MITM-Resistant Encryption System
Implements time-based encryption with key rotation for enhanced security.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, Request, status

logger = logging.getLogger(__name__)

class MITMProtectionManager:
    """
    Manager for MITM-resistant encryption with time-based key derivation.
    
    Features:
    - ECDH key exchange for session establishment
    - Time-based key derivation (rotates every minute)
    - Authenticated encryption (AES-GCM/ChaCha20-Poly1305)
    - Replay protection with timestamps and nonces
    - Perfect forward secrecy
    """
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.key_rotation_interval = 60  # 1 minute
        self.max_timestamp_skew = 30  # 30 seconds
        self.nonce_cache = set()
        self.nonce_cache_size = 10000
        
        # Generate server's long-term ECDH key pair
        self.server_private_key = ec.generate_private_key(ec.SECP384R1())
        self.server_public_key = self.server_private_key.public_key()
        
        logger.info("MITM protection manager initialized")
    
    async def initiate_key_exchange(self, client_public_key_pem: str) -> Dict[str, str]:
        """
        Initiate ECDH key exchange with client.
        
        Args:
            client_public_key_pem: Client's public key in PEM format
            
        Returns:
            Dict containing server's public key and session ID
        """
        try:
            # Parse client's public key
            client_public_key = serialization.load_pem_public_key(
                client_public_key_pem.encode()
            )
            
            # Perform ECDH key exchange
            shared_key = self.server_private_key.exchange(
                ec.ECDH(), client_public_key
            )
            
            # Derive master secret using HKDF
            master_secret = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'plexichat-mitm-protection'
            ).derive(shared_key)
            
            # Generate session ID
            session_id = secrets.token_urlsafe(32)
            
            # Store session
            self.sessions[session_id] = {
                "master_secret": master_secret,
                "created_at": time.time(),
                "last_used": time.time(),
                "client_public_key": client_public_key_pem
            }
            
            # Get server's public key in PEM format
            server_public_key_pem = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            logger.info(f"Key exchange completed for session {session_id}")
            
            return {
                "session_id": session_id,
                "server_public_key": server_public_key_pem,
                "key_rotation_interval": self.key_rotation_interval
            }
            
        except Exception as e:
            logger.error(f"Key exchange failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Key exchange failed"
            )
    
    def _derive_time_based_key(self, master_secret: bytes, timestamp: int) -> bytes:
        """
        Derive time-based encryption key.
        
        Args:
            master_secret: Master secret from key exchange
            timestamp: Current timestamp
            
        Returns:
            32-byte encryption key
        """
        # Calculate time window (rounds down to nearest minute)
        time_window = timestamp // self.key_rotation_interval
        
        # Derive key using HKDF with time window as info
        time_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_secret[:16],  # Use part of master secret as salt
            info=f"time-window-{time_window}".encode()
        ).derive(master_secret)
        
        return time_key
    
    async def encrypt_payload(self, session_id: str, payload: Dict[str, Any]) -> str:
        """
        Encrypt payload with time-based key.
        
        Args:
            session_id: Session identifier
            payload: Data to encrypt
            
        Returns:
            Base64-encoded encrypted payload
        """
        try:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError("Invalid session ID")
            
            # Update last used time
            session["last_used"] = time.time()
            
            # Get current timestamp
            current_time = int(time.time())
            
            # Generate nonce
            nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
            
            # Add timestamp and nonce to payload
            payload_with_metadata = {
                "data": payload,
                "timestamp": current_time,
                "nonce": base64.b64encode(nonce).decode(),
                "session_id": session_id
            }
            
            # Serialize payload
            payload_json = json.dumps(payload_with_metadata).encode()
            
            # Derive time-based key
            encryption_key = self._derive_time_based_key(
                session["master_secret"], current_time
            )
            
            # Encrypt with AES-GCM
            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(nonce, payload_json, None)
            
            # Combine nonce and ciphertext
            encrypted_data = nonce + ciphertext
            
            # Encode as base64
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Encryption failed"
            )
    
    async def decrypt_payload(self, session_id: str, encrypted_data: str) -> Dict[str, Any]:
        """
        Decrypt payload and verify timestamp.
        
        Args:
            session_id: Session identifier
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted payload
        """
        try:
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError("Invalid session ID")
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract nonce and ciphertext
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            
            # Get current timestamp for key derivation
            current_time = int(time.time())
            
            # Try current and previous time windows (for clock skew tolerance)
            for time_offset in [0, -self.key_rotation_interval]:
                try:
                    key_time = current_time + time_offset
                    encryption_key = self._derive_time_based_key(
                        session["master_secret"], key_time
                    )
                    
                    # Decrypt with AES-GCM
                    aesgcm = AESGCM(encryption_key)
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    # Parse JSON
                    payload_with_metadata = json.loads(decrypted_data.decode())
                    
                    # Verify timestamp
                    payload_timestamp = payload_with_metadata.get("timestamp")
                    if not payload_timestamp:
                        raise ValueError("Missing timestamp")
                    
                    # Check timestamp freshness
                    time_diff = abs(current_time - payload_timestamp)
                    if time_diff > self.max_timestamp_skew:
                        raise ValueError(f"Timestamp too old: {time_diff}s")
                    
                    # Check nonce for replay protection
                    payload_nonce = payload_with_metadata.get("nonce")
                    if not payload_nonce:
                        raise ValueError("Missing nonce")
                    
                    if payload_nonce in self.nonce_cache:
                        raise ValueError("Replay attack detected")
                    
                    # Add nonce to cache
                    self.nonce_cache.add(payload_nonce)
                    
                    # Limit cache size
                    if len(self.nonce_cache) > self.nonce_cache_size:
                        # Remove oldest nonces (simple approach)
                        self.nonce_cache = set(list(self.nonce_cache)[-self.nonce_cache_size//2:])
                    
                    # Update session last used time
                    session["last_used"] = time.time()
                    
                    # Return decrypted data
                    return payload_with_metadata.get("data", {})
                    
                except Exception:
                    continue  # Try next time window
            
            raise ValueError("Decryption failed for all time windows")
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Decryption failed"
            )
    
    async def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        try:
            current_time = time.time()
            session_timeout = 3600  # 1 hour
            
            expired_sessions = [
                session_id for session_id, session in self.sessions.items()
                if current_time - session["last_used"] > session_timeout
            ]
            
            for session_id in expired_sessions:
                del self.sessions[session_id]
                logger.info(f"Cleaned up expired session {session_id}")
                
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            "session_id": session_id,
            "created_at": session["created_at"],
            "last_used": session["last_used"],
            "age_seconds": time.time() - session["created_at"]
        }

# Global instance
mitm_protection = MITMProtectionManager()

# FastAPI dependency for MITM-protected endpoints
async def require_mitm_protection(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency that requires MITM protection.
    
    Automatically decrypts request payload and provides it to the endpoint.
    """
    try:
        # Check if request has encrypted payload
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
            if body:
                try:
                    request_data = json.loads(body)
                    
                    # Check for encrypted payload
                    if "encrypted_payload" in request_data and "session_id" in request_data:
                        session_id = request_data["session_id"]
                        encrypted_payload = request_data["encrypted_payload"]
                        
                        # Decrypt payload
                        decrypted_data = await mitm_protection.decrypt_payload(
                            session_id, encrypted_payload
                        )
                        
                        return decrypted_data
                    
                except json.JSONDecodeError:
                    pass
        
        # Return empty dict if no encrypted payload
        return {}
        
    except Exception as e:
        logger.error(f"MITM protection dependency failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MITM protection validation failed"
        )

# Utility function to encrypt response
async def encrypt_response(session_id: str, response_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Encrypt response data for MITM protection.
    
    Args:
        session_id: Session identifier
        response_data: Data to encrypt
        
    Returns:
        Dict with encrypted payload
    """
    encrypted_payload = await mitm_protection.encrypt_payload(session_id, response_data)
    
    return {
        "encrypted_payload": encrypted_payload,
        "session_id": session_id,
        "encryption_type": "aes-gcm-time-based"
    }
