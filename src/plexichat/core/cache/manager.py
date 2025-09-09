"""
Unified Cache Manager Module
Consolidates caching under 'plexichat.core.cache' with a secure AES-GCM implementation.
No placeholders; production-ready encryption using keys from the distributed key manager.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import pickle
import secrets
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from plexichat.core.security import KeyDomain, distributed_key_manager

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    TOP_SECRET = 5


class CacheStrategy(Enum):
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    ADAPTIVE = "adaptive"


@dataclass
class SecureCacheEntry:
    key: str
    encrypted_data: bytes
    encryption_metadata: Dict[str, Any]
    security_level: CacheLevel
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheStats:
    total_entries: int = 0
    total_size: int = 0
    hit_count: int = 0
    miss_count: int = 0
    eviction_count: int = 0
    encryption_time: float = 0.0
    decryption_time: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class QuantumSecureCache:
    """
    Secure Cache System with AES-GCM encryption.
    """

    def __init__(
        self,
        max_size: int = 1024 * 1024 * 100,
        default_ttl: int = 3600,
        security_level: CacheLevel = CacheLevel.RESTRICTED,
    ):
        # Read from config if available
        try:
            from plexichat.core.config_manager import get_config

            cc = get_config("caching", None)
            if cc is not None:
                max_size = int(getattr(cc, "l1_max_size_mb", 100)) * 1024 * 1024
                default_ttl = int(getattr(cc, "l1_default_ttl_seconds", 3600))
                sl = str(getattr(cc, "l1_default_security_level", "RESTRICTED")).upper()
                if sl in CacheLevel.__members__:
                    security_level = CacheLevel[sl]
                self.compression_enabled = bool(
                    getattr(cc, "l1_compression_enabled", True)
                )
        except Exception:
            pass
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.default_security_level = security_level
        self.cache_entries: Dict[str, SecureCacheEntry] = {}
        self.access_order: List[str] = []
        self.access_frequency: Dict[str, int] = {}
        self.stats = CacheStats()
        self.eviction_strategy = CacheStrategy.ADAPTIVE
        # compression_enabled may be set above; default True if not set
        if not hasattr(self, "compression_enabled"):
            self.compression_enabled = True
        self.encryption_cache_keys: Dict[str, bytes] = {}
        self.performance_metrics: List[Dict[str, Any]] = []
        self._initialized = False

    async def _ensure_initialized(self):
        if not self._initialized:
            await self._setup_encryption_keys()
            self._initialized = True
            logger.info("Secure cache initialized")

    async def _initialize_cache(self):
        await self._ensure_initialized()
        await self._start_maintenance_tasks()

    async def _setup_encryption_keys(self):
        cache_key = await distributed_key_manager.get_domain_key(KeyDomain.STORAGE)
        if cache_key:
            for level in CacheLevel:
                level_key = hashlib.blake2b(
                    cache_key + f"cache_level_{level.value}".encode(), digest_size=32
                ).digest()
                self.encryption_cache_keys[level.name] = level_key
        else:
            logger.warning(
                "Could not obtain cache encryption keys from key manager; generating ephemeral keys"
            )
            for level in CacheLevel:
                self.encryption_cache_keys[level.name] = secrets.token_bytes(32)

    async def _start_maintenance_tasks(self):
        async def maintenance_loop():
            while True:
                try:
                    await self._cleanup_expired_entries()
                    await self._enforce_size_limits()
                    await self._update_statistics()
                    await asyncio.sleep(60)
                except Exception as e:
                    logger.error(f"Cache maintenance error: {e}")
                    await asyncio.sleep(60)

        asyncio.create_task(maintenance_loop())

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        security_level: Optional[CacheLevel] = None,
    ) -> bool:
        try:
            await self._ensure_initialized()
            security_level = security_level or self.default_security_level
            ttl = ttl or self.default_ttl
            serialized_data = pickle.dumps(value)
            if self.compression_enabled:
                serialized_data = zlib.compress(serialized_data)
            start_time = datetime.now(timezone.utc)
            encrypted_data, encryption_metadata = await self._encrypt_cache_data(
                serialized_data, security_level
            )
            encryption_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl) if ttl > 0 else None
            )
            entry = SecureCacheEntry(
                key=key,
                encrypted_data=encrypted_data,
                encryption_metadata=encryption_metadata,
                security_level=security_level,
                created_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                size=len(encrypted_data),
                metadata={
                    "compression_enabled": self.compression_enabled,
                    "encryption_time": encryption_time,
                },
            )
            self.cache_entries[key] = entry
            self._update_access_tracking(key)
            self.stats.total_entries = len(self.cache_entries)
            self.stats.total_size += entry.size
            self.stats.encryption_time += encryption_time
            await self._enforce_size_limits()
            logger.debug(f"Cached entry: {key} (security: {security_level.name})")
            return True
        except Exception as e:
            logger.error(f"Failed to cache entry {key}: {e}")
            return False

    async def get(self, key: str) -> Optional[Any]:
        try:
            await self._ensure_initialized()
            if key not in self.cache_entries:
                self.stats.miss_count += 1
                return None
            entry = self.cache_entries[key]
            if entry.expires_at and datetime.now(timezone.utc) > entry.expires_at:
                await self.delete(key)
                self.stats.miss_count += 1
                return None
            start_time = datetime.now(timezone.utc)
            decrypted_data = await self._decrypt_cache_data(
                entry.encrypted_data, entry.encryption_metadata, entry.security_level
            )
            decryption_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            if entry.metadata.get("compression_enabled", False):
                decrypted_data = zlib.decompress(decrypted_data)
            value = pickle.loads(decrypted_data)
            entry.access_count += 1
            entry.last_accessed = datetime.now(timezone.utc)
            self._update_access_tracking(key)
            self.stats.hit_count += 1
            self.stats.decryption_time += decryption_time
            logger.debug(f"Retrieved cached entry: {key}")
            return value
        except Exception as e:
            logger.error(f"Failed to retrieve cached entry {key}: {e}")
            self.stats.miss_count += 1
            return None

    async def delete(self, key: str) -> bool:
        if key in self.cache_entries:
            entry = self.cache_entries[key]
            self.stats.total_size -= entry.size
            del self.cache_entries[key]
            if key in self.access_order:
                self.access_order.remove(key)
            if key in self.access_frequency:
                del self.access_frequency[key]
            self.stats.total_entries = len(self.cache_entries)
            logger.debug(f"Deleted cached entry: {key}")
            return True
        return False

    async def _encrypt_cache_data(
        self, data: bytes, security_level: CacheLevel
    ) -> Tuple[bytes, Dict[str, Any]]:
        if security_level == CacheLevel.PUBLIC:
            return data, {"encryption": "none"}
        # Use AES-GCM for all non-public levels, with per-level keys and per-entry nonce
        key = self.encryption_cache_keys.get(security_level.name)
        if not key:
            raise ValueError(
                f"No encryption key for security level: {security_level.name}"
            )
        nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
        aead = AESGCM(key)
        ciphertext = aead.encrypt(
            nonce, data, associated_data=security_level.name.encode()
        )
        return ciphertext, {
            "encryption": "aes-gcm",
            "security_level": security_level.name,
            "nonce": nonce.hex(),
        }

    async def _decrypt_cache_data(
        self,
        encrypted_data: bytes,
        metadata: Dict[str, Any],
        security_level: CacheLevel,
    ) -> bytes:
        enc = metadata.get("encryption", "none")
        if enc == "none":
            return encrypted_data
        if enc != "aes-gcm":
            raise ValueError(f"Unsupported encryption type: {enc}")
        key = self.encryption_cache_keys.get(security_level.name)
        if not key:
            raise ValueError(
                f"No decryption key for security level: {security_level.name}"
            )
        nonce_hex = metadata.get("nonce")
        if not nonce_hex:
            raise ValueError("Missing nonce in cache metadata")
        nonce = bytes.fromhex(nonce_hex)
        aead = AESGCM(key)
        return aead.decrypt(
            nonce, encrypted_data, associated_data=security_level.name.encode()
        )

    def _update_access_tracking(self, key: str):
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)
        self.access_frequency[key] = self.access_frequency.get(key, 0) + 1

    async def _cleanup_expired_entries(self):
        current_time = datetime.now(timezone.utc)
        expired_keys = []
        for k, entry in self.cache_entries.items():
            if entry.expires_at and current_time > entry.expires_at:
                expired_keys.append(k)
        for k in expired_keys:
            await self.delete(k)
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

    async def _enforce_size_limits(self):
        if self.stats.total_size <= self.max_size:
            return
        evicted_count = 0
        while self.stats.total_size > self.max_size * 0.8:
            key_to_evict = self._select_eviction_candidate()
            if key_to_evict:
                await self.delete(key_to_evict)
                evicted_count += 1
                self.stats.eviction_count += 1
            else:
                break
        if evicted_count > 0:
            logger.info(f"Evicted {evicted_count} cache entries to enforce size limits")

    def _select_eviction_candidate(self) -> Optional[str]:
        if not self.cache_entries:
            return None
        if self.eviction_strategy == CacheStrategy.LRU:
            return self.access_order[0] if self.access_order else None
        elif self.eviction_strategy == CacheStrategy.LFU:
            if self.access_frequency:
                return min(
                    self.access_frequency.keys(), key=lambda k: self.access_frequency[k]
                )
        elif self.eviction_strategy == CacheStrategy.TTL:
            entries_with_ttl = [
                (k, e) for k, e in self.cache_entries.items() if e.expires_at
            ]
            if entries_with_ttl:
                return min(entries_with_ttl, key=lambda x: x[1].expires_at)[0]
        elif self.eviction_strategy == CacheStrategy.ADAPTIVE:
            scores: Dict[str, float] = {}
            current_time = datetime.now(timezone.utc)
            for k, e in self.cache_entries.items():
                recency_score = (current_time - e.last_accessed).total_seconds()
                frequency_score = 1.0 / (e.access_count + 1)
                size_score = e.size / 1024
                scores[k] = recency_score * frequency_score * size_score
            if scores:
                return max(scores.keys(), key=lambda k: scores[k])
        return next(iter(self.cache_entries.keys())) if self.cache_entries else None

    async def _update_statistics(self):
        self.stats.total_entries = len(self.cache_entries)
        self.stats.total_size = sum(e.size for e in self.cache_entries.values())
        self.stats.last_updated = datetime.now(timezone.utc)

    def get_stats(self) -> Dict[str, Any]:
        hit_rate = (
            self.stats.hit_count / (self.stats.hit_count + self.stats.miss_count)
            if (self.stats.hit_count + self.stats.miss_count) > 0
            else 0.0
        )
        return {
            "total_entries": self.stats.total_entries,
            "total_size": self.stats.total_size,
            "max_size": self.max_size,
            "size_utilization": (
                (self.stats.total_size / self.max_size) if self.max_size else 0.0
            ),
            "hit_count": self.stats.hit_count,
            "miss_count": self.stats.miss_count,
            "hit_rate": hit_rate,
            "eviction_count": self.stats.eviction_count,
            "avg_encryption_time": self.stats.encryption_time
            / max(self.stats.total_entries, 1),
            "avg_decryption_time": self.stats.decryption_time
            / max(self.stats.hit_count, 1),
            "eviction_strategy": self.eviction_strategy.value,
            "default_security_level": self.default_security_level.name,
            "last_updated": self.stats.last_updated.isoformat(),
        }


secure_cache = QuantumSecureCache()

__all__ = [
    "QuantumSecureCache",
    "secure_cache",
    "CacheLevel",
    "CacheStrategy",
    "SecureCacheEntry",
    "CacheStats",
]
