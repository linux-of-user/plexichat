"""
Database Proxy Manager

Provides proxy mode operation when main database is lost, caching messages
and operations for later storage when database connectivity is restored.
"""

import asyncio
import logging
import secrets
import json
import gzip
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import aiofiles
from collections import deque

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    """Proxy operation modes."""
    NORMAL = "normal"
    PROXY_ACTIVE = "proxy_active"
    RECOVERY_MODE = "recovery_mode"
    EMERGENCY = "emergency"


class MessageType(Enum):
    """Types of cached messages."""
    CHAT_MESSAGE = "chat_message"
    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    BACKUP_OPERATION = "backup_operation"
    ADMIN_COMMAND = "admin_command"


class CacheStatus(Enum):
    """Status of cached operations."""
    PENDING = "pending"
    PROCESSING = "processing"
    STORED = "stored"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class CachedMessage:
    """Represents a cached message during proxy mode."""
    message_id: str
    message_type: MessageType
    user_id: Optional[str]
    channel_id: Optional[str]
    content: Dict[str, Any]
    timestamp: datetime
    priority: int
    status: CacheStatus
    retry_count: int = 0
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyStats:
    """Proxy mode statistics."""
    mode: ProxyMode
    started_at: datetime
    messages_cached: int
    messages_processed: int
    messages_failed: int
    cache_size_bytes: int
    database_reconnect_attempts: int
    last_database_contact: Optional[datetime]


class DatabaseProxyManager:
    """
    Database Proxy Manager
    
    Provides resilient operation when main database is unavailable:
    - Message caching during database outages
    - Automatic database reconnection
    - Priority-based message processing
    - Cache persistence and recovery
    - Emergency operation modes
    - Seamless transition back to normal operation
    """
    
    def __init__(self, backup_manager):
        """Initialize the database proxy manager."""
        self.backup_manager = backup_manager
        self.proxy_dir = backup_manager.backup_dir / "proxy"
        self.cache_dir = self.proxy_dir / "cache"
        self.emergency_dir = self.proxy_dir / "emergency"
        
        # Ensure directories exist
        for directory in [self.proxy_dir, self.cache_dir, self.emergency_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Proxy state
        self.current_mode = ProxyMode.NORMAL
        self.message_cache: deque = deque(maxlen=10000)  # In-memory cache
        self.cached_messages: Dict[str, CachedMessage] = {}
        self.proxy_stats = ProxyStats(
            mode=ProxyMode.NORMAL,
            started_at=datetime.now(timezone.utc),
            messages_cached=0,
            messages_processed=0,
            messages_failed=0,
            cache_size_bytes=0,
            database_reconnect_attempts=0,
            last_database_contact=datetime.now(timezone.utc)
        )
        
        # Configuration
        self.max_cache_size = 100 * 1024 * 1024  # 100MB
        self.max_cache_age_hours = 72  # 3 days
        self.reconnect_interval = 30  # 30 seconds
        self.max_retry_attempts = 5
        self.high_priority_threshold = 8
        
        # Database connections
        self.main_db_available = True
        self.proxy_db_path = backup_manager.databases_dir / "proxy_cache.db"
        
        logger.info("Database Proxy Manager initialized")
    
    async def initialize(self):
        """Initialize the proxy manager."""
        await self._initialize_proxy_database()
        await self._load_cached_messages()
        await self._check_database_connectivity()
        
        # Start background tasks
        asyncio.create_task(self._database_monitoring_task())
        asyncio.create_task(self._cache_processing_task())
        asyncio.create_task(self._cache_cleanup_task())
        
        logger.info("Proxy Manager initialized successfully")
    
    async def _initialize_proxy_database(self):
        """Initialize proxy cache database."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            # Cached messages table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cached_messages (
                    message_id TEXT PRIMARY KEY,
                    message_type TEXT NOT NULL,
                    user_id TEXT,
                    channel_id TEXT,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    expires_at TEXT,
                    metadata TEXT
                )
            """)
            
            # Proxy statistics table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS proxy_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    messages_cached INTEGER DEFAULT 0,
                    messages_processed INTEGER DEFAULT 0,
                    messages_failed INTEGER DEFAULT 0,
                    cache_size_bytes INTEGER DEFAULT 0,
                    database_reconnect_attempts INTEGER DEFAULT 0
                )
            """)
            
            # Database connectivity log
            await db.execute("""
                CREATE TABLE IF NOT EXISTS connectivity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    database_available BOOLEAN NOT NULL,
                    response_time_ms REAL,
                    error_message TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_cached_messages(self):
        """Load cached messages from persistent storage."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            async with db.execute("SELECT * FROM cached_messages WHERE status IN ('pending', 'processing')") as cursor:
                async for row in cursor:
                    message = CachedMessage(
                        message_id=row[0],
                        message_type=MessageType(row[1]),
                        user_id=row[2],
                        channel_id=row[3],
                        content=json.loads(row[4]),
                        timestamp=datetime.fromisoformat(row[5]),
                        priority=row[6],
                        status=CacheStatus(row[7]),
                        retry_count=row[8],
                        expires_at=datetime.fromisoformat(row[9]) if row[9] else None,
                        metadata=json.loads(row[10]) if row[10] else {}
                    )
                    self.cached_messages[message.message_id] = message
                    self.message_cache.append(message)
        
        logger.info(f"Loaded {len(self.cached_messages)} cached messages from persistent storage")
    
    async def _check_database_connectivity(self):
        """Check main database connectivity."""
        try:
            # Try to connect to main database
            # This would be replaced with actual database connection test
            start_time = datetime.now(timezone.utc)
            
            # Simulate database check
            await asyncio.sleep(0.1)  # Simulate connection time
            
            response_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            self.main_db_available = True
            self.proxy_stats.last_database_contact = datetime.now(timezone.utc)
            
            # Log connectivity event
            await self._log_connectivity_event("database_check", True, response_time)
            
            # Switch to normal mode if we were in proxy mode
            if self.current_mode != ProxyMode.NORMAL:
                await self._switch_to_normal_mode()
            
        except Exception as e:
            self.main_db_available = False
            await self._log_connectivity_event("database_check", False, None, str(e))
            
            # Switch to proxy mode if not already
            if self.current_mode == ProxyMode.NORMAL:
                await self._switch_to_proxy_mode()
    
    async def _switch_to_proxy_mode(self):
        """Switch to proxy mode when database is unavailable."""
        self.current_mode = ProxyMode.PROXY_ACTIVE
        self.proxy_stats.mode = ProxyMode.PROXY_ACTIVE
        
        logger.warning("Switched to PROXY MODE - database unavailable, caching messages")
        
        # Notify system components about proxy mode
        await self._notify_proxy_mode_change(ProxyMode.PROXY_ACTIVE)
    
    async def _switch_to_normal_mode(self):
        """Switch back to normal mode when database is available."""
        previous_mode = self.current_mode
        self.current_mode = ProxyMode.NORMAL
        self.proxy_stats.mode = ProxyMode.NORMAL
        
        logger.info("Switched to NORMAL MODE - database connectivity restored")
        
        # Process any cached messages
        if previous_mode != ProxyMode.NORMAL:
            await self._process_cached_messages()
        
        # Notify system components about mode change
        await self._notify_proxy_mode_change(ProxyMode.NORMAL)
    
    async def _notify_proxy_mode_change(self, new_mode: ProxyMode):
        """Notify system components about proxy mode changes."""
        # This would notify other system components
        logger.info(f"Proxy mode changed to: {new_mode.value}")
    
    async def cache_message(
        self,
        message_type: MessageType,
        content: Dict[str, Any],
        user_id: Optional[str] = None,
        channel_id: Optional[str] = None,
        priority: int = 5
    ) -> str:
        """Cache a message during proxy mode."""
        message_id = f"cached_{message_type.value}_{secrets.token_hex(16)}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Create cached message
        cached_message = CachedMessage(
            message_id=message_id,
            message_type=message_type,
            user_id=user_id,
            channel_id=channel_id,
            content=content,
            timestamp=datetime.now(timezone.utc),
            priority=priority,
            status=CacheStatus.PENDING,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=self.max_cache_age_hours)
        )
        
        # Add to cache
        self.cached_messages[message_id] = cached_message
        self.message_cache.append(cached_message)
        self.proxy_stats.messages_cached += 1
        
        # Save to persistent storage
        await self._save_cached_message(cached_message)
        
        logger.debug(f"Cached message {message_id} (type: {message_type.value}, priority: {priority})")
        return message_id
    
    async def _save_cached_message(self, message: CachedMessage):
        """Save cached message to persistent storage."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO cached_messages (
                    message_id, message_type, user_id, channel_id, content,
                    timestamp, priority, status, retry_count, expires_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message.message_id,
                message.message_type.value,
                message.user_id,
                message.channel_id,
                json.dumps(message.content),
                message.timestamp.isoformat(),
                message.priority,
                message.status.value,
                message.retry_count,
                message.expires_at.isoformat() if message.expires_at else None,
                json.dumps(message.metadata)
            ))
            await db.commit()
    
    async def _log_connectivity_event(
        self,
        event_type: str,
        database_available: bool,
        response_time_ms: Optional[float] = None,
        error_message: Optional[str] = None
    ):
        """Log database connectivity events."""
        async with aiosqlite.connect(self.proxy_db_path) as db:
            await db.execute("""
                INSERT INTO connectivity_log (
                    timestamp, event_type, database_available, response_time_ms, error_message
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                event_type,
                database_available,
                response_time_ms,
                error_message
            ))
            await db.commit()
