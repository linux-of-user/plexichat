#!/usr/bin/env python3
"""
Database Service Layer for PlexiChat API

This service layer provides a clean interface between API endpoints and the database
abstraction layer, with integrated caching for optimal performance.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import json
import hashlib

# Import database abstraction layer
try:
    from plexichat.core.database import (
        database_manager, execute_query, get_database_manager,
        DatabaseConfig, DatabaseType
    )
    DATABASE_AVAILABLE = True
except ImportError:
    database_manager = None
    execute_query = None
    DATABASE_AVAILABLE = False

# Import unified config system
try:
    from plexichat.core.unified_config import get_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    def get_config(): return None

# Import caching system
try:
    from plexichat.core.caching.unified_cache_integration import (
        cache_get, cache_set, cache_delete, CacheKeyBuilder
    )
    CACHE_AVAILABLE = True
except ImportError:
    async def cache_get(key: str, default=None): return default
    async def cache_set(key: str, value, ttl=None): return True
    async def cache_delete(key: str): return True
    class CacheKeyBuilder:
        @staticmethod
        def user_key(user_id: str): return f"user:{user_id}"
        @staticmethod
        def message_key(msg_id: str): return f"message:{msg_id}"
        @staticmethod
        def session_key(session_id: str): return f"session:{session_id}"
    CACHE_AVAILABLE = False

logger = logging.getLogger(__name__)

class DatabaseService:
    """
    Database service layer that provides a unified interface for all database operations
    with integrated caching and fallback to in-memory storage.
    
        def __init__(self):
        self.db_manager = None
        self.fallback_storage = {
            'users': {},
            'messages': {},
            'sessions': {},
            'files': {}
        }
        self.initialized = False
    
    async def initialize(self):
        """Initialize the database service using unified configuration."""
        try:
            # Get configuration
            config = get_config() if CONFIG_AVAILABLE else None

            if DATABASE_AVAILABLE and database_manager:
                self.db_manager = database_manager

                # Configure database manager with unified config if available
                if config:
                    db_config = config.database
                    logger.info(f"Initializing database service with {db_config.type} database")

                    # Apply database configuration
                    if hasattr(database_manager, 'configure'):
                        await database_manager.configure({
                            'type': db_config.type,
                            'host': db_config.host,
                            'port': db_config.port,
                            'name': db_config.name,
                            'username': db_config.username,
                            'password': db_config.password,
                            'path': db_config.path,
                            'pool_size': db_config.pool_size,
                            'max_overflow': db_config.max_overflow,
                            'echo': db_config.echo,
                            'connection_timeout': db_config.connection_timeout
                        })

                await self._ensure_tables_exist()
                self.initialized = True
                logger.info("Database service initialized with database abstraction layer")
            else:
                logger.warning("Database abstraction layer not available, using in-memory fallback")
                self.initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize database service: {e}")
            logger.warning("Falling back to in-memory storage")
            self.initialized = True
    
    async def _ensure_tables_exist(self):
        """Ensure required tables exist in the database.
        if not self.db_manager:
            return
        
        try:
            # Create users table
            await execute_query("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    display_name TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    bio TEXT,
                    avatar_url TEXT,
                    location TEXT,
                    website TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_verified BOOLEAN DEFAULT FALSE,
                    custom_fields TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_active TIMESTAMP
                )
            """)
            
            # Create messages table
            await execute_query(
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    original_content TEXT NOT NULL,
                    message_type TEXT DEFAULT 'text',
                    encrypted BOOLEAN DEFAULT FALSE,
                    read BOOLEAN DEFAULT FALSE,
                    deleted BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deleted_at TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (recipient_id) REFERENCES users (id)
                )
            """)
            
            # Create sessions table
            await execute_query("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            logger.info("Database tables ensured")
            
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
    
    # User operations
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID with caching."""
        cache_key = CacheKeyBuilder.user_key(user_id)
        
        # Try cache first
        cached_user = await cache_get(cache_key)
        if cached_user:
            return cached_user
        
        try:
            if self.db_manager:
                result = await execute_query(
                    "SELECT * FROM users WHERE id = :user_id",
                    {"user_id": user_id}
                )
                if result and result.get("rows"):
                    user = result["rows"][0]
                    # Parse custom_fields JSON if present
                    if user.get("custom_fields"):
                        try:
                            user["custom_fields"] = json.loads(user["custom_fields"])
                        except json.JSONDecodeError:
                            user["custom_fields"] = {}
                    
                    # Cache for 15 minutes
                    await cache_set(cache_key, user, ttl=900)
                    return user
            else:
                # Fallback to in-memory storage
                user = self.fallback_storage['users'].get(user_id)
                if user:
                    await cache_set(cache_key, user, ttl=900)
                return user
                
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            # Try fallback storage
            return self.fallback_storage['users'].get(user_id)
        
        return None
    
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        try:
            if self.db_manager:
                result = await execute_query(
                    "SELECT * FROM users WHERE username = :username",
                    {"username": username}
                )
                if result and result.get("rows"):
                    user = result["rows"][0]
                    if user.get("custom_fields"):
                        try:
                            user["custom_fields"] = json.loads(user["custom_fields"])
                        except json.JSONDecodeError:
                            user["custom_fields"] = {}
                    return user
            else:
                # Fallback: search in-memory storage
                for user in self.fallback_storage['users'].values():
                    if user.get('username') == username:
                        return user
                        
        except Exception as e:
            logger.error(f"Error getting user by username {username}: {e}")
            # Try fallback storage
            for user in self.fallback_storage['users'].values():
                if user.get('username') == username:
                    return user
        
        return None
    
    async def create_user(self, user_data: Dict[str, Any]) -> Optional[str]:
        """Create a new user.
        try:
            user_id = user_data.get('id')
            if not user_id:
                import uuid
                user_id = str(uuid.uuid4())
                user_data['id'] = user_id
            
            # Serialize custom_fields if present
            custom_fields_json = None
            if user_data.get('custom_fields'):
                custom_fields_json = json.dumps(user_data['custom_fields'])
            
            if self.db_manager:
                await execute_query("""
                    INSERT INTO users (
                        id, username, email, password_hash, display_name,
                        first_name, last_name, bio, avatar_url, location,
                        website, is_active, is_verified, custom_fields,
                        created_at, updated_at
                    ) VALUES (
                        :id, :username, :email, :password_hash, :display_name,
                        :first_name, :last_name, :bio, :avatar_url, :location,
                        :website, :is_active, :is_verified, :custom_fields,
                        :created_at, :updated_at
                    )
                """, {
                    'id': user_id,
                    'username': user_data.get('username'),
                    'email': user_data.get('email'),
                    'password_hash': user_data.get('password_hash'),
                    'display_name': user_data.get('display_name'),
                    'first_name': user_data.get('first_name'),
                    'last_name': user_data.get('last_name'),
                    'bio': user_data.get('bio'),
                    'avatar_url': user_data.get('avatar_url'),
                    'location': user_data.get('location'),
                    'website': user_data.get('website'),
                    'is_active': user_data.get('is_active', True),
                    'is_verified': user_data.get('is_verified', False),
                    'custom_fields': custom_fields_json,
                    'created_at': user_data.get('created_at', datetime.now()),
                    'updated_at': user_data.get('updated_at', datetime.now())
                })
            else:
                # Fallback to in-memory storage
                self.fallback_storage['users'][user_id] = user_data
            
            # Invalidate related caches
            await cache_delete(f"user_list:0:20")  # Invalidate user list cache
            
            logger.info(f"User created: {user_id}")
            return user_id
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user data."""
        try:
            # Serialize custom_fields if present
            if 'custom_fields' in updates and updates['custom_fields']:
                updates['custom_fields'] = json.dumps(updates['custom_fields'])
            
            updates['updated_at'] = datetime.now()
            
            if self.db_manager:
                # Build dynamic update query
                set_clauses = []
                params = {'user_id': user_id}
                
                for key, value in updates.items():
                    if key != 'id':  # Don't update ID
                        set_clauses.append(f"{key} = :{key}")
                        params[key] = value
                
                if set_clauses:
                    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = :user_id"
                    await execute_query(query, params)
            else:
                # Fallback to in-memory storage
                if user_id in self.fallback_storage['users']:
                    self.fallback_storage['users'][user_id].update(updates)
            
            # Invalidate caches
            await cache_delete(CacheKeyBuilder.user_key(user_id))
            await cache_delete(f"public_profile:{user_id}")
            
            logger.info(f"User updated: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False

    # Message operations
    async def get_messages_for_conversation(self, user1_id: str, user2_id: str,
                                        limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get messages between two users.
        try:
            if self.db_manager:
                result = await execute_query("""
                    SELECT * FROM messages
                    WHERE ((sender_id = :user1 AND recipient_id = :user2)
                        OR (sender_id = :user2 AND recipient_id = :user1))
                    AND deleted = FALSE
                    ORDER BY created_at ASC
                    LIMIT :limit OFFSET :offset
                """, {
                    'user1': user1_id,
                    'user2': user2_id,
                    'limit': limit,
                    'offset': offset
                })
                return result.get("rows", []) if result else []
            else:
                # Fallback to in-memory storage
                messages = []
                for msg in self.fallback_storage['messages'].values():
                    if (not msg.get('deleted') and
                        ((msg.get('sender_id') == user1_id and msg.get('recipient_id') == user2_id) or
                        (msg.get('sender_id') == user2_id and msg.get('recipient_id') == user1_id))):
                        messages.append(msg)

                # Sort by timestamp and apply pagination
                messages.sort(key=lambda x: x.get('created_at', datetime.min))
                return messages[offset:offset + limit]

        except Exception as e:
            logger.error(f"Error getting conversation messages: {e}")
            return []

    async def create_message(self, message_data: Dict[str, Any]) -> Optional[str]:
        """Create a new message.
        try:
            message_id = message_data.get('id')
            if not message_id:
                import uuid
                message_id = str(uuid.uuid4())
                message_data['id'] = message_id

            if self.db_manager:
                await execute_query("""
                    INSERT INTO messages (
                        id, sender_id, recipient_id, content, original_content,
                        message_type, encrypted, read, deleted, created_at
                    ) VALUES (
                        :id, :sender_id, :recipient_id, :content, :original_content,
                        :message_type, :encrypted, :read, :deleted, :created_at
                    )
                """, {
                    'id': message_id,
                    'sender_id': message_data.get('sender_id'),
                    'recipient_id': message_data.get('recipient_id'),
                    'content': message_data.get('content'),
                    'original_content': message_data.get('original_content'),
                    'message_type': message_data.get('message_type', 'text'),
                    'encrypted': message_data.get('encrypted', False),
                    'read': message_data.get('read', False),
                    'deleted': message_data.get('deleted', False),
                    'created_at': message_data.get('created_at', datetime.now())
                })
            else:
                # Fallback to in-memory storage
                self.fallback_storage['messages'][message_id] = message_data

            logger.info(f"Message created: {message_id}")
            return message_id

        except Exception as e:
            logger.error(f"Error creating message: {e}")
            return None

    async def get_user_conversations(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all conversations for a user.
        try:
            if self.db_manager:
                result = await execute_query("""
                    SELECT DISTINCT
                        CASE
                            WHEN sender_id = :user_id THEN recipient_id
                            ELSE sender_id
                        END as other_user_id,
                        MAX(created_at) as last_message_time
                    FROM messages
                    WHERE (sender_id = :user_id OR recipient_id = :user_id)
                    AND deleted = FALSE
                    GROUP BY other_user_id
                    ORDER BY last_message_time DESC
                """, {'user_id': user_id})

                conversations = []
                for row in result.get("rows", []):
                    other_user = await self.get_user(row['other_user_id'])
                    if other_user:
                        conversations.append({
                            'user_id': row['other_user_id'],
                            'username': other_user.get('username'),
                            'display_name': other_user.get('display_name'),
                            'last_message_time': row['last_message_time']
                        })

                return conversations
            else:
                # Fallback implementation
                conversations = {}
                for msg in self.fallback_storage['messages'].values():
                    if msg.get('deleted'):
                        continue

                    other_user_id = None
                    if msg.get('sender_id') == user_id:
                        other_user_id = msg.get('recipient_id')
                    elif msg.get('recipient_id') == user_id:
                        other_user_id = msg.get('sender_id')

                    if other_user_id and other_user_id in self.fallback_storage['users']:
                        if other_user_id not in conversations:
                            user = self.fallback_storage['users'][other_user_id]
                            conversations[other_user_id] = {
                                'user_id': other_user_id,
                                'username': user.get('username'),
                                'display_name': user.get('display_name'),
                                'last_message_time': msg.get('created_at')
                            }
                        else:
                            # Update if this message is newer
                            if msg.get('created_at', datetime.min) > conversations[other_user_id].get('last_message_time', datetime.min):
                                conversations[other_user_id]['last_message_time'] = msg.get('created_at')

                return list(conversations.values())

        except Exception as e:
            logger.error(f"Error getting user conversations: {e}")
            return []

# Global database service instance
_database_service = None

async def get_database_service() -> DatabaseService:
    """Get the global database service instance."""
    global _database_service
    if _database_service is None:
        _database_service = DatabaseService()
        await _database_service.initialize()
    return _database_service
