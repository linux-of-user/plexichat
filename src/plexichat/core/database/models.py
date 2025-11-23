"""
PlexiChat Database Models
=========================

SQLAlchemy models for the PlexiChat database.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    """User model."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="user", cascade="all, delete-orphan")

class Session(Base):
    """Session model for tracking user sessions."""
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user_agent = Column(String(500))
    ip_address = Column(String(50))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")

class Channel(Base):
    """Channel model for messaging."""
    __tablename__ = "channels"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_private = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    messages = relationship("Message", back_populates="channel", cascade="all, delete-orphan")

class Message(Base):
    """Message model."""
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    edited_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="messages")
    channel = relationship("Channel", back_populates="messages")

class MessageThread(Base):
    """Message thread model."""
    __tablename__ = "message_threads"

    id = Column(String(36), primary_key=True)
    parent_message_id = Column(String(36), nullable=True)
    title = Column(String(255), nullable=False)
    creator_id = Column(String(36), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    reply_count = Column(Integer, default=0)
    is_archived = Column(Boolean, default=False)

class ThreadReply(Base):
    """Thread reply model."""
    __tablename__ = "thread_replies"

    id = Column(String(36), primary_key=True)
    thread_id = Column(String(36), ForeignKey("message_threads.id"), nullable=False)
    message_content = Column(Text, nullable=False)
    user_id = Column(String(36), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_edited = Column(Boolean, default=False)

    # Relationships
    thread = relationship("MessageThread", backref="replies")

class ThreadTask(Base):
    """Thread task logging model."""
    __tablename__ = "thread_tasks"

    task_id = Column(String(255), primary_key=True)
    function_name = Column(String(255), nullable=False)
    duration = Column(Float, nullable=False)
    status = Column(String(50), nullable=False)
    created_at = Column(Float, nullable=False)
    completed_at = Column(Float, nullable=False)

class KeyboardShortcut(Base):
    """Keyboard shortcut model."""
    __tablename__ = "keyboard_shortcuts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    shortcut_key = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False)
    description = Column(String(255))
    is_custom = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

# Schema definitions for raw SQL usage
MESSAGE_THREADS_SCHEMA = """
CREATE TABLE IF NOT EXISTS message_threads (
    id VARCHAR(36) PRIMARY KEY,
    parent_message_id VARCHAR(36),
    title VARCHAR(255) NOT NULL,
    creator_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reply_count INTEGER DEFAULT 0,
    is_archived BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS thread_replies (
    id VARCHAR(36) PRIMARY KEY,
    thread_id VARCHAR(36) NOT NULL,
    message_content TEXT NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_edited BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (thread_id) REFERENCES message_threads(id) ON DELETE CASCADE
);
"""

THREAD_TASKS_SCHEMA = """
CREATE TABLE IF NOT EXISTS thread_tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    function_name VARCHAR(255) NOT NULL,
    duration FLOAT NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_at FLOAT NOT NULL,
    completed_at FLOAT NOT NULL
);
"""

KEYBOARD_SHORTCUTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS keyboard_shortcuts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(255) NOT NULL,
    shortcut_key VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    is_custom BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""
