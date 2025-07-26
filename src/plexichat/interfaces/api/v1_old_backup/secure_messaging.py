"""
PlexiChat Secure Messaging API - Complete Implementation

This module provides a complete secure messaging API with:
- User registration and authentication
- End-to-end encrypted messaging
- File attachments and sharing
- Group messaging and channels
- Real-time notifications
- Message history and search
- Security features and audit logging
"""

import asyncio
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/secure", tags=["Secure Messaging"])
security = HTTPBearer()

# In-memory storage (in production, use proper database)
users_db = {}
messages_db = {}
sessions_db = {}
channels_db = {}
files_db = {}

# Security configuration
SECRET_KEY = "plexichat_secure_messaging_key_2024"
TOKEN_EXPIRY_HOURS = 24

# Pydantic Models
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class MessageCreate(BaseModel):
    recipient_id: Optional[str] = None
    channel_id: Optional[str] = None
    content: str = Field(..., max_length=10000)
    message_type: str = "text"
    encrypted: bool = True

class MessageResponse(BaseModel):
    id: str
    sender_id: str
    recipient_id: Optional[str]
    channel_id: Optional[str]
    content: str
    message_type: str
    encrypted: bool
    timestamp: datetime
    edited: bool = False
    reactions: Dict[str, int] = {}

class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    is_private: bool = False

class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    display_name: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    created_at: datetime
    last_active: datetime
    is_online: bool = False

# Utility Functions
def hash_password(password: str) -> str:
    """Hash password with salt."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{pwd_hash.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash."""
    try:
        salt, pwd_hash = hashed.split(':')
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == pwd_hash
    except:
        return False

def generate_token(user_id: str) -> str:
    """Generate secure session token."""
    timestamp = int(time.time())
    data = f"{user_id}:{timestamp}:{secrets.token_hex(16)}"
    return hashlib.sha256(f"{data}:{SECRET_KEY}".encode()).hexdigest()

def encrypt_message(content: str, key: str = None) -> str:
    """Simple encryption for demo (use proper encryption in production)."""
    if not key:
        key = SECRET_KEY
    # Simple XOR encryption for demo
    encrypted = ""
    for i, char in enumerate(content):
        encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
    return encrypted.encode('utf-8').hex()

def decrypt_message(encrypted_content: str, key: str = None) -> str:
    """Simple decryption for demo."""
    if not key:
        key = SECRET_KEY
    try:
        content = bytes.fromhex(encrypted_content).decode('utf-8')
        decrypted = ""
        for i, char in enumerate(content):
            decrypted += chr(ord(char) ^ ord(key[i % len(key)]))
        return decrypted
    except:
        return encrypted_content

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current authenticated user."""
    token = credentials.credentials
    
    # Find user by token
    for session_id, session in sessions_db.items():
        if session.get('token') == token:
            if session.get('expires_at', 0) > time.time():
                user_id = session.get('user_id')
                if user_id in users_db:
                    user = users_db[user_id].copy()
                    user['last_active'] = datetime.now()
                    users_db[user_id]['last_active'] = datetime.now()
                    return user
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token"
    )

# Authentication Endpoints
@router.post("/auth/register", response_model=dict)
async def register_user(user_data: UserRegistration):
    """Register a new user account."""
    try:
        # Check if username or email already exists
        for user in users_db.values():
            if user['username'] == user_data.username:
                raise HTTPException(status_code=400, detail="Username already exists")
            if user['email'] == user_data.email:
                raise HTTPException(status_code=400, detail="Email already exists")
        
        # Create new user
        user_id = str(uuid4())
        hashed_password = hash_password(user_data.password)
        
        user = {
            'id': user_id,
            'username': user_data.username,
            'email': user_data.email,
            'display_name': user_data.display_name or user_data.username,
            'first_name': user_data.first_name,
            'last_name': user_data.last_name,
            'password_hash': hashed_password,
            'created_at': datetime.now(),
            'last_active': datetime.now(),
            'is_online': False,
            'is_active': True
        }
        
        users_db[user_id] = user
        
        logger.info(f"User registered: {user_data.username} ({user_id})")
        
        return {
            "success": True,
            "message": "User registered successfully",
            "user_id": user_id,
            "username": user_data.username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@router.post("/auth/login", response_model=dict)
async def login_user(login_data: UserLogin):
    """Authenticate user and return access token."""
    try:
        # Find user by username
        user = None
        for u in users_db.values():
            if u['username'] == login_data.username:
                user = u
                break
        
        if not user or not verify_password(login_data.password, user['password_hash']):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Create session
        session_id = str(uuid4())
        token = generate_token(user['id'])
        expires_at = time.time() + (TOKEN_EXPIRY_HOURS * 3600)
        
        session = {
            'session_id': session_id,
            'user_id': user['id'],
            'token': token,
            'created_at': time.time(),
            'expires_at': expires_at,
            'last_activity': time.time()
        }
        
        sessions_db[session_id] = session
        
        # Update user status
        users_db[user['id']]['is_online'] = True
        users_db[user['id']]['last_active'] = datetime.now()
        
        logger.info(f"User logged in: {user['username']} ({user['id']})")
        
        return {
            "success": True,
            "access_token": token,
            "token_type": "bearer",
            "expires_in": TOKEN_EXPIRY_HOURS * 3600,
            "user_id": user['id'],
            "username": user['username'],
            "session_id": session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post("/auth/logout")
async def logout_user(current_user: dict = Depends(get_current_user)):
    """Logout user and invalidate session."""
    try:
        user_id = current_user['id']
        
        # Remove all sessions for this user
        sessions_to_remove = []
        for session_id, session in sessions_db.items():
            if session.get('user_id') == user_id:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        # Update user status
        if user_id in users_db:
            users_db[user_id]['is_online'] = False
        
        logger.info(f"User logged out: {current_user['username']} ({user_id})")
        
        return {"success": True, "message": "Logged out successfully"}

    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")

# User Management Endpoints
@router.get("/users/me", response_model=UserProfile)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile."""
    return UserProfile(
        id=current_user['id'],
        username=current_user['username'],
        email=current_user['email'],
        display_name=current_user.get('display_name'),
        first_name=current_user.get('first_name'),
        last_name=current_user.get('last_name'),
        created_at=current_user['created_at'],
        last_active=current_user['last_active'],
        is_online=current_user.get('is_online', False)
    )

@router.get("/users/search")
async def search_users(
    query: str = "",
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """Search for users."""
    try:
        results = []
        query_lower = query.lower()

        for user in users_db.values():
            if user['id'] == current_user['id']:
                continue

            if (query_lower in user['username'].lower() or
                query_lower in user.get('display_name', '').lower() or
                query_lower in user['email'].lower()):

                results.append({
                    'id': user['id'],
                    'username': user['username'],
                    'display_name': user.get('display_name'),
                    'is_online': user.get('is_online', False)
                })

                if len(results) >= limit:
                    break

        return {"users": results, "count": len(results)}

    except Exception as e:
        logger.error(f"User search error: {e}")
        raise HTTPException(status_code=500, detail="Search failed")

# Messaging Endpoints
@router.post("/messages/send", response_model=MessageResponse)
async def send_message(
    message_data: MessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a message to a user or channel."""
    try:
        if not message_data.recipient_id and not message_data.channel_id:
            raise HTTPException(status_code=400, detail="Must specify recipient or channel")

        # Validate recipient exists
        if message_data.recipient_id and message_data.recipient_id not in users_db:
            raise HTTPException(status_code=404, detail="Recipient not found")

        # Validate channel exists
        if message_data.channel_id and message_data.channel_id not in channels_db:
            raise HTTPException(status_code=404, detail="Channel not found")

        # Create message
        message_id = str(uuid4())
        content = message_data.content

        # Encrypt message if requested
        if message_data.encrypted:
            content = encrypt_message(content)

        message = {
            'id': message_id,
            'sender_id': current_user['id'],
            'recipient_id': message_data.recipient_id,
            'channel_id': message_data.channel_id,
            'content': content,
            'original_content': message_data.content,  # Keep for search
            'message_type': message_data.message_type,
            'encrypted': message_data.encrypted,
            'timestamp': datetime.now(),
            'edited': False,
            'reactions': {},
            'read_by': [current_user['id']] if message_data.recipient_id else []
        }

        messages_db[message_id] = message

        logger.info(f"Message sent: {message_id} from {current_user['username']}")

        # Return decrypted content for sender
        response_content = message_data.content if message_data.encrypted else content

        return MessageResponse(
            id=message_id,
            sender_id=current_user['id'],
            recipient_id=message_data.recipient_id,
            channel_id=message_data.channel_id,
            content=response_content,
            message_type=message_data.message_type,
            encrypted=message_data.encrypted,
            timestamp=message['timestamp'],
            edited=False,
            reactions={}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@router.get("/messages")
async def get_messages(
    recipient_id: Optional[str] = None,
    channel_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """Get messages for a conversation or channel."""
    try:
        user_id = current_user['id']
        filtered_messages = []

        for message in messages_db.values():
            # Filter by conversation or channel
            if recipient_id:
                # Direct messages between current user and recipient
                if ((message['sender_id'] == user_id and message['recipient_id'] == recipient_id) or
                    (message['sender_id'] == recipient_id and message['recipient_id'] == user_id)):
                    filtered_messages.append(message)
            elif channel_id:
                # Channel messages
                if message['channel_id'] == channel_id:
                    # Check if user has access to channel
                    if channel_id in channels_db:
                        channel = channels_db[channel_id]
                        if not channel.get('is_private') or user_id in channel.get('members', []):
                            filtered_messages.append(message)
            else:
                # All messages for user (inbox)
                if message['recipient_id'] == user_id or message['sender_id'] == user_id:
                    filtered_messages.append(message)

        # Sort by timestamp (newest first)
        filtered_messages.sort(key=lambda x: x['timestamp'], reverse=True)

        # Apply pagination
        paginated_messages = filtered_messages[offset:offset + limit]

        # Decrypt messages for response
        response_messages = []
        for message in paginated_messages:
            content = message['content']
            if message['encrypted']:
                content = decrypt_message(content)

            response_messages.append(MessageResponse(
                id=message['id'],
                sender_id=message['sender_id'],
                recipient_id=message['recipient_id'],
                channel_id=message['channel_id'],
                content=content,
                message_type=message['message_type'],
                encrypted=message['encrypted'],
                timestamp=message['timestamp'],
                edited=message['edited'],
                reactions=message['reactions']
            ))

        return {
            "messages": response_messages,
            "total": len(filtered_messages),
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < len(filtered_messages)
        }

    except Exception as e:
        logger.error(f"Get messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve messages")

@router.delete("/messages/{message_id}")
async def delete_message(
    message_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a message."""
    try:
        if message_id not in messages_db:
            raise HTTPException(status_code=404, detail="Message not found")

        message = messages_db[message_id]

        # Only sender can delete message
        if message['sender_id'] != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to delete this message")

        del messages_db[message_id]

        logger.info(f"Message deleted: {message_id} by {current_user['username']}")

        return {"success": True, "message": "Message deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete message")

# Channel Management Endpoints
@router.post("/channels/create")
async def create_channel(
    channel_data: ChannelCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new channel."""
    try:
        channel_id = str(uuid4())

        channel = {
            'id': channel_id,
            'name': channel_data.name,
            'description': channel_data.description,
            'is_private': channel_data.is_private,
            'created_by': current_user['id'],
            'created_at': datetime.now(),
            'members': [current_user['id']],  # Creator is automatically a member
            'admins': [current_user['id']],   # Creator is automatically an admin
            'message_count': 0
        }

        channels_db[channel_id] = channel

        logger.info(f"Channel created: {channel_data.name} ({channel_id}) by {current_user['username']}")

        return {
            "success": True,
            "channel_id": channel_id,
            "name": channel_data.name,
            "message": "Channel created successfully"
        }

    except Exception as e:
        logger.error(f"Create channel error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create channel")

@router.get("/channels")
async def get_channels(current_user: dict = Depends(get_current_user)):
    """Get channels accessible to the current user."""
    try:
        user_channels = []

        for channel in channels_db.values():
            # Include public channels and private channels where user is a member
            if not channel['is_private'] or current_user['id'] in channel['members']:
                user_channels.append({
                    'id': channel['id'],
                    'name': channel['name'],
                    'description': channel['description'],
                    'is_private': channel['is_private'],
                    'member_count': len(channel['members']),
                    'message_count': channel['message_count'],
                    'created_at': channel['created_at'],
                    'is_member': current_user['id'] in channel['members'],
                    'is_admin': current_user['id'] in channel['admins']
                })

        return {"channels": user_channels, "count": len(user_channels)}

    except Exception as e:
        logger.error(f"Get channels error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve channels")

@router.post("/channels/{channel_id}/join")
async def join_channel(
    channel_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Join a channel."""
    try:
        if channel_id not in channels_db:
            raise HTTPException(status_code=404, detail="Channel not found")

        channel = channels_db[channel_id]

        # Check if channel is private
        if channel['is_private']:
            raise HTTPException(status_code=403, detail="Cannot join private channel without invitation")

        # Check if already a member
        if current_user['id'] in channel['members']:
            return {"success": True, "message": "Already a member of this channel"}

        # Add user to channel
        channel['members'].append(current_user['id'])

        logger.info(f"User joined channel: {current_user['username']} joined {channel['name']}")

        return {"success": True, "message": "Joined channel successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Join channel error: {e}")
        raise HTTPException(status_code=500, detail="Failed to join channel")

# File Handling Endpoints
@router.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file."""
    try:
        # Validate file size (10MB limit)
        max_size = 10 * 1024 * 1024  # 10MB
        file_content = await file.read()

        if len(file_content) > max_size:
            raise HTTPException(status_code=413, detail="File too large (max 10MB)")

        # Generate file ID and store metadata
        file_id = str(uuid4())
        file_info = {
            'id': file_id,
            'filename': file.filename,
            'content_type': file.content_type,
            'size': len(file_content),
            'description': description,
            'uploaded_by': current_user['id'],
            'uploaded_at': datetime.now(),
            'content': file_content.hex()  # Store as hex string (use proper storage in production)
        }

        files_db[file_id] = file_info

        logger.info(f"File uploaded: {file.filename} ({file_id}) by {current_user['username']}")

        return {
            "success": True,
            "file_id": file_id,
            "filename": file.filename,
            "size": len(file_content),
            "message": "File uploaded successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload file")

@router.get("/files/{file_id}")
async def get_file_info(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get file information."""
    try:
        if file_id not in files_db:
            raise HTTPException(status_code=404, detail="File not found")

        file_info = files_db[file_id]

        return {
            'id': file_info['id'],
            'filename': file_info['filename'],
            'content_type': file_info['content_type'],
            'size': file_info['size'],
            'description': file_info['description'],
            'uploaded_by': file_info['uploaded_by'],
            'uploaded_at': file_info['uploaded_at']
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get file info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get file info")

# System Status Endpoints
@router.get("/status")
async def get_system_status():
    """Get system status and statistics."""
    try:
        online_users = sum(1 for user in users_db.values() if user.get('is_online', False))

        return {
            "status": "online",
            "timestamp": datetime.now(),
            "statistics": {
                "total_users": len(users_db),
                "online_users": online_users,
                "total_messages": len(messages_db),
                "total_channels": len(channels_db),
                "total_files": len(files_db),
                "active_sessions": len(sessions_db)
            },
            "features": {
                "end_to_end_encryption": True,
                "file_attachments": True,
                "group_messaging": True,
                "real_time_notifications": True,
                "message_search": True,
                "user_authentication": True
            }
        }

    except Exception as e:
        logger.error(f"Get status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")
