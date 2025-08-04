"""
PlexiChat API v1 Router
========================

Core API endpoints for user management, messages, files, and admin operations.
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Optional
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Router
v1_router = APIRouter(prefix="/api/v1")
root_router = APIRouter()  # Root-level endpoints for backward compatibility

# Pydantic models
class User(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool = True

class UserCreate(BaseModel):
    username: str
    email: str  # Basic string type, no email validation
    password: str

class Message(BaseModel):
    id: int
    content: str
    sender_id: int
    recipient_id: Optional[int] = None
    timestamp: str

class MessageCreate(BaseModel):
    content: str
    recipient_id: Optional[int] = None

class FileUpload(BaseModel):
    filename: str
    content_type: str
    size: int

# Mock data storage (replace with database in production)
users_db = [
    {"id": 1, "username": "admin", "email": "admin@plexichat.com", "is_active": True},
    {"id": 2, "username": "user1", "email": "user1@example.com", "is_active": True},
]

messages_db = [
    {"id": 1, "content": "Hello World", "sender_id": 1, "recipient_id": 2, "timestamp": "2025-07-30T12:00:00"},
    {"id": 2, "content": "Welcome to PlexiChat", "sender_id": 2, "recipient_id": 1, "timestamp": "2025-07-30T12:01:00"},
]

files_db = []

# Dependency to get current user
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Mock authentication - replace with real auth
    return users_db[0] if users_db else None

# User endpoints
@v1_router.get("/users/me", response_model=User)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user

@v1_router.get("/users/{user_id}", response_model=User)
async def get_user(user_id: int):
    """Get user by ID."""
    user = next((u for u in users_db if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@v1_router.get("/users", response_model=List[User])
async def list_users(skip: int = 0, limit: int = 100):
    """List all users."""
    return users_db[skip:skip + limit]

@v1_router.post("/users", response_model=User)
async def create_user(user: UserCreate):
    """Create a new user."""
    new_user = {
        "id": len(users_db) + 1,
        "username": user.username,
        "email": user.email,
        "is_active": True
    }
    users_db.append(new_user)
    return new_user

# Message endpoints
@v1_router.get("/messages", response_model=List[Message])
async def get_messages(skip: int = 0, limit: int = 100):
    """Get all messages."""
    return messages_db[skip:skip + limit]

@v1_router.get("/messages/{message_id}", response_model=Message)
async def get_message(message_id: int):
    """Get message by ID."""
    message = next((m for m in messages_db if m["id"] == message_id), None)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return message

@v1_router.post("/messages", response_model=Message)
async def create_message(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Create a new message."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    new_message = {
        "id": len(messages_db) + 1,
        "content": message.content,
        "sender_id": current_user["id"],
        "recipient_id": message.recipient_id,
        "timestamp": "2025-07-30T12:00:00"
    }
    messages_db.append(new_message)
    return new_message

@v1_router.post("/messages/send")
async def send_message(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Send a message (alias for create_message)."""
    return await create_message(message, current_user)

# File endpoints
@v1_router.get("/files")
async def list_files():
    """List all uploaded files."""
    return files_db

@v1_router.post("/files/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file."""
    file_info = {
        "filename": file.filename,
        "content_type": file.content_type,
        "size": 0  # Mock size for now
    }
    files_db.append(file_info)
    return {}}"message": "File uploaded successfully", "file": file_info}

# Admin endpoints
@v1_router.get("/admin/users")
async def admin_list_users():
    """Admin endpoint to list all users."""
    return {}}"users": users_db, "total": len(users_db)}

@v1_router.get("/admin/stats")
async def admin_stats():
    """Admin endpoint for system statistics."""
    return {}}
        "total_users": len(users_db),
        "total_messages": len(messages_db),
        "total_files": len(files_db),
        "system_status": "healthy"
    }

@v1_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: int):
    """Admin endpoint to delete a user."""
    global users_db
    users_db = [u for u in users_db if u["id"] != user_id]
    return {}}"message": f"User {user_id} deleted"}

# Additional endpoints for testing
@v1_router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {}}"status": "healthy", "timestamp": "2025-07-30T12:00:00"}

@v1_router.get("/test")
async def test_endpoint():
    """Test endpoint for connectivity."""
    return {}}"message": "API v1 is working"}

logger.info("[CHECK] API v1 router initialized with all endpoints")

# Root-level endpoints for backward compatibility
@root_router.get("/users/me", response_model=User)
async def get_current_user_root(current_user: dict = Depends(get_current_user)):
    """Get current user information at root level."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user

@root_router.get("/users/{user_id}", response_model=User)
async def get_user_root(user_id: int):
    """Get user by ID at root level."""
    user = next((u for u in users_db if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@root_router.get("/users", response_model=List[User])
async def list_users_root(skip: int = 0, limit: int = 100):
    """List all users at root level."""
    return users_db[skip:skip + limit]

@root_router.post("/users", response_model=User)
async def create_user_root(user: UserCreate):
    """Create a new user at root level."""
    new_user = {
        "id": len(users_db) + 1,
        "username": user.username,
        "email": user.email,
        "is_active": True
    }
    users_db.append(new_user)
    return new_user

@root_router.get("/messages", response_model=List[Message])
async def get_messages_root(skip: int = 0, limit: int = 100):
    """Get all messages at root level."""
    return messages_db[skip:skip + limit]

@root_router.get("/messages/{message_id}", response_model=Message)
async def get_message_root(message_id: int):
    """Get message by ID at root level."""
    message = next((m for m in messages_db if m["id"] == message_id), None)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return message

@root_router.post("/messages", response_model=Message)
async def create_message_root(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Create a new message at root level."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    new_message = {
        "id": len(messages_db) + 1,
        "content": message.content,
        "sender_id": current_user["id"],
        "recipient_id": message.recipient_id,
        "timestamp": "2025-07-30T12:00:00"
    }
    messages_db.append(new_message)
    return new_message

@root_router.post("/messages/send")
async def send_message_root(message: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Send a message at root level."""
    return await create_message_root(message, current_user)

@root_router.get("/files")
async def list_files_root():
    """List all uploaded files at root level."""
    return files_db

@root_router.post("/files/upload")
async def upload_file_root(file: UploadFile = File(...)):
    """Upload a file at root level."""
    file_info = {
        "filename": file.filename,
        "content_type": file.content_type,
        "size": 0  # Mock size for now
    }
    files_db.append(file_info)
    return {}}"message": "File uploaded successfully", "file": file_info}

@root_router.get("/admin/users")
async def admin_list_users_root():
    """Admin endpoint to list all users at root level."""
    return {}}"users": users_db, "total": len(users_db)}

@root_router.get("/admin/stats")
async def admin_stats_root():
    """Admin endpoint for system statistics at root level."""
    return {}}
        "total_users": len(users_db),
        "total_messages": len(messages_db),
        "total_files": len(files_db),
        "system_status": "healthy"
    }

@root_router.delete("/admin/users/{user_id}")
async def admin_delete_user_root(user_id: int):
    """Admin endpoint to delete a user at root level."""
    global users_db
    users_db = [u for u in users_db if u["id"] != user_id]
    return {}}"message": f"User {user_id} deleted"}

logger.info("[CHECK] Root-level endpoints added for backward compatibility")