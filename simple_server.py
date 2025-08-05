#!/usr/bin/env python3
"""
Simple PlexiChat Server
=======================

A minimal working server for testing the Go client connection.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import time
from datetime import datetime

# Create FastAPI app
app = FastAPI(
    title="PlexiChat API",
    description="Simple PlexiChat Server for Testing",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class HealthResponse(BaseModel):
    status: str
    version: str
    uptime: str
    checks: Optional[List[str]] = []

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: Optional[datetime] = None
    two_fa_required: bool = False
    methods: Optional[List[str]] = []

class User(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

class Message(BaseModel):
    id: int
    content: str
    channel_id: str
    user_id: int
    created_at: datetime

class MessageCreate(BaseModel):
    content: str
    channel_id: str

# In-memory storage
users_db = [
    {"id": 1, "username": "admin", "email": "admin@plexichat.com", "created_at": datetime.now()},
    {"id": 2, "username": "user1", "email": "user1@plexichat.com", "created_at": datetime.now()},
]

messages_db = [
    {"id": 1, "content": "Welcome to PlexiChat!", "channel_id": "general", "user_id": 1, "created_at": datetime.now()},
    {"id": 2, "content": "Hello everyone!", "channel_id": "general", "user_id": 2, "created_at": datetime.now()},
]

# Server start time
start_time = time.time()

# Health endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    uptime_seconds = int(time.time() - start_time)
    uptime_str = f"{uptime_seconds}s"
    
    return HealthResponse(
        status="ok",
        version="test-enhanced",
        uptime=uptime_str,
        checks=["database", "cache", "auth"]
    )

# API v1 routes
@app.get("/api/v1/")
async def api_root():
    return {
        "message": "PlexiChat API v1",
        "version": "1.0.0",
        "endpoints": [
            "/health",
            "/api/v1/auth/",
            "/api/v1/users/",
            "/api/v1/messages/",
            "/api/v1/files/"
        ]
    }

# Auth endpoints
@app.get("/api/v1/auth/")
async def auth_info():
    return {
        "message": "Authentication endpoints",
        "endpoints": [
            "POST /api/v1/auth/login",
            "POST /api/v1/auth/logout",
            "GET /api/v1/auth/me"
        ]
    }

@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    # Simple authentication - accept admin/password123
    if request.username == "admin" and request.password == "password123":
        return LoginResponse(
            access_token="test-token-12345",
            expires_at=datetime.now(),
            two_fa_required=False,
            methods=["password"]
        )
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# Users endpoints
@app.get("/api/v1/users/")
async def list_users():
    return {
        "users": users_db,
        "total": len(users_db)
    }

@app.get("/api/v1/users/{user_id}")
async def get_user(user_id: int):
    user = next((u for u in users_db if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Messages endpoints
@app.get("/api/v1/messages/")
async def list_messages():
    return {
        "messages": messages_db,
        "total": len(messages_db)
    }

@app.post("/api/v1/messages/", status_code=201)
async def create_message(message: MessageCreate):
    new_message = {
        "id": len(messages_db) + 1,
        "content": message.content,
        "channel_id": message.channel_id,
        "user_id": 1,  # Default to admin user
        "created_at": datetime.now()
    }
    messages_db.append(new_message)
    return new_message

# Files endpoints
@app.get("/api/v1/files/")
async def list_files():
    return {
        "files": [],
        "total": 0,
        "message": "File upload endpoint available"
    }

@app.post("/api/v1/files/upload")
async def upload_file():
    return {
        "message": "File upload endpoint",
        "status": "not implemented",
        "file_id": "test-file-123"
    }

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "PlexiChat Simple Server",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1/"
    }

if __name__ == "__main__":
    print("Starting PlexiChat Simple Server...")
    print("API Documentation: http://localhost:8001/docs")
    print("Health Check: http://localhost:8001/health")
    print("API Root: http://localhost:8001/api/v1/")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )
