# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Setup Router

Web interface for initial setup, database configuration, and admin account creation.
Provides a complete setup wizard accessible via web browser.
"""

import json
import logging
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/setup", tags=["setup"])

# Templates
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")

@router.get("/", response_class=HTMLResponse)
async def setup_home(request: Request):
    """Main setup page."""
    try:
        # Check if setup is already completed
        if is_setup_completed():
            return RedirectResponse(url="/", status_code=302)
        
        return templates.TemplateResponse("setup/index.html", {
            "request": request,
            "title": "PlexiChat Setup",
            "step": "welcome"
        })
    except Exception as e:
        logger.error(f"Setup home error: {e}")
        raise HTTPException(status_code=500, detail="Setup page error")

@router.get("/database", response_class=HTMLResponse)
async def setup_database_page(request: Request):
    """Database setup page."""
    try:
        return templates.TemplateResponse("setup/database.html", {
            "request": request,
            "title": "Database Setup",
            "step": "database"
        })
    except Exception as e:
        logger.error(f"Database setup page error: {e}")
        raise HTTPException(status_code=500, detail="Database setup error")

@router.post("/database")
async def setup_database(
    request: Request,
    db_type: str = Form(...),
    db_host: Optional[str] = Form(None),
    db_port: Optional[int] = Form(None),
    db_name: Optional[str] = Form(None),
    db_username: Optional[str] = Form(None),
    db_password: Optional[str] = Form(None)
):
    """Process database setup."""
    try:
        config_path = get_config_path()
        
        # Create database configuration
        db_config = {
            "type": db_type,
            "path": str(config_path / "plexichat.db") if db_type == "sqlite" else None,
            "host": db_host,
            "port": db_port,
            "name": db_name,
            "username": db_username,
            "password": db_password,
            "backup_enabled": True
        }
        
        # Test database connection
        if not test_database_connection(db_config):
            return templates.TemplateResponse("setup/database.html", {
                "request": request,
                "title": "Database Setup",
                "step": "database",
                "error": "Failed to connect to database. Please check your settings."
            })
        
        # Initialize database
        if db_type == "sqlite":
            initialize_sqlite_database(config_path / "plexichat.db")
        
        # Save database configuration
        save_database_config(db_config)
        
        return RedirectResponse(url="/setup/admin", status_code=302)
        
    except Exception as e:
        logger.error(f"Database setup error: {e}")
        return templates.TemplateResponse("setup/database.html", {
            "request": request,
            "title": "Database Setup",
            "step": "database",
            "error": f"Database setup failed: {str(e)}"
        })

@router.get("/admin", response_class=HTMLResponse)
async def setup_admin_page(request: Request):
    """Admin account setup page."""
    try:
        return templates.TemplateResponse("setup/admin.html", {
            "request": request,
            "title": "Admin Account Setup",
            "step": "admin"
        })
    except Exception as e:
        logger.error(f"Admin setup page error: {e}")
        raise HTTPException(status_code=500, detail="Admin setup error")

@router.post("/admin")
async def setup_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    email: str = Form(...)
):
    """Process admin account setup."""
    try:
        # Validate input
        if password != confirm_password:
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": "Passwords do not match"
            })
        
        if len(password) < 8:
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": "Password must be at least 8 characters long"
            })
        
        # Create admin account
        create_admin_account(username, password, email)
        
        return RedirectResponse(url="/setup/complete", status_code=302)
        
    except Exception as e:
        logger.error(f"Admin setup error: {e}")
        return templates.TemplateResponse("setup/admin.html", {
            "request": request,
            "title": "Admin Account Setup",
            "step": "admin",
            "error": f"Admin setup failed: {str(e)}"
        })

@router.get("/complete", response_class=HTMLResponse)
async def setup_complete(request: Request):
    """Setup completion page."""
    try:
        # Mark setup as completed
        mark_setup_completed()
        
        return templates.TemplateResponse("setup/complete.html", {
            "request": request,
            "title": "Setup Complete",
            "step": "complete"
        })
    except Exception as e:
        logger.error(f"Setup complete error: {e}")
        raise HTTPException(status_code=500, detail="Setup completion error")

# Helper functions

def get_config_path() -> Path:
    """Get configuration path."""
    return Path.home() / ".plexichat"

def is_setup_completed() -> bool:
    """Check if setup is already completed."""
    try:
        config_path = get_config_path()
        setup_file = config_path / "setup_completed"
        return setup_file.exists()
    except Exception:
        return False

def test_database_connection(db_config: Dict[str, Any]) -> bool:
    """Test database connection."""
    try:
        if db_config["type"] == "sqlite":
            # Test SQLite connection
            db_path = db_config["path"]
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.close()
            return True
        else:
            # For other databases, you would implement connection testing here
            return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

def initialize_sqlite_database(db_path: Path):
    """Initialize SQLite database with required tables."""
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'user',
                active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info(f"Database initialized at {db_path}")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def save_database_config(db_config: Dict[str, Any]):
    """Save database configuration."""
    try:
        config_path = get_config_path()
        config_path.mkdir(parents=True, exist_ok=True)
        
        config_file = config_path / "database.json"
        with open(config_file, 'w') as f:
            json.dump(db_config, f, indent=2)
        
        logger.info(f"Database configuration saved to {config_file}")
        
    except Exception as e:
        logger.error(f"Failed to save database config: {e}")
        raise

def create_admin_account(username: str, password: str, email: str):
    """Create admin account."""
    try:
        config_path = get_config_path()
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Create credentials structure
        credentials = {
            "admin": {
                "username": username,
                "password_hash": password_hash,
                "email": email,
                "role": "admin",
                "created_at": str(datetime.now()),
                "active": True
            }
        }
        
        # Save credentials
        creds_file = config_path / "default-creds.json"
        with open(creds_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        
        # Also add to database if it exists
        db_file = config_path / "plexichat.db"
        if db_file.exists():
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO users (username, password_hash, email, role, active)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, email, "admin", True))
            
            conn.commit()
            conn.close()
        
        logger.info(f"Admin account created: {username}")
        
    except Exception as e:
        logger.error(f"Failed to create admin account: {e}")
        raise

def mark_setup_completed():
    """Mark setup as completed."""
    try:
        config_path = get_config_path()
        config_path.mkdir(parents=True, exist_ok=True)
        
        setup_file = config_path / "setup_completed"
        setup_file.write_text(str(datetime.now()))
        
        logger.info("Setup marked as completed")
        
    except Exception as e:
        logger.error(f"Failed to mark setup as completed: {e}")
        raise
