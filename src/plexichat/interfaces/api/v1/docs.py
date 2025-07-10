"""
PlexiChat Documentation API
Enhanced documentation system with interactive viewer and editor.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import os
import json
from pathlib import Path

from plexichat.app.logger_config import logger
from plexichat.core.security.government_auth import get_current_admin


router = APIRouter(prefix="/docs", tags=["documentation"])
templates = Jinja2Templates(directory="src/plexichat/app/web/templates")


class DocumentModel(BaseModel):
    """Document model for API operations."""
    title: str
    content: str
    category: str
    tags: List[str] = []
    author: Optional[str] = None
    version: str = "1.0"


class DocumentUpdateModel(BaseModel):
    """Document update model."""
    content: str
    version: Optional[str] = None


# Document storage (in production, this would be a database)
DOCS_STORAGE = {
    "installation": {
        "title": "Installation Guide",
        "content": """# PlexiChat Installation Guide

## System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 10GB disk space
- SSL certificate (optional, can be auto-generated)

## Installation Steps

1. Clone the repository
2. Install dependencies
3. Run initial setup
4. Configure security settings
5. Start the server

## Quick Start

```bash
git clone https://github.com/your-org/plexichat.git
cd plexichat
pip install -r requirements.txt
python run.py --setup
```

## Configuration

Edit the `config/plexichat.yaml` file to customize your installation.

## First-Time Setup

1. **Default Credentials**: Check the `default_admin_credentials.txt` file in the project root for auto-generated admin credentials
2. **Mandatory Password Change**: You must change the default password on first login
3. **2FA Setup**: Enable two-factor authentication for enhanced security
4. **SSL Configuration**: Configure HTTPS certificates for secure communication

## Directory Structure

```
plexichat/
├── src/                    # Source code only
├── config/                 # Configuration files (auto-created)
├── logs/                   # Log files (auto-created)
├── data/                   # Database files (auto-created)
├── backups/                # Backup storage (auto-created)
├── gui/                    # Desktop GUI application
├── web/                    # Web interface files
└── docs/                   # Documentation files
```

## Running the Application

### Web Interface
```bash
python run.py --web
```

### Desktop GUI
```bash
cd gui
python launch_gui.py
```

### CLI Administration
```bash
python -m plexichat.cli.admin_cli --help
```
""",
        "category": "setup",
        "tags": ["installation", "setup", "configuration"],
        "author": "PlexiChat Team",
        "version": "1.0"
    },
    "security": {
        "title": "Security Configuration",
        "content": """# Security Configuration

## Government-Level Security

PlexiChat implements government-level security measures designed for organizations requiring the highest levels of protection.

### Authentication System
- **Auto-generated Credentials**: Secure random passwords generated on first install
- **Mandatory Password Changes**: Default passwords must be changed on first login
- **Multi-factor Authentication**: TOTP, SMS, email, and backup codes supported
- **Session Management**: Advanced session handling with automatic timeouts
- **Account Lockout**: Protection against brute force attacks

### Encryption Standards
- **Database Encryption**: AES-256 encryption for all stored data
- **Communication Security**: TLS 1.3 for all client-server communications
- **Certificate Management**: Automatic HTTPS certificate generation and management
- **MITM Protection**: Certificate pinning and request integrity validation

### Access Control
- **Role-based Permissions**: Granular permission system for different user roles
- **IP Whitelisting/Blacklisting**: Network-level access control
- **Rate Limiting**: Comprehensive DDoS protection and abuse prevention
- **Endpoint Protection**: All admin endpoints protected except /docs

## Security Configuration Steps

### 1. Initial Security Setup
```bash
# Change default admin password
python -m plexichat.cli.admin_cli change-password

# Enable 2FA
python -m plexichat.cli.admin_cli setup-2fa
```

### 2. SSL/TLS Configuration
- Automatic Let's Encrypt certificates
- Self-signed certificate generation
- Custom certificate installation
- HTTPS redirect enforcement

### 3. Backup Security
- Encrypted backup shards
- Distributed storage with redundancy
- Secure backup node authentication
- Immutable backup verification

## Security Best Practices

1. **Change Default Passwords**: Immediately change all default credentials
2. **Enable 2FA**: Require two-factor authentication for all admin accounts
3. **Regular Audits**: Perform security audits and penetration testing
4. **Monitor Logs**: Continuously monitor access and security logs
5. **Update System**: Keep PlexiChat and dependencies updated
6. **Network Security**: Use firewalls and network segmentation
7. **Backup Security**: Ensure backups are encrypted and distributed

## Security Monitoring

### Real-time Alerts
- Failed login attempts
- Suspicious activity detection
- Certificate expiration warnings
- System security status

### Audit Logging
- All authentication events
- Administrative actions
- System configuration changes
- Security policy violations

## Compliance Features

PlexiChat includes features designed for regulatory compliance:
- Comprehensive audit trails
- Data encryption at rest and in transit
- Access control and user management
- Secure backup and recovery
- Security incident reporting
""",
        "category": "security",
        "tags": ["security", "authentication", "encryption", "compliance"],
        "author": "Security Team",
        "version": "1.0"
    },
    "api-reference": {
        "title": "API Reference",
        "content": """# PlexiChat API Reference

## Authentication

All API endpoints except `/docs` require authentication using session tokens or API keys.

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your_password",
  "totp_code": "123456"
}
```

### Response
```json
{
  "success": true,
  "session_token": "secure_token",
  "must_change_password": false,
  "requires_2fa": false
}
```

## Admin API Endpoints

### User Management
- `GET /api/v1/admin/users` - List all users
- `POST /api/v1/admin/users` - Create new user
- `PUT /api/v1/admin/users/{user_id}` - Update user
- `DELETE /api/v1/admin/users/{user_id}` - Delete user

### Security Management
- `GET /api/v1/admin/security/alerts` - Get security alerts
- `POST /api/v1/admin/security/settings` - Update security settings
- `GET /api/v1/admin/security/sessions` - List active sessions

### System Management
- `GET /api/v1/admin/system/stats` - Get system statistics
- `POST /api/v1/admin/system/restart` - Restart server
- `GET /api/v1/admin/system/logs` - Get system logs

### Backup Management
- `GET /api/v1/admin/backup/status` - Get backup status
- `POST /api/v1/admin/backup/start` - Start backup process
- `GET /api/v1/admin/backup/nodes` - List backup nodes

## Documentation API

### Document Management
- `GET /docs/api/documents` - List all documents
- `GET /docs/api/documents/{doc_id}` - Get document content
- `POST /docs/api/documents/{doc_id}` - Update document (admin only)
- `POST /docs/api/documents` - Create document (admin only)
- `DELETE /docs/api/documents/{doc_id}` - Delete document (admin only)

### Search and Discovery
- `GET /docs/api/search?q={query}` - Search documents
- `GET /docs/api/categories` - Get all categories
- `GET /docs/api/tags` - Get all tags
- `GET /docs/api/stats` - Get documentation statistics

## Error Handling

All API endpoints return consistent error responses:

```json
{
  "success": false,
  "error": "Error description",
  "code": "ERROR_CODE",
  "details": {}
}
```

## Rate Limiting

API endpoints are protected by rate limiting:
- Authentication endpoints: 5 requests per minute
- Admin endpoints: 100 requests per minute
- Documentation endpoints: 200 requests per minute

## WebSocket API

Real-time communication endpoints:
- `/ws/admin` - Admin dashboard updates
- `/ws/logs` - Real-time log streaming
- `/ws/monitoring` - System monitoring data
""",
        "category": "api",
        "tags": ["api", "reference", "endpoints", "authentication"],
        "author": "Development Team",
        "version": "1.0"
    }
}


@router.get("/", response_class=HTMLResponse)
async def enhanced_docs_page(request: Request):
    """Serve enhanced documentation page."""
    try:
        return templates.TemplateResponse(
            "docs/enhanced_docs.html",
            {"request": request}
        )
    except Exception as e:
        logger.error(f"Error serving enhanced docs: {e}")
        raise HTTPException(status_code=500, detail="Failed to load documentation")


@router.get("/api/documents")
async def list_documents():
    """List all available documents."""
    try:
        documents = []
        for doc_id, doc_data in DOCS_STORAGE.items():
            documents.append({
                "id": doc_id,
                "title": doc_data["title"],
                "category": doc_data["category"],
                "tags": doc_data["tags"],
                "author": doc_data["author"],
                "version": doc_data["version"]
            })
        
        return {
            "success": True,
            "documents": documents,
            "total": len(documents)
        }
    except Exception as e:
        logger.error(f"Error listing documents: {e}")
        raise HTTPException(status_code=500, detail="Failed to list documents")


@router.get("/api/documents/{document_id}")
async def get_document(document_id: str):
    """Get specific document content."""
    try:
        if document_id not in DOCS_STORAGE:
            raise HTTPException(status_code=404, detail="Document not found")

        document = DOCS_STORAGE[document_id]
        return {
            "success": True,
            "document": {
                "id": document_id,
                **document
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting document {document_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get document")


@router.post("/api/documents/{document_id}")
async def update_document(
    document_id: str,
    update_data: DocumentUpdateModel,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Update document content (requires admin authentication)."""
    try:
        if document_id not in DOCS_STORAGE:
            raise HTTPException(status_code=404, detail="Document not found")

        # Update document
        DOCS_STORAGE[document_id]["content"] = update_data.content
        if update_data.version:
            DOCS_STORAGE[document_id]["version"] = update_data.version

        # Log the update
        logger.info(f"Document {document_id} updated by {current_admin['username']}")

        return {
            "success": True,
            "message": "Document updated successfully",
            "document": {
                "id": document_id,
                **DOCS_STORAGE[document_id]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating document {document_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update document")


@router.post("/api/documents")
async def create_document(
    document: DocumentModel,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Create new document (requires admin authentication)."""
    try:
        # Generate document ID from title
        doc_id = document.title.lower().replace(" ", "-").replace("/", "-")

        if doc_id in DOCS_STORAGE:
            raise HTTPException(status_code=409, detail="Document already exists")

        # Create document
        DOCS_STORAGE[doc_id] = {
            "title": document.title,
            "content": document.content,
            "category": document.category,
            "tags": document.tags,
            "author": document.author or current_admin['username'],
            "version": document.version
        }

        # Log the creation
        logger.info(f"Document {doc_id} created by {current_admin['username']}")

        return {
            "success": True,
            "message": "Document created successfully",
            "document": {
                "id": doc_id,
                **DOCS_STORAGE[doc_id]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating document: {e}")
        raise HTTPException(status_code=500, detail="Failed to create document")


@router.delete("/api/documents/{document_id}")
async def delete_document(
    document_id: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Delete document (requires admin authentication)."""
    try:
        if document_id not in DOCS_STORAGE:
            raise HTTPException(status_code=404, detail="Document not found")

        # Delete document
        deleted_doc = DOCS_STORAGE.pop(document_id)

        # Log the deletion
        logger.info(f"Document {document_id} deleted by {current_admin['username']}")

        return {
            "success": True,
            "message": "Document deleted successfully",
            "deleted_document": {
                "id": document_id,
                "title": deleted_doc["title"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting document {document_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete document")


@router.get("/api/search")
async def search_documents(q: str, category: Optional[str] = None):
    """Search documents by content and metadata."""
    try:
        results = []
        query = q.lower()

        for doc_id, doc_data in DOCS_STORAGE.items():
            # Check if document matches search criteria
            matches = False

            # Search in title, content, and tags
            if (query in doc_data["title"].lower() or
                query in doc_data["content"].lower() or
                any(query in tag.lower() for tag in doc_data["tags"])):
                matches = True

            # Filter by category if specified
            if category and doc_data["category"] != category:
                matches = False

            if matches:
                # Calculate relevance score (simple implementation)
                score = 0
                if query in doc_data["title"].lower():
                    score += 10
                if query in doc_data["content"].lower():
                    score += 5
                for tag in doc_data["tags"]:
                    if query in tag.lower():
                        score += 3

                results.append({
                    "id": doc_id,
                    "title": doc_data["title"],
                    "category": doc_data["category"],
                    "tags": doc_data["tags"],
                    "score": score,
                    "excerpt": doc_data["content"][:200] + "..." if len(doc_data["content"]) > 200 else doc_data["content"]
                })

        # Sort by relevance score
        results.sort(key=lambda x: x["score"], reverse=True)

        return {
            "success": True,
            "query": q,
            "category": category,
            "results": results,
            "total": len(results)
        }
    except Exception as e:
        logger.error(f"Error searching documents: {e}")
        raise HTTPException(status_code=500, detail="Failed to search documents")


@router.get("/api/categories")
async def get_categories():
    """Get all document categories."""
    try:
        categories = set()
        for doc_data in DOCS_STORAGE.values():
            categories.add(doc_data["category"])

        return {
            "success": True,
            "categories": sorted(list(categories))
        }
    except Exception as e:
        logger.error(f"Error getting categories: {e}")
        raise HTTPException(status_code=500, detail="Failed to get categories")


@router.get("/api/tags")
async def get_tags():
    """Get all document tags."""
    try:
        tags = set()
        for doc_data in DOCS_STORAGE.values():
            tags.update(doc_data["tags"])

        return {
            "success": True,
            "tags": sorted(list(tags))
        }
    except Exception as e:
        logger.error(f"Error getting tags: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tags")


@router.get("/api/stats")
async def get_documentation_stats():
    """Get documentation statistics."""
    try:
        categories = {}
        total_content_length = 0

        for doc_data in DOCS_STORAGE.values():
            category = doc_data["category"]
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
            total_content_length += len(doc_data["content"])

        return {
            "success": True,
            "stats": {
                "total_documents": len(DOCS_STORAGE),
                "categories": categories,
                "total_content_length": total_content_length,
                "average_document_length": total_content_length // len(DOCS_STORAGE) if DOCS_STORAGE else 0
            }
        }
    except Exception as e:
        logger.error(f"Error getting documentation stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get documentation stats")
