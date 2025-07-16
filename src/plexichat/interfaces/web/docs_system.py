# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import markdown

from pathlib import Path
from datetime import datetime


from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

"""
PlexiChat Enhanced Documentation System
Comprehensive documentation interface with advanced search, navigation, and modern UI.
"""

logger = logging.getLogger(__name__)

# Documentation router
docs_router = APIRouter(prefix="/docs", tags=["documentation"])

# Templates
template_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=template_dir)

class EnhancedDocumentationManager:
    """Enhanced documentation manager with advanced features."""

    def __init__(self):
        self.from pathlib import Path
docs_dir = Path()("docs")
        self.docs_dir.mkdir(exist_ok=True)
        self.cache = {}
        self.search_index = {}
        self.last_indexed = None

        # Initialize documentation
        self._create_default_docs()
        self._build_search_index()
        self.doc_structure = self._build_doc_structure()

        logger.info(f"Enhanced documentation manager initialized: {self.docs_dir}")

    def _create_default_docs(self):
        """Create default documentation files."""
        docs_content = {
            "README.md": """# PlexiChat Documentation

Welcome to PlexiChat - a comprehensive network management and administration platform.

## Quick Start

1. **Installation**: Follow the setup wizard for easy installation
2. **Login**: Use the secure login interface at `/auth/login`
3. **Admin Panel**: Access the admin interface at `/admin/`
4. **API**: Explore the API documentation at `/api/docs`

## Features

- **Secure Authentication**: Multi-factor authentication with session management
- **Admin Interface**: Comprehensive web-based administration
- **API Access**: RESTful API with full documentation
- **Performance Monitoring**: Real-time system monitoring
- **User Management**: Complete user and permission management
- **Configuration**: Web-based system configuration

## Support

For support and questions, check the documentation sections below.
""",

            "installation.md": """# Installation Guide

## System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 10GB disk space
- Network connectivity

## Quick Installation

### Option 1: Setup Wizard (Recommended)

1. Download PlexiChat from the repository
2. Run the setup wizard:
   ```bash
   python setup_wizard.py
   ```
3. Follow the guided installation process

### Option 2: Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/plexichat.git
   cd plexichat
   ```

2. Create virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run initial setup:
   ```bash
   python -m plexichat.setup
   ```

5. Start the application:
   ```bash
   python run.py
   ```

## Configuration

The system will create default configuration files in the `config/` directory.
You can modify these files or use the web interface for configuration.

## First Login

- Default username: `admin`
- Default password: `PlexiChat2025!`
- **Important**: Change the default password after first login!

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in configuration
2. **Permission denied**: Run with appropriate permissions
3. **Module not found**: Ensure all dependencies are installed

### Getting Help

- Check the logs in `logs/` directory
- Run system diagnostics: `python -m plexichat.diagnostics`
- Contact support with error details
""",

            "api-guide.md": """# API Guide

PlexiChat provides a comprehensive RESTful API for all administrative functions.

## Authentication

All API endpoints require authentication using session cookies or API keys.

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your_password"
}
```

## API Endpoints

### Admin Accounts
- `GET /api/v1/admin/accounts` - List all admin accounts
- `POST /api/v1/admin/accounts` - Create new admin account
- `GET /api/v1/admin/accounts/{username}` - Get specific account
- `PUT /api/v1/admin/accounts/{username}` - Update account
- `DELETE /api/v1/admin/accounts/{username}` - Delete account

### System Management
- `GET /api/v1/admin/system/status` - Get system status
- `POST /api/v1/admin/system/command` - Execute system command
- `GET /api/v1/admin/config` - Get configuration
- `PUT /api/v1/admin/config` - Update configuration

### User Profile
- `GET /api/v1/admin/profile` - Get current user profile
- `PUT /api/v1/admin/profile` - Update profile
- `POST /api/v1/admin/profile/change-password` - Change password

## Response Format

All API responses follow this format:

```json
{
  "success": true,
  "data": {...},
  "message": "Operation completed successfully",
  "timestamp": "2025-06-29T12:00:00Z"
}
```

## Error Handling

Error responses include detailed error information:

```json
{
  "success": false,
  "error": "Invalid credentials",
  "error_code": "AUTH_FAILED",
  "details": {...}
}
```

## Rate Limiting

API endpoints are rate limited:
- 100 requests per minute for authenticated users
- 10 requests per minute for unauthenticated requests

## Examples

### Create Admin Account
```bash
curl -X POST "http://localhost:8000/api/v1/admin/accounts" \\
  -H "Content-Type: application/json" \\
  -d '{
    "username": "newadmin",
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "role": "admin",
    "permissions": ["view", "manage_users"]
  }'
```

### Get System Status
```bash
curl -X GET "http://localhost:8000/api/v1/admin/system/status" \\
  -H "Authorization: Bearer your_session_token"
```
""",

            "user-guide.md": """# User Guide

## Getting Started

### Logging In

1. Navigate to the login page at `/auth/login`
2. Enter your username and password
3. Click "Sign In Securely"
4. You'll be redirected to the admin dashboard

### Dashboard Overview

The admin dashboard provides:
- **System Status**: Real-time system health and performance
- **Quick Actions**: Common administrative tasks
- **Recent Activity**: Latest system events and logs
- **Statistics**: Key metrics and usage data

## User Management

### Creating Users

1. Go to **Admin**  **Users**
2. Click "Add New User"
3. Fill in the required information:
   - Username (3-50 characters, letters/numbers/underscore/hyphen only)
   - Email address
   - Password (minimum 8 characters with complexity requirements)
   - Role (admin or super_admin)
   - Permissions

### Managing Permissions

Available permissions:
- **view**: Access to dashboard and read-only features
- **manage_users**: Create, edit, and delete user accounts
- **view_logs**: Access to system logs and audit trails
- **system_config**: Modify system configuration
- **system_admin**: Full system administration access

### Password Reset

If you forget your password:
1. Click "Forgot your password?" on the login page
2. Enter your username and email
3. Check the CLI terminal for the reset code
4. Enter the reset code and new password

## System Configuration

### Server Settings

Configure server parameters:
- **Host**: Server bind address
- **Port**: Server port number
- **Debug Mode**: Enable/disable debug logging
- **Log Level**: Set logging verbosity

### Security Settings

Configure security parameters:
- **Session Timeout**: How long sessions remain active
- **Max Login Attempts**: Failed attempts before account lockout
- **Force HTTPS**: Require secure connections
- **Two-Factor Authentication**: Enable 2FA (coming soon)

### Performance Settings

Optimize system performance:
- **Worker Processes**: Number of worker processes
- **Request Timeout**: Maximum request processing time
- **Enable Caching**: Response caching for better performance
- **Enable Compression**: Compress responses to save bandwidth

## Monitoring and Logs

### System Monitoring

The system provides real-time monitoring of:
- CPU usage and load average
- Memory usage and availability
- Disk space and I/O
- Network connections
- Active sessions

### Log Management

Access and manage system logs:
- **View Logs**: Browse logs with filtering and search
- **Download Logs**: Export logs for external analysis
- **Log Rotation**: Automatic log rotation and cleanup
- **Log Levels**: Filter by severity (DEBUG, INFO, WARNING, ERROR)

### Performance Metrics

Track system performance:
- Response times and throughput
- Error rates and success rates
- Cache hit rates and efficiency
- Resource utilization trends

## Troubleshooting

### Common Issues

1. **Cannot login**: Check username/password, account may be locked
2. **Slow performance**: Check system resources and cache settings
3. **Permission denied**: Verify user permissions and role
4. **Session expired**: Login again, check session timeout settings

### Getting Help

1. Check the system logs for error details
2. Run system diagnostics from the admin panel
3. Review the API documentation for integration issues
4. Contact system administrator with specific error messages

## Best Practices

### Security

- Use strong passwords with complexity requirements
- Enable two-factor authentication when available
- Regularly review user accounts and permissions
- Monitor login attempts and suspicious activity
- Keep the system updated with latest security patches

### Performance

- Monitor system resources regularly
- Configure appropriate cache settings
- Use log rotation to manage disk space
- Optimize database queries and connections
- Set reasonable session timeouts

### Maintenance

- Backup configuration regularly
- Test system recovery procedures
- Monitor system health metrics
- Keep documentation updated
- Train users on proper system usage
""",

            "troubleshooting.md": """# Troubleshooting Guide

## Common Issues and Solutions

### Authentication Issues

#### Cannot Login
**Symptoms**: Login fails with "Invalid credentials" message

**Solutions**:
1. Verify username and password are correct
2. Check if account is locked (too many failed attempts)
3. Ensure caps lock is not enabled
4. Try password reset if needed

#### Session Expired
**Symptoms**: Redirected to login page unexpectedly

**Solutions**:
1. Login again (sessions expire for security)
2. Check session timeout settings in configuration
3. Ensure browser cookies are enabled

#### Account Locked
**Symptoms**: "Account locked" message on login

**Solutions**:
1. Wait for lockout period to expire (default: 30 minutes)
2. Contact administrator to unlock account manually
3. Use password reset to unlock account

### Performance Issues

#### Slow Response Times
**Symptoms**: Pages load slowly, timeouts occur

**Solutions**:
1. Check system resource usage (CPU, memory, disk)
2. Verify network connectivity
3. Clear browser cache
4. Check server logs for errors
5. Restart the application if needed

#### High Memory Usage
**Symptoms**: System becomes unresponsive, out of memory errors

**Solutions**:
1. Restart the application
2. Check for memory leaks in logs
3. Reduce cache size in configuration
4. Increase system memory if possible

#### Database Connection Issues
**Symptoms**: Database errors, connection timeouts

**Solutions**:
1. Check database service status
2. Verify database connection settings
3. Check database disk space
4. Restart database service if needed

### Configuration Issues

#### Port Already in Use
**Symptoms**: "Port 8000 already in use" error on startup

**Solutions**:
1. Change port in configuration file
2. Stop other services using the port
3. Use `netstat` or `lsof` to find conflicting processes

#### Permission Denied
**Symptoms**: File access errors, permission denied messages

**Solutions**:
1. Check file permissions on data directories
2. Run with appropriate user permissions
3. Verify directory ownership
4. Check SELinux/AppArmor policies if applicable

#### Configuration File Errors
**Symptoms**: Invalid configuration errors on startup

**Solutions**:
1. Validate JSON syntax in configuration files
2. Check for missing required configuration keys
3. Reset to default configuration if needed
4. Review configuration documentation

### Network Issues

#### Cannot Access Web Interface
**Symptoms**: Browser cannot connect to the application

**Solutions**:
1. Verify the application is running
2. Check firewall settings
3. Ensure correct IP address and port
4. Try accessing from localhost first

#### API Requests Failing
**Symptoms**: API calls return connection errors

**Solutions**:
1. Check API endpoint URLs
2. Verify authentication credentials
3. Check rate limiting settings
4. Review API documentation for correct usage

### System Issues

#### Application Won't Start
**Symptoms**: Startup errors, application crashes immediately

**Solutions**:
1. Check Python version compatibility (3.8+ required)
2. Verify all dependencies are installed
3. Check for missing configuration files
4. Review startup logs for specific errors

#### Disk Space Issues
**Symptoms**: "No space left on device" errors

**Solutions**:
1. Clean up old log files
2. Remove temporary files
3. Increase disk space
4. Configure log rotation

#### Memory Leaks
**Symptoms**: Memory usage increases over time

**Solutions**:
1. Restart the application regularly
2. Monitor memory usage patterns
3. Check for unclosed resources in logs
4. Update to latest version with fixes

## Diagnostic Tools

### Built-in Diagnostics

Run system diagnostics:
```bash
python -m plexichat.diagnostics
```

This will check:
- System requirements
- Configuration validity
- Database connectivity
- File permissions
- Network connectivity

### Log Analysis

Check application logs:
```bash
# View recent logs
tail -f logs/plexichat.log

# Search for errors
grep ERROR logs/plexichat.log

# View specific time range
grep "2025-06-29 12:" logs/plexichat.log
```

### System Health Check

Access health check endpoint:
```bash
curl http://localhost:8000/health
```

### Performance Monitoring

Monitor system resources:
```bash
# CPU and memory usage
top

# Disk usage
df -h

# Network connections
netstat -an | grep 8000
```

## Getting Help

### Information to Collect

When reporting issues, include:
1. **Error messages**: Exact error text and codes
2. **Log files**: Relevant log entries with timestamps
3. **System information**: OS, Python version, hardware specs
4. **Configuration**: Relevant configuration settings
5. **Steps to reproduce**: Detailed steps that cause the issue

### Log Locations

- Application logs: `logs/plexichat.log`
- Error logs: `logs/error.log`
- Access logs: `logs/access.log`
- Audit logs: `logs/audit.log`

### Support Channels

1. **Documentation**: Check this documentation first
2. **System diagnostics**: Run built-in diagnostic tools
3. **Community forums**: Search for similar issues
4. **Issue tracker**: Report bugs and feature requests
5. **Professional support**: Contact for enterprise support

## Prevention

### Regular Maintenance

1. **Monitor system health**: Check dashboards regularly
2. **Review logs**: Look for warnings and errors
3. **Update software**: Keep system updated
4. **Backup data**: Regular backups of configuration and data
5. **Test procedures**: Verify backup and recovery procedures

### Best Practices

1. **Resource monitoring**: Set up alerts for resource usage
2. **Log rotation**: Configure automatic log cleanup
3. **Security updates**: Apply security patches promptly
4. **Documentation**: Keep configuration changes documented
5. **Training**: Ensure users know proper procedures
"""
        }

        # Create documentation files
        for filename, content in docs_content.items():
            doc_file = self.docs_dir / filename
            if not doc_file.exists():
                with open(doc_file, 'w', encoding='utf-8') as f:
                    f.write(content)

    def _build_search_index(self):
        """Build comprehensive search index."""
        self.search_index = {}

        for doc_file in self.docs_dir.glob("*.md"):
            try:
                with open(doc_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract metadata
                title = self._extract_title(content)
                headings = self._extract_headings(content)
                word_count = len(content.split())

                self.search_index[doc_file.name] = {
                    'title': title,
                    'content': content,
                    'headings': headings,
                    'word_count': word_count,
                    'last_modified': doc_file.stat().st_mtime,
                    'file_path': str(doc_file)
                }

            except Exception as e:
                logger.error(f"Failed to index {doc_file}: {e}")

        self.from datetime import datetime
last_indexed = datetime().now()
        logger.info(f"Search index built with {len(self.search_index)} documents")

    def _extract_title(self, content: str) -> str:
        """Extract title from markdown content."""
        lines = content.split('\n')
        for line in lines:
            if line.startswith('# '):
                return line[2:].strip()
        return "Untitled"

    def _extract_headings(self, content: str) -> List[Dict[str, Any]]:
        """Extract all headings from markdown content."""
        headings = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            if line.startswith('#'):
                level = len(line) - len(line.lstrip('#'))
                text = line.lstrip('#').strip()
                if text:
                    headings.append({
                        'level': level,
                        'text': text,
                        'line': i + 1,
                        'id': self._generate_heading_id(text)
                    })

        return headings

    def _generate_heading_id(self, text: str) -> str:
        """Generate URL-friendly ID from heading text."""
        return re.sub(r'[^\w\s-]', '', text.lower()).replace(' ', '-')

    def _build_doc_structure(self) -> Dict[str, Any]:
        """Build enhanced documentation structure."""
        return {
            "Getting Started": [
                {"title": "Overview", "file": "README.md", "icon": "fas fa-home", "description": "Welcome to PlexiChat"},
                {"title": "Installation", "file": "installation.md", "icon": "fas fa-download", "description": "Setup and installation guide"},
                {"title": "Getting Started", "file": "GETTING_STARTED.md", "icon": "fas fa-rocket", "description": "Quick start guide"},
                {"title": "User Guide", "file": "user-guide.md", "icon": "fas fa-user", "description": "Complete user manual"}
            ],
            "API Documentation": [
                {"title": "API Reference", "file": "api_reference.md", "icon": "fas fa-code", "description": "Complete API documentation"},
                {"title": "API Guide", "file": "api-guide.md", "icon": "fas fa-book", "description": "API usage guide"},
                {"title": "Interactive API", "url": "/api/docs", "icon": "fas fa-play-circle", "description": "Swagger UI"},
                {"title": "OpenAPI Schema", "url": "/api/openapi.json", "icon": "fas fa-file-code", "description": "OpenAPI specification"}
            ],
            "System Administration": [
                {"title": "Configuration", "file": "configuration.md", "icon": "fas fa-cog", "description": "System configuration guide"},
                {"title": "User Management", "file": "user-management.md", "icon": "fas fa-users", "description": "User and permission management"},
                {"title": "Security", "file": "security.md", "icon": "fas fa-shield-alt", "description": "Security configuration"},
                {"title": "Monitoring", "file": "monitoring.md", "icon": "fas fa-chart-line", "description": "System monitoring"}
            ],
            "Advanced Features": [
                {"title": "Clustering", "file": "clustering-system.md", "icon": "fas fa-network-wired", "description": "Multi-node clustering"},
                {"title": "Backup System", "file": "backup-system.md", "icon": "fas fa-database", "description": "Backup and recovery"},
                {"title": "Update System", "file": "update-system.md", "icon": "fas fa-sync-alt", "description": "Version management"},
                {"title": "Troubleshooting", "file": "troubleshooting.md", "icon": "fas fa-tools", "description": "Problem resolution"}
            ],
            "Development": [
                {"title": "Module Development", "file": "module_development.md", "icon": "fas fa-puzzle-piece", "description": "Creating custom modules"},
                {"title": "Database Setup", "file": "database_setup_guide.md", "icon": "fas fa-database", "description": "Database configuration"},
                {"title": "Testing", "file": "testing.md", "icon": "fas fa-vial", "description": "Testing framework"},
                {"title": "Contributing", "file": "contributing.md", "icon": "fas fa-hands-helping", "description": "Contribution guidelines"}
            ]
        }

    def advanced_search(self, query: str, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Advanced search with filters and ranking."""
        if not query.strip():
            return []

        results = []
        query_lower = query.lower()
        filters = filters or {}

        for filename, doc_info in self.search_index.items():
            score = 0
            matches = []

            # Title match (highest weight)
            if query_lower in doc_info['title'].lower():
                score += 10
                matches.append({
                    'type': 'title',
                    'text': doc_info['title'],
                    'context': doc_info['title']
                })

            # Heading matches (high weight)
            for heading in doc_info['headings']:
                if query_lower in heading['text'].lower():
                    score += 5
                    matches.append({
                        'type': 'heading',
                        'text': heading['text'],
                        'context': heading['text'],
                        'level': heading['level']
                    })

            # Content matches (medium weight)
            content_lines = doc_info['content'].split('\n')
            for i, line in enumerate(content_lines):
                if query_lower in line.lower():
                    score += 1
                    # Get context around the match
                    start = max(0, i - 2)
                    end = min(len(content_lines), i + 3)
                    context = '\n'.join(content_lines[start:end])

                    matches.append({
                        'type': 'content',
                        'text': line.strip(),
                        'context': context,
                        'line_number': i + 1
                    })

            if matches:
                results.append({
                    'filename': filename,
                    'title': doc_info['title'],
                    'score': score,
                    'matches': matches[:5],  # Limit matches per document
                    'word_count': doc_info['word_count'],
                    'last_modified': doc_info['last_modified']
                })

        # Sort by score (descending)
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:20]  # Limit total results

    def get_document(self, filename: str) -> Optional[str]:
        """Get enhanced document content with metadata."""
        doc_file = self.docs_dir / filename
        if doc_file.exists() and doc_file.suffix == '.md':
            # Check cache first
            cache_key = f"{filename}_{doc_file.stat().st_mtime}"
            if cache_key in self.cache:
                return self.cache[cache_key]

            with open(doc_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Enhanced markdown processing
            html_content = markdown.markdown(
                content,
                extensions=[
                    'codehilite',
                    'toc',
                    'tables',
                    'fenced_code',
                    'attr_list'
                ]
            )

            # Cache the result
            self.cache[cache_key] = html_content
            return html_content
        return None

    def search_documents(self, query: str) -> List[Dict[str, Any]]:
        """Enhanced search through documentation."""
        return self.advanced_search(query)

    def get_document_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get document metadata."""
        if filename in self.search_index:
            doc_info = self.search_index[filename]
            return {
                'title': doc_info['title'],
                'headings': doc_info['headings'],
                'word_count': doc_info['word_count'],
                'last_modified': datetime.fromtimestamp(doc_info['last_modified']).isoformat(),
                'file_path': doc_info['file_path']
            }
        return None

    def get_all_documents(self) -> List[Dict[str, Any]]:
        """Get all documents with metadata."""
        documents = []

        for filename, doc_info in self.search_index.items():
            documents.append({
                'filename': filename,
                'title': doc_info['title'],
                'word_count': doc_info['word_count'],
                'last_modified': datetime.fromtimestamp(doc_info['last_modified']).isoformat(),
                'headings_count': len(doc_info['headings'])
            })

        return sorted(documents, key=lambda x: x['title'])

    def refresh_index(self):
        """Refresh the search index."""
        self._build_search_index()
        logger.info("Documentation search index refreshed")

# Documentation routes
@docs_router.get("/", response_class=HTMLResponse)
async def docs_home(request: Request):
    """Documentation home page."""
    return templates.TemplateResponse("docs/index.html", {
        "request": request,
        "doc_structure": doc_manager.doc_structure,
        "page_title": "PlexiChat Documentation"
    })

@docs_router.get("/search")
async def search_docs(request: Request, q: str = ""):
    """Search documentation."""
    if not q:
        return JSONResponse({"results": []})

    results = doc_manager.search_documents(q)
    return JSONResponse({"results": results, "query": q})

@docs_router.get("/{doc_name}", response_class=HTMLResponse)
async def view_document(request: Request, doc_name: str):
    """View specific documentation."""
    # Add .md extension if not present
    if not doc_name.endswith('.md'):
        doc_name += '.md'

    content = doc_manager.get_document(doc_name)
    if not content:
        raise HTTPException(status_code=404, detail="Document not found")

    # Get document title from filename
    title = doc_name.replace('.md', '').replace('-', ' ').title()

    return templates.TemplateResponse("docs/document.html", {
        "request": request,
        "content": content,
        "title": title,
        "doc_structure": doc_manager.doc_structure,
        "page_title": f"{title} - PlexiChat Documentation"
    })

# Global enhanced documentation manager
doc_manager = EnhancedDocumentationManager()

@docs_router.get("/api/structure")
async def get_doc_structure():
    """Get documentation structure as JSON."""
    return JSONResponse(doc_manager.doc_structure)

@docs_router.get("/search")
async def search_docs(
    request: Request,
    q: str = Query("", description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(20, description="Maximum results")
):
    """Enhanced search documentation with filters."""
    if not q:
        return JSONResponse({"results": [], "total": 0, "query": q})

    filters = {}
    if category:
        filters['category'] = category

    results = doc_manager.advanced_search(q, filters)

    # Limit results
    limited_results = results[:limit]

    return JSONResponse({
        "results": limited_results,
        "total": len(results),
        "query": q,
        "filters": filters,
        "categories": list(doc_manager.doc_structure.keys())
    })

@docs_router.get("/api/documents")
async def get_all_documents():
    """Get all documents with metadata."""
    documents = doc_manager.get_all_documents()
    return JSONResponse({
        "documents": documents,
        "total": len(documents),
        "last_indexed": doc_manager.last_indexed.isoformat() if doc_manager.last_indexed else None
    })

@docs_router.get("/api/document/{filename}/metadata")
async def get_document_metadata(filename: str):
    """Get document metadata."""
    metadata = doc_manager.get_document_metadata(filename)
    if not metadata:
        raise HTTPException(status_code=404, detail="Document not found")
    return JSONResponse(metadata)

@docs_router.post("/api/refresh-index")
async def refresh_search_index():
    """Refresh the documentation search index."""
    doc_manager.refresh_index()
    return JSONResponse({
        "message": "Search index refreshed successfully",
        "documents_indexed": len(doc_manager.search_index),
        "last_indexed": doc_manager.last_indexed.isoformat()
    })
