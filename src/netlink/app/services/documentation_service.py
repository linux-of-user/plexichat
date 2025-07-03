"""
Advanced Documentation Service for NetLink.
Provides comprehensive documentation management with search, filtering, and categorization.
"""

import os
import json
import markdown
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import re

from netlink.app.logger_config import logger


class DocumentationService:
    """Advanced documentation service with search and categorization."""
    
    def __init__(self, docs_dir: str = "docs"):
        self.docs_dir = Path(docs_dir)
        self.docs_cache = {}
        self.search_index = {}
        self.categories = {}
        
        # Ensure docs directory exists
        self.docs_dir.mkdir(exist_ok=True)
        
        # Initialize documentation
        self._initialize_docs()
        self._build_search_index()
        
        logger.info(f"📚 Documentation service initialized: {self.docs_dir}")
    
    def _initialize_docs(self):
        """Initialize documentation structure."""
        # Create default documentation structure
        default_docs = {
            "README.md": {
                "title": "NetLink Documentation",
                "category": "overview",
                "content": """# NetLink Documentation

Welcome to the comprehensive NetLink documentation system.

## Quick Navigation

- [Getting Started](getting-started.md)
- [API Reference](api-reference.md)
- [Administration Guide](admin-guide.md)
- [Security Guide](security-guide.md)
- [Development Guide](development-guide.md)

## Features

NetLink provides a comprehensive communication platform with:

- Real-time messaging
- File sharing with security scanning
- Voice and video calling
- Advanced backup system
- Multi-database support
- Clustering capabilities
- AI-powered moderation
- Social features

## Support

For support and questions, please refer to the appropriate documentation section or contact the development team.
"""
            },
            "getting-started.md": {
                "title": "Getting Started",
                "category": "user-guide",
                "content": """# Getting Started with NetLink

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python -m uvicorn src.netlink.app.main_simple_working:app`

## First Steps

1. Access the web interface at http://localhost:8000
2. Create your first user account
3. Explore the dashboard features
4. Configure your preferences

## Basic Usage

### Sending Messages
- Navigate to the messaging interface
- Select a channel or create a new one
- Type your message and press Enter

### File Sharing
- Click the file upload button
- Select your file (automatically scanned for security)
- Add a description if needed
- Share with your contacts

### Voice/Video Calls
- Click the call button next to a user
- Choose voice or video call
- Wait for the other user to accept

## Next Steps

- [User Manual](user-manual.md)
- [Configuration Guide](configuration.md)
- [Security Best Practices](security-guide.md)
"""
            },
            "api-reference.md": {
                "title": "API Reference",
                "category": "development",
                "content": """# NetLink API Reference

## Authentication

All API endpoints require authentication via JWT tokens.

```bash
# Login to get token
curl -X POST http://localhost:8000/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "user", "password": "password"}'

# Use token in subsequent requests
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:8000/api/v1/messages
```

## Endpoints

### Messages API
- `GET /api/v1/messages` - List messages
- `POST /api/v1/messages` - Send message
- `PUT /api/v1/messages/{id}` - Edit message
- `DELETE /api/v1/messages/{id}` - Delete message

### Files API
- `POST /api/v1/files/upload` - Upload file
- `GET /api/v1/files/{id}` - Download file
- `DELETE /api/v1/files/{id}` - Delete file

### Users API
- `GET /api/v1/users/me` - Get current user
- `PUT /api/v1/users/me` - Update profile
- `GET /api/v1/users/{id}` - Get user info

### Social API
- `POST /api/v1/social/friends/request` - Send friend request
- `GET /api/v1/social/friends` - List friends
- `POST /api/v1/social/profile` - Update profile

## WebSocket API

Connect to `ws://localhost:8000/ws` for real-time messaging.

```javascript
const ws = new WebSocket("ws://localhost:8000/ws");
ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    console.log("Received:", message);
};
```

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "details": {}
}
```
"""
            },
            "admin-guide.md": {
                "title": "Administration Guide",
                "category": "administration",
                "content": """# NetLink Administration Guide

## Admin Dashboard

Access the admin dashboard at http://localhost:8000/admin

### User Management
- View all users
- Create/edit/delete users
- Manage user permissions
- Reset passwords

### System Monitoring
- View system statistics
- Monitor performance metrics
- Check backup status
- Review security logs

### Configuration
- Update server settings
- Configure database connections
- Manage security settings
- Set up clustering

## Database Management

### Backup Operations
```bash
# Create backup
curl -X POST http://localhost:8000/api/v1/database/backup

# List backups
curl http://localhost:8000/api/v1/database/backups

# Restore backup
curl -X POST http://localhost:8000/api/v1/database/restore \\
  -d '{"backup_path": "backup.db", "confirm": true}'
```

### Migration
```bash
# Migrate to PostgreSQL
curl -X POST http://localhost:8000/api/v1/database/migrate \\
  -d '{
    "target_config": {
      "db_type": "postgresql",
      "host": "localhost",
      "database": "netlink"
    }
  }'
```

## Security Management

### File Scanning
- Configure antivirus settings
- Review threat logs
- Manage blocked domains
- Update security rules

### User Permissions
- Role-based access control
- Permission inheritance
- Custom permission sets
- Audit logging

## Troubleshooting

### Common Issues
1. **Database Connection Errors**
   - Check database configuration
   - Verify connection credentials
   - Test database connectivity

2. **File Upload Issues**
   - Check file size limits
   - Verify disk space
   - Review security scan logs

3. **Performance Issues**
   - Monitor system resources
   - Check database performance
   - Review clustering status
"""
            },
            "security-guide.md": {
                "title": "Security Guide",
                "category": "security",
                "content": """# NetLink Security Guide

## Security Features

### File Scanning
- Real-time malware detection
- Virus signature database
- Suspicious file blocking
- Quarantine system

### Network Security
- Rate limiting and DDoS protection
- IP blocking and whitelisting
- SSL/TLS encryption
- Secure WebSocket connections

### Data Protection
- End-to-end encryption
- Database encryption at rest
- Secure backup storage
- Key management

## Best Practices

### Server Security
1. Use HTTPS in production
2. Configure firewall rules
3. Regular security updates
4. Monitor access logs

### User Security
1. Strong password policies
2. Two-factor authentication
3. Regular password changes
4. Security awareness training

### Data Security
1. Regular backups
2. Encryption key rotation
3. Access control reviews
4. Audit trail maintenance

## Compliance

### Government Standards
- FIPS 140-2 compliance
- AES-256 encryption
- Secure key derivation
- Audit logging

### Privacy Protection
- GDPR compliance features
- Data retention policies
- User consent management
- Right to deletion

## Incident Response

### Security Incidents
1. Immediate containment
2. Impact assessment
3. Evidence collection
4. Recovery procedures

### Monitoring
- Real-time threat detection
- Automated alerting
- Security dashboards
- Forensic capabilities
"""
            },
            "development-guide.md": {
                "title": "Development Guide",
                "category": "development",
                "content": """# NetLink Development Guide

## Architecture

NetLink follows a modular architecture with clear separation of concerns:

```
src/netlink/app/
├── api/          # REST API endpoints
├── services/     # Business logic
├── models/       # Data models
├── database/     # Database abstraction
└── config/       # Configuration management
```

## Development Setup

1. **Clone Repository**
```bash
git clone https://github.com/your-org/netlink.git
cd netlink
```

2. **Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\\Scripts\\activate   # Windows
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

4. **Run in Development Mode**
```bash
python -m uvicorn src.netlink.app.main_simple_working:app --reload
```

## Adding New Features

### API Endpoints
1. Create endpoint in `src/netlink/app/api/v1/`
2. Add route to main application
3. Implement business logic in services
4. Add tests for new functionality

### Database Models
1. Define model in `src/netlink/app/models/`
2. Create migration if needed
3. Update database schema
4. Test model operations

### Services
1. Implement in `src/netlink/app/services/`
2. Follow dependency injection patterns
3. Add comprehensive error handling
4. Include logging and monitoring

## Testing

### Unit Tests
```bash
pytest tests/unit/
```

### Integration Tests
```bash
pytest tests/integration/
```

### API Tests
```bash
pytest tests/api/
```

### Individual Endpoint Tests
Access the testing dashboard at:
http://localhost:8000/api/v1/individual-testing/dashboard

## Code Style

### Python Standards
- Follow PEP 8
- Use type hints
- Comprehensive docstrings
- Error handling

### API Design
- RESTful principles
- Consistent response formats
- Proper HTTP status codes
- Comprehensive documentation

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request
5. Code review process

## Deployment

### Production Deployment
```bash
gunicorn src.netlink.app.main_simple_working:app \\
  -w 4 -k uvicorn.workers.UvicornWorker
```

### Docker Deployment
```bash
docker build -t netlink .
docker run -p 8000:8000 netlink
```

### Environment Variables
```bash
DATABASE_URL=postgresql://user:pass@localhost/netlink
SECRET_KEY=your-secret-key
DEBUG=false
```
"""
            }
        }
        
        # Create default documentation files
        for filename, doc_info in default_docs.items():
            doc_path = self.docs_dir / filename
            if not doc_path.exists():
                with open(doc_path, 'w', encoding='utf-8') as f:
                    f.write(doc_info['content'])
                logger.info(f"📄 Created documentation: {filename}")
    
    def _build_search_index(self):
        """Build search index for all documentation."""
        self.search_index = {}
        self.categories = {}
        
        for doc_path in self.docs_dir.glob("*.md"):
            try:
                with open(doc_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Extract metadata and content
                doc_info = self._parse_document(doc_path.name, content)
                
                # Add to search index
                self.search_index[doc_path.name] = doc_info
                
                # Categorize
                category = doc_info.get('category', 'general')
                if category not in self.categories:
                    self.categories[category] = []
                self.categories[category].append(doc_path.name)
                
            except Exception as e:
                logger.error(f"Failed to index document {doc_path}: {e}")
    
    def _parse_document(self, filename: str, content: str) -> Dict[str, Any]:
        """Parse document and extract metadata."""
        lines = content.split('\n')
        
        # Extract title (first # heading)
        title = filename.replace('.md', '').replace('-', ' ').title()
        for line in lines:
            if line.startswith('# '):
                title = line[2:].strip()
                break
        
        # Extract category from content or filename
        category = 'general'
        if 'api' in filename.lower():
            category = 'development'
        elif 'admin' in filename.lower():
            category = 'administration'
        elif 'security' in filename.lower():
            category = 'security'
        elif 'getting-started' in filename.lower() or 'user' in filename.lower():
            category = 'user-guide'
        
        # Extract headings for navigation
        headings = []
        for line in lines:
            if line.startswith('#'):
                level = len(line) - len(line.lstrip('#'))
                heading_text = line.lstrip('#').strip()
                if heading_text:
                    headings.append({
                        'level': level,
                        'text': heading_text,
                        'id': self._generate_heading_id(heading_text)
                    })
        
        # Extract keywords for search
        keywords = set()
        words = re.findall(r'\b\w+\b', content.lower())
        keywords.update(word for word in words if len(word) > 3)
        
        return {
            'filename': filename,
            'title': title,
            'category': category,
            'content': content,
            'headings': headings,
            'keywords': list(keywords),
            'word_count': len(words),
            'last_modified': datetime.now().isoformat()
        }
    
    def _generate_heading_id(self, heading_text: str) -> str:
        """Generate URL-friendly ID from heading text."""
        return re.sub(r'[^\w\s-]', '', heading_text.lower()).replace(' ', '-')
    
    def get_all_documents(self) -> List[Dict[str, Any]]:
        """Get all documents with metadata."""
        documents = []
        
        for filename, doc_info in self.search_index.items():
            documents.append({
                'filename': filename,
                'title': doc_info['title'],
                'category': doc_info['category'],
                'word_count': doc_info['word_count'],
                'last_modified': doc_info['last_modified'],
                'headings_count': len(doc_info['headings'])
            })
        
        return sorted(documents, key=lambda x: x['title'])
    
    def get_document(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get specific document with full content."""
        if filename in self.search_index:
            doc_info = self.search_index[filename].copy()
            
            # Convert markdown to HTML
            doc_info['html_content'] = markdown.markdown(
                doc_info['content'],
                extensions=['toc', 'codehilite', 'tables']
            )
            
            return doc_info
        
        return None
    
    def search_documents(self, query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search documents by query."""
        query_words = set(query.lower().split())
        results = []
        
        for filename, doc_info in self.search_index.items():
            # Filter by category if specified
            if category and doc_info['category'] != category:
                continue
            
            # Calculate relevance score
            score = 0
            
            # Title matches (highest weight)
            title_words = set(doc_info['title'].lower().split())
            title_matches = len(query_words.intersection(title_words))
            score += title_matches * 10
            
            # Content matches
            content_words = set(doc_info['keywords'])
            content_matches = len(query_words.intersection(content_words))
            score += content_matches
            
            # Heading matches
            for heading in doc_info['headings']:
                heading_words = set(heading['text'].lower().split())
                heading_matches = len(query_words.intersection(heading_words))
                score += heading_matches * 5
            
            if score > 0:
                # Extract relevant snippets
                snippets = self._extract_snippets(doc_info['content'], query_words)
                
                results.append({
                    'filename': filename,
                    'title': doc_info['title'],
                    'category': doc_info['category'],
                    'score': score,
                    'snippets': snippets,
                    'word_count': doc_info['word_count']
                })
        
        # Sort by relevance score
        return sorted(results, key=lambda x: x['score'], reverse=True)
    
    def _extract_snippets(self, content: str, query_words: set, max_snippets: int = 3) -> List[str]:
        """Extract relevant snippets from content."""
        sentences = re.split(r'[.!?]+', content)
        snippets = []
        
        for sentence in sentences:
            sentence_words = set(sentence.lower().split())
            if query_words.intersection(sentence_words):
                snippet = sentence.strip()
                if len(snippet) > 20:  # Minimum snippet length
                    snippets.append(snippet[:200] + '...' if len(snippet) > 200 else snippet)
                
                if len(snippets) >= max_snippets:
                    break
        
        return snippets
    
    def get_categories(self) -> Dict[str, List[str]]:
        """Get all categories with document counts."""
        category_info = {}
        
        for category, documents in self.categories.items():
            category_info[category] = {
                'name': category.replace('-', ' ').title(),
                'count': len(documents),
                'documents': [
                    {
                        'filename': doc,
                        'title': self.search_index[doc]['title']
                    }
                    for doc in documents
                ]
            }
        
        return category_info
    
    def get_navigation_tree(self) -> Dict[str, Any]:
        """Get hierarchical navigation tree."""
        tree = {}
        
        for category, category_info in self.get_categories().items():
            tree[category] = {
                'name': category_info['name'],
                'documents': []
            }
            
            for doc_info in category_info['documents']:
                doc_data = self.search_index[doc_info['filename']]
                tree[category]['documents'].append({
                    'filename': doc_info['filename'],
                    'title': doc_info['title'],
                    'headings': doc_data['headings']
                })
        
        return tree
    
    def refresh_index(self):
        """Refresh the search index."""
        logger.info("🔄 Refreshing documentation index...")
        self._build_search_index()
        logger.info("✅ Documentation index refreshed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get documentation statistics."""
        total_docs = len(self.search_index)
        total_words = sum(doc['word_count'] for doc in self.search_index.values())
        
        category_stats = {}
        for category, documents in self.categories.items():
            category_stats[category] = {
                'count': len(documents),
                'words': sum(self.search_index[doc]['word_count'] for doc in documents)
            }
        
        return {
            'total_documents': total_docs,
            'total_words': total_words,
            'categories': len(self.categories),
            'category_breakdown': category_stats,
            'last_updated': datetime.now().isoformat()
        }


# Global documentation service instance
documentation_service = DocumentationService()
