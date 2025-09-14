"""
PlexiChat Help Router

Comprehensive help system with interactive tutorials, searchable documentation,
keyboard shortcuts reference, FAQ section, and contextual help.
"""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from plexichat.core.auth.fastapi_adapter import get_current_user
from plexichat.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["help"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))

# Help content data
HELP_CONTENT = {
    "getting_started": {
        "title": "Getting Started",
        "content": """
        <h3>Welcome to PlexiChat!</h3>
        <p>PlexiChat is a modern, secure communication platform designed for teams and organizations.</p>

        <h4>Quick Start Guide</h4>
        <ol>
            <li><strong>Sign Up:</strong> Create your account using the registration form</li>
            <li><strong>Join Servers:</strong> Browse and join available servers or create your own</li>
            <li><strong>Start Chatting:</strong> Send messages, share files, and collaborate with your team</li>
            <li><strong>Customize:</strong> Set up your profile and preferences</li>
        </ol>

        <h4>Key Features</h4>
        <ul>
            <li>Real-time messaging with WebSocket support</li>
            <li>File sharing and management</li>
            <li>Server and channel organization</li>
            <li>Advanced security and encryption</li>
            <li>Plugin system for extensibility</li>
        </ul>
        """,
        "category": "basics",
    },
    "messaging": {
        "title": "Messaging Guide",
        "content": """
        <h3>Messaging in PlexiChat</h3>

        <h4>Sending Messages</h4>
        <ul>
            <li>Type your message in the input field at the bottom of any channel</li>
            <li>Press Enter to send, Shift+Enter for new line</li>
            <li>Use @username to mention specific users</li>
            <li>Use #channel to link to channels</li>
        </ul>

        <h4>Message Features</h4>
        <ul>
            <li><strong>Formatting:</strong> Use Markdown for text formatting</li>
            <li><strong>Emojis:</strong> Type :emoji_name: or use the emoji picker</li>
            <li><strong>Code blocks:</strong> Use ```language for syntax highlighting</li>
            <li><strong>Links:</strong> URLs are automatically detected and clickable</li>
        </ul>

        <h4>Message History</h4>
        <p>You can scroll up to view previous messages. Use the search function to find specific messages.</p>
        """,
        "category": "features",
    },
    "files": {
        "title": "File Management",
        "content": """
        <h3>Managing Files in PlexiChat</h3>

        <h4>Uploading Files</h4>
        <ul>
            <li>Click the paperclip icon or drag files into the message input</li>
            <li>Supported formats: images, documents, archives, and more</li>
            <li>Maximum file size: 100MB per file</li>
        </ul>

        <h4>File Organization</h4>
        <ul>
            <li>Files are organized by channel and server</li>
            <li>Use the Files tab to browse all uploaded files</li>
            <li>Search files by name, type, or uploader</li>
        </ul>

        <h4>Security</h4>
        <p>All files are scanned for security threats before upload and storage.</p>
        """,
        "category": "features",
    },
    "servers": {
        "title": "Server Management",
        "content": """
        <h3>Managing Servers</h3>

        <h4>Creating a Server</h4>
        <ol>
            <li>Click the "+" button next to "Servers" in the sidebar</li>
            <li>Enter a server name and description</li>
            <li>Set privacy settings (public or private)</li>
            <li>Invite members using the invite link</li>
        </ol>

        <h4>Server Settings</h4>
        <ul>
            <li><strong>Roles:</strong> Define member permissions</li>
            <li><strong>Channels:</strong> Create text and voice channels</li>
            <li><strong>Moderation:</strong> Set up auto-moderation rules</li>
            <li><strong>Integrations:</strong> Connect external services</li>
        </ul>
        """,
        "category": "advanced",
    },
    "security": {
        "title": "Security & Privacy",
        "content": """
        <h3>Security Features</h3>

        <h4>End-to-End Encryption</h4>
        <p>All messages and files are encrypted in transit and at rest using industry-standard encryption.</p>

        <h4>Two-Factor Authentication</h4>
        <p>Enable 2FA in your account settings for additional security.</p>

        <h4>Privacy Controls</h4>
        <ul>
            <li>Control who can see your online status</li>
            <li>Manage message history visibility</li>
            <li>Set up privacy for direct messages</li>
        </ul>

        <h4>Reporting</h4>
        <p>Report suspicious activity or violations using the report feature.</p>
        """,
        "category": "security",
    },
}

KEYBOARD_SHORTCUTS = {
    "general": [
        {"keys": ["Ctrl", "K"], "description": "Open command palette"},
        {"keys": ["Ctrl", "/", "?"], "description": "Open help"},
        {"keys": ["Ctrl", "Shift", "A"], "description": "Toggle accessibility mode"},
        {"keys": ["Esc"], "description": "Close modals or return to previous view"},
    ],
    "messaging": [
        {"keys": ["Enter"], "description": "Send message"},
        {"keys": ["Shift", "Enter"], "description": "New line in message"},
        {"keys": ["Ctrl", "Enter"], "description": "Send message (alternative)"},
        {"keys": ["↑"], "description": "Edit last message"},
        {"keys": ["Tab"], "description": "Navigate through mentions"},
    ],
    "navigation": [
        {"keys": ["Alt", "↑"], "description": "Previous channel"},
        {"keys": ["Alt", "↓"], "description": "Next channel"},
        {"keys": ["Ctrl", "1-9"], "description": "Switch to server 1-9"},
        {"keys": ["Ctrl", "Shift", "↑"], "description": "Scroll to top"},
        {"keys": ["Ctrl", "Shift", "↓"], "description": "Scroll to bottom"},
    ],
}

FAQ_CONTENT = [
    {
        "question": "How do I reset my password?",
        "answer": "Click 'Forgot Password' on the login page and follow the instructions sent to your email.",
    },
    {
        "question": "Can I use PlexiChat on mobile devices?",
        "answer": "Yes, PlexiChat has a responsive web interface that works on all modern mobile browsers.",
    },
    {
        "question": "How do I create a new server?",
        "answer": "Click the '+' button next to 'Servers' in the left sidebar, then follow the setup wizard.",
    },
    {
        "question": "Are my messages private?",
        "answer": "Messages in private channels are only visible to invited members. Public channels are visible to all server members.",
    },
    {
        "question": "How do I report inappropriate content?",
        "answer": "Right-click on the message and select 'Report' from the context menu.",
    },
    {
        "question": "Can I integrate PlexiChat with other tools?",
        "answer": "Yes, PlexiChat supports webhooks and has a plugin system for integrations.",
    },
]

TUTORIALS = [
    {
        "id": "welcome",
        "title": "Welcome to PlexiChat",
        "description": "Learn the basics of using PlexiChat",
        "steps": [
            {
                "title": "Explore the Interface",
                "content": "Take a moment to explore the main interface elements.",
            },
            {
                "title": "Join a Server",
                "content": "Click on a server in the left sidebar to join.",
            },
            {
                "title": "Send Your First Message",
                "content": "Type a message in the input field and press Enter.",
            },
            {
                "title": "Customize Your Profile",
                "content": "Click on your avatar to access profile settings.",
            },
        ],
    },
    {
        "id": "advanced_messaging",
        "title": "Advanced Messaging",
        "description": "Master advanced messaging features",
        "steps": [
            {
                "title": "Use Markdown",
                "content": "Learn to format your messages with **bold**, *italic*, and `code`.",
            },
            {
                "title": "Mention Users",
                "content": "Type @ followed by a username to mention someone.",
            },
            {
                "title": "Share Files",
                "content": "Click the paperclip icon to upload and share files.",
            },
            {
                "title": "Use Emojis",
                "content": "Add emojis to your messages using the emoji picker.",
            },
        ],
    },
]


@router.get("/", response_class=HTMLResponse)
async def help_center(
    request: Request, current_user: dict[str, Any] | None = Depends(get_current_user)
):
    """Main help center page with comprehensive help system."""
    if not templates:
        return HTMLResponse(content=get_fallback_help_page())

    try:
        return templates.TemplateResponse(
            "help.html",
            {
                "request": request,
                "current_user": current_user,
                "title": "Help Center - PlexiChat",
                "help_content": HELP_CONTENT,
                "keyboard_shortcuts": KEYBOARD_SHORTCUTS,
                "faq": FAQ_CONTENT,
                "tutorials": TUTORIALS,
            },
        )
    except Exception as e:
        logger.error(f"Help template error: {e}")
        return HTMLResponse(content=get_fallback_help_page())


@router.get("/api/search", response_class=JSONResponse)
async def search_help(
    q: str,
    category: str | None = None,
    current_user: dict[str, Any] | None = Depends(get_current_user),
):
    """Search help content."""
    try:
        results = []
        query = q.lower()

        # Search in help content
        for key, content in HELP_CONTENT.items():
            if query in content["title"].lower() or query in content["content"].lower():
                if not category or content.get("category") == category:
                    results.append(
                        {
                            "id": key,
                            "title": content["title"],
                            "category": content.get("category", "general"),
                            "type": "article",
                            "snippet": content["content"][:200] + "...",
                        }
                    )

        # Search in FAQ
        for faq in FAQ_CONTENT:
            if query in faq["question"].lower() or query in faq["answer"].lower():
                results.append(
                    {
                        "id": f"faq_{FAQ_CONTENT.index(faq)}",
                        "title": faq["question"],
                        "category": "faq",
                        "type": "faq",
                        "snippet": faq["answer"][:200] + "...",
                    }
                )

        return {"results": results, "total": len(results)}

    except Exception as e:
        logger.error(f"Search error: {e}")
        return JSONResponse(
            content={"error": "Search failed", "results": []}, status_code=500
        )


@router.get("/api/content/{content_id}", response_class=JSONResponse)
async def get_help_content(
    content_id: str, current_user: dict[str, Any] | None = Depends(get_current_user)
):
    """Get specific help content."""
    try:
        if content_id in HELP_CONTENT:
            return HELP_CONTENT[content_id]
        elif content_id.startswith("faq_"):
            index = int(content_id.split("_")[1])
            if 0 <= index < len(FAQ_CONTENT):
                return FAQ_CONTENT[index]

        raise HTTPException(status_code=404, detail="Content not found")

    except Exception as e:
        logger.error(f"Content retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve content")


@router.get("/api/tutorials", response_class=JSONResponse)
async def get_tutorials(
    current_user: dict[str, Any] | None = Depends(get_current_user),
):
    """Get available tutorials."""
    return {"tutorials": TUTORIALS}


@router.get("/api/tutorial/{tutorial_id}", response_class=JSONResponse)
async def get_tutorial(
    tutorial_id: str, current_user: dict[str, Any] | None = Depends(get_current_user)
):
    """Get specific tutorial."""
    try:
        for tutorial in TUTORIALS:
            if tutorial["id"] == tutorial_id:
                return tutorial

        raise HTTPException(status_code=404, detail="Tutorial not found")

    except Exception as e:
        logger.error(f"Tutorial retrieval error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve tutorial")


@router.get("/api/keyboard-shortcuts", response_class=JSONResponse)
async def get_keyboard_shortcuts(
    current_user: dict[str, Any] | None = Depends(get_current_user),
):
    """Get keyboard shortcuts reference."""
    return {"shortcuts": KEYBOARD_SHORTCUTS}


def get_fallback_help_page() -> str:
    """Fallback HTML for help page when templates are not available."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Help Center - PlexiChat</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .help-container { background: rgba(255,255,255,0.95); margin: 20px; border-radius: 20px; padding: 40px; }
            .search-box { max-width: 600px; margin: 0 auto 40px; }
            .help-section { margin-bottom: 40px; }
            .help-card { background: white; border-radius: 10px; padding: 20px; margin: 20px 0; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        </style>
    </head>
    <body>
        <div class="help-container">
            <div class="text-center mb-5">
                <h1><i class="fas fa-question-circle text-primary"></i> Help Center</h1>
                <p class="lead">Find answers and learn how to use PlexiChat</p>
            </div>

            <div class="search-box">
                <div class="input-group">
                    <input type="text" class="form-control" placeholder="Search help topics..." id="search-input">
                    <button class="btn btn-primary" type="button" id="search-btn">
                        <i class="fas fa-search"></i> Search
                    </button>
                </div>
            </div>

            <div class="row">
                <div class="col-md-8">
                    <div class="help-section">
                        <h3>Getting Started</h3>
                        <div class="help-card">
                            <h5>Welcome to PlexiChat</h5>
                            <p>PlexiChat is a modern communication platform designed for teams and organizations.</p>
                            <a href="#getting-started" class="btn btn-sm btn-outline-primary">Read More</a>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Features</h3>
                        <div class="help-card">
                            <h5>Messaging Guide</h5>
                            <p>Learn how to send messages, use formatting, and collaborate effectively.</p>
                            <a href="#messaging" class="btn btn-sm btn-outline-primary">Read More</a>
                        </div>
                        <div class="help-card">
                            <h5>File Management</h5>
                            <p>Upload, share, and organize files securely.</p>
                            <a href="#files" class="btn btn-sm btn-outline-primary">Read More</a>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="help-section">
                        <h3>Quick Links</h3>
                        <div class="list-group">
                            <a href="#shortcuts" class="list-group-item list-group-item-action">
                                <i class="fas fa-keyboard me-2"></i>Keyboard Shortcuts
                            </a>
                            <a href="#faq" class="list-group-item list-group-item-action">
                                <i class="fas fa-question me-2"></i>FAQ
                            </a>
                            <a href="#tutorials" class="list-group-item list-group-item-action">
                                <i class="fas fa-graduation-cap me-2"></i>Tutorials
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            // Basic search functionality
            document.getElementById('search-btn').addEventListener('click', function() {
                const query = document.getElementById('search-input').value;
                if (query.trim()) {
                    alert('Search functionality would be implemented here. Query: ' + query);
                }
            });

            document.getElementById('search-input').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    document.getElementById('search-btn').click();
                }
            });
        </script>
    </body>
    </html>
    """
