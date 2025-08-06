"""
PlexiChat WebUI Router
=====================

Provides web-based user interface endpoints for PlexiChat.
"""

import logging
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional

try:
    from plexichat.core.unified_config import get_app_version
    PLEXICHAT_VERSION = get_app_version()
except ImportError:
    PLEXICHAT_VERSION = "2.0.0"
from plexichat.core.security.security_decorators import require_auth, rate_limit, audit_access
from plexichat.core.logging_advanced.enhanced_logging_system import get_logger

# Initialize logging
logger = get_logger('plexichat.interfaces.web.routers.webui')

# Create router
router = APIRouter(prefix="/ui", tags=["webui"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))

@router.get("/", response_class=HTMLResponse)
@rate_limit(requests_per_minute=60)
@audit_access("view", "webui")
async def webui_home(request: Request):
    """Main WebUI dashboard."""
    if not templates:
        # Fallback HTML if templates not available
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PlexiChat WebUI</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh; display: flex; align-items: center; justify-content: center;
                }}
                .container {{ 
                    background: white; padding: 40px; border-radius: 12px; 
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 800px; width: 90%;
                }}
                h1 {{ color: #333; margin-bottom: 20px; }}
                .version {{ color: #666; font-size: 0.9em; margin-bottom: 30px; }}
                .features {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .feature {{ 
                    padding: 20px; background: #f8f9fa; border-radius: 8px; 
                    border-left: 4px solid #667eea; text-align: center;
                }}
                .feature h3 {{ margin: 0 0 10px 0; color: #333; }}
                .feature p {{ margin: 0; color: #666; font-size: 0.9em; }}
                .links {{ margin-top: 30px; text-align: center; }}
                .links a {{ 
                    display: inline-block; margin: 0 10px; padding: 10px 20px; 
                    background: #667eea; color: white; text-decoration: none; 
                    border-radius: 6px; transition: background 0.3s;
                }}
                .links a:hover {{ background: #5a6fd8; }}
                .status {{ 
                    background: #d4edda; color: #155724; padding: 15px; 
                    border-radius: 6px; margin-bottom: 20px; text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="status">? PlexiChat is running successfully</div>
                <h1>PlexiChat WebUI</h1>
                <div class="version">Version: {PLEXICHAT_VERSION}</div>
                
                <div class="features">
                    <div class="feature">
                        <h3>? Authentication</h3>
                        <p>Secure user authentication and session management</p>
                    </div>
                    <div class="feature">
                        <h3>[CLI] Messaging</h3>
                        <p>Real-time messaging with WebSocket support</p>
                    </div>
                    <div class="feature">
                        <h3>[FOLDER] File Management</h3>
                        <p>Upload, download, and manage files securely</p>
                    </div>
                    <div class="feature">
                        <h3>?? Administration</h3>
                        <p>System administration and user management</p>
                    </div>
                    <div class="feature">
                        <h3>[STATS] Monitoring</h3>
                        <p>System health and performance monitoring</p>
                    </div>
                    <div class="feature">
                        <h3>? Plugins</h3>
                        <p>Extensible plugin system for custom features</p>
                    </div>
                </div>
                
                <div class="links">
                    <a href="/docs">API Documentation</a>
                    <a href="/admin">Admin Panel</a>
                    <a href="/auth/login">Login</a>
                    <a href="/system/status">System Status</a>
                </div>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)
    
    try:
        return templates.TemplateResponse(
            "webui/dashboard.html",
            {
                "request": request,
                "version": PLEXICHAT_VERSION,
                "title": "PlexiChat WebUI"
            }
        )
    except Exception as e:
        logger.warning(f"Template error: {e}")
        raise HTTPException(status_code=500, detail="WebUI template error")

@router.get("/login", response_class=HTMLResponse)
@rate_limit(requests_per_minute=30)
async def webui_login(request: Request):
    """WebUI login page."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - PlexiChat WebUI</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh; display: flex; align-items: center; justify-content: center;
            }}
            .login-container {{ 
                background: white; padding: 40px; border-radius: 12px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.2); width: 400px; max-width: 90%;
            }}
            h1 {{ text-align: center; color: #333; margin-bottom: 30px; }}
            .form-group {{ margin-bottom: 20px; }}
            label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
            input {{ 
                width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; 
                font-size: 16px; box-sizing: border-box;
            }}
            button {{ 
                width: 100%; padding: 12px; background: #667eea; color: white; 
                border: none; border-radius: 6px; font-size: 16px; cursor: pointer;
                transition: background 0.3s;
            }}
            button:hover {{ background: #5a6fd8; }}
            .links {{ text-align: center; margin-top: 20px; }}
            .links a {{ color: #667eea; text-decoration: none; }}
            .links a:hover {{ text-decoration: underline; }}
            .version {{ text-align: center; color: #666; font-size: 0.8em; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>PlexiChat Login</h1>
            <form action="/auth/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="links">
                <a href="/ui">< Back to WebUI</a>
            </div>
            <div class="version">PlexiChat {PLEXICHAT_VERSION}</div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/dashboard", response_class=HTMLResponse)
@require_auth()
@rate_limit(requests_per_minute=60)
async def webui_dashboard(request: Request):
    """Authenticated user dashboard."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - PlexiChat WebUI</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0; padding: 20px; background: #f5f5f5;
            }}
            .header {{ 
                background: white; padding: 20px; border-radius: 8px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px;
                display: flex; justify-content: space-between; align-items: center;
            }}
            .dashboard-grid {{ 
                display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 20px;
            }}
            .widget {{ 
                background: white; padding: 20px; border-radius: 8px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .widget h3 {{ margin: 0 0 15px 0; color: #333; }}
            .logout {{ 
                background: #dc3545; color: white; padding: 8px 16px; 
                text-decoration: none; border-radius: 4px;
            }}
            .logout:hover {{ background: #c82333; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>PlexiChat Dashboard</h1>
            <a href="/auth/logout" class="logout">Logout</a>
        </div>
        
        <div class="dashboard-grid">
            <div class="widget">
                <h3>[CLI] Messages</h3>
                <p>Send and receive messages in real-time.</p>
                <a href="/messages">View Messages</a>
            </div>
            
            <div class="widget">
                <h3>[FOLDER] Files</h3>
                <p>Upload and manage your files securely.</p>
                <a href="/files">Manage Files</a>
            </div>
            
            <div class="widget">
                <h3>? Users</h3>
                <p>View and manage user accounts.</p>
                <a href="/users">User Management</a>
            </div>
            
            <div class="widget">
                <h3>[STATS] System Status</h3>
                <p>Monitor system health and performance.</p>
                <a href="/system/status">View Status</a>
            </div>

            <div class="widget" style="background: linear-gradient(45deg, #ff6b6b, #4ecdc4); cursor: pointer;" onclick="easterEggClick()" id="easterEggWidget">
                <h3>? Easter Eggs</h3>
                <p>Discover hidden features and fun surprises!</p>
                <a href="/api/v1/easter-eggs/">Explore Easter Eggs</a>
            </div>
        </div>

        <div style="text-align: center; margin-top: 40px; color: #666;">
            PlexiChat {PLEXICHAT_VERSION}
            <div id="secretMessage" style="display: none; margin-top: 10px; color: #4ecdc4;">
                [SUCCESS] You found the secret! Try the Konami code: ^^vv<><>BA
            </div>
        </div>

        <script>
            // Easter egg functionality
            let clickCount = 0;
            let konamiSequence = [];
            const konamiCode = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'KeyB', 'KeyA'];

            function easterEggClick() {{
                clickCount++;
                if (clickCount === 3) {{
                    document.getElementById('secretMessage').style.display = 'block';
                    setTimeout(() => {{
                        document.getElementById('secretMessage').style.display = 'none';
                    }}, 5000);
                }}
                if (clickCount === 7) {{
                    showDeveloperInfo();
                }}
            }}

            function showDeveloperInfo() {{
                alert('[SETUP] PlexiChat Developer Mode\\n\\n' +
                      '[START] Version: {PLEXICHAT_VERSION}\\n' +
                      '[LAUNCH] Framework: FastAPI + HTML/CSS/JS\\n' +
                      '? Security: Enterprise-grade\\n' +
                      '? Performance: Sub-millisecond API\\n\\n' +
                      '[GAME] Easter Eggs Found: ' + (clickCount >= 7 ? 'Developer Mode!' : clickCount) + '\\n\\n' +
                      'Thanks for exploring PlexiChat! ?');
            }}

            // Konami code listener
            document.addEventListener('keydown', function(event) {{
                konamiSequence.push(event.code);
                if (konamiSequence.length > 10) {{
                    konamiSequence.shift();
                }}

                if (konamiSequence.join(',') === konamiCode.join(',')) {{
                    showKonamiEasterEgg();
                    konamiSequence = [];
                }}
            }});

            function showKonamiEasterEgg() {{
                // Create Easter egg overlay
                const overlay = document.createElement('div');
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.9);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 9999;
                    color: white;
                    text-align: center;
                    font-family: Arial, sans-serif;
                `;

                overlay.innerHTML = `
                    <div>
                        <h1 style="font-size: 3em; margin-bottom: 20px;">[GAME] KONAMI CODE ACTIVATED! [GAME]</h1>
                        <p style="font-size: 1.5em; margin-bottom: 20px;">^ ^ v v < > < > B A</p>
                        <p style="font-size: 1.2em; margin-bottom: 30px;">
                            [SUCCESS] Congratulations! You found the secret Konami code!<br>
                            [START] PlexiChat WebUI Developer Mode Unlocked!<br>
                            ? Thanks for exploring our Easter eggs!
                        </p>
                        <button onclick="this.parentElement.parentElement.remove()"
                                style="padding: 15px 30px; font-size: 1.2em; background: #4ecdc4;
                                       color: white; border: none; border-radius: 5px; cursor: pointer;">
                            Awesome! [SUCCESS]
                        </button>
                    </div>
                `;

                document.body.appendChild(overlay);

                // Auto-remove after 10 seconds
                setTimeout(() => {{
                    if (overlay.parentElement) {{
                        overlay.remove();
                    }}
                }}, 10000);
            }}

            // Secret 42 reference
            let keySequence = '';
            document.addEventListener('keypress', function(event) {{
                keySequence += event.key;
                if (keySequence.length > 10) {{
                    keySequence = keySequence.slice(-10);
                }}

                if (keySequence.includes('42')) {{
                    show42Reference();
                    keySequence = '';
                }}
            }});

            function show42Reference() {{
                alert('? The Answer to Everything: 42\\n\\n' +
                      '"The Answer to the Ultimate Question of Life, ' +
                      'the Universe, and Everything is 42."\\n\\n' +
                      '- The Hitchhiker\\'s Guide to the Galaxy\\n' +
                      'by Douglas Adams\\n\\n' +
                      'Don\\'t Panic! [START]');
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# Initialize enhanced security and logging
logger.info("Enhanced security and logging initialized for webui")