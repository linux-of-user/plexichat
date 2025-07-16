# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportOptionalMemberAccess=false
import asyncio
import json
import logging
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from ...infrastructure.modules.enhanced_plugin_manager import get_enhanced_plugin_manager, PluginStatus, PluginType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/plugins", tags=["Plugin Management"])


class PluginInfo(BaseModel):
    """Plugin information model."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    status: str
    enabled: bool
    category: str
    tags: List[str]
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str
    icon: Optional[str] = None
    download_count: int
    rating: float
    last_updated: Optional[str] = None
    size_bytes: int
    ui_pages: List[Dict[str, str]]
    api_endpoints: List[str]
    webhooks: List[str]
    auto_start: bool
    background_tasks: List[str]


class PluginInstallRequest(BaseModel):
    """Plugin installation request model."""
    plugin_id: str
    version: Optional[str] = None
    source: str = "marketplace"  # marketplace, zip, url


class PluginUpdateRequest(BaseModel):
    """Plugin update request model."""
    plugin_name: str
    enabled: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None


@router.get("/", response_class=HTMLResponse)
async def plugin_management_page(request: Request):
    """Plugin management main page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        plugins_info = plugin_manager.get_all_plugins_info()
        
        # Convert to list for easier template handling
        plugins_list = []
        for plugin_name, info in plugins_info.items():
            if info:
                plugins_list.append({
                    "name": plugin_name,
                    **info
                })
        
        # Sort by name
        plugins_list.sort(key=lambda x: x["name"])
        
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Plugin Management - PlexiChat</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .plugin-card {{
                    transition: transform 0.2s;
                    border: 1px solid #e9ecef;
                }}
                .plugin-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                }}
                .status-badge {{
                    font-size: 0.75rem;
                }}
                .plugin-icon {{
                    font-size: 2rem;
                    color: #6c757d;
                }}
                .stats-card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                }}
            </style>
        </head>
        <body>
            <div class="container-fluid">
                <div class="row">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1><i class="bi bi-puzzle"></i> Plugin Management</h1>
                            <div>
                                <button class="btn btn-primary me-2" onclick="showInstallModal()">
                                    <i class="bi bi-plus-circle"></i> Install Plugin
                                </button>
                                <button class="btn btn-outline-secondary" onclick="refreshPlugins()">
                                    <i class="bi bi-arrow-clockwise"></i> Refresh
                                </button>
                            </div>
                        </div>
                        
                        <!-- Statistics Cards -->
                        <div class="row mb-4">
                            <div class="col-md-3">
                                <div class="card stats-card">
                                    <div class="card-body">
                                        <h5 class="card-title">Total Plugins</h5>
                                        <h2>{len(plugins_list)}</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stats-card">
                                    <div class="card-body">
                                        <h5 class="card-title">Enabled</h5>
                                        <h2>{len([p for p in plugins_list if p.get('enabled', False)])}</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stats-card">
                                    <div class="card-body">
                                        <h5 class="card-title">Loaded</h5>
                                        <h2>{len([p for p in plugins_list if p.get('loaded', False)])}</h2>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card stats-card">
                                    <div class="card-body">
                                        <h5 class="card-title">Errors</h5>
                                        <h2>{len([p for p in plugins_list if p.get('status') == 'error'])}</h2>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Plugin Grid -->
                        <div class="row" id="plugins-grid">
                            {''.join([f'''
                            <div class="col-md-6 col-lg-4 mb-4">
                                <div class="card plugin-card h-100">
                                    <div class="card-header d-flex justify-content-between align-items-center">
                                        <div class="d-flex align-items-center">
                                            <i class="bi bi-{plugin.get('metadata', {}).get('icon', 'puzzle')} plugin-icon me-2"></i>
                                            <h6 class="mb-0">{plugin['name']}</h6>
                                        </div>
                                        <div class="dropdown">
                                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                                <i class="bi bi-three-dots"></i>
                                            </button>
                                            <ul class="dropdown-menu">
                                                <li><a class="dropdown-item" href="#" onclick="viewPlugin('{plugin['name']}')">
                                                    <i class="bi bi-eye"></i> View Details
                                                </a></li>
                                                <li><a class="dropdown-item" href="#" onclick="configurePlugin('{plugin['name']}')">
                                                    <i class="bi bi-gear"></i> Configure
                                                </a></li>
                                                <li><a class="dropdown-item" href="#" onclick="togglePlugin('{plugin['name']}', {not plugin.get('enabled', False)})">
                                                    <i class="bi bi-{'pause' if plugin.get('enabled', False) else 'play'}"></i> 
                                                    {'Disable' if plugin.get('enabled', False) else 'Enable'}
                                                </a></li>
                                                <li><hr class="dropdown-divider"></li>
                                                <li><a class="dropdown-item text-danger" href="#" onclick="removePlugin('{plugin['name']}')">
                                                    <i class="bi bi-trash"></i> Remove
                                                </a></li>
                                            </ul>
                                        </div>
                                    </div>
                                    <div class="card-body">
                                        <p class="card-text text-muted">{plugin.get('metadata', {}).get('description', 'No description available')}</p>
                                        <div class="mb-2">
                                            <span class="badge bg-{'success' if plugin.get('enabled', False) else 'secondary'} status-badge">
                                                {plugin.get('status', 'unknown')}
                                            </span>
                                            <span class="badge bg-info status-badge">{plugin.get('metadata', {}).get('category', 'general')}</span>
                                        </div>
                                        <div class="small text-muted">
                                            <div>Version: {plugin.get('metadata', {}).get('version', 'unknown')}</div>
                                            <div>Author: {plugin.get('metadata', {}).get('author', 'unknown')}</div>
                                            <div>Type: {plugin.get('metadata', {}).get('plugin_type', 'unknown')}</div>
                                        </div>
                                    </div>
                                    <div class="card-footer">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <small class="text-muted">
                                                {len(plugin.get('ui_pages', []))} UI pages • {len(plugin.get('api_endpoints', []))} API endpoints
                                            </small>
                                            <div class="form-check form-switch">
                                                <input class="form-check-input" type="checkbox" 
                                                       {'checked' if plugin.get('enabled', False) else ''}
                                                       onchange="togglePlugin('{plugin['name']}', this.checked)">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            ''' for plugin in plugins_list])}
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Install Plugin Modal -->
            <div class="modal fade" id="installModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Install Plugin</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <ul class="nav nav-tabs" id="installTabs">
                                <li class="nav-item">
                                    <a class="nav-link active" data-bs-toggle="tab" href="#marketplace">Marketplace</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" data-bs-toggle="tab" href="#upload">Upload ZIP</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" data-bs-toggle="tab" href="#url">From URL</a>
                                </li>
                            </ul>
                            <div class="tab-content mt-3">
                                <div class="tab-pane fade show active" id="marketplace">
                                    <div class="mb-3">
                                        <input type="text" class="form-control" id="searchQuery" placeholder="Search plugins...">
                                    </div>
                                    <div id="marketplace-results">
                                        <div class="text-center text-muted">
                                            <i class="bi bi-search"></i> Search for plugins to install
                                        </div>
                                    </div>
                                </div>
                                <div class="tab-pane fade" id="upload">
                                    <form id="uploadForm">
                                        <div class="mb-3">
                                            <label class="form-label">Plugin ZIP File</label>
                                            <input type="file" class="form-control" id="pluginFile" accept=".zip">
                                        </div>
                                        <button type="submit" class="btn btn-primary">Upload & Install</button>
                                    </form>
                                </div>
                                <div class="tab-pane fade" id="url">
                                    <form id="urlForm">
                                        <div class="mb-3">
                                            <label class="form-label">Plugin URL</label>
                                            <input type="url" class="form-control" id="pluginUrl" placeholder="https://...">
                                        </div>
                                        <button type="submit" class="btn btn-primary">Download & Install</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                function showInstallModal() {{
                    new bootstrap.Modal(document.getElementById('installModal')).show();
                }}
                
                function refreshPlugins() {{
                    location.reload();
                }}
                
                async function togglePlugin(name, enabled) {{
                    try {{
                        const response = await fetch(`/api/v1/plugins/${{name}}/toggle`, {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{enabled: enabled}})
                        }});
                        if (response.ok) {{
                            location.reload();
                        }} else {{
                            alert('Failed to toggle plugin');
                        }}
                    }} catch (error) {{
                        console.error('Error:', error);
                        alert('Error toggling plugin');
                    }}
                }}
                
                async function removePlugin(name) {{
                    if (confirm(`Are you sure you want to remove the plugin "${{name}}"?`)) {{
                        try {{
                            const response = await fetch(`/api/v1/plugins/${{name}}/remove`, {{
                                method: 'DELETE'
                            }});
                            if (response.ok) {{
                                location.reload();
                            }} else {{
                                alert('Failed to remove plugin');
                            }}
                        }} catch (error) {{
                            console.error('Error:', error);
                            alert('Error removing plugin');
                        }}
                    }}
                }}
                
                function viewPlugin(name) {{
                    window.open(`/api/v1/plugins/${{name}}/info`, '_blank');
                }}
                
                function configurePlugin(name) {{
                    window.open(`/plugins/${{name}}/configure`, '_blank');
                }}
                
                // Search marketplace
                document.getElementById('searchQuery').addEventListener('input', async function() {{
                    const query = this.value;
                    if (query.length > 2) {{
                        try {{
                            const response = await fetch(`/api/v1/plugins/marketplace/search?q=${{encodeURIComponent(query)}}`);
                            const results = await response.json();
                            displayMarketplaceResults(results);
                        }} catch (error) {{
                            console.error('Search error:', error);
                        }}
                    }}
                }});
                
                function displayMarketplaceResults(results) {{
                    const container = document.getElementById('marketplace-results');
                    if (results.length === 0) {{
                        container.innerHTML = '<div class="text-center text-muted">No plugins found</div>';
                        return;
                    }}
                    
                    container.innerHTML = results.map(plugin => `
                        <div class="card mb-2">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <h6 class="card-title">${{plugin.name}}</h6>
                                        <p class="card-text small">${{plugin.description}}</p>
                                        <div class="small text-muted">
                                            Version: ${{plugin.version}} • Downloads: ${{plugin.download_count}} • Rating: ${{plugin.rating}}/5
                                        </div>
                                    </div>
                                    <button class="btn btn-sm btn-primary" onclick="installFromMarketplace('${{plugin.id}}')">
                                        Install
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }}
                
                async function installFromMarketplace(pluginId) {{
                    try {{
                        const response = await fetch('/api/v1/plugins/install', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{plugin_id: pluginId, source: 'marketplace'}})
                        }});
                        if (response.ok) {{
                            alert('Plugin installed successfully!');
                            location.reload();
                        }} else {{
                            alert('Failed to install plugin');
                        }}
                    }} catch (error) {{
                        console.error('Install error:', error);
                        alert('Error installing plugin');
                    }}
                }}
                
                // Handle file upload
                document.getElementById('uploadForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    const fileInput = document.getElementById('pluginFile');
                    const file = fileInput.files[0];
                    if (!file) {{
                        alert('Please select a file');
                        return;
                    }}
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {{
                        const response = await fetch('/api/v1/plugins/install/zip', {{
                            method: 'POST',
                            body: formData
                        }});
                        if (response.ok) {{
                            alert('Plugin installed successfully!');
                            location.reload();
                        }} else {{
                            alert('Failed to install plugin');
                        }}
                    }} catch (error) {{
                        console.error('Upload error:', error);
                        alert('Error uploading plugin');
                    }}
                }});
                
                // Handle URL installation
                document.getElementById('urlForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    const url = document.getElementById('pluginUrl').value;
                    if (!url) {{
                        alert('Please enter a URL');
                        return;
                    }}
                    
                    try {{
                        const response = await fetch('/api/v1/plugins/install', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{plugin_id: url, source: 'url'}})
                        }});
                        if (response.ok) {{
                            alert('Plugin installed successfully!');
                            location.reload();
                        }} else {{
                            alert('Failed to install plugin');
                        }}
                    }} catch (error) {{
                        console.error('URL install error:', error);
                        alert('Error installing plugin from URL');
                    }}
                }});
            </script>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Error rendering plugin management page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load plugin management page")


@router.get("/api/v1/plugins")
async def list_plugins():
    """Get list of all plugins."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        plugins_info = plugin_manager.get_all_plugins_info()
        
        # Convert to list format
        plugins_list = []
        for plugin_name, info in plugins_info.items():
            if info:
                plugins_list.append({
                    "name": plugin_name,
                    **info
                })
        
        return {"plugins": plugins_list}
    except Exception as e:
        logger.error(f"Error listing plugins: {e}")
        raise HTTPException(status_code=500, detail="Failed to list plugins")


@router.get("/api/v1/plugins/{plugin_name}")
async def get_plugin_info(plugin_name: str):
    """Get detailed information about a specific plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        plugin_info = plugin_manager.get_plugin_info(plugin_name)
        
        if not plugin_info:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        return plugin_info
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting plugin info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin info")


@router.post("/api/v1/plugins/{plugin_name}/toggle")
async def toggle_plugin(plugin_name: str, enabled: bool):
    """Enable or disable a plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        if enabled:
            # Load plugin
            success = await plugin_manager.load_plugin(plugin_name)
            if not success:
                raise HTTPException(status_code=400, detail="Failed to enable plugin")
        else:
            # Unload plugin
            success = await plugin_manager.unload_plugin(plugin_name)
            if not success:
                raise HTTPException(status_code=400, detail="Failed to disable plugin")
        
        return {"success": True, "message": f"Plugin {plugin_name} {'enabled' if enabled else 'disabled'}"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling plugin: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle plugin")


@router.delete("/api/v1/plugins/{plugin_name}/remove")
async def remove_plugin(plugin_name: str):
    """Remove a plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        success = await plugin_manager.remove_plugin(plugin_name)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to remove plugin")
        
        return {"success": True, "message": f"Plugin {plugin_name} removed"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing plugin: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove plugin")


@router.post("/api/v1/plugins/install")
async def install_plugin(request: PluginInstallRequest):
    """Install a plugin from marketplace or URL."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        if request.source == "marketplace":
            # Install from marketplace
            plugin_file = await plugin_manager.marketplace.download_plugin(request.plugin_id, request.version)
            if not plugin_file:
                raise HTTPException(status_code=400, detail="Failed to download plugin from marketplace")
            
            success = await plugin_manager.install_plugin_from_zip(plugin_file)
            plugin_file.unlink()  # Clean up temp file
            
        elif request.source == "url":
            # Install from URL
            import aiohttp
            import tempfile
            
            async with aiohttp.ClientSession() as session:
                async with session.get(request.plugin_id) as response:
                    if response.status != 200:
                        raise HTTPException(status_code=400, detail="Failed to download plugin from URL")
                    
                    # Save to temp file
                    temp_file = Path(tempfile.mktemp(suffix=".zip"))
                    with open(temp_file, 'wb') as f:
                        f.write(await response.read())
                    
                    success = await plugin_manager.install_plugin_from_zip(temp_file)
                    temp_file.unlink()  # Clean up temp file
        else:
            raise HTTPException(status_code=400, detail="Invalid source")
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to install plugin")
        
        return {"success": True, "message": "Plugin installed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error installing plugin: {e}")
        raise HTTPException(status_code=500, detail="Failed to install plugin")


@router.post("/api/v1/plugins/install/zip")
async def install_plugin_from_zip(file: UploadFile = File(...)):
    """Install a plugin from uploaded ZIP file."""
    try:
        if not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="File must be a ZIP file")
        
        # Save uploaded file to temp location
        temp_file = Path(tempfile.mktemp(suffix=".zip"))
        with open(temp_file, 'wb') as f:
            shutil.copyfileobj(file.file, f)
        
        plugin_manager = get_enhanced_plugin_manager()
        success = await plugin_manager.install_plugin_from_zip(temp_file)
        
        # Clean up temp file
        temp_file.unlink()
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to install plugin")
        
        return {"success": True, "message": "Plugin installed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error installing plugin from ZIP: {e}")
        raise HTTPException(status_code=500, detail="Failed to install plugin")


@router.get("/api/v1/plugins/marketplace/search")
async def search_marketplace(query: str = "", category: str = "", plugin_type: str = ""):
    """Search plugins in marketplace."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Convert plugin type string to enum if provided
        plugin_type_enum = None
        if plugin_type:
            try:
                plugin_type_enum = PluginType(plugin_type)
            except ValueError:
                pass
        
        results = await plugin_manager.marketplace.search_plugins(
            query=query,
            category=category,
            plugin_type=plugin_type_enum
        )
        
        return {"results": results}
    except Exception as e:
        logger.error(f"Error searching marketplace: {e}")
        raise HTTPException(status_code=500, detail="Failed to search marketplace")


@router.get("/api/v1/plugins/marketplace/{plugin_id}")
async def get_marketplace_plugin(plugin_id: str):
    """Get detailed information about a marketplace plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        plugin_info = await plugin_manager.marketplace.get_plugin_info(plugin_id)
        
        if not plugin_info:
            raise HTTPException(status_code=404, detail="Plugin not found in marketplace")
        
        return plugin_info
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting marketplace plugin info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get marketplace plugin info")


@router.get("/api/v1/plugins/{plugin_name}/configure")
async def configure_plugin_page(plugin_name: str, request: Request):
    """Plugin configuration page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        plugin_info = plugin_manager.get_plugin_info(plugin_name)
        
        if not plugin_info:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        # Get plugin settings schema
        settings_schema = plugin_info.get("metadata", {}).get("settings_schema", {})
        
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Configure {plugin_name} - PlexiChat</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-4">
                <div class="row">
                    <div class="col-12">
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <h1><i class="bi bi-gear"></i> Configure {plugin_name}</h1>
                            <a href="/plugins" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left"></i> Back to Plugins
                            </a>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <h5>Plugin Information</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Name:</strong> {plugin_info.get('metadata', {}).get('name', 'N/A')}</p>
                                        <p><strong>Version:</strong> {plugin_info.get('metadata', {}).get('version', 'N/A')}</p>
                                        <p><strong>Author:</strong> {plugin_info.get('metadata', {}).get('author', 'N/A')}</p>
                                        <p><strong>Status:</strong> <span class="badge bg-{'success' if plugin_info.get('enabled', False) else 'secondary'}">{plugin_info.get('status', 'unknown')}</span></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Type:</strong> {plugin_info.get('metadata', {}).get('plugin_type', 'N/A')}</p>
                                        <p><strong>Category:</strong> {plugin_info.get('metadata', {}).get('category', 'N/A')}</p>
                                        <p><strong>License:</strong> {plugin_info.get('metadata', {}).get('license', 'N/A')}</p>
                                        <p><strong>Description:</strong> {plugin_info.get('metadata', {}).get('description', 'No description available')}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="card mt-4">
                            <div class="card-header">
                                <h5>Configuration</h5>
                            </div>
                            <div class="card-body">
                                <form id="configForm">
                                    <div id="config-fields">
                                        <!-- Configuration fields will be generated here -->
                                        <div class="text-center text-muted">
                                            <i class="bi bi-info-circle"></i> No configuration options available for this plugin
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="bi bi-check-circle"></i> Save Configuration
                                        </button>
                                        <button type="button" class="btn btn-outline-secondary ms-2" onclick="resetForm()">
                                            <i class="bi bi-arrow-clockwise"></i> Reset
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card mt-4">
                            <div class="card-header">
                                <h5>Plugin Actions</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <button class="btn btn-{'danger' if plugin_info.get('enabled', False) else 'success'} w-100 mb-2" onclick="togglePlugin()">
                                            <i class="bi bi-{'pause' if plugin_info.get('enabled', False) else 'play'}"></i> 
                                            {'Disable' if plugin_info.get('enabled', False) else 'Enable'} Plugin
                                        </button>
                                    </div>
                                    <div class="col-md-6">
                                        <button class="btn btn-warning w-100 mb-2" onclick="restartPlugin()">
                                            <i class="bi bi-arrow-clockwise"></i> Restart Plugin
                                        </button>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6">
                                        <button class="btn btn-info w-100 mb-2" onclick="viewLogs()">
                                            <i class="bi bi-file-text"></i> View Logs
                                        </button>
                                    </div>
                                    <div class="col-md-6">
                                        <button class="btn btn-outline-danger w-100 mb-2" onclick="removePlugin()">
                                            <i class="bi bi-trash"></i> Remove Plugin
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                // Generate configuration form based on schema
                const settingsSchema = {json.dumps(settings_schema)};
                
                function generateConfigForm(schema) {{
                    const container = document.getElementById('config-fields');
                    if (!schema || !schema.properties) {{
                        return;
                    }}
                    
                    container.innerHTML = '';
                    
                    Object.entries(schema.properties).forEach(([key, config]) => {{
                        const field = createConfigField(key, config);
                        container.appendChild(field);
                    }});
                }}
                
                function createConfigField(key, config) {{
                    const div = document.createElement('div');
                    div.className = 'mb-3';
                    
                    const label = document.createElement('label');
                    label.className = 'form-label';
                    label.textContent = config.title || key;
                    if (config.description) {{
                        label.title = config.description;
                    }}
                    
                    const input = createInputField(key, config);
                    
                    div.appendChild(label);
                    div.appendChild(input);
                    
                    if (config.description) {{
                        const help = document.createElement('div');
                        help.className = 'form-text';
                        help.textContent = config.description;
                        div.appendChild(help);
                    }}
                    
                    return div;
                }}
                
                function createInputField(key, config) {{
                    let input;
                    
                    switch (config.type) {{
                        case 'boolean':
                            input = document.createElement('input');
                            input.type = 'checkbox';
                            input.className = 'form-check-input';
                            input.id = key;
                            input.name = key;
                            if (config.default) {{
                                input.checked = true;
                            }}
                            break;
                            
                        case 'integer':
                            input = document.createElement('input');
                            input.type = 'number';
                            input.className = 'form-control';
                            input.id = key;
                            input.name = key;
                            if (config.minimum !== undefined) input.min = config.minimum;
                            if (config.maximum !== undefined) input.max = config.maximum;
                            if (config.default !== undefined) input.value = config.default;
                            break;
                            
                        case 'string':
                            if (config.enum) {{
                                input = document.createElement('select');
                                input.className = 'form-select';
                                input.id = key;
                                input.name = key;
                                
                                config.enum.forEach(option => {{
                                    const optionElement = document.createElement('option');
                                    optionElement.value = option;
                                    optionElement.textContent = option;
                                    if (option === config.default) {{
                                        optionElement.selected = true;
                                    }}
                                    input.appendChild(optionElement);
                                }});
                            }} else {{
                                input = document.createElement('input');
                                input.type = 'text';
                                input.className = 'form-control';
                                input.id = key;
                                input.name = key;
                                if (config.default) input.value = config.default;
                            }}
                            break;
                            
                        case 'array':
                            input = document.createElement('textarea');
                            input.className = 'form-control';
                            input.id = key;
                            input.name = key;
                            input.rows = 3;
                            input.placeholder = 'Enter values separated by commas';
                            if (config.default) input.value = config.default.join(', ');
                            break;
                            
                        default:
                            input = document.createElement('input');
                            input.type = 'text';
                            input.className = 'form-control';
                            input.id = key;
                            input.name = key;
                    }}
                    
                    return input;
                }}
                
                // Initialize form
                generateConfigForm(settingsSchema);
                
                // Handle form submission
                document.getElementById('configForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    
                    const formData = new FormData(this);
                    const config = {{}};
                    
                    for (const [key, value] of formData.entries()) {{
                        if (value === 'true') {{
                            config[key] = true;
                        }} else if (value === 'false') {{
                            config[key] = false;
                        }} else if (!isNaN(value) && value !== '') {{
                            config[key] = parseInt(value);
                        }} else if (value.includes(',')) {{
                            config[key] = value.split(',').map(v => v.trim());
                        }} else {{
                            config[key] = value;
                        }}
                    }}
                    
                    try {{
                        const response = await fetch('/api/v1/plugins/{plugin_name}/configure', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{settings: config}})
                        }});
                        
                        if (response.ok) {{
                            alert('Configuration saved successfully!');
                        }} else {{
                            alert('Failed to save configuration');
                        }}
                    }} catch (error) {{
                        console.error('Error:', error);
                        alert('Error saving configuration');
                    }}
                }});
                
                function resetForm() {{
                    document.getElementById('configForm').reset();
                }}
                
                async function togglePlugin() {{
                    const enabled = !{str(plugin_info.get('enabled', False)).lower()};
                    try {{
                        const response = await fetch('/api/v1/plugins/{plugin_name}/toggle', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{enabled: enabled}})
                        }});
                        if (response.ok) {{
                            location.reload();
                        }} else {{
                            alert('Failed to toggle plugin');
                        }}
                    }} catch (error) {{
                        console.error('Error:', error);
                        alert('Error toggling plugin');
                    }}
                }}
                
                async function restartPlugin() {{
                    try {{
                        const response = await fetch('/api/v1/plugins/{plugin_name}/restart', {{
                            method: 'POST'
                        }});
                        if (response.ok) {{
                            alert('Plugin restarted successfully!');
                        }} else {{
                            alert('Failed to restart plugin');
                        }}
                    }} catch (error) {{
                        console.error('Error:', error);
                        alert('Error restarting plugin');
                    }}
                }}
                
                function viewLogs() {{
                    window.open('/api/v1/plugins/{plugin_name}/logs', '_blank');
                }}
                
                async function removePlugin() {{
                    if (confirm('Are you sure you want to remove this plugin? This action cannot be undone.')) {{
                        try {{
                            const response = await fetch('/api/v1/plugins/{plugin_name}/remove', {{
                                method: 'DELETE'
                            }});
                            if (response.ok) {{
                                window.location.href = '/plugins';
                            }} else {{
                                alert('Failed to remove plugin');
                            }}
                        }} catch (error) {{
                            console.error('Error:', error);
                            alert('Error removing plugin');
                        }}
                    }}
                }}
            </script>
        </body>
        </html>
        """)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rendering plugin configuration page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load plugin configuration page")


@router.post("/api/v1/plugins/{plugin_name}/configure")
async def save_plugin_configuration(plugin_name: str, settings: Dict[str, Any]):
    """Save plugin configuration."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Get plugin instance
        plugin = plugin_manager.plugins.get(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        # Update plugin configuration
        if hasattr(plugin, 'config'):
            plugin.config.update(settings)
        
        # Save configuration to file
        config_file = Path(f"data/plugins/{plugin_name}/config.json")
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        return {"success": True, "message": "Configuration saved successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving plugin configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to save configuration")


@router.post("/api/v1/plugins/{plugin_name}/restart")
async def restart_plugin(plugin_name: str):
    """Restart a plugin."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Unload plugin
        await plugin_manager.unload_plugin(plugin_name)
        
        # Reload plugin
        success = await plugin_manager.load_plugin(plugin_name)
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to restart plugin")
        
        return {"success": True, "message": f"Plugin {plugin_name} restarted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error restarting plugin: {e}")
        raise HTTPException(status_code=500, detail="Failed to restart plugin")


@router.get("/api/v1/plugins/{plugin_name}/logs")
async def get_plugin_logs(plugin_name: str, lines: int = 100):
    """Get plugin logs."""
    try:
        log_file = Path(f"logs/plugins/{plugin_name}.log")
        
        if not log_file.exists():
            return {"logs": [], "message": "No logs available"}
        
        # Read last N lines
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
            logs = all_lines[-lines:] if len(all_lines) > lines else all_lines
        
        return {"logs": logs, "total_lines": len(all_lines)}
    except Exception as e:
        logger.error(f"Error getting plugin logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin logs") 
