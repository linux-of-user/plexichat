import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ...infrastructure.modules.enhanced_plugin_manager import get_enhanced_plugin_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/marketplace", tags=["Plugin Marketplace"])


class MarketplacePlugin(BaseModel):
    """Marketplace plugin model."""
    id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    category: str
    tags: List[str]
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str
    icon: Optional[str] = None
    screenshots: List[str]
    changelog: List[Dict[str, str]]
    download_count: int
    rating: float
    last_updated: str
    size_bytes: int
    checksum: str
    ui_pages: List[Dict[str, str]]
    api_endpoints: List[str]
    webhooks: List[str]
    settings_schema: Optional[Dict[str, Any]]
    auto_start: bool
    background_tasks: List[str]
    dependencies: List[str]
    permissions: List[str]
    min_plexichat_version: str


class MarketplaceCategory(BaseModel):
    """Marketplace category model."""
    id: str
    name: str
    description: str
    icon: str
    plugin_count: int


@router.get("/", response_class=HTMLResponse)
async def marketplace_page(request: Request):
    """Plugin marketplace main page."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Get categories
        categories = [
            {"id": "security", "name": "Security", "description": "Security and authentication plugins", "icon": "shield-check", "plugin_count": 0},
            {"id": "analytics", "name": "Analytics", "description": "Data analysis and reporting plugins", "icon": "graph-up", "plugin_count": 0},
            {"id": "automation", "name": "Automation", "description": "Workflow and automation plugins", "icon": "gear", "plugin_count": 0},
            {"id": "backup", "name": "Backup", "description": "Backup and recovery plugins", "icon": "cloud-arrow-up", "plugin_count": 0},
            {"id": "monitoring", "name": "Monitoring", "description": "System monitoring plugins", "icon": "activity", "plugin_count": 0},
            {"id": "notification", "name": "Notifications", "description": "Communication and notification plugins", "icon": "bell", "plugin_count": 0},
            {"id": "integration", "name": "Integrations", "description": "Third-party integration plugins", "icon": "plug", "plugin_count": 0},
            {"id": "theme", "name": "Themes", "description": "UI theme and customization plugins", "icon": "palette", "plugin_count": 0},
            {"id": "utility", "name": "Utilities", "description": "Utility and helper plugins", "icon": "tools", "plugin_count": 0}
        ]
        
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Plugin Marketplace - PlexiChat</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
            <style>
                .category-card {{
                    transition: transform 0.2s;
                    border: 1px solid #e9ecef;
                    cursor: pointer;
                }}
                .category-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                }}
                .plugin-card {{
                    transition: transform 0.2s;
                    border: 1px solid #e9ecef;
                }}
                .plugin-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                }}
                .rating-stars {{
                    color: #ffc107;
                }}
                .featured-badge {{
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    background: linear-gradient(45deg, #ff6b6b, #ee5a24);
                    color: white;
                    padding: 2px 8px;
                    border-radius: 12px;
                    font-size: 0.75rem;
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
                            <h1><i class="bi bi-shop"></i> Plugin Marketplace</h1>
                            <div>
                                <button class="btn btn-outline-secondary me-2" onclick="refreshMarketplace()">
                                    <i class="bi bi-arrow-clockwise"></i> Refresh
                                </button>
                                <a href="/plugins" class="btn btn-primary">
                                    <i class="bi bi-puzzle"></i> My Plugins
                                </a>
                            </div>
                        </div>
                        
                        <!-- Search and Filters -->
                        <div class="card mb-4">
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="input-group">
                                            <span class="input-group-text"><i class="bi bi-search"></i></span>
                                            <input type="text" class="form-control" id="searchQuery" placeholder="Search plugins...">
                                        </div>
                                    </div>
                                    <div class="col-md-3">
                                        <select class="form-select" id="categoryFilter">
                                            <option value="">All Categories</option>
                                            {''.join([f'<option value="{cat["id"]}">{cat["name"]}</option>' for cat in categories])}
                                        </select>
                                    </div>
                                    <div class="col-md-3">
                                        <select class="form-select" id="sortBy">
                                            <option value="popular">Most Popular</option>
                                            <option value="newest">Newest</option>
                                            <option value="rating">Highest Rated</option>
                                            <option value="name">Name A-Z</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Categories -->
                        <div class="mb-4">
                            <h4>Categories</h4>
                            <div class="row" id="categories-grid">
                                {''.join([f'''
                                <div class="col-md-4 col-lg-3 mb-3">
                                    <div class="card category-card h-100" onclick="filterByCategory('{cat["id"]}')">
                                        <div class="card-body text-center">
                                            <i class="bi bi-{cat["icon"]} fs-1 text-primary mb-3"></i>
                                            <h6 class="card-title">{cat["name"]}</h6>
                                            <p class="card-text small text-muted">{cat["description"]}</p>
                                            <span class="badge bg-secondary">{cat["plugin_count"]} plugins</span>
                                        </div>
                                    </div>
                                </div>
                                ''' for cat in categories])}
                            </div>
                        </div>
                        
                        <!-- Featured Plugins -->
                        <div class="mb-4">
                            <h4>Featured Plugins</h4>
                            <div class="row" id="featured-plugins">
                                <div class="col-12 text-center text-muted">
                                    <i class="bi bi-star"></i> Loading featured plugins...
                                </div>
                            </div>
                        </div>
                        
                        <!-- All Plugins -->
                        <div class="mb-4">
                            <h4>All Plugins</h4>
                            <div class="row" id="plugins-grid">
                                <div class="col-12 text-center text-muted">
                                    <i class="bi bi-search"></i> Search for plugins to browse
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Plugin Details Modal -->
            <div class="modal fade" id="pluginModal" tabindex="-1">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="pluginModalTitle">Plugin Details</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body" id="pluginModalBody">
                            <!-- Plugin details will be loaded here -->
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            <button type="button" class="btn btn-primary" id="installPluginBtn">Install Plugin</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            <script>
                let currentPlugins = [];
                let currentCategory = '';
                let currentSearch = '';
                let currentSort = 'popular';
                
                // Initialize marketplace
                document.addEventListener('DOMContentLoaded', function() {{
                    loadFeaturedPlugins();
                    setupEventListeners();
                }});
                
                function setupEventListeners() {{
                    // Search functionality
                    document.getElementById('searchQuery').addEventListener('input', function() {{
                        currentSearch = this.value;
                        debounce(searchPlugins, 300)();
                    }});
                    
                    // Category filter
                    document.getElementById('categoryFilter').addEventListener('change', function() {{
                        currentCategory = this.value;
                        searchPlugins();
                    }});
                    
                    // Sort functionality
                    document.getElementById('sortBy').addEventListener('change', function() {{
                        currentSort = this.value;
                        searchPlugins();
                    }});
                }}
                
                function debounce(func, wait) {{
                    let timeout;
                    return function executedFunction(...args) {{
                        const later = () => {{
                            clearTimeout(timeout);
                            func(...args);
                        }};
                        clearTimeout(timeout);
                        timeout = setTimeout(later, wait);
                    }};
                }}
                
                async function loadFeaturedPlugins() {{
                    try {{
                        const response = await fetch('/api/v1/marketplace/featured');
                        const data = await response.json();
                        displayFeaturedPlugins(data.plugins);
                    }} catch (error) {{
                        console.error('Error loading featured plugins:', error);
                    }}
                }}
                
                function displayFeaturedPlugins(plugins) {{
                    const container = document.getElementById('featured-plugins');
                    
                    if (plugins.length === 0) {{
                        container.innerHTML = '<div class="col-12 text-center text-muted">No featured plugins available</div>';
                        return;
                    }}
                    
                    container.innerHTML = plugins.map(plugin => `
                        <div class="col-md-6 col-lg-4 mb-4">
                            <div class="card plugin-card h-100 position-relative">
                                ${{plugin.featured ? '<div class="featured-badge">Featured</div>' : ''}}
                                <div class="card-header">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-${{plugin.icon || 'puzzle'}} fs-4 me-2"></i>
                                        <h6 class="mb-0">${{plugin.name}}</h6>
                                    </div>
                                </div>
                                <div class="card-body">
                                    <p class="card-text">${{plugin.description}}</p>
                                    <div class="mb-2">
                                        <div class="rating-stars">
                                            ${{'★'.repeat(Math.floor(plugin.rating))}}${{'☆'.repeat(5 - Math.floor(plugin.rating))}}
                                        </div>
                                        <small class="text-muted">${{plugin.rating}}/5 (${{plugin.download_count}} downloads)</small>
                                    </div>
                                    <div class="mb-2">
                                        <span class="badge bg-primary">${{plugin.category}}</span>
                                        <span class="badge bg-secondary">${{plugin.plugin_type}}</span>
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <button class="btn btn-primary btn-sm w-100" onclick="viewPluginDetails('${{plugin.id}}')">
                                        <i class="bi bi-eye"></i> View Details
                                    </button>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }}
                
                async function searchPlugins() {{
                    try {{
                        const params = new URLSearchParams();
                        if (currentSearch) params.append('q', currentSearch);
                        if (currentCategory) params.append('category', currentCategory);
                        if (currentSort) params.append('sort', currentSort);
                        
                        const response = await fetch(`/api/v1/marketplace/search?${{params.toString()}}`);
                        const data = await response.json();
                        
                        currentPlugins = data.plugins;
                        displayPlugins(data.plugins);
                    }} catch (error) {{
                        console.error('Error searching plugins:', error);
                    }}
                }}
                
                function displayPlugins(plugins) {{
                    const container = document.getElementById('plugins-grid');
                    
                    if (plugins.length === 0) {{
                        container.innerHTML = '<div class="col-12 text-center text-muted">No plugins found</div>';
                        return;
                    }}
                    
                    container.innerHTML = plugins.map(plugin => `
                        <div class="col-md-6 col-lg-4 mb-4">
                            <div class="card plugin-card h-100">
                                <div class="card-header">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-${{plugin.icon || 'puzzle'}} fs-4 me-2"></i>
                                        <h6 class="mb-0">${{plugin.name}}</h6>
                                    </div>
                                </div>
                                <div class="card-body">
                                    <p class="card-text">${{plugin.description}}</p>
                                    <div class="mb-2">
                                        <div class="rating-stars">
                                            ${{'★'.repeat(Math.floor(plugin.rating))}}${{'☆'.repeat(5 - Math.floor(plugin.rating))}}
                                        </div>
                                        <small class="text-muted">${{plugin.rating}}/5 (${{plugin.download_count}} downloads)</small>
                                    </div>
                                    <div class="mb-2">
                                        <span class="badge bg-primary">${{plugin.category}}</span>
                                        <span class="badge bg-secondary">${{plugin.plugin_type}}</span>
                                    </div>
                                    <div class="small text-muted">
                                        <div>Version: ${{plugin.version}}</div>
                                        <div>Author: ${{plugin.author}}</div>
                                        <div>Updated: ${{new Date(plugin.last_updated).toLocaleDateString()}}</div>
                                    </div>
                                </div>
                                <div class="card-footer">
                                    <div class="d-flex gap-2">
                                        <button class="btn btn-primary btn-sm flex-fill" onclick="viewPluginDetails('${{plugin.id}}')">
                                            <i class="bi bi-eye"></i> Details
                                        </button>
                                        <button class="btn btn-success btn-sm" onclick="installPlugin('${{plugin.id}}')">
                                            <i class="bi bi-download"></i> Install
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }}
                
                function filterByCategory(categoryId) {{
                    document.getElementById('categoryFilter').value = categoryId;
                    currentCategory = categoryId;
                    searchPlugins();
                }}
                
                async function viewPluginDetails(pluginId) {{
                    try {{
                        const response = await fetch(`/api/v1/marketplace/plugins/${{pluginId}}`);
                        const plugin = await response.json();
                        
                        document.getElementById('pluginModalTitle').textContent = plugin.name;
                        document.getElementById('pluginModalBody').innerHTML = generatePluginDetailsHTML(plugin);
                        document.getElementById('installPluginBtn').onclick = () => installPlugin(pluginId);
                        
                        new bootstrap.Modal(document.getElementById('pluginModal')).show();
                    }} catch (error) {{
                        console.error('Error loading plugin details:', error);
                        alert('Failed to load plugin details');
                    }}
                }}
                
                function generatePluginDetailsHTML(plugin) {{
                    return `
                        <div class="row">
                            <div class="col-md-8">
                                <h5>Description</h5>
                                <p>${{plugin.description}}</p>
                                
                                <h5>Features</h5>
                                <ul>
                                    ${{plugin.ui_pages.map(page => `<li>${{page.title}} - ${{page.description}}</li>`).join('')}}
                                </ul>
                                
                                <h5>API Endpoints</h5>
                                <ul>
                                    ${{plugin.api_endpoints.map(endpoint => `<li><code>${{endpoint}}</code></li>`).join('')}}
                                </ul>
                                
                                <h5>Webhooks</h5>
                                <ul>
                                    ${{plugin.webhooks.map(webhook => `<li><code>${{webhook}}</code></li>`).join('')}}
                                </ul>
                                
                                <h5>Dependencies</h5>
                                <ul>
                                    ${{plugin.dependencies.map(dep => `<li>${{dep}}</li>`).join('')}}
                                </ul>
                                
                                <h5>Permissions</h5>
                                <ul>
                                    ${{plugin.permissions.map(perm => `<li><code>${{perm}}</code></li>`).join('')}}
                                </ul>
                            </div>
                            <div class="col-md-4">
                                <div class="card">
                                    <div class="card-body">
                                        <h6>Plugin Information</h6>
                                        <p><strong>Version:</strong> ${{plugin.version}}</p>
                                        <p><strong>Author:</strong> ${{plugin.author}}</p>
                                        <p><strong>License:</strong> ${{plugin.license}}</p>
                                        <p><strong>Category:</strong> ${{plugin.category}}</p>
                                        <p><strong>Type:</strong> ${{plugin.plugin_type}}</p>
                                        <p><strong>Downloads:</strong> ${{plugin.download_count}}</p>
                                        <p><strong>Rating:</strong> ${{plugin.rating}}/5</p>
                                        <p><strong>Size:</strong> ${{formatBytes(plugin.size_bytes)}}</p>
                                        <p><strong>Updated:</strong> ${{new Date(plugin.last_updated).toLocaleDateString()}}</p>
                                        
                                        <div class="rating-stars mb-2">
                                            ${{'★'.repeat(Math.floor(plugin.rating))}}${{'☆'.repeat(5 - Math.floor(plugin.rating))}}
                                        </div>
                                        
                                        ${{plugin.homepage ? `<a href="${{plugin.homepage}}" target="_blank" class="btn btn-outline-primary btn-sm w-100 mb-2">
                                            <i class="bi bi-house"></i> Homepage
                                        </a>` : ''}}
                                        
                                        ${{plugin.repository ? `<a href="${{plugin.repository}}" target="_blank" class="btn btn-outline-secondary btn-sm w-100">
                                            <i class="bi bi-github"></i> Repository
                                        </a>` : ''}}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }}
                
                function formatBytes(bytes) {{
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }}
                
                async function installPlugin(pluginId) {{
                    try {{
                        const response = await fetch('/api/v1/plugins/install', {{
                            method: 'POST',
                            headers: {{'Content-Type': 'application/json'}},
                            body: JSON.stringify({{plugin_id: pluginId, source: 'marketplace'}})
                        }});
                        
                        if (response.ok) {{
                            alert('Plugin installed successfully!');
                            // Close modal if open
                            const modal = bootstrap.Modal.getInstance(document.getElementById('pluginModal'));
                            if (modal) modal.hide();
                        }} else {{
                            const error = await response.json();
                            alert(`Failed to install plugin: ${{error.detail}}`);
                        }}
                    }} catch (error) {{
                        console.error('Error installing plugin:', error);
                        alert('Error installing plugin');
                    }}
                }}
                
                function refreshMarketplace() {{
                    loadFeaturedPlugins();
                    searchPlugins();
                }}
            </script>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Error rendering marketplace page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load marketplace page")


@router.get("/api/v1/marketplace/search")
async def search_marketplace(
    q: str = Query("", description="Search query"),
    category: str = Query("", description="Category filter"),
    sort: str = Query("popular", description="Sort order"),
    page: int = Query(1, description="Page number"),
    limit: int = Query(20, description="Results per page")
):
    """Search plugins in marketplace."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Convert sort parameter
        sort_mapping = {
            "popular": "download_count",
            "newest": "last_updated",
            "rating": "rating",
            "name": "name"
        }
        sort_field = sort_mapping.get(sort, "download_count")
        
        # Search plugins
        results = await plugin_manager.marketplace.search_plugins(
            query=q,
            category=category
        )
        
        # Sort results
        if sort_field == "download_count":
            results.sort(key=lambda x: x.get("download_count", 0), reverse=True)
        elif sort_field == "rating":
            results.sort(key=lambda x: x.get("rating", 0), reverse=True)
        elif sort_field == "name":
            results.sort(key=lambda x: x.get("name", ""))
        elif sort_field == "last_updated":
            results.sort(key=lambda x: x.get("last_updated", ""), reverse=True)
        
        # Pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_results = results[start_idx:end_idx]
        
        return {
            "plugins": paginated_results,
            "total": len(results),
            "page": page,
            "limit": limit,
            "pages": (len(results) + limit - 1) // limit
        }
    except Exception as e:
        logger.error(f"Error searching marketplace: {e}")
        raise HTTPException(status_code=500, detail="Failed to search marketplace")


@router.get("/api/v1/marketplace/featured")
async def get_featured_plugins():
    """Get featured plugins from marketplace."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Search for featured plugins (high rating and download count)
        results = await plugin_manager.marketplace.search_plugins()
        
        # Filter and sort for featured plugins
        featured = []
        for plugin in results:
            if (plugin.get("rating", 0) >= 4.5 and 
                plugin.get("download_count", 0) >= 100):
                plugin["featured"] = True
                featured.append(plugin)
        
        # Sort by rating and download count
        featured.sort(key=lambda x: (x.get("rating", 0), x.get("download_count", 0)), reverse=True)
        
        return {"plugins": featured[:6]}  # Return top 6 featured plugins
    except Exception as e:
        logger.error(f"Error getting featured plugins: {e}")
        raise HTTPException(status_code=500, detail="Failed to get featured plugins")


@router.get("/api/v1/marketplace/plugins/{plugin_id}")
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


@router.get("/api/v1/marketplace/categories")
async def get_marketplace_categories():
    """Get marketplace categories."""
    try:
        categories = [
            {"id": "security", "name": "Security", "description": "Security and authentication plugins", "icon": "shield-check"},
            {"id": "analytics", "name": "Analytics", "description": "Data analysis and reporting plugins", "icon": "graph-up"},
            {"id": "automation", "name": "Automation", "description": "Workflow and automation plugins", "icon": "gear"},
            {"id": "backup", "name": "Backup", "description": "Backup and recovery plugins", "icon": "cloud-arrow-up"},
            {"id": "monitoring", "name": "Monitoring", "description": "System monitoring plugins", "icon": "activity"},
            {"id": "notification", "name": "Notifications", "description": "Communication and notification plugins", "icon": "bell"},
            {"id": "integration", "name": "Integrations", "description": "Third-party integration plugins", "icon": "plug"},
            {"id": "theme", "name": "Themes", "description": "UI theme and customization plugins", "icon": "palette"},
            {"id": "utility", "name": "Utilities", "description": "Utility and helper plugins", "icon": "tools"}
        ]
        
        # Get plugin count for each category
        plugin_manager = get_enhanced_plugin_manager()
        for category in categories:
            results = await plugin_manager.marketplace.search_plugins(category=category["id"])
            category["plugin_count"] = len(results)
        
        return {"categories": categories}
    except Exception as e:
        logger.error(f"Error getting marketplace categories: {e}")
        raise HTTPException(status_code=500, detail="Failed to get marketplace categories")


@router.get("/api/v1/marketplace/stats")
async def get_marketplace_stats():
    """Get marketplace statistics."""
    try:
        plugin_manager = get_enhanced_plugin_manager()
        
        # Get all plugins
        all_plugins = await plugin_manager.marketplace.search_plugins()
        
        # Calculate statistics
        total_plugins = len(all_plugins)
        total_downloads = sum(plugin.get("download_count", 0) for plugin in all_plugins)
        avg_rating = sum(plugin.get("rating", 0) for plugin in all_plugins) / total_plugins if total_plugins > 0 else 0
        
        # Category breakdown
        categories = {}
        for plugin in all_plugins:
            category = plugin.get("category", "unknown")
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        # Type breakdown
        types = {}
        for plugin in all_plugins:
            plugin_type = plugin.get("plugin_type", "unknown")
            if plugin_type not in types:
                types[plugin_type] = 0
            types[plugin_type] += 1
        
        return {
            "total_plugins": total_plugins,
            "total_downloads": total_downloads,
            "average_rating": round(avg_rating, 2),
            "categories": categories,
            "types": types,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting marketplace stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get marketplace statistics") 