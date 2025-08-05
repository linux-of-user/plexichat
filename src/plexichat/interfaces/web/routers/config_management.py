#!/usr/bin/env python3
"""
Configuration Management WebUI Router

Provides a comprehensive web interface for managing all PlexiChat configuration
settings through the unified configuration system.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel

# Import unified config system
try:
    from plexichat.core.unified_config import get_config, ConfigCategory
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

# Import authentication
try:
    from plexichat.interfaces.api.v1.auth import get_current_user
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    async def get_current_user(): return {"id": "admin", "username": "admin", "is_admin": True}

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/config", tags=["Configuration Management"])

# Templates setup
templates_path = Path(__file__).parent.parent / "templates"
templates = None
if templates_path.exists():
    templates = Jinja2Templates(directory=str(templates_path))

class ConfigUpdateRequest(BaseModel):
    """Configuration update request model."""
    field_path: str
    value: Any
    restart_required: bool = False

@router.get("/", response_class=HTMLResponse)
async def config_dashboard(request: Request, current_user: dict = Depends(get_current_user)):
    """Main configuration dashboard."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    # Check admin permissions
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    config = get_config()
    
    # Get configuration sections for WebUI
    config_sections = config.get_webui_config_sections()
    
    # Validation results
    validation = config.validate_config()
    
    if templates:
        return templates.TemplateResponse(
            "admin/config_management.html",
            {
                "request": request,
                "config_sections": config_sections,
                "validation": validation,
                "categories": [cat.value for cat in ConfigCategory],
                "current_user": current_user
            }
        )
    
    # Fallback HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Configuration Management</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            .config-section {{ margin-bottom: 2rem; }}
            .config-field {{ margin-bottom: 1rem; }}
            .validation-errors {{ background: #f8d7da; color: #721c24; padding: 1rem; border-radius: 0.375rem; }}
            .validation-warnings {{ background: #fff3cd; color: #856404; padding: 1rem; border-radius: 0.375rem; }}
            .restart-required {{ color: #dc3545; font-size: 0.875rem; }}
        </style>
    </head>
    <body>
        <div class="container-fluid">
            <div class="row">
                <div class="col-md-3">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-cogs"></i> Configuration Categories</h5>
                        </div>
                        <div class="card-body">
                            <div class="list-group">
                                {"".join([f'<a href="#category-{cat}" class="list-group-item list-group-item-action">{cat.title()}</a>' for cat in [cat.value for cat in ConfigCategory]])}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-9">
                    <div class="card">
                        <div class="card-header">
                            <h4><i class="fas fa-server"></i> PlexiChat Configuration Management</h4>
                        </div>
                        <div class="card-body">
                            <div id="config-content">
                                <p>Configuration management interface will be loaded here.</p>
                                <p>Sections available: {len(config_sections)}</p>
                                <p>Validation errors: {len(validation.get('errors', []))}</p>
                                <p>Validation warnings: {len(validation.get('warnings', []))}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/api/sections")
async def get_config_sections(current_user: dict = Depends(get_current_user)):
    """Get all configuration sections."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    config = get_config()
    sections = config.get_webui_config_sections()
    
    # Convert ConfigField objects to dictionaries
    serialized_sections = {}
    for section_name, fields in sections.items():
        serialized_sections[section_name] = []
        for field in fields:
            serialized_sections[section_name].append({
                "name": field.name,
                "value": config.get_config_value(field.name),
                "category": field.category.value,
                "description": field.description,
                "data_type": field.data_type,
                "required": field.required,
                "sensitive": field.sensitive,
                "restart_required": field.restart_required,
                "options": field.options,
                "min_value": field.min_value,
                "max_value": field.max_value,
                "webui_editable": field.webui_editable,
                "webui_section": field.webui_section
            })
    
    return JSONResponse(content=serialized_sections)

@router.get("/api/category/{category}")
async def get_config_by_category(category: str, current_user: dict = Depends(get_current_user)):
    """Get configuration fields by category."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        config_category = ConfigCategory(category)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid category")
    
    config = get_config()
    fields = config.get_config_fields(config_category)
    
    # Serialize fields
    serialized_fields = {}
    for field_name, field in fields.items():
        serialized_fields[field_name] = {
            "name": field.name,
            "value": config.get_config_value(field.name),
            "category": field.category.value,
            "description": field.description,
            "data_type": field.data_type,
            "required": field.required,
            "sensitive": field.sensitive,
            "restart_required": field.restart_required,
            "options": field.options,
            "min_value": field.min_value,
            "max_value": field.max_value,
            "webui_editable": field.webui_editable,
            "webui_section": field.webui_section
        }
    
    return JSONResponse(content=serialized_fields)

@router.post("/api/update")
async def update_config_value(
    update_request: ConfigUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Update a configuration value."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    config = get_config()
    
    # Update the configuration value
    success = config.update_config_value(update_request.field_path, update_request.value)
    
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update configuration value")
    
    # Save configuration
    save_success = config.save()
    
    if not save_success:
        raise HTTPException(status_code=500, detail="Failed to save configuration")
    
    logger.info(f"Configuration updated by {current_user['username']}: {update_request.field_path} = {update_request.value}")
    
    return JSONResponse(content={
        "success": True,
        "message": "Configuration updated successfully",
        "restart_required": update_request.restart_required
    })

@router.get("/api/validate")
async def validate_config(current_user: dict = Depends(get_current_user)):
    """Validate current configuration."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    config = get_config()
    validation_results = config.validate_config()
    
    return JSONResponse(content=validation_results)

@router.get("/api/export")
async def export_config(
    include_sensitive: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Export configuration for backup."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    config = get_config()
    exported_config = config.export_config(include_sensitive=include_sensitive)
    
    logger.info(f"Configuration exported by {current_user['username']} (include_sensitive={include_sensitive})")
    
    return JSONResponse(content=exported_config)

@router.post("/api/reload")
async def reload_config(current_user: dict = Depends(get_current_user)):
    """Reload configuration from file."""
    if not CONFIG_AVAILABLE:
        raise HTTPException(status_code=503, detail="Configuration system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        config = get_config()
        config.load()
        
        logger.info(f"Configuration reloaded by {current_user['username']}")
        
        return JSONResponse(content={
            "success": True,
            "message": "Configuration reloaded successfully"
        })
    except Exception as e:
        logger.error(f"Failed to reload configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to reload configuration")

# Export router
__all__ = ["router"]
