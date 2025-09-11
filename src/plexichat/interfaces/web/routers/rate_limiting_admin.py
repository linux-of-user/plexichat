#!/usr/bin/env python3
"""
Rate Limiting Administration WebUI Router
"""

import logging

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

try:
    # Import security decorators
    from plexichat.core.config.rate_limiting_config import (
        AccountType,
        DynamicRateLimitConfig,
        IPBlacklistConfig,
        get_rate_limiting_config,
        update_rate_limit_config,
    )
    from plexichat.core.security import SecurityLevel
    from plexichat.core.security.security_decorators import (
        audit_access,
        rate_limit,
        require_admin,
    )
except Exception as e:
    print(f"Import error in rate limiting admin: {e}")
    # Fallback decorators
    def require_admin(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def rate_limit(*args, **kwargs):
        def decorator(func): return func
        return decorator
    def audit_access(*args, **kwargs):
        def decorator(func): return func
        return decorator

    # Fallback classes
    class SecurityLevel:
        BASIC = "basic"
        ELEVATED = "elevated"
        ADMIN = "admin"

    class AccountType:
        FREE = "free"
        PREMIUM = "premium"
        ENTERPRISE = "enterprise"
        ADMIN = "admin"

    class DynamicRateLimitConfig:
        def __init__(self):
            self.enabled = True

    # Fallback functions
    def get_rate_limiting_config():
        return None

    def update_rate_limit_config(config):
        return False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/rate-limiting", tags=["rate-limiting-admin"])

# Try to setup templates
try:
    from pathlib import Path
    template_dir = Path(__file__).parent.parent / "templates"
    templates = Jinja2Templates(directory=str(template_dir))
except Exception as e:
    logger.warning(f"Templates not available: {e}")
    templates = None

@router.get("/", response_class=HTMLResponse)
@require_admin()
@rate_limit(requests_per_minute=30)
@audit_access("view", "rate_limiting_admin")
async def rate_limiting_dashboard(request: Request):
    """Rate limiting administration dashboard."""
    try:
        config = get_rate_limiting_config()
        config_summary = config.get_config_summary()

        if templates:
            return templates.TemplateResponse("rate_limiting_admin.html", {
                "request": request,
                "config": config_summary,
                "account_types": [t.value for t in AccountType],
                "title": "Rate Limiting Administration"
            })
        else:
            # Fallback HTML
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Rate Limiting Administration</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        margin: 0; padding: 20px; background: #f5f5f5;
                    }}
                    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
                    .section {{ margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .status {{ padding: 10px; border-radius: 5px; margin: 10px 0; }}
                    .status.enabled {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
                    .status.disabled {{ background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
                    .form-group {{ margin-bottom: 15px; }}
                    .form-control {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
                    .btn {{ padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }}
                    .btn-primary {{ background: #007bff; color: white; }}
                    .btn-success {{ background: #28a745; color: white; }}
                    .btn-danger {{ background: #dc3545; color: white; }}
                    .table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                    .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    .table th {{ background: #f8f9fa; font-weight: bold; }}
                    .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
                    .metric-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
                    .metric-label {{ font-size: 14px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>? Rate Limiting Administration</h1>
                        <p>Configure and monitor rate limiting settings for PlexiChat</p>
                    </div>
                    
                    <div class="section">
                        <h2>[STATS] Current Status</h2>
                        <div class="status {'enabled' if config_summary['global_enabled'] else 'disabled'}">
                            <strong>Global Rate Limiting:</strong> {'Enabled' if config_summary['global_enabled'] else 'Disabled'}
                        </div>
                        <div class="status {'enabled' if config_summary['dynamic_limiting']['enabled'] else 'disabled'}">
                            <strong>Dynamic Rate Limiting:</strong> {'Enabled' if config_summary['dynamic_limiting']['enabled'] else 'Disabled'}
                            {f" (Current Multiplier: {config_summary['dynamic_limiting']['current_multiplier']:.2f})" if config_summary['dynamic_limiting']['enabled'] else ""}
                        </div>
                        <div class="status {'enabled' if config_summary['ip_blacklist']['enabled'] else 'disabled'}">
                            <strong>IP Blacklist:</strong> {'Enabled' if config_summary['ip_blacklist']['enabled'] else 'Disabled'}
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>? Account Type Limits</h2>
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Account Type</th>
                                    <th>Status</th>
                                    <th>Requests/Min</th>
                                    <th>Requests/Hour</th>
                                    <th>Concurrent</th>
                                    <th>Endpoint Overrides</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
            """

            for account_type, limits in config_summary['account_types'].items():
                status_class = "enabled" if limits['enabled'] else "disabled"
                status_text = "Enabled" if limits['enabled'] else "Disabled"
                html_content += f"""
                                <tr>
                                    <td><strong>{account_type.upper()}</strong></td>
                                    <td><span class="status {status_class}">{status_text}</span></td>
                                    <td>{limits['requests_per_minute']}</td>
                                    <td>{limits['requests_per_hour']}</td>
                                    <td>{limits['concurrent_requests']}</td>
                                    <td>{limits['endpoint_overrides']} overrides</td>
                                    <td>
                                        <button class="btn btn-primary" onclick="editAccountType('{account_type}')">Edit</button>
                                    </td>
                                </tr>
                """

            html_content += f"""
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="section">
                        <h2>[WEB] IP Blacklist Status</h2>
                        <div class="metric">
                            <div class="metric-value">{config_summary['ip_blacklist']['permanent_entries']}</div>
                            <div class="metric-label">Permanent Blocks</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">{config_summary['ip_blacklist']['temporary_entries']}</div>
                            <div class="metric-label">Temporary Blocks</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">{config_summary['ip_blacklist']['whitelist_entries']}</div>
                            <div class="metric-label">Whitelisted IPs</div>
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>?? Global Settings</h2>
                        <form id="globalSettingsForm" onsubmit="updateGlobalSettings(event)">
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" {'checked' if config_summary['global_enabled'] else ''}> 
                                    Enable Global Rate Limiting
                                </label>
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" {'checked' if config_summary['dynamic_limiting']['enabled'] else ''}> 
                                    Enable Dynamic Rate Limiting (based on system load)
                                </label>
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" {'checked' if config_summary['ip_blacklist']['enabled'] else ''}> 
                                    Enable IP Blacklist
                                </label>
                            </div>
                            <button type="submit" class="btn btn-success">Update Settings</button>
                        </form>
                    </div>
                    
                    <div class="section">
                        <h2>[SETUP] Quick Actions</h2>
                        <button class="btn btn-primary" onclick="refreshConfig()">Refresh Configuration</button>
                        <button class="btn btn-success" onclick="exportConfig()">Export Configuration</button>
                        <button class="btn btn-danger" onclick="resetToDefaults()">Reset to Defaults</button>
                    </div>
                </div>
                
                <script>
                    function editAccountType(accountType) {{
                        alert('Edit functionality for ' + accountType + ' will be implemented in the full interface');
                    }}
                    
                    function updateGlobalSettings(event) {{
                        event.preventDefault();
                        alert('Global settings update functionality will be implemented');
                    }}
                    
                    function refreshConfig() {{
                        window.location.reload();
                    }}
                    
                    function exportConfig() {{
                        window.open('/admin/rate-limiting/export', '_blank');
                    }}
                    
                    function resetToDefaults() {{
                        if (confirm('Are you sure you want to reset all rate limiting settings to defaults?')) {{
                            fetch('/admin/rate-limiting/reset', {{method: 'POST'}})
                                .then(() => window.location.reload());
                        }}
                    }}
                </script>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error(f"Error in rate limiting dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {e!s}")

@router.get("/config", response_class=JSONResponse)
@require_admin()
@rate_limit(requests_per_minute=60)
@audit_access("view", "rate_limiting_config")
async def get_rate_limiting_config_api():
    """Get current rate limiting configuration as JSON."""
    try:
        config = get_rate_limiting_config()
        return JSONResponse(content=config.get_config_summary())
    except Exception as e:
        logger.error(f"Error getting rate limiting config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/config/update")
@require_admin()
@rate_limit(requests_per_minute=30)
@audit_access("modify", "rate_limiting_config")
async def update_rate_limiting_config_api(
    global_enabled: bool = Form(True),
    strict_mode: bool = Form(False),
    dynamic_enabled: bool = Form(True)
):
    """Update global rate limiting configuration."""
    try:
        success = update_rate_limit_config(
            global_enabled=global_enabled,
            strict_mode=strict_mode
        )

        if success:
            # Update dynamic config separately
            config = get_rate_limiting_config()
            config.dynamic_config.enabled = dynamic_enabled
            config.save_config()

            return JSONResponse(content={"success": True, "message": "Configuration updated successfully"})
        else:
            raise HTTPException(status_code=500, detail="Failed to update configuration")
    except Exception as e:
        logger.error(f"Error updating rate limiting config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/account-type/{account_type}/update")
@require_admin()
@rate_limit(requests_per_minute=30)
@audit_access("modify", "rate_limiting_account_config")
async def update_account_type_limits(
    account_type: str,
    requests_per_minute: int = Form(...),
    requests_per_hour: int = Form(...),
    concurrent_requests: int = Form(...),
    enabled: bool = Form(True)
):
    """Update rate limits for a specific account type."""
    try:
        account_type_enum = AccountType(account_type)
        config = get_rate_limiting_config()

        config.update_account_limit(
            account_type_enum,
            global_requests_per_minute=requests_per_minute,
            global_requests_per_hour=requests_per_hour,
            concurrent_requests=concurrent_requests,
            enabled=enabled
        )

        return JSONResponse(content={"success": True, "message": f"Updated limits for {account_type}"})
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid account type: {account_type}")
    except Exception as e:
        logger.error(f"Error updating account type limits: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/blacklist/add")
@require_admin()
@rate_limit(requests_per_minute=30)
@audit_access("modify", "ip_blacklist")
async def add_to_blacklist(
    ip_address: str = Form(...),
    permanent: bool = Form(False),
    duration: int = Form(3600)
):
    """Add IP address to blacklist."""
    try:
        config = get_rate_limiting_config()
        config.add_to_blacklist(ip_address, permanent, duration)

        return JSONResponse(content={"success": True, "message": f"Added {ip_address} to blacklist"})
    except Exception as e:
        logger.error(f"Error adding to blacklist: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/blacklist/remove")
@require_admin()
@rate_limit(requests_per_minute=30)
@audit_access("modify", "ip_blacklist")
async def remove_from_blacklist(ip_address: str = Form(...)):
    """Remove IP address from blacklist."""
    try:
        config = get_rate_limiting_config()
        config.remove_from_blacklist(ip_address)

        return JSONResponse(content={"success": True, "message": f"Removed {ip_address} from blacklist"})
    except Exception as e:
        logger.error(f"Error removing from blacklist: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export")
@require_admin()
@rate_limit(requests_per_minute=10)
@audit_access("export", "rate_limiting_config")
async def export_configuration():
    """Export rate limiting configuration."""
    try:
        config = get_rate_limiting_config()
        return JSONResponse(
            content=config.get_config_summary(),
            headers={"Content-Disposition": "attachment; filename=rate_limiting_config.json"}
        )
    except Exception as e:
        logger.error(f"Error exporting configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reset")
@require_admin()
@rate_limit(requests_per_minute=5)
@audit_access("reset", "rate_limiting_config")
async def reset_to_defaults():
    """Reset rate limiting configuration to defaults."""
    try:
        config = get_rate_limiting_config()
        config.account_type_limits = config._get_default_account_limits()
        config.dynamic_config = DynamicRateLimitConfig()
        config.ip_blacklist_config = IPBlacklistConfig()
        config.save_config()

        return JSONResponse(content={"success": True, "message": "Configuration reset to defaults"})
    except Exception as e:
        logger.error(f"Error resetting configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))
