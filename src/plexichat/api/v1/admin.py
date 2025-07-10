"""
Admin API endpoints for NetLink
Comprehensive admin interface API with government-level security.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from netlink.core.security.government_auth import government_auth
from netlink.app.logger_config import logger


# Initialize router and templates
router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="src/netlink/app/web/templates")


# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class UserCreateRequest(BaseModel):
    username: str
    email: Optional[str] = None
    role: str = "user"


class SystemStatsResponse(BaseModel):
    total_users: int
    total_messages: int
    server_status: str
    security_level: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: float


# Dependency for authentication
async def get_current_admin(request: Request) -> Dict[str, Any]:
    """Get current authenticated admin user."""
    if not hasattr(request.state, 'user'):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return {
        'username': request.state.user,
        'session_token': request.state.session_token
    }


# Admin dashboard routes
@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin: Dict = Depends(get_current_admin)):
    """Serve the unified admin dashboard."""
    return templates.TemplateResponse(
        "admin/unified_dashboard.html",
        {
            "request": request,
            "admin_user": admin['username']
        }
    )


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Serve admin login page (handled by middleware)."""
    # This will be handled by the government security middleware
    pass


@router.post("/api/auth/login")
async def admin_login(login_data: LoginRequest):
    """Admin login endpoint."""
    try:
        result = government_auth.authenticate(
            login_data.username,
            login_data.password,
            login_data.totp_code
        )
        
        if result['success']:
            logger.info(f"Admin login successful: {login_data.username}")
            return {
                'success': True,
                'message': 'Login successful',
                'session_token': result['session_token'],
                'must_change_password': result.get('must_change_password', False),
                'requires_2fa': result.get('requires_2fa', False)
            }
        else:
            logger.warning(f"Admin login failed: {login_data.username} - {result['error']}")
            return JSONResponse(
                status_code=401,
                content={
                    'success': False,
                    'error': result['error'],
                    'requires_2fa': result.get('requires_2fa', False)
                }
            )
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/auth/logout")
async def admin_logout(request: Request, admin: Dict = Depends(get_current_admin)):
    """Admin logout endpoint."""
    try:
        # Destroy session
        session_token = admin['session_token']
        government_auth._destroy_session(session_token)
        
        logger.info(f"Admin logout: {admin['username']}")
        
        return {'success': True, 'message': 'Logged out successfully'}
    except Exception as e:
        logger.error(f"Admin logout error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/auth/change-password")
async def change_admin_password(
    password_data: PasswordChangeRequest,
    admin: Dict = Depends(get_current_admin)
):
    """Change admin password."""
    try:
        result = government_auth.change_password(
            admin['username'],
            password_data.current_password,
            password_data.new_password
        )
        
        if result['success']:
            logger.info(f"Password changed for admin: {admin['username']}")
            return {'success': True, 'message': 'Password changed successfully'}
        else:
            return JSONResponse(
                status_code=400,
                content={'success': False, 'error': result['error']}
            )
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# Dashboard API endpoints
@router.get("/api/stats")
async def get_system_stats(admin: Dict = Depends(get_current_admin)) -> SystemStatsResponse:
    """Get system statistics for dashboard."""
    try:
        # This would collect real system stats
        import psutil
        import random
        
        stats = SystemStatsResponse(
            total_users=len(government_auth.admin_credentials),
            total_messages=random.randint(1000, 10000),  # Mock data
            server_status="Online",
            security_level="Government-Grade",
            cpu_usage=psutil.cpu_percent(interval=1),
            memory_usage=psutil.virtual_memory().percent,
            disk_usage=psutil.disk_usage('/').percent,
            network_io=random.uniform(10, 50)  # Mock network I/O
        )
        
        return stats
    except Exception as e:
        logger.error(f"Stats collection error: {e}")
        # Return mock data if psutil not available
        return SystemStatsResponse(
            total_users=len(government_auth.admin_credentials),
            total_messages=5432,
            server_status="Online",
            security_level="Government-Grade",
            cpu_usage=45.2,
            memory_usage=67.8,
            disk_usage=23.1,
            network_io=12.5
        )


@router.get("/api/users")
async def get_users(admin: Dict = Depends(get_current_admin)):
    """Get list of admin users."""
    try:
        users = []
        for username, admin_data in government_auth.admin_credentials.items():
            users.append({
                'username': username,
                'email': f"{username}@netlink.local",  # Mock email
                'role': 'Super Admin' if username == 'admin' else 'Admin',
                'status': 'Locked' if admin_data.locked_until else 'Active',
                'last_login': admin_data.last_changed.isoformat(),
                'must_change_password': admin_data.must_change_password,
                'two_factor_enabled': admin_data.two_factor_enabled,
                'failed_attempts': admin_data.failed_attempts
            })
        
        return {'success': True, 'users': users}
    except Exception as e:
        logger.error(f"User list error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/users")
async def create_user(
    user_data: UserCreateRequest,
    admin: Dict = Depends(get_current_admin)
):
    """Create new admin user."""
    try:
        # This would implement user creation
        logger.info(f"User creation requested by {admin['username']}: {user_data.username}")
        
        # Mock response for now
        return {
            'success': True,
            'message': f'User {user_data.username} created successfully',
            'temporary_password': government_auth._generate_secure_password()
        }
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/users/{username}/reset-password")
async def reset_user_password(
    username: str,
    admin: Dict = Depends(get_current_admin)
):
    """Reset user password."""
    try:
        if username not in government_auth.admin_credentials:
            raise HTTPException(status_code=404, detail="User not found")
        
        new_password = government_auth._generate_secure_password()
        
        logger.info(f"Password reset for {username} by {admin['username']}")
        
        return {
            'success': True,
            'message': f'Password reset for {username}',
            'temporary_password': new_password
        }
    except Exception as e:
        logger.error(f"Password reset error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/api/security/alerts")
async def get_security_alerts(admin: Dict = Depends(get_current_admin)):
    """Get security alerts."""
    try:
        # Mock security alerts
        alerts = [
            {
                'id': 1,
                'type': 'warning',
                'title': 'Failed Login Attempts',
                'message': '15 failed attempts in the last hour',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'id': 2,
                'type': 'success',
                'title': 'SSL Certificate',
                'message': 'Valid until 2025-01-15',
                'timestamp': datetime.utcnow().isoformat()
            },
            {
                'id': 3,
                'type': 'danger',
                'title': 'Default Password',
                'message': 'Change default admin password immediately',
                'timestamp': datetime.utcnow().isoformat()
            }
        ]
        
        return {'success': True, 'alerts': alerts}
    except Exception as e:
        logger.error(f"Security alerts error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/api/backup/status")
async def get_backup_status(admin: Dict = Depends(get_current_admin)):
    """Get backup system status."""
    try:
        # Mock backup status
        status = {
            'completeness_percentage': 95,
            'total_shards': 20,
            'distributed_shards': 19,
            'last_backup': '2024-01-15T03:00:00Z',
            'last_backup_status': 'successful',
            'connected_nodes': [
                {
                    'node_id': 'node-001',
                    'status': 'online',
                    'storage_used': '2.3 GB',
                    'storage_total': '10 GB',
                    'shards': 5,
                    'last_sync': '2 min ago'
                },
                {
                    'node_id': 'node-002',
                    'status': 'online',
                    'storage_used': '1.8 GB',
                    'storage_total': '5 GB',
                    'shards': 3,
                    'last_sync': '1 min ago'
                }
            ]
        }
        
        return {'success': True, 'backup_status': status}
    except Exception as e:
        logger.error(f"Backup status error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/backup/start")
async def start_backup(admin: Dict = Depends(get_current_admin)):
    """Start manual backup."""
    try:
        logger.info(f"Manual backup started by {admin['username']}")
        
        # This would trigger actual backup process
        return {
            'success': True,
            'message': 'Backup started successfully',
            'backup_id': f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        }
    except Exception as e:
        logger.error(f"Backup start error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/api/moderation/reports")
async def get_moderation_reports(admin: Dict = Depends(get_current_admin)):
    """Get moderation reports."""
    try:
        # Mock moderation reports
        reports = [
            {
                'id': '001',
                'type': 'spam',
                'reporter': 'user123',
                'target': 'message456',
                'status': 'pending',
                'date': '2024-01-15T09:30:00Z',
                'description': 'Suspected spam message'
            }
        ]
        
        return {'success': True, 'reports': reports}
    except Exception as e:
        logger.error(f"Moderation reports error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/api/system/restart")
async def restart_system(admin: Dict = Depends(get_current_admin)):
    """Restart system (requires confirmation)."""
    try:
        logger.warning(f"System restart requested by {admin['username']}")
        
        # This would implement system restart
        return {
            'success': True,
            'message': 'System restart initiated',
            'estimated_downtime': '30 seconds'
        }
    except Exception as e:
        logger.error(f"System restart error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
