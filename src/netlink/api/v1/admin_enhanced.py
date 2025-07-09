"""
Enhanced admin API for NetLink.
Provides comprehensive administrative functionality and statistics.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func
from pathlib import Path

from netlink.app.db import get_session
from netlink.app.models.enhanced_models import EnhancedUser, UserStatus
from netlink.app.models.message import Message
from netlink.app.models.enhanced_backup import EnhancedBackup, BackupNode
from netlink.app.models.moderation import ModerationLog, UserModerationStatus
from netlink.app.utils.auth import get_current_user
from netlink.app.logger_config import logger


# Setup templates
templates_dir = Path(__file__).parent.parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

router = APIRouter(prefix="/api/v1/admin", tags=["Enhanced Admin"])


@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
):
    """Serve the enhanced admin dashboard."""
    # Check if user has admin privileges
    # For now, allow all authenticated users - in production, check roles
    
    return templates.TemplateResponse("admin_enhanced.html", {
        "request": request,
        "user": current_user
    })


@router.get("/statistics")
async def get_admin_statistics(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get comprehensive system statistics."""
    try:
        # User statistics
        total_users = session.exec(select(func.count(EnhancedUser.id))).first()
        active_users = session.exec(
            select(func.count(EnhancedUser.id)).where(EnhancedUser.status == UserStatus.ACTIVE)
        ).first()
        
        # Message statistics
        total_messages = session.exec(select(func.count(Message.id))).first()
        recent_messages = session.exec(
            select(func.count(Message.id)).where(
                Message.timestamp >= datetime.utcnow() - timedelta(days=7)
            )
        ).first()
        
        # Backup statistics
        total_backups = session.exec(select(func.count(EnhancedBackup.id))).first()
        completed_backups = session.exec(
            select(func.count(EnhancedBackup.id)).where(
                EnhancedBackup.status == "completed"
            )
        ).first()
        
        # System uptime (placeholder - would be calculated from actual system start time)
        uptime_seconds = 86400 * 7  # 7 days placeholder
        
        return {
            "total_users": total_users or 0,
            "active_users": active_users or 0,
            "total_messages": total_messages or 0,
            "recent_messages": recent_messages or 0,
            "total_backups": total_backups or 0,
            "completed_backups": completed_backups or 0,
            "uptime_seconds": uptime_seconds,
            "system_health": "healthy",
            "last_updated": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting admin statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get statistics"
        )


@router.get("/recent-activity")
async def get_recent_activity(
    limit: int = 20,
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get recent system activity."""
    try:
        activities = []
        
        # Recent user registrations
        recent_users = session.exec(
            select(EnhancedUser).where(
                EnhancedUser.created_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(EnhancedUser.created_at.desc()).limit(5)
        ).all()
        
        for user in recent_users:
            activities.append({
                "type": "user_registered",
                "description": f"New user registered: {user.username}",
                "timestamp": user.created_at.isoformat(),
                "user_id": user.id
            })
        
        # Recent messages
        recent_messages = session.exec(
            select(Message).where(
                Message.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).order_by(Message.timestamp.desc()).limit(5)
        ).all()
        
        for message in recent_messages:
            activities.append({
                "type": "message_sent",
                "description": f"Message sent by user {message.sender_id}",
                "timestamp": message.timestamp.isoformat(),
                "message_id": message.id
            })
        
        # Recent moderation actions
        recent_moderation = session.exec(
            select(ModerationLog).where(
                ModerationLog.created_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(ModerationLog.created_at.desc()).limit(5)
        ).all()
        
        for mod_log in recent_moderation:
            activities.append({
                "type": "moderation_action",
                "description": f"Moderation action: {mod_log.action.value} by {mod_log.moderator_id}",
                "timestamp": mod_log.created_at.isoformat(),
                "moderation_id": mod_log.id
            })
        
        # Recent backups
        recent_backups = session.exec(
            select(EnhancedBackup).where(
                EnhancedBackup.created_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(EnhancedBackup.created_at.desc()).limit(3)
        ).all()
        
        for backup in recent_backups:
            activities.append({
                "type": "backup_created",
                "description": f"Backup created: {backup.backup_name}",
                "timestamp": backup.created_at.isoformat(),
                "backup_id": backup.id
            })
        
        # Sort all activities by timestamp and limit
        activities.sort(key=lambda x: x["timestamp"], reverse=True)
        return activities[:limit]
        
    except Exception as e:
        logger.error(f"Error getting recent activity: {e}")
        return []


@router.get("/system-health")
async def get_system_health(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get comprehensive system health information."""
    try:
        # Database health
        try:
            session.exec(select(func.count(EnhancedUser.id))).first()
            db_health = "healthy"
        except Exception:
            db_health = "unhealthy"
        
        # Backup system health
        recent_backups = session.exec(
            select(EnhancedBackup).where(
                EnhancedBackup.created_at >= datetime.utcnow() - timedelta(days=1)
            )
        ).all()
        
        backup_health = "healthy" if recent_backups else "warning"
        
        # Node health
        backup_nodes = session.exec(select(BackupNode)).all()
        online_nodes = len([node for node in backup_nodes if node.is_online])
        total_nodes = len(backup_nodes)
        
        node_health = "healthy" if online_nodes == total_nodes else "warning" if online_nodes > 0 else "critical"
        
        # Moderation health
        pending_moderation = session.exec(
            select(func.count(ModerationLog.id)).where(
                ModerationLog.status == "pending"
            )
        ).first()
        
        moderation_health = "healthy" if (pending_moderation or 0) < 10 else "warning"
        
        return {
            "overall_status": "healthy",
            "components": {
                "database": {
                    "status": db_health,
                    "message": "Database connection active"
                },
                "backup_system": {
                    "status": backup_health,
                    "message": f"Recent backups: {len(recent_backups)}"
                },
                "backup_nodes": {
                    "status": node_health,
                    "message": f"Online nodes: {online_nodes}/{total_nodes}"
                },
                "moderation": {
                    "status": moderation_health,
                    "message": f"Pending actions: {pending_moderation or 0}"
                }
            },
            "last_checked": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return {
            "overall_status": "error",
            "error": str(e),
            "last_checked": datetime.utcnow().isoformat()
        }


@router.get("/performance-metrics")
async def get_performance_metrics(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get system performance metrics."""
    try:
        # Message throughput
        now = datetime.utcnow()
        hourly_messages = []
        
        for i in range(24):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            
            count = session.exec(
                select(func.count(Message.id)).where(
                    (Message.timestamp >= hour_start) & (Message.timestamp < hour_end)
                )
            ).first()
            
            hourly_messages.append({
                "hour": hour_start.strftime("%H:00"),
                "count": count or 0
            })
        
        # User activity
        daily_active_users = session.exec(
            select(func.count(EnhancedUser.id)).where(
                EnhancedUser.last_activity_at >= now - timedelta(days=1)
            )
        ).first()
        
        weekly_active_users = session.exec(
            select(func.count(EnhancedUser.id)).where(
                EnhancedUser.last_activity_at >= now - timedelta(days=7)
            )
        ).first()
        
        # Storage metrics
        total_backup_size = session.exec(
            select(func.sum(EnhancedBackup.total_size_bytes))
        ).first()
        
        return {
            "message_throughput": {
                "hourly": hourly_messages,
                "total_24h": sum(h["count"] for h in hourly_messages)
            },
            "user_activity": {
                "daily_active": daily_active_users or 0,
                "weekly_active": weekly_active_users or 0
            },
            "storage": {
                "total_backup_bytes": total_backup_size or 0,
                "total_backup_gb": (total_backup_size or 0) / (1024**3)
            },
            "timestamp": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return {"error": str(e)}


@router.post("/maintenance/cleanup")
async def run_maintenance_cleanup(
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Run system maintenance and cleanup tasks."""
    try:
        cleanup_results = {
            "deleted_messages": 0,
            "cleaned_logs": 0,
            "optimized_backups": 0
        }
        
        # Clean up old deleted messages (older than 30 days)
        old_deleted_messages = session.exec(
            select(Message).where(
                (Message.is_deleted == True) &
                (Message.timestamp < datetime.utcnow() - timedelta(days=30))
            )
        ).all()
        
        for message in old_deleted_messages:
            session.delete(message)
            cleanup_results["deleted_messages"] += 1
        
        # Clean up old moderation logs (older than 1 year)
        old_mod_logs = session.exec(
            select(ModerationLog).where(
                ModerationLog.created_at < datetime.utcnow() - timedelta(days=365)
            )
        ).all()
        
        for log in old_mod_logs:
            session.delete(log)
            cleanup_results["cleaned_logs"] += 1
        
        session.commit()
        
        logger.info(f"Maintenance cleanup completed: {cleanup_results}")
        
        return JSONResponse({
            "success": True,
            "results": cleanup_results,
            "message": "Maintenance cleanup completed successfully"
        })
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error during maintenance cleanup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Maintenance cleanup failed"
        )


@router.get("/export/users")
async def export_users(
    format: str = "json",
    session: Session = Depends(get_session),
    current_user: EnhancedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Export user data for backup or analysis."""
    try:
        users = session.exec(select(EnhancedUser)).all()
        
        user_data = []
        for user in users:
            user_data.append({
                "id": user.id,
                "uuid": user.uuid,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
                "status": user.status.value if user.status else None,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_activity_at": user.last_activity_at.isoformat() if user.last_activity_at else None,
                "is_verified": user.is_verified,
                "login_count": user.login_count,
                "message_count": user.message_count
            })
        
        return {
            "export_type": "users",
            "format": format,
            "count": len(user_data),
            "exported_at": datetime.utcnow().isoformat(),
            "data": user_data
        }
        
    except Exception as e:
        logger.error(f"Error exporting users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export users"
        )
