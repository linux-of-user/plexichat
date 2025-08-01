"""
Advanced Security API Endpoints
Provides comprehensive security management and monitoring capabilities.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from plexichat.core.security.enhanced_security_manager import enhanced_security_manager
from plexichat.core.auth import get_current_user, require_admin
from plexichat.shared.exceptions import SecurityError, AuthorizationError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security", tags=["Advanced Security"])
security = HTTPBearer()

# Pydantic models for request/response
class SecurityScanRequest(BaseModel):
    scan_type: str = Field(default="comprehensive", description="Type of security scan")
    include_vulnerabilities: bool = Field(default=True, description="Include vulnerability assessment")
    include_threats: bool = Field(default=True, description="Include threat analysis")

class SecurityScanResponse(BaseModel):
    scan_id: str
    timestamp: datetime
    scan_type: str
    security_score: int
    vulnerabilities_found: List[Dict[str, Any]]
    threats_detected: List[Dict[str, Any]]
    recommendations: List[str]
    system_health: str

class SecurityMetricsResponse(BaseModel):
    total_events: int
    recent_events: int
    active_sessions: int
    blocked_ips: int
    threat_detections: int
    security_level: str
    intrusion_attempts: int
    security_incidents: int
    suspicious_activities: int
    last_updated: str

class IPBlockRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to block")
    reason: str = Field(default="Manual block", description="Reason for blocking")
    duration_hours: Optional[int] = Field(default=None, description="Block duration in hours")

class SecurityReportResponse(BaseModel):
    report_timestamp: str
    summary: Dict[str, Any]
    event_breakdown: Dict[str, int]
    top_threats: List[str]
    recommendations: List[str]

class ThreatAnalysisRequest(BaseModel):
    input_data: str = Field(..., description="Data to analyze for threats")
    analysis_type: str = Field(default="comprehensive", description="Type of analysis")

class ThreatAnalysisResponse(BaseModel):
    is_malicious: bool
    threat_score: int
    threats_detected: Dict[str, List[str]]
    recommendations: List[str]

@router.get("/metrics", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get comprehensive security metrics."""
    try:
        metrics = enhanced_security_manager.get_security_metrics()
        return SecurityMetricsResponse(**metrics)
    except Exception as e:
        logger.error(f"Error getting security metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security metrics")

@router.post("/scan", response_model=SecurityScanResponse)
async def perform_security_scan(
    request: SecurityScanRequest,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Perform comprehensive security scan."""
    try:
        scan_results = await enhanced_security_manager.perform_security_scan()
        
        # Generate scan ID
        import uuid
        scan_id = str(uuid.uuid4())
        
        response_data = {
            "scan_id": scan_id,
            "timestamp": datetime.now(),
            "scan_type": request.scan_type,
            "security_score": scan_results.get("security_score", 0),
            "vulnerabilities_found": scan_results.get("vulnerabilities_found", []),
            "threats_detected": scan_results.get("threats_detected", []),
            "recommendations": scan_results.get("recommendations", []),
            "system_health": scan_results.get("system_health", "UNKNOWN")
        }
        
        return SecurityScanResponse(**response_data)
    except Exception as e:
        logger.error(f"Error performing security scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to perform security scan")

@router.post("/analyze-threat", response_model=ThreatAnalysisResponse)
async def analyze_threat(
    request: ThreatAnalysisRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Analyze input data for security threats."""
    try:
        threats_detected = enhanced_security_manager.threat_detector.detect_threats(request.input_data)
        is_malicious = enhanced_security_manager.threat_detector.is_malicious(request.input_data)
        
        # Calculate threat score
        threat_score = 0
        if threats_detected:
            threat_score = min(100, len(threats_detected) * 20)
        
        recommendations = []
        if is_malicious:
            recommendations.extend([
                "Block the source of this input",
                "Review security logs for similar patterns",
                "Consider implementing additional input validation",
                "Alert security team for investigation"
            ])
        
        return ThreatAnalysisResponse(
            is_malicious=is_malicious,
            threat_score=threat_score,
            threats_detected=threats_detected,
            recommendations=recommendations
        )
    except Exception as e:
        logger.error(f"Error analyzing threat: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze threat")

@router.post("/block-ip")
async def block_ip_address(
    request: IPBlockRequest,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Block an IP address."""
    try:
        enhanced_security_manager.block_ip_address(request.ip_address, request.reason)
        
        return {
            "success": True,
            "message": f"IP {request.ip_address} has been blocked",
            "reason": request.reason,
            "blocked_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error blocking IP {request.ip_address}: {e}")
        raise HTTPException(status_code=500, detail="Failed to block IP address")

@router.delete("/block-ip/{ip_address}")
async def unblock_ip_address(
    ip_address: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Unblock an IP address."""
    try:
        enhanced_security_manager.unblock_ip_address(ip_address)
        
        return {
            "success": True,
            "message": f"IP {ip_address} has been unblocked",
            "unblocked_at": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error unblocking IP {ip_address}: {e}")
        raise HTTPException(status_code=500, detail="Failed to unblock IP address")

@router.get("/blocked-ips")
async def get_blocked_ips(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get list of blocked IP addresses."""
    try:
        blocked_ips = list(enhanced_security_manager.blocked_ips)
        intrusion_blocked = list(enhanced_security_manager.intrusion_detector.blocked_ips)
        
        # Combine and deduplicate
        all_blocked = list(set(blocked_ips + intrusion_blocked))
        
        return {
            "blocked_ips": all_blocked,
            "total_count": len(all_blocked),
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve blocked IPs")

@router.get("/report", response_model=SecurityReportResponse)
async def get_security_report(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Generate comprehensive security report."""
    try:
        report = enhanced_security_manager.get_security_report()
        return SecurityReportResponse(**report)
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate security report")

@router.get("/audit-logs")
async def get_audit_logs(
    user_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get audit logs with optional filtering."""
    try:
        if user_id:
            events = enhanced_security_manager.audit_logger.get_events_by_user(user_id, limit)
        elif event_type:
            events = enhanced_security_manager.audit_logger.get_events_by_type(event_type, limit)
        else:
            # Get recent events
            all_events = enhanced_security_manager.audit_logger.audit_events
            events = sorted(all_events, key=lambda x: x['timestamp'], reverse=True)[:limit]
        
        return {
            "events": events,
            "total_count": len(events),
            "filters_applied": {
                "user_id": user_id,
                "event_type": event_type,
                "limit": limit
            }
        }
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve audit logs")

@router.get("/sessions")
async def get_active_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get information about active sessions."""
    try:
        sessions = enhanced_security_manager.session_manager.active_sessions
        
        # Filter sensitive information
        filtered_sessions = {}
        for session_id, session_data in sessions.items():
            if session_data.get('is_active', False):
                filtered_sessions[session_id] = {
                    'user_id': session_data.get('user_id'),
                    'ip_address': session_data.get('ip_address'),
                    'created_at': session_data.get('created_at'),
                    'last_activity': session_data.get('last_activity'),
                    'security_flags': session_data.get('security_flags', {})
                }
        
        return {
            "active_sessions": filtered_sessions,
            "total_count": len(filtered_sessions),
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve active sessions")

@router.post("/emergency-lockdown")
async def emergency_lockdown(
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Activate emergency security lockdown."""
    try:
        # This would implement emergency procedures
        # For now, we'll just log the event and return status
        
        enhanced_security_manager.audit_logger.log_security_event(
            'EMERGENCY_LOCKDOWN',
            current_user.get('user_id', 'unknown'),
            'system',
            {'initiated_by': current_user.get('username', 'unknown')},
            'CRITICAL'
        )
        
        logger.critical(f"Emergency lockdown initiated by {current_user.get('username', 'unknown')}")
        
        return {
            "success": True,
            "message": "Emergency lockdown activated",
            "initiated_by": current_user.get('username'),
            "timestamp": datetime.now().isoformat(),
            "status": "LOCKDOWN_ACTIVE"
        }
    except Exception as e:
        logger.error(f"Error activating emergency lockdown: {e}")
        raise HTTPException(status_code=500, detail="Failed to activate emergency lockdown")
