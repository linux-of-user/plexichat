"""
PlexiChat Security API Endpoints

Security management and monitoring API endpoints.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query, UploadFile, File
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, Dict, Any, List
import asyncio

try:
    from plexichat.core.security.security_manager import security_manager
    from plugins.advanced_antivirus.core.antivirus_engine import AdvancedAntivirusEngine
    from plugins.advanced_antivirus.core import ScanType
    from plexichat.interfaces.api.v1.auth import get_current_user
    from plexichat.core.logging import get_logger
except ImportError:
    security_manager = None
    get_current_user = lambda: {}
    get_logger = lambda name: print

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/security", tags=["security"])

# Request/Response Models
class SecurityScanRequest(BaseModel):
    target_type: str  # "file", "url", "text"
    target: str
    scan_options: Dict[str, Any] = {}

class SecurityScanResponse(BaseModel):
    scan_id: str
    status: str
    threat_level: str
    threats_found: List[Dict[str, Any]]
    scan_time: float
    recommendations: List[str]

class FirewallRuleRequest(BaseModel):
    action: str  # "allow", "deny", "log"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    description: str

class SecurityEventResponse(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    source_ip: str
    description: str
    status: str

class ThreatIntelResponse(BaseModel):
    ip_reputation: Dict[str, Any]
    domain_reputation: Dict[str, Any]
    file_hash_reputation: Dict[str, Any]
    threat_feeds: List[Dict[str, Any]]

# Admin permission check
async def require_security_admin(current_user: Dict = Depends(get_current_user)):
    """Require security admin permissions."""
    user_roles = current_user.get("roles", [])
    if not ("admin" in user_roles or "security_admin" in user_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security admin privileges required"
        )
    return current_user

@router.post("/scan", response_model=SecurityScanResponse)
async def security_scan(
    request: SecurityScanRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Perform security scan on target."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        scan_result = await security_manager.perform_scan()
        return SecurityScanResponse(
            scan_id=scan_result.scan_id,
            status=scan_result.status,
            threat_level=scan_result.threat_level,
            threats_found=scan_result.threats,
            scan_time=scan_result.scan_time,
            recommendations=scan_result.recommendations
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Security scan error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    current_user: Dict = Depends(get_current_user)
):
    """Scan uploaded file for threats."""
    try:
        # Read file content
        file_content = await file.read()
        # Save to temp file for scanning
        import tempfile
        from pathlib import Path
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_content)
            tmp_path = Path(tmp.name)
        # Instantiate the antivirus engine
        antivirus = AdvancedAntivirusEngine(data_dir=Path("./data"))
        scan_result = await antivirus.scan_file(tmp_path, scan_type=ScanType.FULL_SCAN)
        return {
            "filename": file.filename,
            "file_size": len(file_content),
            "scan_result": scan_result.status if hasattr(scan_result, 'status') else str(scan_result),
            "threats_found": getattr(scan_result, 'threats', []),
            "is_safe": getattr(scan_result, 'is_safe', True),
            "scan_time": getattr(scan_result, 'scan_time', 0.0)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    admin_user: Dict = Depends(require_security_admin)
):
    """Get security events with filtering."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        events = await security_manager.get_security_events()
        return [
            SecurityEventResponse(
                event_id=event["event_id"],
                timestamp=event["timestamp"],
                event_type=event["event_type"],
                severity=event["severity"],
                source_ip=event["source_ip"],
                description=event["description"],
                status=event["status"]
            )
            for event in events
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get security events error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/firewall/rules")
async def add_firewall_rule(
    request: FirewallRuleRequest,
    admin_user: Dict = Depends(require_security_admin)
):
    """Add firewall rule."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        rule_id = await security_manager.add_firewall_rule()
        return {
            "rule_id": rule_id,
            "message": "Firewall rule added successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Add firewall rule error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/firewall/rules")
async def get_firewall_rules(
    admin_user: Dict = Depends(require_security_admin)
):
    """Get all firewall rules."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        rules = await security_manager.get_firewall_rules()
        return {"rules": rules}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get firewall rules error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/firewall/rules/{rule_id}")
async def delete_firewall_rule(
    rule_id: str,
    admin_user: Dict = Depends(require_security_admin)
):
    """Delete firewall rule."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        success = await security_manager.delete_firewall_rule(rule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Firewall rule not found")

        return {"message": "Firewall rule deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete firewall rule error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/threat-intel", response_model=ThreatIntelResponse)
async def get_threat_intelligence(
    ip: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    file_hash: Optional[str] = Query(None),
    admin_user: Dict = Depends(require_security_admin)
):
    """Get threat intelligence data."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        threat_intel = await security_manager.get_threat_intelligence()
        return ThreatIntelResponse(
            ip_reputation=threat_intel.get("ip_reputation", {}),
            domain_reputation=threat_intel.get("domain_reputation", {}),
            file_hash_reputation=threat_intel.get("file_hash_reputation", {}),
            threat_feeds=threat_intel.get("threat_feeds", [])
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get threat intelligence error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/quarantine/{file_id}")
async def quarantine_file(
    file_id: str,
    admin_user: Dict = Depends(require_security_admin)
):
    """Quarantine a file."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        success = await security_manager.quarantine_file(file_id)

        if not success:
            raise HTTPException(status_code=404, detail="File not found")

        return {"message": "File quarantined successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Quarantine file error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/quarantine")
async def get_quarantined_files(
    admin_user: Dict = Depends(require_security_admin)
):
    """Get list of quarantined files."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        files = await security_manager.get_quarantined_files()
        return {"quarantined_files": files}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get quarantined files error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/incident/report")
async def report_security_incident(
    incident_data: Dict[str, Any],
    current_user: Dict = Depends(get_current_user)
):
    """Report a security incident."""
    try:
        if not security_manager:
            raise HTTPException(status_code=503, detail="Security service unavailable")

        incident_id = await security_manager.report_incident()
        return {
            "incident_id": incident_id,
            "message": "Security incident reported successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report incident error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/health")
async def security_health_check():
    """Get security service health status."""
    try:
        health_status = {
            "security_manager": security_manager is not None,
            "firewall_active": False,
            "threat_intel_active": False
        }

        if security_manager:
            detailed_health = await security_manager.health_check()
            health_status.update(detailed_health)

        return {
            "service": "security",
            "status": "online" if health_status["security_manager"] else "degraded",
            "components": health_status
        }

    except Exception as e:
        logger.error(f"Security health check error: {e}")
        return {
            "service": "security",
            "status": "error",
            "error": str(e)
        }

@router.get("/status")
async def security_status():
    """Get security service status."""
    return {
        "service": "security",
        "status": "online",
        "security_manager": security_manager is not None
    }
