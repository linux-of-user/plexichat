import base64
from datetime import datetime, timezone
from typing import Any, Dict, Optional


from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from plexichat.core.logging import get_logger
from plexichat.core_system.security.certificate_manager import get_certificate_manager
from plexichat.core_system.security.unified_security_manager import (
    get_unified_security_manager,
)
from plexichat.features.security.network_protection import get_network_protection

"""
PlexiChat Unified Security API - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple security API endpoints:
- interfaces/api/v1/security/security.py - REMOVED
- Various security endpoints scattered across the API - INTEGRATED

Features:
- Comprehensive threat detection and scanning
- Network protection and rate limiting management
- Input validation and sanitization
- Certificate and SSL management
- Security monitoring and audit trails
- Decentralized security node management
- Real-time threat intelligence
"""

logger = get_logger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/security", tags=["security"])


# Pydantic models for API
class LinkCheckRequest(BaseModel):
    url: str


class InputSanitizeRequest(BaseModel):
    input_text: str
    allow_html: bool = False


class SqlInjectionCheckRequest(BaseModel):
    input_text: str
    source: str = "api"


class IPManagementRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = None


class ThreatReportRequest(BaseModel):
    threat_type: str
    description: str
    source_ip: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class SecurityConfigRequest(BaseModel):
    config_key: str
    config_value: Any


# File Scanning Endpoints
@router.post("/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Scan an uploaded file for malware and threats."""
    try:
        security_manager = get_unified_security_manager()

        # Read file content
        file_content = await file.read()

        # Perform security scan
        scan_result = await security_manager.scan_file_content(
            file_content, file.filename or "unknown"
        )

        response_data = {
            "safe": scan_result.get("safe", False),
            "filename": file.filename,
            "file_size": len(file_content),
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }

        if not scan_result.get("safe"):
            threat = scan_result.get("threat")
            if threat:
                response_data.update(
                    {
                        "threat_id": threat.get("threat_id"),
                        "threat_type": threat.get("threat_type"),
                        "threat_level": threat.get("threat_level"),
                        "description": threat.get("description"),
                        "mitigation": threat.get("mitigation_action"),
                    }
                )

        return response_data

    except Exception as e:
        logger.error(f"Failed to scan file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/file_base64")
async def scan_base64_file(filename: str, file_data: str, encoding: str = "base64"):
    """Scan a base64-encoded file for malware and threats."""
    try:
        security_manager = get_unified_security_manager()

        # Decode file content
        if encoding == "base64":
            file_content = base64.b64decode(file_data)
        else:
            raise HTTPException(
                status_code=400, detail="Only base64 encoding is supported"
            )

        # Perform security scan
        scan_result = await security_manager.scan_file_content(file_content, filename)

        response_data = {
            "safe": scan_result.get("safe", False),
            "filename": filename,
            "file_size": len(file_content),
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }

        if not scan_result.get("safe"):
            threat = scan_result.get("threat")
            if threat:
                response_data.update(
                    {
                        "threat_id": threat.get("threat_id"),
                        "threat_type": threat.get("threat_type"),
                        "threat_level": threat.get("threat_level"),
                        "description": threat.get("description"),
                    }
                )

        return response_data

    except Exception as e:
        logger.error(f"Failed to scan base64 file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Link and URL Security
@router.post("/check/link")
async def check_link_safety(request: LinkCheckRequest):
    """Check if a URL is safe."""
    try:
        security_manager = get_unified_security_manager()

        safety_result = await security_manager.check_url_safety(request.url)

        response_data = {
            "safe": safety_result.get("safe", False),
            "url": request.url,
            "check_time": datetime.now(timezone.utc).isoformat(),
        }

        if not safety_result.get("safe"):
            threat = safety_result.get("threat")
            if threat:
                response_data.update(
                    {
                        "threat_id": threat.get("threat_id"),
                        "threat_type": threat.get("threat_type"),
                        "threat_level": threat.get("threat_level"),
                        "description": threat.get("description"),
                        "categories": threat.get("categories", []),
                    }
                )

        return response_data

    except Exception as e:
        logger.error(f"Failed to check link safety: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Input Validation and Sanitization
@router.post("/sanitize/input")
async def sanitize_input(request: InputSanitizeRequest):
    """Sanitize user input to prevent XSS and other attacks."""
    try:
        security_manager = get_unified_security_manager()

        sanitized_text = await security_manager.sanitize_input(
            request.input_text, allow_html=request.allow_html
        )

        return {
            "original": request.input_text,
            "sanitized": sanitized_text,
            "changes_made": request.input_text != sanitized_text,
            "allow_html": request.allow_html,
        }

    except Exception as e:
        logger.error(f"Failed to sanitize input: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check/sql_injection")
async def check_sql_injection(request: SqlInjectionCheckRequest):
    """Check input for SQL injection attempts."""
    try:
        security_manager = get_unified_security_manager()

        injection_result = await security_manager.detect_sql_injection(
            request.input_text, request.source
        )

        response_data = {
            "input": request.input_text,
            "source": request.source,
            "is_injection": injection_result.get("is_injection", False),
            "confidence": injection_result.get("confidence", 0.0),
        }

        if injection_result.get("is_injection"):
            response_data.update(
                {
                    "patterns_detected": injection_result.get("patterns", []),
                    "severity": injection_result.get("severity", "medium"),
                    "mitigation": "Input blocked and logged",
                }
            )

        return response_data

    except Exception as e:
        logger.error(f"Failed to check SQL injection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Network Protection and Rate Limiting
@router.get("/network/status")
async def get_network_protection_status():
    """Get network protection system status."""
    try:
        network_protection = get_network_protection()
        status = network_protection.get_status()

        return {
            "success": True,
            "network_protection": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to get network protection status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/whitelist")
async def add_ip_to_whitelist(request: IPManagementRequest):
    """Add IP address to whitelist."""
    try:
        network_protection = get_network_protection()
        network_protection.add_to_whitelist(request.ip_address)

        return {
            "success": True,
            "message": f"IP {request.ip_address} added to whitelist",
            "reason": request.reason,
        }

    except Exception as e:
        logger.error(f"Failed to add IP to whitelist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/network/blacklist")
async def add_ip_to_blacklist(request: IPManagementRequest):
    """Add IP address to blacklist."""
    try:
        network_protection = get_network_protection()
        network_protection.add_to_blacklist(
            request.ip_address, request.reason or "Manual blacklist"
        )

        return {
            "success": True,
            "message": f"IP {request.ip_address} added to blacklist",
            "reason": request.reason,
        }

    except Exception as e:
        logger.error(f"Failed to add IP to blacklist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/network/blacklist/{ip_address}")
async def remove_ip_from_blacklist(ip_address: str):
    """Remove IP address from blacklist."""
    try:
        network_protection = get_network_protection()
        network_protection.remove_from_blacklist(ip_address)

        return {"success": True, "message": f"IP {ip_address} removed from blacklist"}

    except Exception as e:
        logger.error(f"Failed to remove IP from blacklist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Certificate Management
@router.get("/certificates/status")
async def get_certificate_status():
    """Get certificate management status."""
    try:
        cert_manager = get_certificate_manager()

        # Get status for all certificates
        certificates = {}
        for domain in cert_manager.certificates:
            certificates[domain] = cert_manager.get_certificate_status(domain)

        return {
            "success": True,
            "certificates": certificates,
            "total_certificates": len(certificates),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to get certificate status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Threat Intelligence and Monitoring
@router.get("/threats/recent")
async def get_recent_threats(limit: int = 50):
    """Get recent security threats."""
    try:
        security_manager = get_unified_security_manager()
        threats = await security_manager.get_recent_threats(limit)

        return {
            "success": True,
            "threats": threats,
            "total_threats": len(threats),
            "limit": limit,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to get recent threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threats/report")
async def report_threat(request: ThreatReportRequest):
    """Report a security threat."""
    try:
        security_manager = get_unified_security_manager()

        threat_id = await security_manager.report_threat(
            threat_type=request.threat_type,
            description=request.description,
            source_ip=request.source_ip,
            metadata=request.metadata or {},
        )

        return {
            "success": True,
            "threat_id": threat_id,
            "message": "Threat reported successfully",
        }

    except Exception as e:
        logger.error(f"Failed to report threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Security System Status
@router.get("/status")
async def get_security_system_status():
    """Get comprehensive security system status."""
    try:
        security_manager = get_unified_security_manager()
        network_protection = get_network_protection()
        cert_manager = get_certificate_manager()

        return {
            "success": True,
            "security_manager": await security_manager.get_status(),
            "network_protection": network_protection.get_status(),
            "certificate_manager": {
                "initialized": cert_manager.initialized,
                "certificates_count": len(cert_manager.certificates),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to get security system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Export router
__all__ = ["router"]
