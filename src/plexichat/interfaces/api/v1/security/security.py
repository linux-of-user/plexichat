"""
Security & Anti-Virus API endpoints for PlexiChat.
Provides comprehensive security features including file scanning,
link checking, and threat management.
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Request
from pydantic import BaseModel
import base64

from plexichat.app.services.security_service import security_service, ThreatType, ThreatLevel
from plexichat.app.logger_config import logger


# Pydantic models for API
class LinkCheckRequest(BaseModel):
    url: str


class InputSanitizeRequest(BaseModel):
    input_text: str
    allow_html: bool = False


class SqlInjectionCheckRequest(BaseModel):
    input_text: str
    source: str = "api"


class IpBlockRequest(BaseModel):
    ip_address: str
    duration_minutes: Optional[int] = None


class FileUploadResponse(BaseModel):
    safe: bool
    filename: str
    threat_id: Optional[str] = None
    threat_type: Optional[str] = None
    threat_level: Optional[str] = None
    description: Optional[str] = None
    witty_response: Optional[str] = None


router = APIRouter(prefix="/api/v1/security", tags=["Security & Anti-Virus"])


@router.post("/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Scan an uploaded file for malware and threats."""
    try:
        # Read file content
        file_content = await file.read()
        
        # Scan the file
        is_safe, threat = security_service.scan_file_content(file_content, file.filename)
        
        if is_safe:
            return FileUploadResponse(
                safe=True,
                filename=file.filename,
                description="File scan completed - no threats detected"
            )
        else:
            return FileUploadResponse(
                safe=False,
                filename=file.filename,
                threat_id=threat.threat_id,
                threat_type=threat.threat_type.value,
                threat_level=threat.threat_level.value,
                description=threat.description,
                witty_response=threat.witty_response
            )
            
    except Exception as e:
        logger.error(f"Failed to scan file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/file_base64")
async def scan_base64_file(
    filename: str,
    file_data: str,
    encoding: str = "base64"
):
    """Scan a base64-encoded file for malware and threats."""
    try:
        # Decode file content
        if encoding == "base64":
            file_content = base64.b64decode(file_data)
        else:
            raise HTTPException(status_code=400, detail="Only base64 encoding is supported")
        
        # Scan the file
        is_safe, threat = security_service.scan_file_content(file_content, filename)
        
        response_data = {
            "safe": is_safe,
            "filename": filename,
            "file_size": len(file_content)
        }
        
        if not is_safe and threat:
            response_data.update({
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type.value,
                "threat_level": threat.threat_level.value,
                "description": threat.description,
                "witty_response": threat.witty_response
            })
        
        return response_data
        
    except Exception as e:
        logger.error(f"Failed to scan base64 file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check/link")
async def check_link_safety(request: LinkCheckRequest):
    """Check if a URL is safe."""
    try:
        is_safe, threat = security_service.check_link_safety(request.url)
        
        response_data = {
            "safe": is_safe,
            "url": request.url
        }
        
        if not is_safe and threat:
            response_data.update({
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type.value,
                "threat_level": threat.threat_level.value,
                "description": threat.description,
                "witty_response": threat.witty_response
            })
        
        return response_data
        
    except Exception as e:
        logger.error(f"Failed to check link safety: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check/sql_injection")
async def check_sql_injection(request: SqlInjectionCheckRequest):
    """Check input for SQL injection attempts."""
    try:
        is_injection, threat = security_service.detect_sql_injection(
            request.input_text,
            request.source
        )
        
        response_data = {
            "sql_injection_detected": is_injection,
            "input_length": len(request.input_text),
            "source": request.source
        }
        
        if is_injection and threat:
            response_data.update({
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type.value,
                "threat_level": threat.threat_level.value,
                "description": threat.description,
                "witty_response": threat.witty_response,
                "patterns_detected": len(threat.metadata.get("patterns", []))
            })
        
        return response_data
        
    except Exception as e:
        logger.error(f"Failed to check SQL injection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sanitize")
async def sanitize_input(request: InputSanitizeRequest):
    """Sanitize user input."""
    try:
        sanitized_text = security_service.sanitize_input(
            request.input_text,
            request.allow_html
        )
        
        return {
            "original_text": request.input_text,
            "sanitized_text": sanitized_text,
            "original_length": len(request.input_text),
            "sanitized_length": len(sanitized_text),
            "changes_made": request.input_text != sanitized_text,
            "allow_html": request.allow_html
        }
        
    except Exception as e:
        logger.error(f"Failed to sanitize input: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rate_limit/check")
async def check_rate_limit(request: Request, identifier: Optional[str] = None):
    """Check rate limiting for an identifier."""
    try:
        # Use IP address if no identifier provided
        check_identifier = identifier or request.client.host
        
        is_allowed, threat = security_service.check_rate_limit(check_identifier)
        
        response_data = {
            "allowed": is_allowed,
            "identifier": check_identifier,
            "current_requests": len(security_service.rate_limits.get(check_identifier, []))
        }
        
        if not is_allowed and threat:
            response_data.update({
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type.value,
                "threat_level": threat.threat_level.value,
                "description": threat.description,
                "witty_response": threat.witty_response
            })
        
        return response_data
        
    except Exception as e:
        logger.error(f"Failed to check rate limit: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/block/ip")
async def block_ip_address(request: IpBlockRequest):
    """Block an IP address."""
    try:
        security_service.block_ip(request.ip_address, request.duration_minutes)
        
        return {
            "success": True,
            "message": f"IP address {request.ip_address} has been blocked",
            "ip_address": request.ip_address,
            "duration_minutes": request.duration_minutes or security_service.block_duration_minutes
        }
        
    except Exception as e:
        logger.error(f"Failed to block IP: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/block/ip/{ip_address}")
async def check_ip_blocked(ip_address: str):
    """Check if an IP address is blocked."""
    try:
        is_blocked = security_service.is_ip_blocked(ip_address)
        
        return {
            "ip_address": ip_address,
            "is_blocked": is_blocked
        }
        
    except Exception as e:
        logger.error(f"Failed to check IP block status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats")
async def get_recent_threats(limit: int = 50):
    """Get recent security threats."""
    try:
        threats = security_service.get_recent_threats(limit)
        
        return {
            "success": True,
            "threats": threats,
            "total_threats": len(threats),
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Failed to get recent threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threats/{threat_id}")
async def get_threat_details(threat_id: str):
    """Get detailed information about a specific threat."""
    try:
        threat = security_service.detected_threats.get(threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        return {
            "success": True,
            "threat": {
                "threat_id": threat.threat_id,
                "type": threat.threat_type.value,
                "level": threat.threat_level.value,
                "source": threat.source,
                "description": threat.description,
                "detected_at": threat.detected_at.isoformat(),
                "blocked": threat.blocked,
                "witty_response": threat.witty_response,
                "metadata": threat.metadata
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get threat details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_security_statistics():
    """Get security system statistics."""
    try:
        stats = security_service.get_security_statistics()
        
        return {
            "success": True,
            "statistics": stats
        }
        
    except Exception as e:
        logger.error(f"Failed to get security statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/signatures")
async def get_file_signatures():
    """Get loaded file signatures."""
    try:
        signatures = []
        
        for signature in security_service.file_signatures.values():
            signatures.append({
                "signature_id": signature.signature_id,
                "name": signature.name,
                "threat_type": signature.threat_type.value,
                "threat_level": signature.threat_level.value,
                "description": signature.description
            })
        
        return {
            "success": True,
            "signatures": signatures,
            "total_signatures": len(signatures)
        }
        
    except Exception as e:
        logger.error(f"Failed to get file signatures: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/blocked_domains")
async def get_blocked_domains():
    """Get list of blocked domains."""
    try:
        return {
            "success": True,
            "blocked_domains": list(security_service.blocked_domains),
            "total_blocked": len(security_service.blocked_domains)
        }
        
    except Exception as e:
        logger.error(f"Failed to get blocked domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test/all")
async def run_security_tests():
    """Run comprehensive security tests."""
    try:
        test_results = []
        
        # Test SQL injection detection
        sql_test_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM passwords",
            "normal input text"
        ]
        
        for test_input in sql_test_inputs:
            is_injection, threat = security_service.detect_sql_injection(test_input, "test")
            test_results.append({
                "test_type": "sql_injection",
                "input": test_input,
                "detected": is_injection,
                "witty_response": threat.witty_response if threat else None
            })
        
        # Test link safety
        link_test_inputs = [
            "https://malware.com/virus.exe",
            "http://phishing-site.net/login",
            "https://google.com",
            "https://github.com"
        ]
        
        for test_url in link_test_inputs:
            is_safe, threat = security_service.check_link_safety(test_url)
            test_results.append({
                "test_type": "link_safety",
                "input": test_url,
                "safe": is_safe,
                "witty_response": threat.witty_response if threat else None
            })
        
        # Test input sanitization
        sanitize_test_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "normal text input"
        ]
        
        for test_input in sanitize_test_inputs:
            sanitized = security_service.sanitize_input(test_input)
            test_results.append({
                "test_type": "input_sanitization",
                "input": test_input,
                "sanitized": sanitized,
                "changes_made": test_input != sanitized
            })
        
        return {
            "success": True,
            "test_results": test_results,
            "total_tests": len(test_results),
            "message": "Security tests completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to run security tests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Decentralized Security Endpoints
@router.get("/decentralized/status")
async def get_decentralized_security_status():
    """Get decentralized security network status."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security

        security_manager = get_decentralized_security()
        status = security_manager.get_network_security_status()

        return {
            "success": True,
            "decentralized_security": status
        }

    except Exception as e:
        logger.error(f"Failed to get decentralized security status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decentralized/register_node")
async def register_security_node(request: dict):
    """Register a new security node."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security

        security_manager = get_decentralized_security()

        node_id = request.get("node_id")
        public_key = request.get("public_key")
        capabilities = request.get("capabilities", [])

        if not all([node_id, public_key]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        success = security_manager.register_node(node_id, public_key, capabilities)

        if success:
            return {
                "success": True,
                "message": f"Security node '{node_id}' registered successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to register security node")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to register security node: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decentralized/report_event")
async def report_security_event(request: dict):
    """Report a security event."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security, SecurityLevel

        security_manager = get_decentralized_security()

        event_type = request.get("event_type")
        severity = request.get("severity", "medium")
        target_node = request.get("target_node")
        data = request.get("data", {})

        if not event_type:
            raise HTTPException(status_code=400, detail="Event type is required")

        # Convert severity string to enum
        severity_map = {
            "low": SecurityLevel.LOW,
            "medium": SecurityLevel.MEDIUM,
            "high": SecurityLevel.HIGH,
            "critical": SecurityLevel.CRITICAL
        }

        severity_level = severity_map.get(severity.lower(), SecurityLevel.MEDIUM)

        event_id = security_manager.report_security_event(
            event_type, severity_level, target_node, data
        )

        if event_id:
            return {
                "success": True,
                "event_id": event_id,
                "message": "Security event reported successfully"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to report security event")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to report security event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decentralized/vote")
async def vote_on_proposal(request: dict):
    """Vote on a security proposal."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security

        security_manager = get_decentralized_security()

        proposal_id = request.get("proposal_id")
        vote = request.get("vote")
        voter_id = request.get("voter_id")

        if not all([proposal_id, vote is not None, voter_id]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        success = security_manager.vote_on_proposal(proposal_id, bool(vote), voter_id)

        if success:
            return {
                "success": True,
                "message": "Vote recorded successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to record vote")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to vote on proposal: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decentralized/validate_event")
async def validate_security_event(request: dict):
    """Validate a security event."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security

        security_manager = get_decentralized_security()

        event_id = request.get("event_id")
        validator_id = request.get("validator_id")

        if not all([event_id, validator_id]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        is_valid = security_manager.validate_security_event(event_id, validator_id)

        return {
            "success": True,
            "event_id": event_id,
            "is_valid": is_valid,
            "message": "Event validation completed"
        }

    except Exception as e:
        logger.error(f"Failed to validate security event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/decentralized/audit")
async def perform_security_audit():
    """Perform comprehensive security audit."""
    try:
        from plexichat.app.security.decentralized_security import get_decentralized_security

        security_manager = get_decentralized_security()
        audit_results = security_manager.perform_security_audit()

        return {
            "success": True,
            "audit_results": audit_results
        }

    except Exception as e:
        logger.error(f"Failed to perform security audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))
