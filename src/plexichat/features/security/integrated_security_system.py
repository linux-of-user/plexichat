"""
Integrated Security System
Combines all security enhancements into a unified system for PlexiChat.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException

from .enhanced_input_validation import get_input_validator, ValidationLevel
from .enhanced_auth_system import get_auth_system
from .api_security_decorators import enhanced_security, SecurityLevel
from ..monitoring.enhanced_security_monitor import get_security_monitor, create_login_event, create_permission_denied_event
from ..monitoring.enhanced_audit_logger import get_audit_logger, AuditEventType, ComplianceStandard

logger = logging.getLogger(__name__)


class IntegratedSecuritySystem:
    """Integrated security system that coordinates all security components."""

    def __init__(self, app: FastAPI):
        self.app = app
        self.input_validator = get_input_validator()
        self.auth_system = get_auth_system()
        self.security_monitor = get_security_monitor()
        self.audit_logger = get_audit_logger()
        
        # Security configuration
        self.config = {
            "enable_real_time_monitoring": True,
            "enable_audit_logging": True,
            "enable_threat_detection": True,
            "enable_auto_response": True,
            "compliance_standards": [
                ComplianceStandard.SOX,
                ComplianceStandard.GDPR,
                ComplianceStandard.ISO27001
            ],
            "security_headers": {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
            }
        }
        
        # Initialize security components
        self._setup_security_monitoring()
        self._setup_middleware()

    def _setup_security_monitoring(self):
        """Setup security monitoring with alert callbacks."""
        async def security_alert_handler(alert_data: Dict[str, Any]):
            """Handle security alerts."""
            try:
                # Log to audit system
                await self.audit_logger.log_event(
                    event_type=AuditEventType.SECURITY_EVENT,
                    user_id=alert_data.get("user_id"),
                    session_id=None,
                    source_ip=alert_data.get("source_ip", "unknown"),
                    user_agent="Security Monitor",
                    resource="security_system",
                    action="alert_generated",
                    outcome="success",
                    details=alert_data,
                    compliance_tags=self.config["compliance_standards"],
                    risk_level=alert_data.get("threat_level", "medium"),
                    data_classification="confidential"
                )
                
                # Send notifications (email, Slack, etc.)
                await self._send_security_notification(alert_data)
                
            except Exception as e:
                logger.error(f"Security alert handler error: {e}")

        self.security_monitor.add_alert_callback(security_alert_handler)

    def _setup_middleware(self):
        """Setup security middleware."""
        @self.app.middleware("http")
        async def integrated_security_middleware(request: Request, call_next):
            """Integrated security middleware."""
            start_time = datetime.now()
            client_ip = request.client.host
            user_agent = request.headers.get("user-agent", "")
            
            try:
                # 1. Check if IP is blocked
                if self.security_monitor.is_ip_blocked(client_ip):
                    await self._log_blocked_request(request, client_ip)
                    raise HTTPException(status_code=403, detail="Access denied")
                
                # 2. Input validation for query parameters
                for key, value in request.query_params.items():
                    result = self.input_validator.validate_input(value, ValidationLevel.STANDARD)
                    if not result.is_valid:
                        await self._log_validation_failure(request, key, result.threats_detected)
                        raise HTTPException(status_code=400, detail=f"Invalid parameter: {key}")
                
                # 3. Process request
                response = await call_next(request)
                
                # 4. Add security headers
                for header, value in self.config["security_headers"].items():
                    response.headers[header] = value
                
                # 5. Log successful request
                await self._log_successful_request(request, response, start_time)
                
                return response
                
            except HTTPException:
                # Re-raise HTTP exceptions
                raise
            except Exception as e:
                # Log and handle unexpected errors
                await self._log_system_error(request, str(e))
                raise HTTPException(status_code=500, detail="Internal server error")

    async def authenticate_user(self, username: str, password: str, mfa_code: Optional[str] = None,
                              ip_address: str = "", user_agent: str = "") -> Dict[str, Any]:
        """Authenticate user with integrated security."""
        try:
            # Use enhanced auth system
            auth_result = self.auth_system.authenticate(
                username=username,
                password=password,
                mfa_code=mfa_code,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Log authentication attempt
            security_event = create_login_event(
                source_ip=ip_address,
                user_id=username,
                success=auth_result.success,
                details={
                    "user_agent": user_agent,
                    "mfa_required": auth_result.mfa_required,
                    "risk_score": auth_result.risk_score
                }
            )
            await self.security_monitor.log_event(security_event)
            
            # Audit log
            await self.audit_logger.log_event(
                event_type=AuditEventType.USER_LOGIN,
                user_id=username,
                session_id=auth_result.session_token,
                source_ip=ip_address,
                user_agent=user_agent,
                resource="authentication",
                action="login_attempt",
                outcome="success" if auth_result.success else "failure",
                details={
                    "mfa_required": auth_result.mfa_required,
                    "security_level": auth_result.security_level.value,
                    "risk_score": auth_result.risk_score
                },
                compliance_tags=self.config["compliance_standards"],
                risk_level="low" if auth_result.success else "medium"
            )
            
            return {
                "success": auth_result.success,
                "user_id": auth_result.user_id,
                "session_token": auth_result.session_token,
                "mfa_required": auth_result.mfa_required,
                "security_level": auth_result.security_level.value,
                "expires_at": auth_result.expires_at.isoformat() if auth_result.expires_at else None,
                "warnings": auth_result.warnings
            }
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            
            # Log failed authentication
            security_event = create_login_event(
                source_ip=ip_address,
                user_id=username,
                success=False,
                details={"error": str(e), "user_agent": user_agent}
            )
            await self.security_monitor.log_event(security_event)
            
            return {
                "success": False,
                "error": "Authentication failed",
                "user_id": None,
                "session_token": None
            }

    async def validate_session(self, session_token: str, ip_address: str = "") -> Dict[str, Any]:
        """Validate user session with security checks."""
        try:
            # Basic session validation would go here
            # For now, return a mock validation
            
            # Log session validation
            await self.audit_logger.log_event(
                event_type=AuditEventType.DATA_ACCESS,
                user_id="session_user",  # Would be extracted from token
                session_id=session_token[:8],
                source_ip=ip_address,
                user_agent="",
                resource="session",
                action="validate",
                outcome="success",
                details={"session_token_prefix": session_token[:8]},
                compliance_tags=self.config["compliance_standards"],
                risk_level="low"
            )
            
            return {
                "valid": True,
                "user_id": "session_user",
                "permissions": ["read", "write"],
                "expires_at": (datetime.now().timestamp() + 3600)
            }
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return {"valid": False, "error": str(e)}

    async def check_permissions(self, user_id: str, resource: str, action: str, 
                              ip_address: str = "") -> bool:
        """Check user permissions with security logging."""
        try:
            # Mock permission check - in production this would check actual permissions
            has_permission = True  # Simplified for demo
            
            if not has_permission:
                # Log permission denied
                security_event = create_permission_denied_event(
                    source_ip=ip_address,
                    user_id=user_id,
                    endpoint=resource,
                    details={"action": action}
                )
                await self.security_monitor.log_event(security_event)
            
            # Audit log
            await self.audit_logger.log_event(
                event_type=AuditEventType.DATA_ACCESS,
                user_id=user_id,
                session_id=None,
                source_ip=ip_address,
                user_agent="",
                resource=resource,
                action=action,
                outcome="success" if has_permission else "failure",
                details={"permission_check": True},
                compliance_tags=self.config["compliance_standards"],
                risk_level="low"
            )
            
            return has_permission
            
        except Exception as e:
            logger.error(f"Permission check error: {e}")
            return False

    async def _log_blocked_request(self, request: Request, client_ip: str):
        """Log blocked request."""
        await self.audit_logger.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            user_id=None,
            session_id=None,
            source_ip=client_ip,
            user_agent=request.headers.get("user-agent", ""),
            resource=str(request.url.path),
            action="blocked_request",
            outcome="blocked",
            details={"reason": "ip_blocked"},
            compliance_tags=self.config["compliance_standards"],
            risk_level="high"
        )

    async def _log_validation_failure(self, request: Request, parameter: str, threats: List[str]):
        """Log input validation failure."""
        await self.audit_logger.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            user_id=None,
            session_id=None,
            source_ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            resource=str(request.url.path),
            action="validation_failure",
            outcome="blocked",
            details={"parameter": parameter, "threats": threats},
            compliance_tags=self.config["compliance_standards"],
            risk_level="medium"
        )

    async def _log_successful_request(self, request: Request, response, start_time: datetime):
        """Log successful request."""
        duration = (datetime.now() - start_time).total_seconds()
        
        await self.audit_logger.log_event(
            event_type=AuditEventType.API_ACCESS,
            user_id=getattr(request.state, "user_id", None),
            session_id=getattr(request.state, "session_id", None),
            source_ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            resource=str(request.url.path),
            action=request.method,
            outcome="success",
            details={
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2)
            },
            compliance_tags=self.config["compliance_standards"],
            risk_level="low"
        )

    async def _log_system_error(self, request: Request, error: str):
        """Log system error."""
        await self.audit_logger.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            user_id=getattr(request.state, "user_id", None),
            session_id=getattr(request.state, "session_id", None),
            source_ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            resource=str(request.url.path),
            action="system_error",
            outcome="error",
            details={"error": error},
            compliance_tags=self.config["compliance_standards"],
            risk_level="medium"
        )

    async def _send_security_notification(self, alert_data: Dict[str, Any]):
        """Send security notification."""
        # Implementation would send notifications via email, Slack, etc.
        logger.warning(f"Security Alert: {alert_data}")

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        return {
            "monitoring": self.security_monitor.get_statistics(),
            "audit": self.audit_logger.get_statistics(),
            "blocked_ips": len(self.security_monitor.blocked_ips),
            "recent_incidents": len(self.security_monitor.get_recent_incidents()),
            "system_status": "operational"
        }

    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        return {
            "timestamp": datetime.now().isoformat(),
            "monitoring_stats": self.security_monitor.get_statistics(),
            "audit_stats": self.audit_logger.get_statistics(),
            "recent_incidents": [
                {
                    "incident_id": incident.incident_id,
                    "threat_level": incident.threat_level.value,
                    "description": incident.description,
                    "created_at": incident.created_at.isoformat(),
                    "status": incident.status
                }
                for incident in self.security_monitor.get_recent_incidents(10)
            ],
            "security_recommendations": self._get_security_recommendations()
        }

    def _get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on current state."""
        recommendations = []
        
        stats = self.security_monitor.get_statistics()
        
        if stats["ips_blocked"] > 10:
            recommendations.append("High number of blocked IPs detected. Consider reviewing firewall rules.")
        
        if stats["incidents_created"] > 5:
            recommendations.append("Multiple security incidents detected. Review security policies.")
        
        if not recommendations:
            recommendations.append("Security posture is good. Continue monitoring.")
        
        return recommendations


# Global integrated security system
_integrated_security = None


def get_integrated_security() -> IntegratedSecuritySystem:
    """Get the global integrated security system."""
    global _integrated_security
    return _integrated_security


def setup_integrated_security(app: FastAPI) -> IntegratedSecuritySystem:
    """Setup integrated security system for the application."""
    global _integrated_security
    _integrated_security = IntegratedSecuritySystem(app)
    return _integrated_security
