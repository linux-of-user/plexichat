import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from .bug_bounty import SeverityLevel, VulnerabilityType, bug_bounty_manager
from .cicd_security import cicd_scanner
from .csp import csp_manager
from .security_headers import security_headers_manager
from .siem_integration import EventCategory, EventSeverity, SecurityEvent, siem_integration
from .waf import waf

from datetime import datetime
from datetime import datetime
from datetime import datetime


from datetime import datetime
from datetime import datetime
from datetime import datetime

from fastapi import Request
from fastapi.responses import JSONResponse

"""
PlexiChat Phase I Security Integration
Integrates all Phase I security enhancements into a unified system
"""

logger = logging.getLogger(__name__)


class Phase1SecurityCoordinator:
    """
    Phase I Security Coordinator.

    Integrates all Phase I security enhancements:
    1. Web Application Firewall (WAF)
    2. Content Security Policy (CSP)
    3. Bug Bounty Program
    4. SIEM Integration
    5. Advanced Security Headers
    6. CI/CD Vulnerability Scanning
    """

    def __init__(self):
        self.enabled = True
        self.components = {
            "waf": True,
            "csp": True,
            "bug_bounty": True,
            "siem": True,
            "security_headers": True,
            "cicd_scanning": True
        }

        self.statistics = {
            "requests_processed": 0,
            "threats_blocked": 0,
            "vulnerabilities_reported": 0,
            "security_events_sent": 0,
            "last_security_scan": None
        }

        self._initialize_components()

    def _initialize_components(self):
        """Initialize all Phase I security components."""
        try:
            # Initialize SIEM integration
            if self.components["siem"]:
                asyncio.create_task(self._initialize_siem())

            # Set security headers to strict mode
            if self.components["security_headers"]:
                security_headers_manager.set_security_level("strict")

            # Set CSP to production mode
            if self.components["csp"]:
                csp_manager.active_policy = "production"

            logger.info(" Phase I Security Coordinator initialized")

        except Exception as e:
            logger.error(f" Failed to initialize Phase I security components: {e}")

    async def _initialize_siem(self):
        """Initialize SIEM integration with default providers."""
        try:
            # Start SIEM integration service
            await if siem_integration and hasattr(siem_integration, "start"): siem_integration.start()

            # Send initialization event
            init_event = SecurityEvent(
                event_id=f"phase1_init_{int(from datetime import datetime
datetime = datetime.now().timestamp())}",
                timestamp=datetime.now(timezone.utc),
                source_system="plexichat_security",
                event_type="SECURITY_SYSTEM_INIT",
                category=EventCategory.SYSTEM_MONITORING,
                severity=EventSeverity.INFORMATIONAL,
                title="Phase I Security System Initialized",
                description="All Phase I security enhancements have been successfully initialized"
            )

            await siem_integration.send_event(init_event)

        except Exception as e:
            logger.error(f"Failed to initialize SIEM: {e}")

    async def process_request(self, request: Request) -> Dict[str, Any]:
        """Process incoming request through all Phase I security layers."""
        if not self.enabled:
            return {"allowed": True, "components_checked": []}

        self.statistics["requests_processed"] += 1
        security_results = {
            "allowed": True,
            "components_checked": [],
            "violations": [],
            "security_events": []
        }

        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_path = str(request.url.path)

        # 1. WAF Analysis
        if self.components["waf"]:
            try:
                waf_allowed, waf_violation = await waf.analyze_request(request)
                security_results["components_checked"].append("waf")

                if not waf_allowed and waf_violation:
                    security_results["allowed"] = False
                    security_results["violations"].append({
                        "component": "waf",
                        "rule_id": waf_violation.rule_id,
                        "description": waf_violation.description,
                        "severity": waf_violation.severity
                    })

                    self.statistics["threats_blocked"] += 1

                    # Create SIEM event for WAF violation
                    if self.components["siem"]:
                        waf_event = SecurityEvent(
                            event_id=f"waf_violation_{int(from datetime import datetime
datetime = datetime.now().timestamp())}",
                            timestamp=datetime.now(timezone.utc),
                            source_system="plexichat_waf",
                            event_type="WAF_VIOLATION",
                            category=EventCategory.APPLICATION_SECURITY,
                            severity=EventSeverity.HIGH if waf_violation.severity >= 8 else EventSeverity.MEDIUM,
                            title=f"WAF Rule Violation: {waf_violation.rule_id}",
                            description=waf_violation.description,
                            source_ip=client_ip,
                            user_agent=user_agent,
                            request_path=request_path
                        )
                        security_results["security_events"].append(waf_event)

            except Exception as e:
                logger.error(f"WAF analysis failed: {e}")

        # 2. Additional security checks can be added here
        # (Rate limiting, behavioral analysis, etc.)

        # Send security events to SIEM
        if self.components["siem"] and security_results["security_events"]:
            for event in security_results["security_events"]:
                await siem_integration.send_event(event, immediate=True)
                self.statistics["security_events_sent"] += 1

        return security_results

    def generate_security_headers(self,
                                 request: Request,
                                 session_id: Optional[str] = None) -> Dict[str, str]:
        """Generate comprehensive security headers for response."""
        headers = {}

        if not self.components["security_headers"]:
            return headers

        try:
            # Get path-specific security requirements
            request_path = str(request.url.path)
            is_secure_page = (
                request_path.startswith("/admin") or
                request_path.startswith("/api/v1/auth") or
                request_path.startswith("/api/v1/admin")
            )

            # Get security headers
            security_headers = security_headers_manager.get_headers_for_response(
                path=request_path,
                is_secure_page=is_secure_page
            )
            headers.update(security_headers)

            # Get CSP headers
            if self.components["csp"]:
                csp_headers = csp_manager.get_csp_header(session_id)
                headers.update(csp_headers)

        except Exception as e:
            logger.error(f"Failed to generate security headers: {e}")

        return headers

    async def handle_vulnerability_report(self, report_data: Dict[str, Any]) -> str:
        """Handle incoming vulnerability report through bug bounty program."""
        if not self.components["bug_bounty"]:
            raise Exception("Bug bounty program is disabled")

        try:
            report_id = bug_bounty_manager.submit_report(
                researcher_email=report_data["researcher_email"],
                researcher_name=report_data["researcher_name"],
                title=report_data["title"],
                description=report_data["description"],
                vulnerability_type=VulnerabilityType(report_data["vulnerability_type"]),
                severity=SeverityLevel(report_data["severity"]),
                cvss_score=report_data.get("cvss_score", 0.0),
                affected_components=report_data.get("affected_components", []),
                proof_of_concept=report_data.get("proof_of_concept", ""),
                steps_to_reproduce=report_data.get("steps_to_reproduce", []),
                impact_description=report_data.get("impact_description", ""),
                suggested_fix=report_data.get("suggested_fix", ""),
                attachments=report_data.get("attachments", [])
            )

            self.statistics["vulnerabilities_reported"] += 1

            # Send SIEM event for vulnerability report
            if self.components["siem"]:
                vuln_event = SecurityEvent(
                    event_id=f"vuln_report_{report_id}",
                    timestamp=datetime.now(timezone.utc),
                    source_system="plexichat_bugbounty",
                    event_type="VULNERABILITY_REPORTED",
                    category=EventCategory.VULNERABILITY,
                    severity=EventSeverity.HIGH,
                    title=f"New Vulnerability Report: {report_data['title']}",
                    description=f"Vulnerability reported by {report_data['researcher_name']}",
                    user_id=report_data["researcher_email"]
                )
                await siem_integration.send_event(vuln_event)

            return report_id

        except Exception as e:
            logger.error(f"Failed to handle vulnerability report: {e}")
            raise

    async def run_security_scan(self, scan_type: str = "full") -> Dict[str, Any]:
        """Run comprehensive security scan."""
        if not self.components["cicd_scanning"]:
            return {"error": "CI/CD scanning is disabled"}

        try:
            scan_results = []

            # Run dependency scan
            if scan_type in ["full", "dependencies"]:
                dep_scan = await cicd_scanner.run_dependency_scan(".")
                scan_results.append(dep_scan)

            # Run static code analysis
            if scan_type in ["full", "code"]:
                code_scan = await cicd_scanner.run_static_code_analysis(".")
                scan_results.append(code_scan)

            # Evaluate security gate
            gate_result = cicd_scanner.evaluate_security_gate(scan_results)

            self.statistics["last_security_scan"] = datetime.now(timezone.utc)

            # Send SIEM event for security scan
            if self.components["siem"]:
                scan_event = SecurityEvent(
                    event_id=f"security_scan_{int(from datetime import datetime
datetime = datetime.now().timestamp())}",
                    timestamp=datetime.now(timezone.utc),
                    source_system="plexichat_scanner",
                    event_type="SECURITY_SCAN_COMPLETED",
                    category=EventCategory.VULNERABILITY,
                    severity=EventSeverity.CRITICAL if not gate_result["passed"] else EventSeverity.INFORMATIONAL,
                    title=f"Security Scan Completed: {scan_type}",
                    description=f"Security gate {'PASSED' if gate_result['passed'] else 'FAILED'}"
                )
                await siem_integration.send_event(scan_event)

            return {
                "scan_results": [
                    {
                        "scan_id": result.scan_id,
                        "scanner": result.scanner.value,
                        "scan_type": result.scan_type.value,
                        "status": result.status,
                        "vulnerability_count": len(result.vulnerabilities),
                        "severity_counts": result.get_severity_counts()
                    }
                    for result in scan_results
                ],
                "security_gate": gate_result
            }

        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            return {"error": str(e)}

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        return {
            "phase1_enabled": self.enabled,
            "components": self.components,
            "statistics": self.statistics,
            "waf_stats": waf.get_statistics() if self.components["waf"] else None,
            "bug_bounty_info": bug_bounty_manager.get_program_info() if self.components["bug_bounty"] else None,
            "siem_stats": siem_integration.get_statistics() if self.components["siem"] else None,
            "security_level": security_headers_manager.security_level if self.components["security_headers"] else None,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

    async def shutdown(self):
        """Shutdown Phase I security components."""
        try:
            if self.components["siem"]:
                await if siem_integration and hasattr(siem_integration, "stop"): siem_integration.stop()

            logger.info(" Phase I Security Coordinator shutdown complete")

        except Exception as e:
            logger.error(f"Error during Phase I security shutdown: {e}")


# Global Phase I security coordinator
phase1_security = Phase1SecurityCoordinator()


async def phase1_security_middleware(request: Request, call_next):
    """Phase I security middleware for FastAPI."""
    try:
        # Process request through security layers
        security_result = await phase1_security.process_request(request)

        # Block request if not allowed
        if not security_result["allowed"]:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by security system",
                    "violations": security_result["violations"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

        # Process request normally
        response = await call_next(request)

        # Add security headers
        session_id = request.headers.get("x-session-id")
        security_headers = phase1_security.generate_security_headers(request, session_id)

        for header_name, header_value in security_headers.items():
            response.headers[header_name] = header_value

        return response

    except Exception as e:
        logger.error(f"Phase I security middleware error: {e}")
        # Fail open - allow request to proceed
        return await call_next(request)
