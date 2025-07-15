import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


"""
PlexiChat Bug Bounty Program Management
Manages vulnerability reports, rewards, and researcher coordination
"""

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""

    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    CSRF = "cross_site_request_forgery"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    LOCAL_FILE_INCLUSION = "local_file_inclusion"
    REMOTE_FILE_INCLUSION = "remote_file_inclusion"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    BUSINESS_LOGIC_FLAW = "business_logic_flaw"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_MANAGEMENT = "session_management"
    INPUT_VALIDATION = "input_validation"
    CONFIGURATION_ERROR = "configuration_error"
    OTHER = "other"


class SeverityLevel(Enum):
    """CVSS-based severity levels."""

    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"  # 7.0-8.9
    MEDIUM = "medium"  # 4.0-6.9
    LOW = "low"  # 0.1-3.9
    INFORMATIONAL = "informational"  # 0.0


class ReportStatus(Enum):
    """Bug report status."""

    SUBMITTED = "submitted"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"
    REWARDED = "rewarded"


@dataclass
class VulnerabilityReport:
    """Vulnerability report structure."""

    report_id: str
    researcher_email: str
    researcher_name: str
    title: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    cvss_score: float
    affected_components: List[str]
    proof_of_concept: str
    steps_to_reproduce: List[str]
    impact_description: str
    suggested_fix: str
    status: ReportStatus = ReportStatus.SUBMITTED
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    reward_amount: Optional[float] = None
    internal_notes: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "report_id": self.report_id,
            "researcher_email": self.researcher_email,
            "researcher_name": self.researcher_name,
            "title": self.title,
            "description": self.description,
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "affected_components": self.affected_components,
            "proof_of_concept": self.proof_of_concept,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact_description": self.impact_description,
            "suggested_fix": self.suggested_fix,
            "status": self.status.value,
            "submitted_at": self.submitted_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "reward_amount": self.reward_amount,
            "internal_notes": self.internal_notes,
            "attachments": self.attachments,
        }


@dataclass
class BugBountyProgram:
    """Bug bounty program configuration."""

    program_name: str = "PlexiChat Security Research Program"
    program_description: str = (
        "Help us keep PlexiChat secure by reporting vulnerabilities"
    )
    is_active: bool = True
    max_reward: float = 10000.0
    min_reward: float = 100.0

    # Reward structure based on severity
    reward_structure: Dict[SeverityLevel, Dict[str, float]] = field(
        default_factory=lambda: {
            SeverityLevel.CRITICAL: {"min": 5000.0, "max": 10000.0},
            SeverityLevel.HIGH: {"min": 2000.0, "max": 5000.0},
            SeverityLevel.MEDIUM: {"min": 500.0, "max": 2000.0},
            SeverityLevel.LOW: {"min": 100.0, "max": 500.0},
            SeverityLevel.INFORMATIONAL: {"min": 0.0, "max": 100.0},
        }
    )

    # Scope definition
    in_scope: List[str] = field(
        default_factory=lambda: [
            "*.plexichat.com",
            "plexichat.com",
            "api.plexichat.com",
            "app.plexichat.com",
            "admin.plexichat.com",
        ]
    )

    out_of_scope: List[str] = field(
        default_factory=lambda: [
            "Social engineering attacks",
            "Physical attacks",
            "Denial of Service attacks",
            "Spam or content injection",
            "Issues requiring physical access",
            "Third-party services not controlled by PlexiChat",
        ]
    )

    # Program rules
    rules: List[str] = field(
        default_factory=lambda: [
            "Only test against your own accounts",
            "Do not access or modify other users' data",
            "Do not perform attacks that could harm availability",
            "Report vulnerabilities as soon as possible",
            "Do not publicly disclose vulnerabilities before resolution",
            "Provide clear reproduction steps",
            "One vulnerability per report",
            "Be respectful and professional",
        ]
    )


class BugBountyManager:
    """
    Bug Bounty Program Manager.

    Features:
    - Vulnerability report management
    - Automated severity assessment
    - Reward calculation
    - Researcher communication
    - Integration with security team workflows
    - Duplicate detection
    - Statistics and reporting
    """

    def __init__(self):
        self.program = BugBountyProgram()
        self.reports: Dict[str, VulnerabilityReport] = {}
        self.researchers: Dict[str, Dict[str, Any]] = {}
        self.statistics = {
            "total_reports": 0,
            "resolved_reports": 0,
            "total_rewards_paid": 0.0,
            "average_resolution_time": 0.0,
            "top_researchers": [],
            "vulnerability_trends": {},
        }

    def submit_report(
        self,
        researcher_email: str,
        researcher_name: str,
        title: str,
        description: str,
        vulnerability_type: VulnerabilityType,
        severity: SeverityLevel,
        cvss_score: float,
        affected_components: List[str],
        proof_of_concept: str,
        steps_to_reproduce: List[str],
        impact_description: str,
        suggested_fix: str = "",
        attachments: Optional[List[str]] = None,
    ) -> str:
        """Submit a new vulnerability report."""

        report_id = str(uuid.uuid4())

        report = VulnerabilityReport(
            report_id=report_id,
            researcher_email=researcher_email,
            researcher_name=researcher_name,
            title=title,
            description=description,
            vulnerability_type=vulnerability_type,
            severity=severity,
            cvss_score=cvss_score,
            affected_components=affected_components,
            proof_of_concept=proof_of_concept,
            steps_to_reproduce=steps_to_reproduce,
            impact_description=impact_description,
            suggested_fix=suggested_fix,
            attachments=attachments or [],
        )

        self.reports[report_id] = report
        self.statistics["total_reports"] += 1

        # Update researcher profile
        if researcher_email not in self.researchers:
            self.researchers[researcher_email] = {
                "name": researcher_name,
                "email": researcher_email,
                "reports_submitted": 0,
                "reports_confirmed": 0,
                "total_rewards": 0.0,
                "first_report": datetime.now(timezone.utc),
                "last_report": datetime.now(timezone.utc),
            }

        self.researchers[researcher_email]["reports_submitted"] += 1
        self.researchers[researcher_email]["last_report"] = datetime.now(timezone.utc)

        logger.info(
            f" New vulnerability report submitted: {report_id} by {researcher_name}"
        )

        # Auto-triage based on severity
        if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            self._auto_escalate_report(report_id)

        return report_id

    def update_report_status(
        self, report_id: str, status: ReportStatus, notes: str = ""
    ) -> bool:
        """Update report status."""
        if report_id not in self.reports:
            return False

        report = self.reports[report_id]
        old_status = report.status
        report.status = status
        report.updated_at = datetime.now(timezone.utc)

        if notes:
            report.internal_notes.append(
                f"{datetime.now(timezone.utc).isoformat()}: {notes}"
            )

        # Handle status-specific actions
        if status == ReportStatus.RESOLVED:
            report.resolved_at = datetime.now(timezone.utc)
            self.statistics["resolved_reports"] += 1

            # Calculate reward
            reward = self._calculate_reward(report)
            if reward > 0:
                report.reward_amount = reward
                self.researchers[report.researcher_email]["total_rewards"] += reward
                self.statistics["total_rewards_paid"] += reward

        elif status == ReportStatus.CONFIRMED and old_status != ReportStatus.CONFIRMED:
            self.researchers[report.researcher_email]["reports_confirmed"] += 1

        logger.info(
            f" Report {report_id} status updated: {old_status.value} -> {status.value}"
        )
        return True

    def _calculate_reward(self, report: VulnerabilityReport) -> float:
        """Calculate reward amount based on severity and impact."""
        if report.severity not in self.program.reward_structure:
            return 0.0

        reward_range = self.program.reward_structure[report.severity]
        base_reward = (reward_range["min"] + reward_range["max"]) / 2

        # Adjust based on CVSS score within severity range
        if report.severity == SeverityLevel.CRITICAL and report.cvss_score >= 9.5:
            return reward_range["max"]
        elif report.severity == SeverityLevel.HIGH and report.cvss_score >= 8.5:
            return base_reward * 1.2
        elif report.severity == SeverityLevel.MEDIUM and report.cvss_score >= 6.0:
            return base_reward * 1.1

        return base_reward

    def _auto_escalate_report(self, report_id: str):
        """Auto-escalate high-severity reports."""
        report = self.reports[report_id]
        report.status = ReportStatus.TRIAGING
        report.internal_notes.append(
            f"{datetime.now(timezone.utc).isoformat()}: Auto-escalated due to {report.severity.value} severity"
        )
        logger.warning(f" High-severity report auto-escalated: {report_id}")

    def get_program_info(self) -> Dict[str, Any]:
        """Get public program information."""
        return {
            "program_name": self.program.program_name,
            "program_description": self.program.program_description,
            "is_active": self.program.is_active,
            "reward_structure": {
                severity.value: {
                    "min_reward": rewards["min"],
                    "max_reward": rewards["max"],
                }
                for severity, rewards in self.program.reward_structure.items()
            },
            "scope": {
                "in_scope": self.program.in_scope,
                "out_of_scope": self.program.out_of_scope,
            },
            "rules": self.program.rules,
            "statistics": {
                "total_reports": self.statistics["total_reports"],
                "resolved_reports": self.statistics["resolved_reports"],
                "total_rewards_paid": self.statistics["total_rewards_paid"],
            },
        }


# Global bug bounty manager instance
bug_bounty_manager = BugBountyManager()
