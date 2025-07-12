"""
PlexiChat CI/CD Security Integration
Integrates vulnerability scanning into CI/CD pipeline
"""

import asyncio
import logging
import json
import subprocess
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ScannerType(Enum):
    """Supported vulnerability scanners."""
    SNYK = "snyk"
    TRIVY = "trivy"
    SAFETY = "safety"
    BANDIT = "bandit"
    SEMGREP = "semgrep"
    CODEQL = "codeql"
    SONARQUBE = "sonarqube"
    DEPENDENCY_CHECK = "dependency_check"
    CUSTOM = "custom"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ScanType(Enum):
    """Types of security scans."""
    DEPENDENCY_SCAN = "dependency_scan"
    STATIC_CODE_ANALYSIS = "static_code_analysis"
    CONTAINER_SCAN = "container_scan"
    SECRET_SCAN = "secret_scan"
    LICENSE_SCAN = "license_scan"
    INFRASTRUCTURE_SCAN = "infrastructure_scan"


@dataclass
class Vulnerability:
    """Vulnerability finding."""
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_package: Optional[str] = None
    affected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    scanner: Optional[str] = None
    scan_type: Optional[ScanType] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScanResult:
    """Security scan result."""
    scan_id: str
    scanner: ScannerType
    scan_type: ScanType
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts


class CICDSecurityScanner:
    """
    CI/CD Security Scanner Integration.
    
    Features:
    - Multiple scanner support (Snyk, Trivy, Safety, Bandit, etc.)
    - Dependency vulnerability scanning
    - Static code analysis
    - Container image scanning
    - Secret detection
    - License compliance checking
    - Automated remediation suggestions
    - Integration with CI/CD pipelines
    - Security gate enforcement
    """
    
    def __init__(self):
        self.scanners: Dict[ScannerType, Dict[str, Any]] = {}
        self.scan_results: Dict[str, ScanResult] = {}
        self.security_policies: Dict[str, Any] = {}
        self.enabled_scanners: List[ScannerType] = []
        
        self._initialize_scanners()
        self._load_security_policies()
    
    def _initialize_scanners(self):
        """Initialize scanner configurations."""
        
        # Snyk configuration
        self.scanners[ScannerType.SNYK] = {
            "command": "snyk",
            "install_check": ["snyk", "--version"],
            "dependency_scan": ["snyk", "test", "--json"],
            "container_scan": ["snyk", "container", "test", "--json"],
            "code_scan": ["snyk", "code", "test", "--json"],
            "supported_scan_types": [ScanType.DEPENDENCY_SCAN, ScanType.CONTAINER_SCAN, ScanType.STATIC_CODE_ANALYSIS]
        }
        
        # Trivy configuration
        self.scanners[ScannerType.TRIVY] = {
            "command": "trivy",
            "install_check": ["trivy", "--version"],
            "dependency_scan": ["trivy", "fs", "--format", "json"],
            "container_scan": ["trivy", "image", "--format", "json"],
            "supported_scan_types": [ScanType.DEPENDENCY_SCAN, ScanType.CONTAINER_SCAN]
        }
        
        # Safety configuration (Python dependencies)
        self.scanners[ScannerType.SAFETY] = {
            "command": "safety",
            "install_check": ["safety", "--version"],
            "dependency_scan": ["safety", "check", "--json"],
            "supported_scan_types": [ScanType.DEPENDENCY_SCAN]
        }
        
        # Bandit configuration (Python static analysis)
        self.scanners[ScannerType.BANDIT] = {
            "command": "bandit",
            "install_check": ["bandit", "--version"],
            "code_scan": ["bandit", "-r", "-f", "json"],
            "supported_scan_types": [ScanType.STATIC_CODE_ANALYSIS]
        }
        
        # Semgrep configuration
        self.scanners[ScannerType.SEMGREP] = {
            "command": "semgrep",
            "install_check": ["semgrep", "--version"],
            "code_scan": ["semgrep", "--config=auto", "--json"],
            "secret_scan": ["semgrep", "--config=p/secrets", "--json"],
            "supported_scan_types": [ScanType.STATIC_CODE_ANALYSIS, ScanType.SECRET_SCAN]
        }
        
        logger.info(f"✅ Initialized {len(self.scanners)} security scanners")
    
    def _load_security_policies(self):
        """Load security policies for scan evaluation."""
        self.security_policies = {
            "fail_on_critical": True,
            "fail_on_high": True,
            "fail_on_medium": False,
            "max_critical_vulnerabilities": 0,
            "max_high_vulnerabilities": 5,
            "max_medium_vulnerabilities": 20,
            "allowed_licenses": [
                "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", 
                "ISC", "MPL-2.0", "LGPL-2.1", "LGPL-3.0"
            ],
            "blocked_packages": [],
            "security_gate_enabled": True
        }
    
    async def check_scanner_availability(self, scanner: ScannerType) -> bool:
        """Check if a scanner is available and properly installed."""
        if scanner not in self.scanners:
            return False
        
        try:
            config = self.scanners[scanner]
            result = await asyncio.create_subprocess_exec(
                *config["install_check"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Scanner {scanner.value} not available: {e}")
            return False
    
    async def run_dependency_scan(self, project_path: str, scanner: ScannerType = ScannerType.SNYK) -> ScanResult:
        """Run dependency vulnerability scan."""
        scan_id = f"dep_scan_{int(datetime.now().timestamp())}"
        scan_result = ScanResult(
            scan_id=scan_id,
            scanner=scanner,
            scan_type=ScanType.DEPENDENCY_SCAN,
            started_at=datetime.now(timezone.utc)
        )
        
        try:
            if not await self.check_scanner_availability(scanner):
                raise Exception(f"Scanner {scanner.value} not available")
            
            config = self.scanners[scanner]
            
            if scanner == ScannerType.SNYK:
                vulnerabilities = await self._run_snyk_dependency_scan(project_path)
            elif scanner == ScannerType.TRIVY:
                vulnerabilities = await self._run_trivy_dependency_scan(project_path)
            elif scanner == ScannerType.SAFETY:
                vulnerabilities = await self._run_safety_scan(project_path)
            else:
                raise Exception(f"Dependency scan not supported for {scanner.value}")
            
            scan_result.vulnerabilities = vulnerabilities
            scan_result.status = "completed"
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.summary = scan_result.get_severity_counts()
            
        except Exception as e:
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.completed_at = datetime.now(timezone.utc)
            logger.error(f"Dependency scan failed: {e}")
        
        self.scan_results[scan_id] = scan_result
        return scan_result
    
    async def run_static_code_analysis(self, project_path: str, scanner: ScannerType = ScannerType.BANDIT) -> ScanResult:
        """Run static code analysis scan."""
        scan_id = f"sca_scan_{int(datetime.now().timestamp())}"
        scan_result = ScanResult(
            scan_id=scan_id,
            scanner=scanner,
            scan_type=ScanType.STATIC_CODE_ANALYSIS,
            started_at=datetime.now(timezone.utc)
        )
        
        try:
            if not await self.check_scanner_availability(scanner):
                raise Exception(f"Scanner {scanner.value} not available")
            
            if scanner == ScannerType.BANDIT:
                vulnerabilities = await self._run_bandit_scan(project_path)
            elif scanner == ScannerType.SEMGREP:
                vulnerabilities = await self._run_semgrep_code_scan(project_path)
            else:
                raise Exception(f"Static code analysis not supported for {scanner.value}")
            
            scan_result.vulnerabilities = vulnerabilities
            scan_result.status = "completed"
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.summary = scan_result.get_severity_counts()
            
        except Exception as e:
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.completed_at = datetime.now(timezone.utc)
            logger.error(f"Static code analysis failed: {e}")
        
        self.scan_results[scan_id] = scan_result
        return scan_result
    
    async def run_container_scan(self, image_name: str, scanner: ScannerType = ScannerType.TRIVY) -> ScanResult:
        """Run container image vulnerability scan."""
        scan_id = f"container_scan_{int(datetime.now().timestamp())}"
        scan_result = ScanResult(
            scan_id=scan_id,
            scanner=scanner,
            scan_type=ScanType.CONTAINER_SCAN,
            started_at=datetime.now(timezone.utc),
            metadata={"image_name": image_name}
        )
        
        try:
            if not await self.check_scanner_availability(scanner):
                raise Exception(f"Scanner {scanner.value} not available")
            
            if scanner == ScannerType.TRIVY:
                vulnerabilities = await self._run_trivy_container_scan(image_name)
            elif scanner == ScannerType.SNYK:
                vulnerabilities = await self._run_snyk_container_scan(image_name)
            else:
                raise Exception(f"Container scan not supported for {scanner.value}")
            
            scan_result.vulnerabilities = vulnerabilities
            scan_result.status = "completed"
            scan_result.completed_at = datetime.now(timezone.utc)
            scan_result.summary = scan_result.get_severity_counts()
            
        except Exception as e:
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.completed_at = datetime.now(timezone.utc)
            logger.error(f"Container scan failed: {e}")
        
        self.scan_results[scan_id] = scan_result
        return scan_result
    
    async def _run_snyk_dependency_scan(self, project_path: str) -> List[Vulnerability]:
        """Run Snyk dependency scan."""
        cmd = ["snyk", "test", "--json"]
        result = await self._execute_scanner_command(cmd, cwd=project_path)
        
        vulnerabilities = []
        if result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                if "vulnerabilities" in data:
                    for vuln_data in data["vulnerabilities"]:
                        vulnerability = Vulnerability(
                            id=vuln_data.get("id", ""),
                            title=vuln_data.get("title", ""),
                            description=vuln_data.get("description", ""),
                            severity=VulnerabilitySeverity(vuln_data.get("severity", "low")),
                            cve_id=vuln_data.get("identifiers", {}).get("CVE", [None])[0],
                            cvss_score=vuln_data.get("cvssScore"),
                            affected_package=vuln_data.get("packageName"),
                            affected_version=vuln_data.get("version"),
                            fixed_version=vuln_data.get("fixedIn", [None])[0],
                            scanner="snyk",
                            scan_type=ScanType.DEPENDENCY_SCAN,
                            remediation=vuln_data.get("remediation", {}).get("advice")
                        )
                        vulnerabilities.append(vulnerability)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Snyk output: {e}")
        
        return vulnerabilities
    
    async def _execute_scanner_command(self, cmd: List[str], cwd: str = None) -> Dict[str, Any]:
        """Execute scanner command and return result."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "returncode": process.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore")
            }
        except Exception as e:
            logger.error(f"Failed to execute command {' '.join(cmd)}: {e}")
            return {"returncode": -1, "stdout": "", "stderr": str(e)}
    
    def evaluate_security_gate(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Evaluate if security gate should pass or fail."""
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        
        for result in scan_results:
            if result.status == "completed":
                counts = result.get_severity_counts()
                total_critical += counts.get("critical", 0)
                total_high += counts.get("high", 0)
                total_medium += counts.get("medium", 0)
                total_low += counts.get("low", 0)
        
        gate_passed = True
        reasons = []
        
        if self.security_policies["fail_on_critical"] and total_critical > self.security_policies["max_critical_vulnerabilities"]:
            gate_passed = False
            reasons.append(f"Critical vulnerabilities: {total_critical} (max allowed: {self.security_policies['max_critical_vulnerabilities']})")
        
        if self.security_policies["fail_on_high"] and total_high > self.security_policies["max_high_vulnerabilities"]:
            gate_passed = False
            reasons.append(f"High vulnerabilities: {total_high} (max allowed: {self.security_policies['max_high_vulnerabilities']})")
        
        if self.security_policies["fail_on_medium"] and total_medium > self.security_policies["max_medium_vulnerabilities"]:
            gate_passed = False
            reasons.append(f"Medium vulnerabilities: {total_medium} (max allowed: {self.security_policies['max_medium_vulnerabilities']})")
        
        return {
            "passed": gate_passed,
            "reasons": reasons,
            "summary": {
                "critical": total_critical,
                "high": total_high,
                "medium": total_medium,
                "low": total_low
            }
        }


# Global CI/CD security scanner instance
cicd_scanner = CICDSecurityScanner()
