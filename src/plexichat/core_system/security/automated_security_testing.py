import asyncio
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import requests

from ...core_system.config import get_config
from ...core_system.logging import get_logger
from .unified_audit_system import (
    CI/CD,
    CONSOLIDATED,
    ENHANCED,
    INTEGRATED,
    OF,
    SINGLE,
    SOURCE,
    TRUTH,
    Automated,
    Comprehensive,
    Continuous,
    Features:,
    Integration,
    PlexiChat,
    Real-time,
    Security,
    SecurityEventType,
    SecuritySeverity,
    System,
    Testing,
    ThreatLevel,
    Zero-trust,
    """,
    -,
    and,
    architecture,
    commit,
    every,
    features/security/core/penetration_testing.py,
    features/security/core/vulnerability_scanner.py,
    features/security/penetration_tester.py,
    from:,
    generation,
    get_unified_audit_system,
    import,
    integration,
    monitoring,
    on,
    penetration,
    pipeline,
    report,
    scanning,
    security,
    socket,
    ssl,
    testing,
    unified,
    validation,
    verification,
    vulnerability,
    with,
)

logger = get_logger(__name__)


class TestCategory(Enum):
    """Security test categories."""
    NETWORK_SCAN = "network_scan"
    WEB_APPLICATION = "web_application"
    API_SECURITY = "api_security"
    AUTHENTICATION = "authentication"
    INPUT_VALIDATION = "input_validation"
    SESSION_MANAGEMENT = "session_management"
    ENCRYPTION = "encryption"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"
    DEPENDENCY_SCAN = "dependency_scan"
    INFRASTRUCTURE = "infrastructure"
    SOCIAL_ENGINEERING = "social_engineering"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class TestStatus(Enum):
    """Security test status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SecurityVulnerability:
    """Security vulnerability found during testing."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: TestCategory
    affected_component: str
    proof_of_concept: str
    remediation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "affected_component": self.affected_component,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "discovered_at": self.discovered_at.isoformat(),
            "verified": self.verified,
            "false_positive": self.false_positive
        }


@dataclass
class SecurityTestResult:
    """Security test execution result."""
    test_id: str
    test_category: TestCategory
    target: str
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[SecurityVulnerability] = field(default_factory=list)
    test_config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[float]:
        """Get test duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def critical_count(self) -> int:
        """Get count of critical vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL])
    
    @property
    def high_count(self) -> int:
        """Get count of high severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "test_id": self.test_id,
            "test_category": self.test_category.value,
            "target": self.target,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "vulnerability_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                "low": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW]),
                "info": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.INFO])
            },
            "test_config": self.test_config,
            "metadata": self.metadata
        }


class AutomatedSecurityTester:
    """
    Automated Security Testing System - Single Source of Truth
    
    Provides comprehensive automated security testing for CI/CD integration.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        plexi_config = get_config()
        self.config = config or getattr(plexi_config, "security_testing", {})
        self.initialized = False
        
        # Test configuration
        self.base_url = self.config.get("base_url", "http://localhost:8000")
        self.max_concurrent_tests = self.config.get("max_concurrent_tests", 5)
        self.test_timeout = self.config.get("test_timeout", 300)  # 5 minutes
        
        # Test results storage
        self.test_results: Dict[str, SecurityTestResult] = {}
        self.active_tests: Set[str] = set()
        
        # Security components
        self.audit_system = get_unified_audit_system()
        
        # Test payloads and patterns
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "1' AND 1=1 --",
            "admin'--",
            "' OR 1=1#",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        self.command_injection_payloads = [
            "; ls -la",
            "| whoami",
            "&& dir",
            "; cat /etc/passwd",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "`id`",
            "$(whoami)"
        ]
        
        # Statistics
        self.statistics = {
            "total_tests": 0,
            "completed_tests": 0,
            "failed_tests": 0,
            "vulnerabilities_found": 0,
            "critical_vulnerabilities": 0,
            "false_positives": 0,
            "last_test_run": None
        }
        
        logger.info("Automated Security Testing System initialized")
    
    async def initialize(self) -> bool:
        """Initialize the automated security testing system."""
        try:
            # Initialize test database/storage
            await self._initialize_test_storage()
            
            # Load previous test results
            await self._load_test_history()
            
            # Start background monitoring
            asyncio.create_task(self._test_monitor())
            
            self.initialized = True
            logger.info(" Automated Security Testing System fully initialized")
            return True
            
        except Exception as e:
            logger.error(f" Security Testing initialization failed: {e}")
            return False
    
    async def run_ci_cd_security_tests(self, 
                                      commit_hash: str,
                                      branch: str = "main",
                                      test_categories: Optional[List[TestCategory]] = None) -> str:
        """Run automated security tests for CI/CD pipeline."""
        test_id = f"cicd_{commit_hash[:8]}_{int(time.time())}"
        
        if len(self.active_tests) >= self.max_concurrent_tests:
            raise Exception("Maximum concurrent tests reached")
        
        self.active_tests.add(test_id)
        
        try:
            # Log test start
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
                f"CI/CD security tests started for commit {commit_hash}",
                SecuritySeverity.INFO,
                ThreatLevel.LOW,
                user_id="ci_cd_system",
                resource="security_testing",
                details={
                    "commit_hash": commit_hash,
                    "branch": branch,
                    "test_categories": [cat.value for cat in test_categories] if test_categories else "all"
                }
            )
            
            # Default test categories for CI/CD
            if not test_categories:
                test_categories = [
                    TestCategory.API_SECURITY,
                    TestCategory.AUTHENTICATION,
                    TestCategory.INPUT_VALIDATION,
                    TestCategory.DEPENDENCY_SCAN,
                    TestCategory.CONFIGURATION
                ]
            
            # Run tests in parallel
            test_tasks = []
            for category in test_categories:
                task = asyncio.create_task(self._run_test_category(test_id, category))
                test_tasks.append(task)
            
            # Wait for all tests to complete
            results = await asyncio.gather(*test_tasks, return_exceptions=True)
            
            # Aggregate results
            all_vulnerabilities = []
            for result in results:
                if isinstance(result, list):
                    all_vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Test category failed: {result}")
            
            # Create comprehensive test result
            test_result = SecurityTestResult(
                test_id=test_id,
                test_category=TestCategory.COMPLIANCE,  # Overall compliance test
                target=self.base_url,
                status=TestStatus.COMPLETED,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                vulnerabilities=all_vulnerabilities,
                test_config={
                    "commit_hash": commit_hash,
                    "branch": branch,
                    "test_categories": [cat.value for cat in test_categories]
                },
                metadata={
                    "ci_cd_run": True,
                    "automated": True
                }
            )
            
            self.test_results[test_id] = test_result
            self.statistics["total_tests"] += 1
            self.statistics["completed_tests"] += 1
            self.statistics["vulnerabilities_found"] += len(all_vulnerabilities)
            self.statistics["critical_vulnerabilities"] += test_result.critical_count
            self.statistics["last_test_run"] = datetime.now(timezone.utc).isoformat()
            
            # Log test completion
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
                f"CI/CD security tests completed for commit {commit_hash}",
                SecuritySeverity.WARNING if test_result.critical_count > 0 else SecuritySeverity.INFO,
                ThreatLevel.HIGH if test_result.critical_count > 0 else ThreatLevel.LOW,
                user_id="ci_cd_system",
                resource="security_testing",
                details={
                    "test_id": test_id,
                    "vulnerabilities_found": len(all_vulnerabilities),
                    "critical_vulnerabilities": test_result.critical_count,
                    "test_duration": test_result.duration
                }
            )
            
            # Fail CI/CD if critical vulnerabilities found
            if test_result.critical_count > 0:
                logger.critical(f" CI/CD SECURITY FAILURE: {test_result.critical_count} critical vulnerabilities found")
                
                # Log critical security failure
                self.audit_system.log_security_event(
                    SecurityEventType.SECURITY_ALERT,
                    "CI/CD pipeline blocked due to critical security vulnerabilities",
                    SecuritySeverity.CRITICAL,
                    ThreatLevel.CRITICAL,
                    user_id="ci_cd_system",
                    resource="security_testing",
                    details={
                        "test_id": test_id,
                        "critical_vulnerabilities": test_result.critical_count,
                        "commit_hash": commit_hash
                    }
                )
            
            return test_id
            
        except Exception as e:
            logger.error(f"CI/CD security test failed: {e}")
            self.statistics["failed_tests"] += 1
            
            # Log test failure
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                f"CI/CD security test system failure: {str(e)}",
                SecuritySeverity.ERROR,
                ThreatLevel.HIGH,
                user_id="ci_cd_system",
                resource="security_testing",
                details={"error": str(e), "commit_hash": commit_hash}
            )
            
            raise
        
        finally:
            self.active_tests.discard(test_id)

    async def _run_test_category(self, test_id: str, category: TestCategory) -> List[SecurityVulnerability]:
        """Run tests for a specific category."""
        vulnerabilities = []

        try:
            if category == TestCategory.API_SECURITY:
                vulnerabilities.extend(await self._test_api_security())
            elif category == TestCategory.AUTHENTICATION:
                vulnerabilities.extend(await self._test_authentication())
            elif category == TestCategory.INPUT_VALIDATION:
                vulnerabilities.extend(await self._test_input_validation())
            elif category == TestCategory.DEPENDENCY_SCAN:
                vulnerabilities.extend(await self._test_dependencies())
            elif category == TestCategory.CONFIGURATION:
                vulnerabilities.extend(await self._test_configuration())
            elif category == TestCategory.WEB_APPLICATION:
                vulnerabilities.extend(await self._test_web_application())
            elif category == TestCategory.ENCRYPTION:
                vulnerabilities.extend(await self._test_encryption())

        except Exception as e:
            logger.error(f"Test category {category.value} failed: {e}")

        return vulnerabilities

    async def _test_api_security(self) -> List[SecurityVulnerability]:
        """Test API security vulnerabilities."""
        vulnerabilities = []

        # Test common API endpoints
        api_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/users/profile",
            "/api/v1/admin/users",
            "/api/v1/system/config",
            "/api/v1/system/backup"
        ]

        for endpoint in api_endpoints:
            try:
                # Test SQL injection
                for payload in self.sql_injection_payloads:
                    vuln = await self._test_sql_injection(endpoint, payload)
                    if vuln:
                        vulnerabilities.append(vuln)

                # Test authentication bypass
                vuln = await self._test_auth_bypass(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

                # Test rate limiting
                vuln = await self._test_rate_limiting(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)

            except Exception as e:
                logger.error(f"API security test failed for {endpoint}: {e}")

        return vulnerabilities

    async def _test_sql_injection(self, endpoint: str, payload: str) -> Optional[SecurityVulnerability]:
        """Test for SQL injection vulnerabilities."""
        try:
            url = f"{self.base_url}{endpoint}"

            # Test in query parameters
            response = requests.get(f"{url}?id={payload}", timeout=5)

            # Check for SQL error patterns
            error_patterns = [
                "sql syntax",
                "mysql_fetch",
                "ora-",
                "postgresql",
                "sqlite",
                "syntax error",
                "unclosed quotation mark"
            ]

            response_text = response.text.lower()
            for pattern in error_patterns:
                if pattern in response_text:
                    return SecurityVulnerability(
                        id=f"sqli_{hashlib.md5(f'{endpoint}_{payload}'.encode()).hexdigest()[:8]}",
                        title="SQL Injection Vulnerability",
                        description=f"SQL injection detected in {endpoint}",
                        severity=SeverityLevel.HIGH,
                        category=TestCategory.API_SECURITY,
                        affected_component=endpoint,
                        proof_of_concept=f"GET {url}?id={payload}",
                        remediation="Use parameterized queries and input validation"
                    )

        except Exception as e:
            logger.debug(f"SQL injection test error: {e}")

        return None

    async def _test_auth_bypass(self, endpoint: str) -> Optional[SecurityVulnerability]:
        """Test for authentication bypass vulnerabilities."""
        try:
            url = f"{self.base_url}{endpoint}"

            # Test without authentication
            response = requests.get(url, timeout=5)

            # Check if protected endpoint returns sensitive data
            if response.status_code == 200 and len(response.text) > 100:
                # Check for sensitive data patterns
                sensitive_patterns = [
                    "password",
                    "token",
                    "secret",
                    "api_key",
                    "private_key"
                ]

                response_text = response.text.lower()
                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        return SecurityVulnerability(
                            id=f"auth_bypass_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="Authentication Bypass",
                            description=f"Protected endpoint {endpoint} accessible without authentication",
                            severity=SeverityLevel.CRITICAL,
                            category=TestCategory.AUTHENTICATION,
                            affected_component=endpoint,
                            proof_of_concept=f"GET {url} (no auth headers)",
                            remediation="Implement proper authentication checks"
                        )

        except Exception as e:
            logger.debug(f"Auth bypass test error: {e}")

        return None

    async def _test_rate_limiting(self, endpoint: str) -> Optional[SecurityVulnerability]:
        """Test for rate limiting vulnerabilities."""
        try:
            url = f"{self.base_url}{endpoint}"

            # Make rapid requests
            responses = []
            for i in range(20):
                response = requests.get(url, timeout=2)
                responses.append(response.status_code)

            # Check if all requests succeeded (no rate limiting)
            success_count = len([r for r in responses if r == 200])

            if success_count > 15:  # More than 75% success rate indicates weak rate limiting
                return SecurityVulnerability(
                    id=f"rate_limit_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="Insufficient Rate Limiting",
                    description=f"Endpoint {endpoint} lacks proper rate limiting",
                    severity=SeverityLevel.MEDIUM,
                    category=TestCategory.API_SECURITY,
                    affected_component=endpoint,
                    proof_of_concept=f"20 rapid requests to {url}, {success_count} succeeded",
                    remediation="Implement proper rate limiting and throttling"
                )

        except Exception as e:
            logger.debug(f"Rate limiting test error: {e}")

        return None

    async def _test_authentication(self) -> List[SecurityVulnerability]:
        """Test authentication mechanisms."""
        vulnerabilities = []

        try:
            # Test weak password policy
            weak_passwords = ["123456", "password", "admin", "test", ""]

            for password in weak_passwords:
                response = requests.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json={"username": "testuser", "password": password},
                    timeout=5
                )

                if response.status_code == 201:  # Registration successful
                    vulnerabilities.append(SecurityVulnerability(
                        id=f"weak_password_{hashlib.md5(password.encode()).hexdigest()[:8]}",
                        title="Weak Password Policy",
                        description="System accepts weak passwords",
                        severity=SeverityLevel.HIGH,
                        category=TestCategory.AUTHENTICATION,
                        affected_component="/api/v1/auth/register",
                        proof_of_concept=f"Registration with password: '{password}'",
                        remediation="Implement strong password policy"
                    ))
                    break

            # Test session management
            vuln = await self._test_session_management()
            if vuln:
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Authentication test failed: {e}")

        return vulnerabilities

    async def _test_session_management(self) -> Optional[SecurityVulnerability]:
        """Test session management vulnerabilities."""
        try:
            # Test session fixation
            session = requests.Session()

            # Get initial session
            session.get(f"{self.base_url}/api/v1/auth/login", timeout=5)
            initial_cookies = session.cookies.get_dict()

            # Attempt login
            response2 = session.post(
                f"{self.base_url}/api/v1/auth/login",
                json={"username": "admin", "password": "admin"},
                timeout=5
            )

            # Check if session ID changed after login
            final_cookies = session.cookies.get_dict()

            if initial_cookies == final_cookies and response2.status_code == 200:
                return SecurityVulnerability(
                    id=f"session_fixation_{int(time.time())}",
                    title="Session Fixation Vulnerability",
                    description="Session ID does not change after authentication",
                    severity=SeverityLevel.HIGH,
                    category=TestCategory.SESSION_MANAGEMENT,
                    affected_component="/api/v1/auth/login",
                    proof_of_concept="Session ID remains same before and after login",
                    remediation="Regenerate session ID after successful authentication"
                )

        except Exception as e:
            logger.debug(f"Session management test error: {e}")

        return None

    async def _test_input_validation(self) -> List[SecurityVulnerability]:
        """Test input validation vulnerabilities."""
        vulnerabilities = []

        # Test XSS vulnerabilities
        test_endpoints = ["/api/v1/messages", "/api/v1/users/profile"]

        for endpoint in test_endpoints:
            for payload in self.xss_payloads:
                try:
                    response = requests.post(
                        f"{self.base_url}{endpoint}",
                        json={"content": payload},
                        timeout=5
                    )

                    # Check if payload is reflected without encoding
                    if payload in response.text:
                        vulnerabilities.append(SecurityVulnerability(
                            id=f"xss_{hashlib.md5(f'{endpoint}_{payload}'.encode()).hexdigest()[:8]}",
                            title="Cross-Site Scripting (XSS)",
                            description=f"XSS vulnerability in {endpoint}",
                            severity=SeverityLevel.HIGH,
                            category=TestCategory.INPUT_VALIDATION,
                            affected_component=endpoint,
                            proof_of_concept=f"POST {endpoint} with payload: {payload}",
                            remediation="Implement proper input validation and output encoding"
                        ))
                        break

                except Exception as e:
                    logger.debug(f"XSS test error: {e}")

        return vulnerabilities

    async def _test_dependencies(self) -> List[SecurityVulnerability]:
        """Test for vulnerable dependencies."""
        vulnerabilities = []

        try:
            # Run safety check on requirements.txt
            result = subprocess.run(
                ["python", "-m", "safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0 and result.stdout:
                safety_results = json.loads(result.stdout)

                for vuln in safety_results:
                    vulnerabilities.append(SecurityVulnerability(
                        id=f"dep_{vuln.get('id', 'unknown')}",
                        title=f"Vulnerable Dependency: {vuln.get('package_name')}",
                        description=vuln.get('advisory', 'Vulnerable dependency detected'),
                        severity=SeverityLevel.HIGH,
                        category=TestCategory.DEPENDENCY_SCAN,
                        affected_component=f"{vuln.get('package_name')} {vuln.get('installed_version')}",
                        proof_of_concept=f"Package {vuln.get('package_name')} version {vuln.get('installed_version')}",
                        remediation=f"Update to version {vuln.get('fixed_versions', ['latest'])[0]}",
                        cve_id=vuln.get('cve')
                    ))

        except subprocess.TimeoutExpired:
            logger.warning("Dependency scan timed out")
        except Exception as e:
            logger.error(f"Dependency scan failed: {e}")

        return vulnerabilities

    async def _test_configuration(self) -> List[SecurityVulnerability]:
        """Test configuration security."""
        vulnerabilities = []

        try:
            # Test for debug mode enabled
            response = requests.get(f"{self.base_url}/api/v1/system/config", timeout=5)

            if response.status_code == 200:
                config_text = response.text.lower()

                # Check for debug mode
                if "debug" in config_text and "true" in config_text:
                    vulnerabilities.append(SecurityVulnerability(
                        id=f"debug_mode_{int(time.time())}",
                        title="Debug Mode Enabled",
                        description="Application running in debug mode",
                        severity=SeverityLevel.MEDIUM,
                        category=TestCategory.CONFIGURATION,
                        affected_component="/api/v1/system/config",
                        proof_of_concept="Debug mode detected in configuration",
                        remediation="Disable debug mode in production"
                    ))

                # Check for exposed secrets
                secret_patterns = ["password", "secret", "key", "token"]
                for pattern in secret_patterns:
                    if pattern in config_text:
                        vulnerabilities.append(SecurityVulnerability(
                            id=f"exposed_secret_{pattern}_{int(time.time())}",
                            title="Exposed Secrets in Configuration",
                            description=f"Potential secret exposure: {pattern}",
                            severity=SeverityLevel.CRITICAL,
                            category=TestCategory.CONFIGURATION,
                            affected_component="/api/v1/system/config",
                            proof_of_concept=f"Secret pattern '{pattern}' found in config",
                            remediation="Remove secrets from configuration endpoint"
                        ))

        except Exception as e:
            logger.debug(f"Configuration test error: {e}")

        return vulnerabilities

    async def _test_web_application(self) -> List[SecurityVulnerability]:
        """Test web application security."""
        vulnerabilities = []

        try:
            # Test security headers
            response = requests.get(self.base_url, timeout=5)
            headers = response.headers

            required_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000"
            }

            for header, expected_value in required_headers.items():
                if header not in headers:
                    vulnerabilities.append(SecurityVulnerability(
                        id=f"missing_header_{header.lower().replace('-', '_')}",
                        title=f"Missing Security Header: {header}",
                        description=f"Security header {header} is missing",
                        severity=SeverityLevel.MEDIUM,
                        category=TestCategory.WEB_APPLICATION,
                        affected_component=self.base_url,
                        proof_of_concept=f"GET {self.base_url} - missing {header} header",
                        remediation=f"Add {header}: {expected_value} header"
                    ))

        except Exception as e:
            logger.debug(f"Web application test error: {e}")

        return vulnerabilities

    async def _test_encryption(self) -> List[SecurityVulnerability]:
        """Test encryption implementation."""
        vulnerabilities = []

        try:
            # Test SSL/TLS configuration
            hostname = self.base_url.replace("https://", "").replace("http://", "").split("/")[0]

            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()

                    # Check for weak ciphers
                    weak_ciphers = ["RC4", "DES", "MD5"]
                    if cipher and any(weak in cipher[0] for weak in weak_ciphers):
                        vulnerabilities.append(SecurityVulnerability(
                            id=f"weak_cipher_{int(time.time())}",
                            title="Weak SSL/TLS Cipher",
                            description=f"Weak cipher detected: {cipher[0]}",
                            severity=SeverityLevel.HIGH,
                            category=TestCategory.ENCRYPTION,
                            affected_component=hostname,
                            proof_of_concept=f"SSL connection using cipher: {cipher[0]}",
                            remediation="Configure strong SSL/TLS ciphers only"
                        ))

        except Exception as e:
            logger.debug(f"Encryption test error: {e}")

        return vulnerabilities

    async def _initialize_test_storage(self):
        """Initialize test result storage."""
        # This would initialize database or file storage for test results
        logger.info("Test storage initialized")

    async def _load_test_history(self):
        """Load previous test results."""
        # This would load historical test data
        logger.info("Test history loaded")

    async def _test_monitor(self):
        """Background task for monitoring active tests."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                # Check for timed out tests
                current_time = datetime.now(timezone.utc)
                for test_id, result in self.test_results.items():
                    if (result.status == TestStatus.RUNNING and
                        result.start_time and
                        (current_time - result.start_time).total_seconds() > self.test_timeout):

                        result.status = TestStatus.FAILED
                        result.end_time = current_time
                        self.active_tests.discard(test_id)

                        logger.warning(f"Test {test_id} timed out")

            except Exception as e:
                logger.error(f"Test monitor error: {e}")

    def get_test_result(self, test_id: str) -> Optional[SecurityTestResult]:
        """Get test result by ID."""
        return self.test_results.get(test_id)

    def get_security_testing_status(self) -> Dict[str, Any]:
        """Get comprehensive security testing status."""
        return {
            "security_testing": {
                "initialized": self.initialized,
                "active_tests": len(self.active_tests),
                "total_test_results": len(self.test_results),
                "statistics": self.statistics,
                "configuration": {
                    "base_url": self.base_url,
                    "max_concurrent_tests": self.max_concurrent_tests,
                    "test_timeout": self.test_timeout
                }
            }
        }


# Global instance - SINGLE SOURCE OF TRUTH
_automated_security_tester: Optional[AutomatedSecurityTester] = None


def get_automated_security_tester() -> AutomatedSecurityTester:
    """Get the global automated security tester instance."""
    global _automated_security_tester
    if _automated_security_tester is None:
        _automated_security_tester = AutomatedSecurityTester()
    return _automated_security_tester


# Export main components
__all__ = [
    "AutomatedSecurityTester",
    "get_automated_security_tester",
    "TestCategory",
    "SeverityLevel",
    "TestStatus",
    "SecurityVulnerability",
    "SecurityTestResult"
]
