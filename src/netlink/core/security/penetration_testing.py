"""
NetLink Penetration Testing System

Comprehensive penetration testing framework with automated vulnerability
assessment, security scanning, and compliance validation.
"""

import asyncio
import logging
import json
import time
import hashlib
import socket
import ssl
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import requests
from urllib.parse import urljoin, urlparse
import re

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_FLAW = "authorization_flaw"
    INFORMATION_DISCLOSURE = "information_disclosure"
    BUFFER_OVERFLOW = "buffer_overflow"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSECURE_CONFIGURATION = "insecure_configuration"
    WEAK_ENCRYPTION = "weak_encryption"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    OPEN_REDIRECT = "open_redirect"
    FILE_INCLUSION = "file_inclusion"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class TestCategory(Enum):
    """Penetration test categories."""
    NETWORK_SCAN = "network_scan"
    WEB_APPLICATION = "web_application"
    API_SECURITY = "api_security"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    SESSION_MANAGEMENT = "session_management"
    ENCRYPTION = "encryption"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str
    type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    affected_component: str
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_component": self.affected_component,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "discovered_at": self.discovered_at.isoformat(),
            "verified": self.verified,
            "false_positive": self.false_positive
        }


@dataclass
class PenetrationTestResult:
    """Results of a penetration test."""
    test_id: str
    target: str
    test_type: TestCategory
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[timedelta]:
        """Get test duration."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def critical_count(self) -> int:
        """Count of critical vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL])
    
    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "test_id": self.test_id,
            "target": self.target,
            "test_type": self.test_type.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration.total_seconds() if self.duration else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "vulnerability_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                "low": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW]),
                "info": len([v for v in self.vulnerabilities if v.severity == SeverityLevel.INFO])
            },
            "summary": self.summary,
            "recommendations": self.recommendations,
            "compliance_status": self.compliance_status
        }


class PenetrationTestingSystem:
    """Comprehensive penetration testing system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize penetration testing system."""
        self.config = config or {}
        self.test_results: Dict[str, PenetrationTestResult] = {}
        self.active_tests: Set[str] = set()
        
        # Test configuration
        self.max_concurrent_tests = self.config.get("max_concurrent_tests", 5)
        self.test_timeout = self.config.get("test_timeout", 3600)  # 1 hour
        self.enable_aggressive_tests = self.config.get("enable_aggressive_tests", False)
        
        # Vulnerability database
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        logger.info("Penetration Testing System initialized")
    
    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load vulnerability detection patterns."""
        return {
            "sql_injection": {
                "patterns": [
                    r"SQL syntax.*MySQL",
                    r"Warning.*mysql_.*",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*\Wpg_.*",
                    r"valid PostgreSQL result",
                    r"Npgsql\.",
                    r"Driver.*SQL.*Server",
                    r"OLE DB.*SQL Server",
                    r"(\W|\A)SQL Server.*Driver",
                    r"Warning.*mssql_.*",
                    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                    r"Exception.*\WSystem\.Data\.SqlClient\.",
                    r"Exception.*\WRoadhouse\.Cms\.",
                    r"Microsoft Access Driver",
                    r"JET Database Engine",
                    r"Access Database Engine",
                    r"ODBC Microsoft Access",
                    r"Syntax error.*query expression"
                ],
                "payloads": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users; --",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
                ]
            },
            "xss": {
                "patterns": [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"<iframe[^>]*>",
                    r"<object[^>]*>",
                    r"<embed[^>]*>"
                ],
                "payloads": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "<iframe src=javascript:alert('XSS')></iframe>"
                ]
            },
            "command_injection": {
                "patterns": [
                    r"sh: .*: command not found",
                    r"'.*' is not recognized as an internal or external command",
                    r"The system cannot find the file specified",
                    r"Permission denied",
                    r"No such file or directory"
                ],
                "payloads": [
                    "; ls -la",
                    "| whoami",
                    "&& dir",
                    "; cat /etc/passwd",
                    "| type C:\\Windows\\System32\\drivers\\etc\\hosts"
                ]
            }
        }
    
    async def run_comprehensive_test(self, target: str, test_types: Optional[List[TestCategory]] = None) -> str:
        """Run comprehensive penetration test."""
        test_id = f"pentest_{int(time.time())}_{hashlib.md5(target.encode()).hexdigest()[:8]}"
        
        if len(self.active_tests) >= self.max_concurrent_tests:
            raise Exception("Maximum concurrent tests reached")
        
        self.active_tests.add(test_id)
        
        try:
            # Initialize test result
            result = PenetrationTestResult(
                test_id=test_id,
                target=target,
                test_type=TestCategory.WEB_APPLICATION,  # Default
                start_time=datetime.now(timezone.utc)
            )
            
            self.test_results[test_id] = result
            
            # Run tests based on specified types
            if not test_types:
                test_types = [
                    TestCategory.NETWORK_SCAN,
                    TestCategory.WEB_APPLICATION,
                    TestCategory.API_SECURITY,
                    TestCategory.AUTHENTICATION,
                    TestCategory.INPUT_VALIDATION
                ]
            
            for test_type in test_types:
                await self._run_test_category(result, test_type)
            
            # Finalize results
            result.end_time = datetime.now(timezone.utc)
            result.summary = self._generate_test_summary(result)
            result.recommendations = self._generate_recommendations(result)
            result.compliance_status = await self._check_compliance(result)
            
            logger.info(f"Penetration test {test_id} completed with {len(result.vulnerabilities)} vulnerabilities found")
            
            return test_id
            
        finally:
            self.active_tests.discard(test_id)
    
    async def _run_test_category(self, result: PenetrationTestResult, category: TestCategory):
        """Run tests for a specific category."""
        logger.info(f"Running {category.value} tests for {result.target}")
        
        try:
            if category == TestCategory.NETWORK_SCAN:
                await self._run_network_scan(result)
            elif category == TestCategory.WEB_APPLICATION:
                await self._run_web_application_tests(result)
            elif category == TestCategory.API_SECURITY:
                await self._run_api_security_tests(result)
            elif category == TestCategory.AUTHENTICATION:
                await self._run_authentication_tests(result)
            elif category == TestCategory.INPUT_VALIDATION:
                await self._run_input_validation_tests(result)
            elif category == TestCategory.SESSION_MANAGEMENT:
                await self._run_session_management_tests(result)
            elif category == TestCategory.ENCRYPTION:
                await self._run_encryption_tests(result)
            elif category == TestCategory.CONFIGURATION:
                await self._run_configuration_tests(result)
            elif category == TestCategory.COMPLIANCE:
                await self._run_compliance_tests(result)
                
        except Exception as e:
            logger.error(f"Error running {category.value} tests: {e}")
            # Add error as vulnerability
            vulnerability = Vulnerability(
                id=f"test_error_{int(time.time())}",
                type=VulnerabilityType.INSECURE_CONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                title=f"Test Execution Error - {category.value}",
                description=f"Error occurred during {category.value} testing: {str(e)}",
                affected_component=result.target
            )
            result.vulnerabilities.append(vulnerability)

    async def _run_network_scan(self, result: PenetrationTestResult):
        """Run network scanning tests."""
        try:
            parsed_url = urlparse(result.target)
            host = parsed_url.hostname or result.target
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            # Port scanning
            open_ports = await self._scan_ports(host, [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443])

            if open_ports:
                for port_info in open_ports:
                    if port_info['port'] in [21, 23, 25, 110, 143]:  # Insecure protocols
                        vulnerability = Vulnerability(
                            id=f"insecure_port_{port_info['port']}_{int(time.time())}",
                            type=VulnerabilityType.INSECURE_CONFIGURATION,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Insecure Protocol on Port {port_info['port']}",
                            description=f"Insecure protocol detected on port {port_info['port']}. Service: {port_info.get('service', 'Unknown')}",
                            affected_component=f"{host}:{port_info['port']}",
                            remediation="Disable insecure protocols and use encrypted alternatives (SFTP, SSH, HTTPS, etc.)"
                        )
                        result.vulnerabilities.append(vulnerability)

            # SSL/TLS testing
            if 443 in [p['port'] for p in open_ports]:
                await self._test_ssl_configuration(result, host, 443)

        except Exception as e:
            logger.error(f"Network scan error: {e}")

    async def _scan_ports(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Scan for open ports."""
        open_ports = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))

                if result == 0:
                    service = socket.getservbyport(port) if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995] else "unknown"
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })

                sock.close()

            except Exception:
                continue

        return open_ports

    async def _test_ssl_configuration(self, result: PenetrationTestResult, host: str, port: int):
        """Test SSL/TLS configuration."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check for weak SSL/TLS versions
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerability = Vulnerability(
                            id=f"weak_tls_{int(time.time())}",
                            type=VulnerabilityType.WEAK_ENCRYPTION,
                            severity=SeverityLevel.HIGH,
                            title=f"Weak TLS Version: {version}",
                            description=f"Server supports weak TLS version {version}",
                            affected_component=f"{host}:{port}",
                            remediation="Disable weak TLS versions and use TLS 1.2 or higher"
                        )
                        result.vulnerabilities.append(vulnerability)

                    # Check for weak ciphers
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                            vulnerability = Vulnerability(
                                id=f"weak_cipher_{int(time.time())}",
                                type=VulnerabilityType.WEAK_ENCRYPTION,
                                severity=SeverityLevel.MEDIUM,
                                title=f"Weak Cipher Suite: {cipher_name}",
                                description=f"Server supports weak cipher suite: {cipher_name}",
                                affected_component=f"{host}:{port}",
                                remediation="Disable weak cipher suites and use strong encryption"
                            )
                            result.vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.error(f"SSL test error: {e}")

    async def _run_web_application_tests(self, result: PenetrationTestResult):
        """Run web application security tests."""
        try:
            # Test for missing security headers
            await self._test_security_headers(result)

            # Test for common vulnerabilities
            await self._test_common_web_vulnerabilities(result)

            # Test for information disclosure
            await self._test_information_disclosure(result)

        except Exception as e:
            logger.error(f"Web application test error: {e}")

    async def _test_security_headers(self, result: PenetrationTestResult):
        """Test for missing security headers."""
        try:
            response = requests.get(result.target, timeout=10, verify=False)
            headers = response.headers

            required_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection',
                'Referrer-Policy': 'Referrer information control'
            }

            for header, description in required_headers.items():
                if header not in headers:
                    vulnerability = Vulnerability(
                        id=f"missing_header_{header.lower().replace('-', '_')}_{int(time.time())}",
                        type=VulnerabilityType.MISSING_SECURITY_HEADERS,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Missing Security Header: {header}",
                        description=f"Missing {header} header. This header provides {description}.",
                        affected_component=result.target,
                        remediation=f"Add {header} header to HTTP responses"
                    )
                    result.vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.error(f"Security headers test error: {e}")

    async def _test_common_web_vulnerabilities(self, result: PenetrationTestResult):
        """Test for common web vulnerabilities."""
        # Test for directory traversal
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]

        for payload in traversal_payloads:
            try:
                test_url = f"{result.target.rstrip('/')}/{payload}"
                response = requests.get(test_url, timeout=5, verify=False)

                if any(indicator in response.text.lower() for indicator in ['root:', 'localhost', 'windows']):
                    vulnerability = Vulnerability(
                        id=f"directory_traversal_{int(time.time())}",
                        type=VulnerabilityType.DIRECTORY_TRAVERSAL,
                        severity=SeverityLevel.HIGH,
                        title="Directory Traversal Vulnerability",
                        description="Application is vulnerable to directory traversal attacks",
                        affected_component=test_url,
                        proof_of_concept=f"GET {test_url}",
                        remediation="Implement proper input validation and file access controls"
                    )
                    result.vulnerabilities.append(vulnerability)
                    break

            except Exception:
                continue

    async def _test_information_disclosure(self, result: PenetrationTestResult):
        """Test for information disclosure vulnerabilities."""
        disclosure_paths = [
            "/.git/config",
            "/.env",
            "/config.php",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/admin",
            "/backup",
            "/test"
        ]

        for path in disclosure_paths:
            try:
                test_url = f"{result.target.rstrip('/')}{path}"
                response = requests.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # Check for sensitive information patterns
                    sensitive_patterns = [
                        r'password\s*[=:]\s*["\']?[\w\-!@#$%^&*()]+',
                        r'api[_\-]?key\s*[=:]\s*["\']?[\w\-]+',
                        r'secret\s*[=:]\s*["\']?[\w\-!@#$%^&*()]+',
                        r'database.*password',
                        r'mysql.*password'
                    ]

                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerability = Vulnerability(
                                id=f"info_disclosure_{path.replace('/', '_')}_{int(time.time())}",
                                type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                severity=SeverityLevel.HIGH,
                                title=f"Information Disclosure: {path}",
                                description=f"Sensitive information exposed at {path}",
                                affected_component=test_url,
                                proof_of_concept=f"GET {test_url}",
                                remediation="Remove or restrict access to sensitive files"
                            )
                            result.vulnerabilities.append(vulnerability)
                            break

            except Exception:
                continue

    async def _run_api_security_tests(self, result: PenetrationTestResult):
        """Run API security tests."""
        # Test for common API endpoints
        api_endpoints = [
            "/api/v1/users",
            "/api/users",
            "/rest/users",
            "/graphql",
            "/api/admin",
            "/api/config"
        ]

        for endpoint in api_endpoints:
            try:
                test_url = f"{result.target.rstrip('/')}{endpoint}"
                response = requests.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # Check if API returns sensitive data without authentication
                    if any(keyword in response.text.lower() for keyword in ['password', 'token', 'secret', 'key']):
                        vulnerability = Vulnerability(
                            id=f"api_exposure_{endpoint.replace('/', '_')}_{int(time.time())}",
                            type=VulnerabilityType.BROKEN_ACCESS_CONTROL,
                            severity=SeverityLevel.HIGH,
                            title=f"API Endpoint Exposure: {endpoint}",
                            description=f"API endpoint {endpoint} exposes sensitive data without authentication",
                            affected_component=test_url,
                            proof_of_concept=f"GET {test_url}",
                            remediation="Implement proper authentication and authorization for API endpoints"
                        )
                        result.vulnerabilities.append(vulnerability)

            except Exception:
                continue

    async def _run_authentication_tests(self, result: PenetrationTestResult):
        """Run authentication security tests."""
        # Test for default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test")
        ]

        login_endpoints = [
            "/login",
            "/admin/login",
            "/api/login",
            "/auth/login"
        ]

        for endpoint in login_endpoints:
            for username, password in default_creds:
                try:
                    test_url = f"{result.target.rstrip('/')}{endpoint}"
                    data = {"username": username, "password": password}
                    response = requests.post(test_url, data=data, timeout=5, verify=False)

                    # Check for successful login indicators
                    if any(indicator in response.text.lower() for indicator in ['welcome', 'dashboard', 'success', 'token']):
                        vulnerability = Vulnerability(
                            id=f"default_creds_{username}_{int(time.time())}",
                            type=VulnerabilityType.AUTHENTICATION_BYPASS,
                            severity=SeverityLevel.CRITICAL,
                            title=f"Default Credentials: {username}/{password}",
                            description=f"Default credentials {username}/{password} are still active",
                            affected_component=test_url,
                            proof_of_concept=f"POST {test_url} with {username}:{password}",
                            remediation="Change default credentials and enforce strong password policies"
                        )
                        result.vulnerabilities.append(vulnerability)

                except Exception:
                    continue

    async def _run_input_validation_tests(self, result: PenetrationTestResult):
        """Run input validation tests."""
        # SQL injection tests
        sql_payloads = self.vulnerability_patterns["sql_injection"]["payloads"]

        # Test common parameters
        test_params = ["id", "user", "search", "q", "query", "name"]

        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{result.target}?{param}={payload}"
                    response = requests.get(test_url, timeout=5, verify=False)

                    # Check for SQL error patterns
                    for pattern in self.vulnerability_patterns["sql_injection"]["patterns"]:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerability = Vulnerability(
                                id=f"sql_injection_{param}_{int(time.time())}",
                                type=VulnerabilityType.SQL_INJECTION,
                                severity=SeverityLevel.CRITICAL,
                                title=f"SQL Injection in {param} parameter",
                                description=f"SQL injection vulnerability detected in {param} parameter",
                                affected_component=test_url,
                                proof_of_concept=f"GET {test_url}",
                                remediation="Use parameterized queries and input validation"
                            )
                            result.vulnerabilities.append(vulnerability)
                            break

                except Exception:
                    continue

        # XSS tests
        xss_payloads = self.vulnerability_patterns["xss"]["payloads"]

        for param in test_params:
            for payload in xss_payloads:
                try:
                    test_url = f"{result.target}?{param}={payload}"
                    response = requests.get(test_url, timeout=5, verify=False)

                    # Check if payload is reflected
                    if payload in response.text:
                        vulnerability = Vulnerability(
                            id=f"xss_{param}_{int(time.time())}",
                            type=VulnerabilityType.XSS,
                            severity=SeverityLevel.HIGH,
                            title=f"Cross-Site Scripting in {param} parameter",
                            description=f"XSS vulnerability detected in {param} parameter",
                            affected_component=test_url,
                            proof_of_concept=f"GET {test_url}",
                            remediation="Implement proper input validation and output encoding"
                        )
                        result.vulnerabilities.append(vulnerability)
                        break

                except Exception:
                    continue

    async def _run_session_management_tests(self, result: PenetrationTestResult):
        """Run session management tests."""
        # Test for session fixation and weak session management
        try:
            session = requests.Session()
            response = session.get(result.target, timeout=5, verify=False)

            # Check for secure cookie attributes
            for cookie in session.cookies:
                if not cookie.secure and result.target.startswith('https'):
                    vulnerability = Vulnerability(
                        id=f"insecure_cookie_{cookie.name}_{int(time.time())}",
                        type=VulnerabilityType.SESSION_MANAGEMENT,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Insecure Cookie: {cookie.name}",
                        description=f"Cookie {cookie.name} lacks Secure flag",
                        affected_component=result.target,
                        remediation="Set Secure flag on all cookies for HTTPS sites"
                    )
                    result.vulnerabilities.append(vulnerability)

                if not getattr(cookie, 'httponly', False):
                    vulnerability = Vulnerability(
                        id=f"httponly_cookie_{cookie.name}_{int(time.time())}",
                        type=VulnerabilityType.SESSION_MANAGEMENT,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Missing HttpOnly: {cookie.name}",
                        description=f"Cookie {cookie.name} lacks HttpOnly flag",
                        affected_component=result.target,
                        remediation="Set HttpOnly flag on session cookies"
                    )
                    result.vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.error(f"Session management test error: {e}")

    async def _run_encryption_tests(self, result: PenetrationTestResult):
        """Run encryption tests."""
        # Already covered in SSL/TLS testing
        pass

    async def _run_configuration_tests(self, result: PenetrationTestResult):
        """Run configuration security tests."""
        # Test for common misconfigurations
        config_files = [
            "/.htaccess",
            "/web.config",
            "/robots.txt",
            "/sitemap.xml"
        ]

        for config_file in config_files:
            try:
                test_url = f"{result.target.rstrip('/')}{config_file}"
                response = requests.get(test_url, timeout=5, verify=False)

                if response.status_code == 200 and config_file in ["/.htaccess", "/web.config"]:
                    vulnerability = Vulnerability(
                        id=f"config_exposure_{config_file.replace('/', '_')}_{int(time.time())}",
                        type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        severity=SeverityLevel.MEDIUM,
                        title=f"Configuration File Exposure: {config_file}",
                        description=f"Configuration file {config_file} is accessible",
                        affected_component=test_url,
                        remediation="Restrict access to configuration files"
                    )
                    result.vulnerabilities.append(vulnerability)

            except Exception:
                continue

    async def _run_compliance_tests(self, result: PenetrationTestResult):
        """Run compliance tests."""
        # Basic compliance checks
        compliance_checks = {
            "https_enforced": False,
            "security_headers_present": False,
            "strong_encryption": False,
            "no_default_credentials": True
        }

        # Check HTTPS enforcement
        if result.target.startswith('https'):
            compliance_checks["https_enforced"] = True

        # Check for security headers
        try:
            response = requests.get(result.target, timeout=5, verify=False)
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
            if any(header in response.headers for header in security_headers):
                compliance_checks["security_headers_present"] = True
        except Exception:
            pass

        # Check for default credentials (mark as non-compliant if found)
        default_cred_vulns = [v for v in result.vulnerabilities if v.type == VulnerabilityType.AUTHENTICATION_BYPASS]
        if default_cred_vulns:
            compliance_checks["no_default_credentials"] = False

        result.compliance_status = compliance_checks

    def _generate_test_summary(self, result: PenetrationTestResult) -> Dict[str, Any]:
        """Generate test summary."""
        return {
            "total_vulnerabilities": len(result.vulnerabilities),
            "critical_vulnerabilities": result.critical_count,
            "high_vulnerabilities": result.high_count,
            "test_duration": result.duration.total_seconds() if result.duration else 0,
            "target_analyzed": result.target,
            "most_common_vulnerability": self._get_most_common_vulnerability_type(result),
            "security_score": self._calculate_security_score(result)
        }

    def _get_most_common_vulnerability_type(self, result: PenetrationTestResult) -> str:
        """Get the most common vulnerability type."""
        if not result.vulnerabilities:
            return "None"

        type_counts = {}
        for vuln in result.vulnerabilities:
            vuln_type = vuln.type.value
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        return max(type_counts, key=type_counts.get)

    def _calculate_security_score(self, result: PenetrationTestResult) -> float:
        """Calculate security score (0-100)."""
        if not result.vulnerabilities:
            return 100.0

        # Weighted scoring based on severity
        severity_weights = {
            SeverityLevel.CRITICAL: 20,
            SeverityLevel.HIGH: 10,
            SeverityLevel.MEDIUM: 5,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }

        total_penalty = sum(severity_weights.get(vuln.severity, 0) for vuln in result.vulnerabilities)

        # Cap at 0, start from 100
        score = max(0, 100 - total_penalty)
        return float(score)

    def _generate_recommendations(self, result: PenetrationTestResult) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        # Group vulnerabilities by type
        vuln_types = set(vuln.type for vuln in result.vulnerabilities)

        if VulnerabilityType.SQL_INJECTION in vuln_types:
            recommendations.append("Implement parameterized queries and input validation to prevent SQL injection")

        if VulnerabilityType.XSS in vuln_types:
            recommendations.append("Implement proper input validation and output encoding to prevent XSS")

        if VulnerabilityType.MISSING_SECURITY_HEADERS in vuln_types:
            recommendations.append("Add security headers (X-Frame-Options, CSP, HSTS, etc.)")

        if VulnerabilityType.WEAK_ENCRYPTION in vuln_types:
            recommendations.append("Upgrade to strong encryption protocols (TLS 1.2+, strong ciphers)")

        if VulnerabilityType.AUTHENTICATION_BYPASS in vuln_types:
            recommendations.append("Change default credentials and implement strong authentication")

        if VulnerabilityType.INFORMATION_DISCLOSURE in vuln_types:
            recommendations.append("Remove or restrict access to sensitive files and information")

        if VulnerabilityType.DIRECTORY_TRAVERSAL in vuln_types:
            recommendations.append("Implement proper file access controls and input validation")

        if VulnerabilityType.BROKEN_ACCESS_CONTROL in vuln_types:
            recommendations.append("Implement proper authorization and access controls")

        # General recommendations
        if result.critical_count > 0:
            recommendations.append("Address critical vulnerabilities immediately")

        if result.high_count > 0:
            recommendations.append("Prioritize fixing high-severity vulnerabilities")

        recommendations.append("Conduct regular security assessments and penetration testing")
        recommendations.append("Implement a security monitoring and incident response plan")

        return recommendations

    async def get_test_result(self, test_id: str) -> Optional[PenetrationTestResult]:
        """Get test result by ID."""
        return self.test_results.get(test_id)

    async def list_test_results(self) -> List[str]:
        """List all test result IDs."""
        return list(self.test_results.keys())

    async def delete_test_result(self, test_id: str) -> bool:
        """Delete test result."""
        if test_id in self.test_results:
            del self.test_results[test_id]
            return True
        return False

    async def export_test_result(self, test_id: str, format: str = "json") -> Optional[str]:
        """Export test result in specified format."""
        result = self.test_results.get(test_id)
        if not result:
            return None

        if format.lower() == "json":
            return json.dumps(result.to_dict(), indent=2)
        elif format.lower() == "html":
            return self._generate_html_report(result)
        else:
            return None

    def _generate_html_report(self, result: PenetrationTestResult) -> str:
        """Generate HTML report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Test Report - {result.test_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ccc; }}
                .critical {{ border-left-color: #d32f2f; background-color: #ffebee; }}
                .high {{ border-left-color: #f57c00; background-color: #fff3e0; }}
                .medium {{ border-left-color: #fbc02d; background-color: #fffde7; }}
                .low {{ border-left-color: #388e3c; background-color: #e8f5e8; }}
                .info {{ border-left-color: #1976d2; background-color: #e3f2fd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Penetration Test Report</h1>
                <p><strong>Test ID:</strong> {result.test_id}</p>
                <p><strong>Target:</strong> {result.target}</p>
                <p><strong>Start Time:</strong> {result.start_time}</p>
                <p><strong>Duration:</strong> {result.duration}</p>
                <p><strong>Total Vulnerabilities:</strong> {len(result.vulnerabilities)}</p>
            </div>

            <h2>Vulnerabilities</h2>
        """

        for vuln in result.vulnerabilities:
            severity_class = vuln.severity.name.lower()
            html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.title}</h3>
                <p><strong>Severity:</strong> {vuln.severity.name}</p>
                <p><strong>Type:</strong> {vuln.type.value}</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>Affected Component:</strong> {vuln.affected_component}</p>
                {f'<p><strong>Proof of Concept:</strong> {vuln.proof_of_concept}</p>' if vuln.proof_of_concept else ''}
                {f'<p><strong>Remediation:</strong> {vuln.remediation}</p>' if vuln.remediation else ''}
            </div>
            """

        html += """
            <h2>Recommendations</h2>
            <ul>
        """

        for rec in result.recommendations:
            html += f"<li>{rec}</li>"

        html += """
            </ul>
        </body>
        </html>
        """

        return html


# Global instance
penetration_tester = PenetrationTestingSystem()
