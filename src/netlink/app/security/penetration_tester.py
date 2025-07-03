"""
Comprehensive Security Audit and Penetration Testing for NetLink
Automated security testing to identify vulnerabilities.
"""

import asyncio
import json
import time
import random
import string
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import logging
import requests
import aiohttp
from concurrent.futures import ThreadPoolExecutor

@dataclass
class SecurityTest:
    """Security test definition."""
    test_id: str
    name: str
    category: str
    description: str
    severity: str  # low, medium, high, critical
    payload: str
    expected_response: str
    endpoint: str
    method: str = "GET"
    headers: Dict[str, str] = None

@dataclass
class SecurityTestResult:
    """Security test result."""
    test_id: str
    test_name: str
    category: str
    severity: str
    endpoint: str
    status: str  # passed, failed, vulnerable, error
    response_code: int
    response_time: float
    vulnerability_details: str
    recommendation: str
    timestamp: datetime

class PenetrationTester:
    """Comprehensive penetration testing system."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.logger = logging.getLogger(__name__)
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[SecurityTestResult] = []
        
        # Test categories
        self.sql_injection_tests = self._create_sql_injection_tests()
        self.xss_tests = self._create_xss_tests()
        self.auth_tests = self._create_auth_tests()
        self.input_validation_tests = self._create_input_validation_tests()
        self.rate_limiting_tests = self._create_rate_limiting_tests()
        self.file_upload_tests = self._create_file_upload_tests()
        self.api_security_tests = self._create_api_security_tests()
        
        # All tests combined
        self.all_tests = (
            self.sql_injection_tests + 
            self.xss_tests + 
            self.auth_tests + 
            self.input_validation_tests + 
            self.rate_limiting_tests + 
            self.file_upload_tests + 
            self.api_security_tests
        )
    
    def _create_sql_injection_tests(self) -> List[SecurityTest]:
        """Create SQL injection test cases."""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "admin' /*",
            "' OR 1=1#",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1 --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' UNION SELECT username, password FROM users --",
            "1; SELECT * FROM information_schema.tables --",
            "' OR SLEEP(5) --",
            "1' WAITFOR DELAY '00:00:05' --"
        ]
        
        tests = []
        endpoints = ["/auth/login", "/api/v1/admin/accounts", "/api/v1/search"]
        
        for i, payload in enumerate(payloads):
            for endpoint in endpoints:
                tests.append(SecurityTest(
                    test_id=f"sql_inj_{i}_{endpoint.replace('/', '_')}",
                    name=f"SQL Injection Test {i+1}",
                    category="SQL Injection",
                    description=f"Test SQL injection with payload: {payload[:20]}...",
                    severity="critical",
                    payload=payload,
                    expected_response="error_or_sanitized",
                    endpoint=endpoint,
                    method="POST"
                ))
        
        return tests
    
    def _create_xss_tests(self) -> List[SecurityTest]:
        """Create XSS test cases."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        tests = []
        endpoints = ["/api/v1/messages", "/api/v1/admin/accounts", "/docs"]
        
        for i, payload in enumerate(payloads):
            for endpoint in endpoints:
                tests.append(SecurityTest(
                    test_id=f"xss_{i}_{endpoint.replace('/', '_')}",
                    name=f"XSS Test {i+1}",
                    category="Cross-Site Scripting",
                    description=f"Test XSS with payload: {payload[:30]}...",
                    severity="high",
                    payload=payload,
                    expected_response="sanitized",
                    endpoint=endpoint,
                    method="POST"
                ))
        
        return tests
    
    def _create_auth_tests(self) -> List[SecurityTest]:
        """Create authentication bypass tests."""
        tests = [
            SecurityTest(
                test_id="auth_bypass_1",
                name="Admin Panel Access Without Auth",
                category="Authentication Bypass",
                description="Try to access admin panel without authentication",
                severity="critical",
                payload="",
                expected_response="401_or_redirect",
                endpoint="/admin/",
                method="GET"
            ),
            SecurityTest(
                test_id="auth_bypass_2",
                name="API Access Without Auth",
                category="Authentication Bypass",
                description="Try to access protected API without authentication",
                severity="critical",
                payload="",
                expected_response="401",
                endpoint="/api/v1/admin/accounts",
                method="GET"
            ),
            SecurityTest(
                test_id="auth_bypass_3",
                name="JWT Token Manipulation",
                category="Authentication Bypass",
                description="Try to access with manipulated JWT token",
                severity="high",
                payload="",
                expected_response="401",
                endpoint="/api/v1/admin/profile",
                method="GET",
                headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.invalid"}
            ),
            SecurityTest(
                test_id="auth_bypass_4",
                name="Session Fixation",
                category="Authentication Bypass",
                description="Try session fixation attack",
                severity="medium",
                payload="",
                expected_response="secure_session",
                endpoint="/auth/login",
                method="POST",
                headers={"Cookie": "netlink_session=fixed_session_id"}
            )
        ]
        
        return tests
    
    def _create_input_validation_tests(self) -> List[SecurityTest]:
        """Create input validation tests."""
        tests = [
            SecurityTest(
                test_id="input_val_1",
                name="Buffer Overflow Test",
                category="Input Validation",
                description="Test with extremely long input",
                severity="medium",
                payload="A" * 10000,
                expected_response="length_limit",
                endpoint="/api/v1/messages",
                method="POST"
            ),
            SecurityTest(
                test_id="input_val_2",
                name="Null Byte Injection",
                category="Input Validation",
                description="Test null byte injection",
                severity="medium",
                payload="test\x00.txt",
                expected_response="sanitized",
                endpoint="/api/v1/files/upload",
                method="POST"
            ),
            SecurityTest(
                test_id="input_val_3",
                name="Unicode Bypass",
                category="Input Validation",
                description="Test Unicode normalization bypass",
                severity="medium",
                payload="<script>alert('XSS')</script>",  # With Unicode chars
                expected_response="sanitized",
                endpoint="/api/v1/messages",
                method="POST"
            ),
            SecurityTest(
                test_id="input_val_4",
                name="Path Traversal",
                category="Input Validation",
                description="Test path traversal attack",
                severity="high",
                payload="../../../etc/passwd",
                expected_response="blocked",
                endpoint="/api/v1/files/download",
                method="GET"
            )
        ]
        
        return tests
    
    def _create_rate_limiting_tests(self) -> List[SecurityTest]:
        """Create rate limiting tests."""
        tests = [
            SecurityTest(
                test_id="rate_limit_1",
                name="API Rate Limiting",
                category="Rate Limiting",
                description="Test API rate limiting with rapid requests",
                severity="medium",
                payload="",
                expected_response="429",
                endpoint="/api/v1/testing/suites",
                method="GET"
            ),
            SecurityTest(
                test_id="rate_limit_2",
                name="Login Brute Force Protection",
                category="Rate Limiting",
                description="Test login brute force protection",
                severity="high",
                payload="",
                expected_response="429_or_blocked",
                endpoint="/auth/login",
                method="POST"
            )
        ]
        
        return tests
    
    def _create_file_upload_tests(self) -> List[SecurityTest]:
        """Create file upload security tests."""
        tests = [
            SecurityTest(
                test_id="file_upload_1",
                name="Malicious File Upload",
                category="File Upload",
                description="Test upload of executable file",
                severity="high",
                payload="<?php system($_GET['cmd']); ?>",
                expected_response="blocked",
                endpoint="/api/v1/files/upload",
                method="POST"
            ),
            SecurityTest(
                test_id="file_upload_2",
                name="Large File Upload",
                category="File Upload",
                description="Test upload of oversized file",
                severity="medium",
                payload="A" * (100 * 1024 * 1024),  # 100MB
                expected_response="413",
                endpoint="/api/v1/files/upload",
                method="POST"
            )
        ]
        
        return tests
    
    def _create_api_security_tests(self) -> List[SecurityTest]:
        """Create API-specific security tests."""
        tests = [
            SecurityTest(
                test_id="api_sec_1",
                name="HTTP Method Override",
                category="API Security",
                description="Test HTTP method override vulnerability",
                severity="medium",
                payload="",
                expected_response="method_not_allowed",
                endpoint="/api/v1/admin/accounts",
                method="GET",
                headers={"X-HTTP-Method-Override": "DELETE"}
            ),
            SecurityTest(
                test_id="api_sec_2",
                name="CORS Misconfiguration",
                category="API Security",
                description="Test CORS policy",
                severity="medium",
                payload="",
                expected_response="proper_cors",
                endpoint="/api/v1/admin/profile",
                method="OPTIONS",
                headers={"Origin": "https://evil.com"}
            ),
            SecurityTest(
                test_id="api_sec_3",
                name="Content Type Confusion",
                category="API Security",
                description="Test content type confusion",
                severity="medium",
                payload='{"malicious": "payload"}',
                expected_response="content_type_validation",
                endpoint="/api/v1/admin/accounts",
                method="POST",
                headers={"Content-Type": "text/plain"}
            )
        ]
        
        return tests
    
    async def run_security_audit(self, test_categories: List[str] = None) -> Dict[str, Any]:
        """Run comprehensive security audit."""
        self.logger.info("Starting comprehensive security audit...")
        start_time = time.time()
        
        # Select tests to run
        if test_categories:
            tests_to_run = [test for test in self.all_tests if test.category in test_categories]
        else:
            tests_to_run = self.all_tests
        
        # Run tests concurrently
        semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
        tasks = [self._run_single_test(test, semaphore) for test in tests_to_run]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        self.results = [r for r in results if isinstance(r, SecurityTestResult)]
        
        # Generate report
        audit_time = time.time() - start_time
        report = self._generate_security_report(audit_time)
        
        self.logger.info(f"Security audit completed in {audit_time:.2f} seconds")
        return report
    
    async def _run_single_test(self, test: SecurityTest, semaphore: asyncio.Semaphore) -> SecurityTestResult:
        """Run a single security test."""
        async with semaphore:
            try:
                start_time = time.time()
                
                # Prepare request
                url = f"{self.base_url}{test.endpoint}"
                headers = test.headers or {}
                
                # Add payload based on method
                if test.method.upper() == "GET":
                    params = {"q": test.payload} if test.payload else {}
                    data = None
                elif test.method.upper() in ["POST", "PUT", "PATCH"]:
                    if test.category == "File Upload":
                        # Special handling for file uploads
                        files = {"file": ("test.txt", test.payload, "text/plain")}
                        data = None
                    else:
                        data = {"input": test.payload} if test.payload else {}
                        params = {}
                else:
                    params = {}
                    data = None
                
                # Make request
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=test.method,
                        url=url,
                        headers=headers,
                        params=params if test.method.upper() == "GET" else None,
                        json=data if data and test.category != "File Upload" else None,
                        data=data if test.category == "File Upload" else None,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        response_time = time.time() - start_time
                        response_text = await response.text()
                        
                        # Analyze response
                        status, vulnerability_details, recommendation = self._analyze_response(
                            test, response.status, response_text, dict(response.headers)
                        )
                        
                        return SecurityTestResult(
                            test_id=test.test_id,
                            test_name=test.name,
                            category=test.category,
                            severity=test.severity,
                            endpoint=test.endpoint,
                            status=status,
                            response_code=response.status,
                            response_time=response_time,
                            vulnerability_details=vulnerability_details,
                            recommendation=recommendation,
                            timestamp=datetime.now()
                        )
            
            except Exception as e:
                return SecurityTestResult(
                    test_id=test.test_id,
                    test_name=test.name,
                    category=test.category,
                    severity=test.severity,
                    endpoint=test.endpoint,
                    status="error",
                    response_code=0,
                    response_time=0,
                    vulnerability_details=f"Test error: {e}",
                    recommendation="Fix test execution error",
                    timestamp=datetime.now()
                )
    
    def _analyze_response(self, test: SecurityTest, status_code: int, 
                         response_text: str, headers: Dict[str, str]) -> Tuple[str, str, str]:
        """Analyze test response for vulnerabilities."""
        
        if test.category == "SQL Injection":
            return self._analyze_sql_injection(test, status_code, response_text)
        elif test.category == "Cross-Site Scripting":
            return self._analyze_xss(test, status_code, response_text)
        elif test.category == "Authentication Bypass":
            return self._analyze_auth_bypass(test, status_code, response_text)
        elif test.category == "Input Validation":
            return self._analyze_input_validation(test, status_code, response_text)
        elif test.category == "Rate Limiting":
            return self._analyze_rate_limiting(test, status_code, response_text)
        elif test.category == "File Upload":
            return self._analyze_file_upload(test, status_code, response_text)
        elif test.category == "API Security":
            return self._analyze_api_security(test, status_code, response_text, headers)
        else:
            return "passed", "Unknown test category", "Review test implementation"
    
    def _analyze_sql_injection(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze SQL injection test results."""
        # Check for SQL error messages
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
            "sqlite_", "postgresql", "warning: pg_", "valid mysql result",
            "sqlstate", "syntax error", "mysql_num_rows", "mysql_query",
            "ora-00921", "ora-00936", "microsoft jet database"
        ]
        
        response_lower = response_text.lower()
        
        # If we get SQL errors, it's vulnerable
        if any(error in response_lower for error in sql_errors):
            return "vulnerable", f"SQL error detected in response: {response_text[:200]}", "Implement proper input sanitization and parameterized queries"
        
        # If we get 500 error, might be vulnerable
        if status_code == 500:
            return "vulnerable", "Internal server error - possible SQL injection", "Review error handling and input validation"
        
        # If we get normal response with suspicious content
        if status_code == 200 and ("admin" in response_lower or "password" in response_lower):
            return "vulnerable", "Possible data exposure", "Implement proper access controls"
        
        # If properly handled
        if status_code in [400, 422]:
            return "passed", "Input properly validated", "Good input validation"
        
        return "passed", "No SQL injection vulnerability detected", "Continue monitoring"
    
    def _analyze_xss(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze XSS test results."""
        # Check if payload is reflected without encoding
        if test.payload in response_text:
            return "vulnerable", f"XSS payload reflected without encoding: {test.payload}", "Implement proper output encoding and CSP headers"
        
        # Check for partial payload reflection
        dangerous_tags = ["<script", "<img", "<svg", "javascript:", "onerror", "onload"]
        if any(tag in response_text.lower() for tag in dangerous_tags):
            return "vulnerable", "Dangerous HTML tags found in response", "Implement HTML sanitization"
        
        # Check if properly encoded
        encoded_payload = test.payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded_payload in response_text:
            return "passed", "XSS payload properly encoded", "Good output encoding"
        
        return "passed", "No XSS vulnerability detected", "Continue monitoring"
    
    def _analyze_auth_bypass(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze authentication bypass test results."""
        if status_code == 200:
            return "vulnerable", "Access granted without proper authentication", "Implement proper authentication checks"
        
        if status_code in [401, 403]:
            return "passed", "Access properly denied", "Good authentication implementation"
        
        if status_code == 302:
            return "passed", "Redirected to login", "Proper authentication flow"
        
        return "passed", "Authentication appears secure", "Continue monitoring"
    
    def _analyze_input_validation(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze input validation test results."""
        if status_code == 413:
            return "passed", "Request too large - proper size limits", "Good input size validation"
        
        if status_code in [400, 422]:
            return "passed", "Input validation working", "Good input validation"
        
        if status_code == 500:
            return "vulnerable", "Server error on malformed input", "Improve error handling and input validation"
        
        return "passed", "Input validation appears adequate", "Continue monitoring"
    
    def _analyze_rate_limiting(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze rate limiting test results."""
        if status_code == 429:
            return "passed", "Rate limiting active", "Good rate limiting implementation"
        
        return "failed", "No rate limiting detected", "Implement rate limiting"
    
    def _analyze_file_upload(self, test: SecurityTest, status_code: int, response_text: str) -> Tuple[str, str, str]:
        """Analyze file upload test results."""
        if status_code in [400, 415, 422]:
            return "passed", "Malicious file upload blocked", "Good file upload validation"
        
        if status_code == 413:
            return "passed", "File size limit enforced", "Good file size validation"
        
        if status_code == 200:
            return "vulnerable", "File upload succeeded - possible security risk", "Implement file type validation and scanning"
        
        return "passed", "File upload security appears adequate", "Continue monitoring"
    
    def _analyze_api_security(self, test: SecurityTest, status_code: int, response_text: str, headers: Dict[str, str]) -> Tuple[str, str, str]:
        """Analyze API security test results."""
        if test.test_id == "api_sec_2":  # CORS test
            cors_header = headers.get("access-control-allow-origin", "")
            if cors_header == "*":
                return "vulnerable", "Wildcard CORS policy", "Implement restrictive CORS policy"
            elif "evil.com" in cors_header:
                return "vulnerable", "Permissive CORS policy", "Restrict CORS origins"
            else:
                return "passed", "CORS policy appears secure", "Good CORS implementation"
        
        if status_code in [405, 400]:
            return "passed", "API security controls working", "Good API security"
        
        return "passed", "API security appears adequate", "Continue monitoring"
    
    def _generate_security_report(self, audit_time: float) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        total_tests = len(self.results)
        vulnerable_tests = [r for r in self.results if r.status == "vulnerable"]
        failed_tests = [r for r in self.results if r.status == "failed"]
        passed_tests = [r for r in self.results if r.status == "passed"]
        error_tests = [r for r in self.results if r.status == "error"]
        
        # Categorize by severity
        critical_vulns = [r for r in vulnerable_tests if r.severity == "critical"]
        high_vulns = [r for r in vulnerable_tests if r.severity == "high"]
        medium_vulns = [r for r in vulnerable_tests if r.severity == "medium"]
        low_vulns = [r for r in vulnerable_tests if r.severity == "low"]
        
        # Calculate security score
        security_score = self._calculate_security_score(total_tests, vulnerable_tests, failed_tests)
        
        return {
            "audit_summary": {
                "total_tests": total_tests,
                "audit_time_seconds": audit_time,
                "security_score": security_score,
                "overall_status": "SECURE" if security_score >= 80 else "VULNERABLE" if security_score >= 60 else "CRITICAL"
            },
            "test_results": {
                "passed": len(passed_tests),
                "vulnerable": len(vulnerable_tests),
                "failed": len(failed_tests),
                "errors": len(error_tests)
            },
            "vulnerability_breakdown": {
                "critical": len(critical_vulns),
                "high": len(high_vulns),
                "medium": len(medium_vulns),
                "low": len(low_vulns)
            },
            "vulnerabilities": [
                {
                    "test_id": r.test_id,
                    "test_name": r.test_name,
                    "category": r.category,
                    "severity": r.severity,
                    "endpoint": r.endpoint,
                    "details": r.vulnerability_details,
                    "recommendation": r.recommendation,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in vulnerable_tests
            ],
            "failed_tests": [
                {
                    "test_id": r.test_id,
                    "test_name": r.test_name,
                    "category": r.category,
                    "endpoint": r.endpoint,
                    "details": r.vulnerability_details,
                    "recommendation": r.recommendation
                }
                for r in failed_tests
            ],
            "recommendations": self._generate_recommendations(vulnerable_tests, failed_tests),
            "next_audit": (datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + 
                          timedelta(days=7)).isoformat()
        }
    
    def _calculate_security_score(self, total_tests: int, vulnerable_tests: List[SecurityTestResult], 
                                 failed_tests: List[SecurityTestResult]) -> float:
        """Calculate overall security score (0-100)."""
        if total_tests == 0:
            return 0
        
        # Weight vulnerabilities by severity
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        
        vulnerability_penalty = sum(
            severity_weights.get(vuln.severity, 1) for vuln in vulnerable_tests
        )
        
        failed_penalty = len(failed_tests) * 2
        
        max_possible_penalty = total_tests * 10  # Assuming all critical
        total_penalty = vulnerability_penalty + failed_penalty
        
        score = max(0, 100 - (total_penalty / max_possible_penalty * 100))
        return round(score, 2)
    
    def _generate_recommendations(self, vulnerable_tests: List[SecurityTestResult], 
                                 failed_tests: List[SecurityTestResult]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Group by category
        categories = {}
        for test in vulnerable_tests + failed_tests:
            if test.category not in categories:
                categories[test.category] = []
            categories[test.category].append(test)
        
        # Generate category-specific recommendations
        for category, tests in categories.items():
            if category == "SQL Injection":
                recommendations.append("Implement parameterized queries and input sanitization")
            elif category == "Cross-Site Scripting":
                recommendations.append("Implement output encoding and Content Security Policy")
            elif category == "Authentication Bypass":
                recommendations.append("Review authentication and authorization mechanisms")
            elif category == "Rate Limiting":
                recommendations.append("Implement comprehensive rate limiting")
            elif category == "File Upload":
                recommendations.append("Implement file type validation and virus scanning")
            elif category == "API Security":
                recommendations.append("Review API security configurations")
        
        # Add general recommendations
        if vulnerable_tests:
            recommendations.extend([
                "Conduct regular security audits",
                "Implement Web Application Firewall (WAF)",
                "Enable security headers (HSTS, CSP, X-Frame-Options)",
                "Regular security training for development team"
            ])
        
        return list(set(recommendations))  # Remove duplicates

# Global penetration tester instance
penetration_tester = PenetrationTester()

# FastAPI dependency
async def get_penetration_tester():
    return penetration_tester
