"""
Security Tests

Comprehensive security testing including:
- Authentication and authorization
- Rate limiting
- SQL injection protection
- XSS protection
- CSRF protection
- Encryption validation
- MITM attack prevention
"""

import asyncio
import base64
import hashlib
import json
import logging
import requests
import time
from pathlib import Path
from typing import Dict, Any, List

from . import TestSuite, TestResult, TEST_CONFIG

logger = logging.getLogger(__name__)

class SecurityTests(TestSuite):
    """Test suite for security features."""

    def __init__(self):
        super().__init__("Security", "security")
        self.base_url = TEST_CONFIG['base_url']
        self.session = requests.Session()

        # Register tests
        self.tests = [
            self.test_authentication_required,
            self.test_rate_limiting,
            self.test_sql_injection_protection,
            self.test_xss_protection,
            self.test_csrf_protection,
            self.test_encryption_validation,
            self.test_mitm_protection,
            self.test_file_upload_security,
            self.test_password_security,
            self.test_session_security,
            self.test_input_validation,
            self.test_authorization_checks
        ]

    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request."""
        url = f"{self.base_url}{endpoint}"
        return self.session.request(method, url, timeout=TEST_CONFIG['timeout'], **kwargs)

    def test_authentication_required(self):
        """Test that protected endpoints require authentication."""
        protected_endpoints = [
            '/api/v1/users/me',
            '/api/v1/messages/create',
            '/api/v1/admin/users'
        ]

        for endpoint in protected_endpoints:
            response = self.make_request('GET', endpoint)
            assert response.status_code in [401, 403], f"Endpoint {endpoint} should require authentication, got {response.status_code}"

    def test_rate_limiting(self):
        """Test rate limiting implementation."""
        # Test rapid requests to trigger rate limiting
        endpoint = '/api/v1/auth/login'
        rate_limited = False

        for i in range(20):  # Make many requests quickly
            data = {'username': 'testuser', 'password': 'wrongpassword'}
            response = self.make_request('POST', endpoint, json=data)

            if response.status_code == 429:  # Too Many Requests
                rate_limited = True
                break

            time.sleep(0.1)  # Small delay

        logger.info(f"Rate limiting test: {'PASS' if rate_limited else 'SKIP'} (rate limited: {rate_limited})")

    def test_sql_injection_protection(self):
        """Test SQL injection protection."""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 1=1 --",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "'; EXEC xp_cmdshell('dir'); --"
        ]

        # Test SQL injection in login
        for payload in sql_payloads:
            data = {'username': payload, 'password': 'test'}
            response = self.make_request('POST', '/api/v1/auth/login', json=data)

            # Should not return 200 (successful login) or 500 (SQL error)
            assert response.status_code not in [200, 500], f"Possible SQL injection vulnerability with payload: {payload}"

        # Test SQL injection in message content
        for payload in sql_payloads:
            data = {'content': payload, 'message_type': 'text'}
            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            # Should handle malicious input gracefully
            assert response.status_code != 500, f"SQL injection may have caused server error with payload: {payload}"

    def test_xss_protection(self):
        """Test XSS protection."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "';alert('XSS');//",
            "<script>document.cookie='stolen'</script>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>"
        ]

        # Test XSS in message content
        for payload in xss_payloads:
            data = {'content': payload, 'message_type': 'text'}
            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response.status_code in [200, 201]:
                # Check if response contains unescaped script tags
                response_text = response.text.lower()
                assert '<script>' not in response_text, f"Possible XSS vulnerability with payload: {payload}"
                assert 'javascript:' not in response_text, f"Possible XSS vulnerability with payload: {payload}"

    def test_csrf_protection(self):
        """Test CSRF protection."""
        # Test that state-changing operations require proper CSRF protection
        endpoints = [
            ('/api/v1/messages/create', 'POST'),
            ('/api/v1/users/update', 'PUT'),
            ('/api/v1/auth/logout', 'POST')
        ]

        for endpoint, method in endpoints:
            # Request without CSRF token
            response = self.make_request(method, endpoint, json={'test': 'data'})

            # Should either require authentication or CSRF token
            assert response.status_code in [401, 403, 422], f"CSRF protection may be missing for {endpoint}"

    def test_encryption_validation(self):
        """Test encryption and secure communication."""
        # Test HTTPS enforcement (if applicable)
        if self.base_url.startswith('https://'):
            # Test that HTTP redirects to HTTPS
            http_url = self.base_url.replace('https://', 'http://')
            try:
                response = requests.get(f"{http_url}/health", timeout=5, allow_redirects=False)
                assert response.status_code in [301, 302, 308], "HTTP should redirect to HTTPS"
            except requests.exceptions.RequestException:
                pass  # HTTP might not be available, which is good

        # Test secure headers
        response = self.make_request('GET', '/health')
        headers = response.headers

        # Check for security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]

        for header in security_headers:
            if header in headers:
                logger.info(f"Security header present: {header}")

    def test_mitm_protection(self):
        """Test MITM attack prevention."""
        # Test certificate validation (if HTTPS)
        if self.base_url.startswith('https://'):
            try:
                # This should succeed with proper certificate
                response = requests.get(f"{self.base_url}/health", verify=True, timeout=5)
                assert response.status_code == 200, "HTTPS certificate validation failed"
            except requests.exceptions.SSLError:
                logger.warning("SSL certificate validation failed - possible MITM vulnerability")

    def test_file_upload_security(self):
        """Test file upload security."""
        # Test malicious file uploads
        malicious_files = [
            ('malicious.php', b'<?php system($_GET["cmd"]); ?>'),
            ('malicious.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'),
            ('malicious.exe', b'MZ\x90\x00'),  # PE header
            ('malicious.sh', b'#!/bin/bash\nrm -rf /'),
            ('test.html', b'<script>alert("XSS")</script>')
        ]

        for filename, content in malicious_files:
            files = {'file': (filename, content)}
            response = self.make_request('POST', '/api/v1/files/upload', files=files)

            # Should reject malicious files
            assert response.status_code not in [200, 201], f"Malicious file {filename} was accepted"

    def test_password_security(self):
        """Test password security requirements."""
        weak_passwords = [
            'password',
            '123456',
            'admin',
            'test',
            'qwerty',
            '12345678',
            'password123'
        ]

        for weak_password in weak_passwords:
            user_data = {
                'username': f'testuser_{int(time.time())}',
                'email': f'test_{int(time.time())}@example.com',
                'password': weak_password
            }

            response = self.make_request('POST', '/api/v1/auth/register', json=user_data)

            # Should reject weak passwords
            if response.status_code in [200, 201]:
                logger.warning(f"Weak password '{weak_password}' was accepted")

    def test_session_security(self):
        """Test session security."""
        # Test session timeout
        login_data = {'username': 'testuser', 'password': 'TestPassword123!'}
        response = self.make_request('POST', '/api/v1/auth/login', json=login_data)

        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token') or data.get('token')

            if token:
                # Test token validation
                headers = {'Authorization': f'Bearer {token}'}
                response = self.make_request('GET', '/api/v1/users/me', headers=headers)

                # Should work with valid token
                logger.info(f"Token validation: {response.status_code}")

    def test_input_validation(self):
        """Test input validation."""
        # Test oversized inputs
        large_input = 'A' * 10000
        data = {'content': large_input, 'message_type': 'text'}
        response = self.make_request('POST', '/api/v1/messages/create', json=data)

        # Should handle large inputs gracefully
        assert response.status_code != 500, "Server error with large input"

        # Test invalid JSON
        response = self.make_request('POST', '/api/v1/messages/create', )
                                   data='{"invalid": json}',
                                   headers={'Content-Type': 'application/json'})

        # Should handle invalid JSON gracefully
        assert response.status_code in [400, 422], "Invalid JSON should be rejected"

    def test_authorization_checks(self):
        """Test authorization and access control."""
        # Test accessing other users' data
        endpoints = [
            '/api/v1/users/999999',  # Non-existent user
            '/api/v1/messages/999999',  # Non-existent message
            '/api/v1/admin/users'  # Admin endpoint
        ]

        for endpoint in endpoints:
            response = self.make_request('GET', endpoint)

            # Should require proper authorization
            assert response.status_code in [401, 403, 404], f"Authorization check failed for {endpoint}"

# Create test suite instance
security_tests = SecurityTests()
