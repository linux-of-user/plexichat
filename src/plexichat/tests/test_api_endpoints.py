# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
API Endpoint Tests

Comprehensive tests for all PlexiChat API endpoints including:
- Authentication endpoints
- User management
- Message operations
- File upload/download
- Admin functions
"""

import asyncio
import json
import logging
import requests
import time
from pathlib import Path
from typing import Dict, Any, Optional

from . import TestSuite, TestResult, TEST_CONFIG

logger = logging.getLogger(__name__)

class APIEndpointTests(TestSuite):
    """Test suite for API endpoints."""

    def __init__(self):
        super().__init__("API Endpoints", "api")
        self.base_url = TEST_CONFIG['base_url']
        self.session = requests.Session()
        self.auth_token = None
        self.test_user_id = None
        self.test_message_id = None
        self.test_file_id = None

        # Register tests
        self.tests = [
            self.test_health_check,
            self.test_api_version,
            self.test_user_registration,
            self.test_user_login,
            self.test_user_profile,
            self.test_message_creation,
            self.test_message_retrieval,
            self.test_message_listing,
            self.test_file_upload,
            self.test_file_download,
            self.test_admin_endpoints,
            self.test_rate_limiting,
            self.test_error_handling
        ]

    async def setup(self):
        """Setup test environment."""
        await super().setup()

        # Create test file
        self.test_file_path = TEST_CONFIG['temp_dir'] / 'test_upload.txt'
        with open(self.test_file_path, 'w') as f:
            f.write("Test file content for API endpoint testing\n")
            f.write(f"Created at: {time.time()}\n")
            f.write("This file contains test data including emojis: 🚀 🎉 ✅\n")

    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with proper headers."""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})

        if self.auth_token:
            headers['Authorization'] = f"Bearer {self.auth_token}"

        headers.setdefault('Accept', 'application/json')

        return self.session.request(method, url, headers=headers, timeout=TEST_CONFIG['timeout'], **kwargs)

    def test_health_check(self):
        """Test health check endpoint."""
        response = self.make_request('GET', '/health')
        assert response.status_code == 200, f"Health check failed: {response.status_code}"

        data = response.json()
        assert 'status' in data, "Health check response missing status"
        assert data['status'] == 'healthy', f"Service not healthy: {data.get('status')}"

    def test_api_version(self):
        """Test API version endpoint."""
        response = self.make_request('GET', '/api/v1/version')
        assert response.status_code == 200, f"Version check failed: {response.status_code}"

        data = response.json()
        assert 'version' in data, "Version response missing version field"
        assert 'api_version' in data, "Version response missing api_version field"

    def test_user_registration(self):
        """Test user registration."""
        user_data = {
            'username': f'testuser_{int(time.time())}',
            'email': f'test_{int(time.time())}@example.com',
            'password': 'TestPassword123!',
            'full_name': 'Test User'
        }

        response = self.make_request('POST', '/api/v1/auth/register', json=user_data)
        assert response.status_code in [200, 201], f"Registration failed: {response.status_code} - {response.text}"

        data = response.json()
        assert 'user_id' in data or 'id' in data, "Registration response missing user ID"
        self.test_user_id = data.get('user_id') or data.get('id')

    def test_user_login(self):
        """Test user login."""
        if not self.test_user_id:
            self.test_user_registration()

        login_data = {
            'username': f'testuser_{int(time.time())}',
            'password': 'TestPassword123!'
        }

        response = self.make_request('POST', '/api/v1/auth/login', json=login_data)

        # If login fails, try with form data
        if response.status_code != 200:
            response = self.make_request('POST', '/api/v1/auth/login', data=login_data)

        if response.status_code == 200:
            data = response.json()
            if 'access_token' in data:
                self.auth_token = data['access_token']
            elif 'token' in data:
                self.auth_token = data['token']

    def test_user_profile(self):
        """Test user profile retrieval."""
        if not self.auth_token:
            self.test_user_login()

        response = self.make_request('GET', '/api/v1/users/me')

        # Profile endpoint might be at different location
        if response.status_code == 404:
            response = self.make_request('GET', '/api/v1/user/profile')

        if response.status_code == 200:
            data = response.json()
            assert 'username' in data or 'email' in data, "Profile response missing user data"

    def test_message_creation(self):
        """Test message creation."""
        message_data = {
            'content': 'Test message with emojis 🚀 and special chars: <script>alert("test")</script>',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=message_data)

        # Try with form data if JSON fails
        if response.status_code not in [200, 201]:
            response = self.make_request('POST', '/api/v1/messages/create', data=message_data)

        if response.status_code in [200, 201]:
            data = response.json()
            self.test_message_id = data.get('id') or data.get('message_id')

    def test_message_retrieval(self):
        """Test message retrieval."""
        if not self.test_message_id:
            self.test_message_creation()

        if self.test_message_id:
            response = self.make_request('GET', f'/api/v1/messages/{self.test_message_id}')

            if response.status_code == 200:
                data = response.json()
                assert 'content' in data, "Message response missing content"

    def test_message_listing(self):
        """Test message listing."""
        response = self.make_request('GET', '/api/v1/messages')

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict)), "Messages response should be list or dict"

    def test_file_upload(self):
        """Test file upload."""
        with open(self.test_file_path, 'rb') as f:
            files = {'file': f}
            response = self.make_request('POST', '/api/v1/files/upload', files=files)

        if response.status_code in [200, 201]:
            data = response.json()
            self.test_file_id = data.get('file_id') or data.get('id')

    def test_file_download(self):
        """Test file download."""
        if not self.test_file_id:
            self.test_file_upload()

        if self.test_file_id:
            response = self.make_request('GET', f'/api/v1/files/{self.test_file_id}')

            if response.status_code == 200:
                assert len(response.content) > 0, "Downloaded file is empty"

    def test_admin_endpoints(self):
        """Test admin endpoints (if accessible)."""
        endpoints = [
            '/api/v1/admin/users',
            '/api/v1/admin/stats',
            '/api/v1/admin/system'
        ]

        for endpoint in endpoints:
            response = self.make_request('GET', endpoint)
            # Admin endpoints might return 401/403, which is expected
            assert response.status_code in [200, 401, 403, 404], f"Unexpected status for {endpoint}: {response.status_code}"

    def test_rate_limiting(self):
        """Test rate limiting."""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = self.make_request('GET', '/health')
            responses.append(response.status_code)

        # Check if any requests were rate limited (429)
        rate_limited = any(status == 429 for status in responses)
        logger.info(f"Rate limiting test: {rate_limited} (responses: {responses})")

    def test_error_handling(self):
        """Test error handling."""
        # Test invalid endpoint
        response = self.make_request('GET', '/api/v1/nonexistent')
        assert response.status_code == 404, f"Expected 404 for invalid endpoint, got {response.status_code}"

        # Test invalid method
        response = self.make_request('DELETE', '/health')
        assert response.status_code in [405, 404], f"Expected 405/404 for invalid method, got {response.status_code}"

# Create test suite instance
api_tests = APIEndpointTests()
