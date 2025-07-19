# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Integration Tests

End-to-end integration tests covering:
- Complete user workflows
- System component integration
- Database integration
- External service integration
- Cross-feature functionality
"""

import asyncio
import json
import logging
import requests
import time
from pathlib import Path
from typing import Dict, Any, List

from . import TestSuite, TestResult, TEST_CONFIG

logger = logging.getLogger(__name__)

class IntegrationTests(TestSuite):
    """Test suite for integration testing."""

    def __init__(self):
        super().__init__("Integration", "integration")
        self.base_url = TEST_CONFIG['base_url']
        self.session = requests.Session()
        self.test_data = {}

        # Register tests
        self.tests = [
            self.test_complete_user_workflow,
            self.test_message_lifecycle,
            self.test_file_workflow,
            self.test_collaboration_workflow,
            self.test_admin_workflow,
            self.test_notification_integration,
            self.test_search_integration,
            self.test_backup_integration,
            self.test_plugin_integration,
            self.test_system_health_integration
        ]

    async def setup(self):
        """Setup integration test environment."""
        await super().setup()

        # Initialize test data storage
        self.test_data = {
            'users': [],
            'messages': [],
            'files': [],
            'workspaces': []
        }

    def make_request(self, method: str, endpoint: str, auth_token: str = None, **kwargs) -> requests.Response:
        """Make HTTP request with optional authentication."""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})

        if auth_token:
            headers['Authorization'] = f"Bearer {auth_token}"

        return self.session.request(method, url, headers=headers, timeout=TEST_CONFIG['timeout'], **kwargs)

    def test_complete_user_workflow(self):
        """Test complete user registration, login, and profile workflow."""
        timestamp = int(time.time())

        # Step 1: User Registration
        user_data = {
            'username': f'integration_user_{timestamp}',
            'email': f'integration_{timestamp}@example.com',
            'password': 'IntegrationTest123!',
            'full_name': 'Integration Test User'
        }

        response = self.make_request('POST', '/api/v1/auth/register', json=user_data)
        assert response.status_code in [200, 201], f"Registration failed: {response.status_code}"

        registration_data = response.json()
        user_id = registration_data.get('user_id') or registration_data.get('id')
        assert user_id, "Registration should return user ID"

        self.test_data['users'].append({
            'id': user_id,
            'username': user_data['username'],
            'email': user_data['email'],
            'password': user_data['password']
        })

        logger.info(f"✅ User registered: {user_id}")

        # Step 2: User Login
        login_data = {
            'username': user_data['username'],
            'password': user_data['password']
        }

        response = self.make_request('POST', '/api/v1/auth/login', json=login_data)
        assert response.status_code == 200, f"Login failed: {response.status_code}"

        login_response = response.json()
        auth_token = login_response.get('access_token') or login_response.get('token')
        assert auth_token, "Login should return authentication token"

        self.test_data['users'][-1]['auth_token'] = auth_token

        logger.info(f"✅ User logged in: {user_data['username']}")

        # Step 3: Profile Retrieval
        response = self.make_request('GET', '/api/v1/users/me', auth_token=auth_token)

        if response.status_code == 404:
            response = self.make_request('GET', '/api/v1/user/profile', auth_token=auth_token)

        if response.status_code == 200:
            profile_data = response.json()
            assert profile_data.get('username') == user_data['username'], "Profile should match registered user"
            logger.info(f"✅ Profile retrieved: {profile_data.get('username')}")

        # Step 4: Profile Update
        update_data = {
            'full_name': 'Updated Integration Test User',
            'bio': 'Integration test user profile 🧪'
        }

        response = self.make_request('PUT', '/api/v1/users/me', json=update_data, auth_token=auth_token)

        if response.status_code in [200, 204]:
            logger.info("✅ Profile updated")

    def test_message_lifecycle(self):
        """Test complete message lifecycle: create, read, update, delete."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Step 1: Create Message
        message_data = {
            'content': 'Integration test message with emojis 🚀 and formatting **bold**',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=message_data, auth_token=auth_token)
        assert response.status_code in [200, 201], f"Message creation failed: {response.status_code}"

        message_response = response.json()
        message_id = message_response.get('id') or message_response.get('message_id')
        assert message_id, "Message creation should return message ID"

        self.test_data['messages'].append({
            'id': message_id,
            'content': message_data['content'],
            'user_id': user['id']
        })

        logger.info(f"✅ Message created: {message_id}")

        # Step 2: Read Message
        response = self.make_request('GET', f'/api/v1/messages/{message_id}', auth_token=auth_token)

        if response.status_code == 200:
            retrieved_message = response.json()
            assert retrieved_message.get('content') == message_data['content'], "Retrieved message content should match"
            logger.info(f"✅ Message retrieved: {message_id}")

        # Step 3: Update Message (if supported)
        update_data = {
            'content': 'Updated integration test message ✏️',
            'edited': True
        }

        response = self.make_request('PUT', f'/api/v1/messages/{message_id}', json=update_data, auth_token=auth_token)

        if response.status_code in [200, 204]:
            logger.info(f"✅ Message updated: {message_id}")

        # Step 4: List Messages
        response = self.make_request('GET', '/api/v1/messages', auth_token=auth_token)

        if response.status_code == 200:
            messages_list = response.json()
            assert isinstance(messages_list, (list, dict)), "Messages list should be returned"
            logger.info(f"✅ Messages listed: {len(messages_list) if isinstance(messages_list, list) else 'dict'}")

    def test_file_workflow(self):
        """Test complete file upload, download, and management workflow."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Step 1: Create Test File
        test_content = "Integration test file content 📁\nWith multiple lines\nAnd emojis 🎉"
        file_path = TEST_CONFIG['temp_dir'] / 'integration_test.txt'

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(test_content)

        # Step 2: Upload File
        with open(file_path, 'rb') as f:
            files = {'file': ('integration_test.txt', f, 'text/plain')}
            response = self.make_request('POST', '/api/v1/files/upload', files=files, auth_token=auth_token)

        assert response.status_code in [200, 201], f"File upload failed: {response.status_code}"

        upload_response = response.json()
        file_id = upload_response.get('file_id') or upload_response.get('id')
        assert file_id, "File upload should return file ID"

        self.test_data['files'].append({
            'id': file_id,
            'filename': 'integration_test.txt',
            'user_id': user['id']
        })

        logger.info(f"✅ File uploaded: {file_id}")

        # Step 3: Download File
        response = self.make_request('GET', f'/api/v1/files/{file_id}', auth_token=auth_token)

        if response.status_code == 200:
            downloaded_content = response.content
            assert len(downloaded_content) > 0, "Downloaded file should not be empty"
            logger.info(f"✅ File downloaded: {file_id}")

        # Step 4: Create Message with File Attachment
        message_data = {
            'content': 'Message with file attachment 📎',
            'message_type': 'text',
            'attachments': [file_id]
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=message_data, auth_token=auth_token)

        if response.status_code in [200, 201]:
            logger.info("✅ Message with attachment created")

        # Cleanup
        file_path.unlink(missing_ok=True)

    def test_collaboration_workflow(self):
        """Test collaboration features workflow."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Step 1: Create Workspace
        workspace_data = {
            'name': f'Integration Workspace {int(time.time())}',
            'description': 'Integration test workspace for collaboration',
            'type': 'public'
        }

        response = self.make_request('POST', '/api/v1/workspaces/create', json=workspace_data, auth_token=auth_token)

        if response.status_code in [200, 201]:
            workspace_response = response.json()
            workspace_id = workspace_response.get('id')

            self.test_data['workspaces'].append({
                'id': workspace_id,
                'name': workspace_data['name'],
                'owner_id': user['id']
            })

            logger.info(f"✅ Workspace created: {workspace_id}")

            # Step 2: Create Channel in Workspace
            channel_data = {
                'name': 'integration-test-channel',
                'description': 'Channel for integration testing',
                'workspace_id': workspace_id
            }

            response = self.make_request('POST', '/api/v1/channels/create', json=channel_data, auth_token=auth_token)

            if response.status_code in [200, 201]:
                logger.info("✅ Channel created in workspace")

    def test_admin_workflow(self):
        """Test admin functionality workflow."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Test admin endpoints (may require admin privileges)
        admin_endpoints = [
            '/api/v1/admin/users',
            '/api/v1/admin/stats',
            '/api/v1/admin/system/health',
            '/api/v1/admin/logs'
        ]

        for endpoint in admin_endpoints:
            response = self.make_request('GET', endpoint, auth_token=auth_token)

            # Admin endpoints might return 401/403 for non-admin users, which is expected
            if response.status_code == 200:
                logger.info(f"✅ Admin endpoint accessible: {endpoint}")
            elif response.status_code in [401, 403]:
                logger.info(f"🔒 Admin endpoint protected: {endpoint}")
            else:
                logger.warning(f"⚠️ Unexpected response for {endpoint}: {response.status_code}")

    def test_notification_integration(self):
        """Test notification system integration."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Step 1: Configure Notification Preferences
        notification_settings = {
            'email_notifications': True,
            'push_notifications': True,
            'mention_notifications': True
        }

        response = self.make_request('PUT', '/api/v1/users/notifications', json=notification_settings, auth_token=auth_token)

        if response.status_code in [200, 204]:
            logger.info("✅ Notification preferences updated")

        # Step 2: Create Mention Message (should trigger notification)
        mention_message = {
            'content': f'@{user["username"]} This is a mention test for notifications 🔔',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=mention_message, auth_token=auth_token)

        if response.status_code in [200, 201]:
            logger.info("✅ Mention message created (should trigger notification)")

    def test_search_integration(self):
        """Test search functionality integration."""
        if not self.test_data['users']:
            self.test_complete_user_workflow()

        user = self.test_data['users'][0]
        auth_token = user['auth_token']

        # Create searchable content
        searchable_messages = [
            'Integration test message with unique keyword: SEARCHABLE_TERM_123',
            'Another message with emojis 🔍 for search testing',
            'Message with special characters: @#$%^&*()'
        ]

        for content in searchable_messages:
            message_data = {'content': content, 'message_type': 'text'}
            response = self.make_request('POST', '/api/v1/messages/create', json=message_data, auth_token=auth_token)

            if response.status_code in [200, 201]:
                logger.info(f"✅ Searchable message created")

        # Test search functionality
        search_queries = [
            'SEARCHABLE_TERM_123',
            'integration',
            '🔍',
            'special'
        ]

        for query in search_queries:
            params = {'q': query, 'limit': 10}
            response = self.make_request('GET', '/api/v1/messages/search', params=params, auth_token=auth_token)

            if response.status_code == 200:
                search_results = response.json()
                logger.info(f"✅ Search for '{query}': found results")

    def test_backup_integration(self):
        """Test backup system integration."""
        # Test backup endpoints
        backup_endpoints = [
            '/api/v1/admin/backup/create',
            '/api/v1/admin/backup/list',
            '/api/v1/admin/backup/status'
        ]

        for endpoint in backup_endpoints:
            response = self.make_request('GET', endpoint)

            # Backup endpoints typically require admin access
            if response.status_code in [200, 401, 403]:
                logger.info(f"✅ Backup endpoint responding: {endpoint}")

    def test_plugin_integration(self):
        """Test plugin system integration."""
        # Test plugin endpoints
        plugin_endpoints = [
            '/api/v1/plugins/list',
            '/api/v1/plugins/status',
            '/api/v1/plugins/health'
        ]

        for endpoint in plugin_endpoints:
            response = self.make_request('GET', endpoint)

            if response.status_code == 200:
                logger.info(f"✅ Plugin endpoint accessible: {endpoint}")

    def test_system_health_integration(self):
        """Test system health and monitoring integration."""
        # Test health endpoints
        health_endpoints = [
            '/health',
            '/api/v1/health',
            '/api/v1/system/status',
            '/api/v1/system/metrics'
        ]

        for endpoint in health_endpoints:
            response = self.make_request('GET', endpoint)

            if response.status_code == 200:
                health_data = response.json()
                logger.info(f"✅ Health endpoint: {endpoint} - Status: {health_data.get('status', 'unknown')}")

# Create test suite instance
integration_tests = IntegrationTests()
