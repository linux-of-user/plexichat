"""
Feature Tests

Tests for specific PlexiChat features including:
- Rich text messaging
- Emoji support
- File attachments
- Notifications
- Collaboration features
- Real-time messaging
- Message formatting
"""

import asyncio
import json
import logging
import requests
import time
try:
    import websocket
except ImportError:
    # Fallback if websocket-client not available
    websocket = None
from pathlib import Path
from typing import Dict, Any, List

from . import TestSuite, TestResult, TEST_CONFIG

logger = logging.getLogger(__name__)

class FeatureTests(TestSuite):
    """Test suite for PlexiChat features."""

    def __init__(self):
        super().__init__("Features", "features")
        self.base_url = TEST_CONFIG['base_url']
        self.session = requests.Session()
        self.auth_token = None

        # Register tests
        self.tests = [
            self.test_rich_text_messaging,
            self.test_emoji_support,
            self.test_file_attachments,
            self.test_message_formatting,
            self.test_notifications,
            self.test_collaboration_features,
            self.test_real_time_messaging,
            self.test_message_search,
            self.test_user_presence,
            self.test_message_reactions,
            self.test_thread_support,
            self.test_message_editing
        ]

    async def setup(self):
        """Setup test environment."""
        await super().setup()

        # Create test files with different types
        self.create_test_files()

        # Attempt to get auth token
        await self.get_auth_token()

    def create_test_files(self):
        """Create test files for attachment testing."""
        test_files = {
            'text_file.txt': 'This is a test text file with emojis 🚀 and special characters: àáâãäå',
            'json_file.json': json.dumps({'test': 'data', 'emoji': '🎉', 'number': 42}),
            'markdown_file.md': '# Test Markdown\n\n**Bold text** with *italic* and `code`\n\n- List item 1\n- List item 2 🔥',
            'csv_file.csv': 'name,age,emoji\nJohn,25,😊\nJane,30,🎈\nBob,35,🚀'
        }

        for filename, content in test_files.items():
            file_path = TEST_CONFIG['temp_dir'] / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

    async def get_auth_token(self):
        """Get authentication token for testing."""
        try:
            # Try to register and login a test user
            user_data = {
                'username': f'featuretest_{int(time.time())}',
                'email': f'featuretest_{int(time.time())}@example.com',
                'password': 'TestPassword123!'
            }

            # Register
            response = self.make_request('POST', '/api/v1/auth/register', json=user_data)

            # Login
            login_data = {'username': user_data['username'], 'password': user_data['password']}
            response = self.make_request('POST', '/api/v1/auth/login', json=login_data)

            if response.status_code == 200:
                data = response.json()
                self.auth_token = data.get('access_token') or data.get('token')
        except Exception as e:
            logger.warning(f"Could not get auth token: {e}")

    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with authentication."""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})

        if self.auth_token:
            headers['Authorization'] = f"Bearer {self.auth_token}"

        return self.session.request(method, url, headers=headers, timeout=TEST_CONFIG['timeout'], **kwargs)

    def test_rich_text_messaging(self):
        """Test rich text message support."""
        rich_text_messages = [
            {
                'content': '**Bold text** and *italic text* with `inline code`',
                'format': 'markdown'
            },
            {
                'content': '<b>HTML bold</b> and <i>HTML italic</i>',
                'format': 'html'
            },
            {
                'content': 'Text with [link](https://example.com) and ![image](https://example.com/image.png)',
                'format': 'markdown'
            }
        ]

        for message in rich_text_messages:
            data = {
                'content': message['content'],
                'message_type': 'rich_text',
                'format': message.get('format', 'markdown')
            }

            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response.status_code in [200, 201]:
                logger.info(f"Rich text message created: {message['format']}")
            else:
                logger.warning(f"Rich text message failed: {response.status_code}")

    def test_emoji_support(self):
        """Test emoji support in messages."""
        emoji_messages = [
            '🚀 Rocket emoji',
            '😀😃😄😁😆😅😂🤣😊😇',  # Multiple emojis
            '👨‍💻 Man technologist (compound emoji)',
            '🏳️‍🌈 Rainbow flag (compound emoji)',
            '🇺🇸 Country flag emoji',
            '1️⃣2️⃣3️⃣ Number emojis',
            '❤️💙💚💛💜 Heart emojis',
            '🎉🎊🎈🎁🎂 Party emojis'
        ]

        for emoji_content in emoji_messages:
            data = {
                'content': emoji_content,
                'message_type': 'text'
            }

            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response.status_code in [200, 201]:
                # Verify emoji is preserved
                message_data = response.json()
                if 'content' in message_data:
                    assert emoji_content in message_data['content'], "Emoji not preserved in message"
                logger.info(f"Emoji message created: {emoji_content[:20]}...")

    def test_file_attachments(self):
        """Test file attachment functionality."""
        test_files = [
            'text_file.txt',
            'json_file.json',
            'markdown_file.md',
            'csv_file.csv'
        ]

        uploaded_files = []

        for filename in test_files:
            file_path = TEST_CONFIG['temp_dir'] / filename

            with open(file_path, 'rb') as f:
                files = {'file': (filename, f, 'text/plain')}
                response = self.make_request('POST', '/api/v1/files/upload', files=files)

            if response.status_code in [200, 201]:
                data = response.json()
                file_id = data.get('file_id') or data.get('id')
                uploaded_files.append((filename, file_id))
                logger.info(f"File uploaded: {filename}")

        # Test creating message with file attachments
        if uploaded_files:
            file_ids = [file_id for _, file_id in uploaded_files]
            data = {
                'content': 'Message with file attachments 📎',
                'message_type': 'text',
                'attachments': file_ids
            }

            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response.status_code in [200, 201]:
                logger.info("Message with attachments created")

    def test_message_formatting(self):
        """Test message formatting options."""
        formatted_messages = [
            {
                'content': 'Code block:\n```python\nprint("Hello, World!")\n```',
                'type': 'code'
            },
            {
                'content': '> This is a quote\n> With multiple lines',
                'type': 'quote'
            },
            {
                'content': '# Heading 1\n## Heading 2\n### Heading 3',
                'type': 'heading'
            },
            {
                'content': '- [ ] Todo item 1\n- [x] Completed item\n- [ ] Todo item 2',
                'type': 'checklist'
            }
        ]

        for message in formatted_messages:
            data = {
                'content': message['content'],
                'message_type': message['type']
            }

            response = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response.status_code in [200, 201]:
                logger.info(f"Formatted message created: {message['type']}")

    def test_notifications(self):
        """Test notification system."""
        # Test notification preferences
        notification_settings = {
            'email_notifications': True,
            'push_notifications': True,
            'mention_notifications': True,
            'dm_notifications': True
        }

        response = self.make_request('PUT', '/api/v1/users/notifications', json=notification_settings)

        if response.status_code in [200, 204]:
            logger.info("Notification settings updated")

        # Test mention notification
        mention_message = {
            'content': '@testuser This is a mention test 📢',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=mention_message)

        if response.status_code in [200, 201]:
            logger.info("Mention message created")

    def test_collaboration_features(self):
        """Test collaboration features."""
        # Test creating a shared workspace/channel
        workspace_data = {
            'name': f'Test Workspace {int(time.time())}',
            'description': 'Test workspace for collaboration features',
            'type': 'public'
        }

        response = self.make_request('POST', '/api/v1/workspaces/create', json=workspace_data)

        if response.status_code in [200, 201]:
            workspace_data = response.json()
            workspace_id = workspace_data.get('id')
            logger.info(f"Workspace created: {workspace_id}")

            # Test inviting users to workspace
            invite_data = {
                'email': 'collaborator@example.com',
                'role': 'member'
            }

            response = self.make_request('POST', f'/api/v1/workspaces/{workspace_id}/invite', json=invite_data)

            if response.status_code in [200, 201]:
                logger.info("User invited to workspace")

    def test_real_time_messaging(self):
        """Test real-time messaging via WebSocket."""
        try:
            ws_url = self.base_url.replace('http://', 'ws://').replace('https://', 'wss://')
            ws_url += '/ws'

            # Simple WebSocket connection test
            def on_message(ws, message):
                logger.info(f"WebSocket message received: {message}")

            def on_error(ws, error):
                logger.warning(f"WebSocket error: {error}")

            def on_close(ws, close_status_code, close_msg):
                logger.info("WebSocket connection closed")

            # This is a basic test - in practice, you'd want more sophisticated WebSocket testing
            logger.info("WebSocket real-time messaging test (basic connection)")

        except Exception as e:
            logger.warning(f"WebSocket test failed: {e}")

    def test_message_search(self):
        """Test message search functionality."""
        search_queries = [
            'test',
            'emoji',
            '🚀',
            'attachment'
        ]

        for query in search_queries:
            params = {'q': query, 'limit': 10}
            response = self.make_request('GET', '/api/v1/messages/search', params=params)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Search for '{query}': {len(data.get('results', []))} results")

    def test_user_presence(self):
        """Test user presence/status features."""
        presence_data = {
            'status': 'online',
            'message': 'Working on tests 🧪'
        }

        response = self.make_request('PUT', '/api/v1/users/presence', json=presence_data)

        if response.status_code in [200, 204]:
            logger.info("User presence updated")

    def test_message_reactions(self):
        """Test message reaction features."""
        # First create a message
        message_data = {
            'content': 'React to this message! 👍',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=message_data)

        if response.status_code in [200, 201]:
            message_id = response.json().get('id')

            if message_id:
                # Add reactions
                reactions = ['👍', '❤️', '😂', '🎉']

                for emoji in reactions:
                    reaction_data = {'emoji': emoji}
                    response = self.make_request('POST', f'/api/v1/messages/{message_id}/reactions', json=reaction_data)

                    if response.status_code in [200, 201]:
                        logger.info(f"Reaction added: {emoji}")

    def test_thread_support(self):
        """Test message threading features."""
        # Create parent message
        parent_message = {
            'content': 'This is a parent message for threading test 🧵',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=parent_message)

        if response.status_code in [200, 201]:
            parent_id = response.json().get('id')

            if parent_id:
                # Create thread reply
                thread_reply = {
                    'content': 'This is a thread reply 💬',
                    'message_type': 'text',
                    'parent_id': parent_id
                }

                response = self.make_request('POST', '/api/v1/messages/create', json=thread_reply)

                if response.status_code in [200, 201]:
                    logger.info("Thread reply created")

    def test_message_editing(self):
        """Test message editing functionality."""
        # Create message
        original_message = {
            'content': 'Original message content',
            'message_type': 'text'
        }

        response = self.make_request('POST', '/api/v1/messages/create', json=original_message)

        if response.status_code in [200, 201]:
            message_id = response.json().get('id')

            if message_id:
                # Edit message
                edited_content = {
                    'content': 'Edited message content ✏️',
                    'edited': True
                }

                response = self.make_request('PUT', f'/api/v1/messages/{message_id}', json=edited_content)

                if response.status_code in [200, 204]:
                    logger.info("Message edited successfully")

# Create test suite instance
feature_tests = FeatureTests()
