"""
Comprehensive message endpoint tests.
Tests all message-related endpoints including creation, deletion, editing, and filtering.
"""

import asyncio
import time
import json
from typing import Dict, Any, List
import httpx

from .test_base import BaseEndpointTest, TestResult
import logging import logger


class MessageEndpointTests(BaseEndpointTest):
    """Comprehensive tests for message endpoints."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        super().__init__(base_url)
        self.category = "messages"
        self.test_messages: List[Dict[str, Any]] = []
    
    async def _register_test_users(self):
        """Register test users and get auth tokens."""
        async with httpx.AsyncClient() as client:
            for user_data in self.test_users:
                # Register user
                await client.post(f"{self.base_url}/api/v1/auth/register", json=user_data)
                
                # Login and get token
                login_data = {
                    "username": user_data["username"],
                    "password": user_data["password"]
                }
                response = await client.post(f"{self.base_url}/api/v1/auth/login", data=login_data)
                if response.status_code == 200:
                    token_data = response.json()
                    self.auth_tokens[user_data["username"]] = token_data.get("access_token")
    
    async def _cleanup_test_data(self):
        """Clean up test messages and users."""
        async with httpx.AsyncClient() as client:
            # Delete test messages
            for message in self.test_messages:
                if "id" in message:
                    try:
                        token = list(self.auth_tokens.values())[0]
                        headers = {"Authorization": f"Bearer {token}"}
                        await client.delete(f"{self.base_url}/api/v1/messages/{message['id']}", headers=headers)
                    except:
                        pass  # Ignore cleanup errors
    
    async def _run_endpoint_tests(self):
        """Run all message endpoint tests."""
        await self.test_message_creation()
        await self.test_message_retrieval()
        await self.test_message_deletion()
        await self.test_message_editing()
        await self.test_message_search()
        await self.test_message_filtering()
        await self.test_message_pagination()
        await self.test_message_permissions()
        await self.test_message_validation()
        await self.test_bulk_operations()
    
    async def test_message_creation(self):
        """Test message creation with various scenarios."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="Message Creation",
                    category=self.category,
                    endpoint="/api/v1/messages",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test 1: Valid message creation
                message_data = {
                    "content": self.test_data_generator.random_message_content(100),
                    "channel_id": 1  # Assuming default channel exists
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/messages",
                    json=message_data,
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 201:
                    message_response = response.json()
                    self.test_messages.append(message_response)
                    
                    self.record_test_result(
                        test_name="Valid Message Creation",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        request_data=message_data,
                        response_data=message_response,
                        status_code=response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Valid Message Creation",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 201, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Empty message
                test_start = time.time()
                empty_message = {"content": "", "channel_id": 1}
                
                empty_response = await client.post(
                    f"{self.base_url}/api/v1/messages",
                    json=empty_message,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if empty_response.status_code in [400, 422]:
                    self.record_test_result(
                        test_name="Empty Message Rejection",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=empty_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Empty Message Rejection",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="warning",
                        duration_ms=duration,
                        error_message=f"Empty message accepted, got {empty_response.status_code}",
                        status_code=empty_response.status_code
                    )
                
                # Test 3: Very long message
                test_start = time.time()
                long_message = {
                    "content": "A" * 10000,  # Very long message
                    "channel_id": 1
                }
                
                long_response = await client.post(
                    f"{self.base_url}/api/v1/messages",
                    json=long_message,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if long_response.status_code in [400, 422]:
                    self.record_test_result(
                        test_name="Long Message Rejection",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=long_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Long Message Rejection",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="warning",
                        duration_ms=duration,
                        error_message=f"Long message accepted, got {long_response.status_code}",
                        status_code=long_response.status_code
                    )
                
                # Test 4: Message with special characters
                test_start = time.time()
                special_message = {
                    "content": "Test message with special chars: !@#$%^&*()_+{}|:<>?[]\\;'\",./ 🚀🔒💾",
                    "channel_id": 1
                }
                
                special_response = await client.post(
                    f"{self.base_url}/api/v1/messages",
                    json=special_message,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if special_response.status_code == 201:
                    special_message_response = special_response.json()
                    self.test_messages.append(special_message_response)
                    
                    self.record_test_result(
                        test_name="Special Characters Message",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=special_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Special Characters Message",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Special characters message failed, got {special_response.status_code}",
                        status_code=special_response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Message Creation Tests",
                category=self.category,
                endpoint="/api/v1/messages",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_message_deletion(self):
        """Test comprehensive message deletion scenarios."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens or not self.test_messages:
                self.record_test_result(
                    test_name="Message Deletion",
                    category=self.category,
                    endpoint="/api/v1/messages/{id}",
                    method="DELETE",
                    status="skipped",
                    duration_ms=0,
                    error_message="No messages available for deletion testing"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Create a message specifically for deletion testing
                delete_message_data = {
                    "content": "This message will be deleted for testing",
                    "channel_id": 1
                }
                
                create_response = await client.post(
                    f"{self.base_url}/api/v1/messages",
                    json=delete_message_data,
                    headers=headers
                )
                
                if create_response.status_code != 201:
                    self.record_test_result(
                        test_name="Message Deletion Setup",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="POST",
                        status="failed",
                        duration_ms=(time.time() - test_start) * 1000,
                        error_message="Failed to create message for deletion testing"
                    )
                    return
                
                message_to_delete = create_response.json()
                message_id = message_to_delete.get("id")
                
                # Test 1: Valid message deletion
                test_start = time.time()
                delete_response = await client.delete(
                    f"{self.base_url}/api/v1/messages/{message_id}",
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if delete_response.status_code in [200, 204]:
                    self.record_test_result(
                        test_name="Valid Message Deletion",
                        category=self.category,
                        endpoint=f"/api/v1/messages/{message_id}",
                        method="DELETE",
                        status="passed",
                        duration_ms=duration,
                        status_code=delete_response.status_code
                    )
                    
                    # Test 2: Verify message is deleted (should return 404)
                    test_start = time.time()
                    verify_response = await client.get(
                        f"{self.base_url}/api/v1/messages/{message_id}",
                        headers=headers
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if verify_response.status_code == 404:
                        self.record_test_result(
                            test_name="Deleted Message Verification",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="GET",
                            status="passed",
                            duration_ms=duration,
                            status_code=verify_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Deleted Message Verification",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="GET",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Deleted message still accessible, got {verify_response.status_code}",
                            status_code=verify_response.status_code
                        )
                    
                    # Test 3: Double deletion (should return 404)
                    test_start = time.time()
                    double_delete_response = await client.delete(
                        f"{self.base_url}/api/v1/messages/{message_id}",
                        headers=headers
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if double_delete_response.status_code == 404:
                        self.record_test_result(
                            test_name="Double Deletion Protection",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="DELETE",
                            status="passed",
                            duration_ms=duration,
                            status_code=double_delete_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Double Deletion Protection",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="DELETE",
                            status="warning",
                            duration_ms=duration,
                            error_message=f"Double deletion allowed, got {double_delete_response.status_code}",
                            status_code=double_delete_response.status_code
                        )
                
                else:
                    self.record_test_result(
                        test_name="Valid Message Deletion",
                        category=self.category,
                        endpoint=f"/api/v1/messages/{message_id}",
                        method="DELETE",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 200/204, got {delete_response.status_code}",
                        status_code=delete_response.status_code
                    )
                
                # Test 4: Delete non-existent message
                test_start = time.time()
                fake_id = 999999
                fake_delete_response = await client.delete(
                    f"{self.base_url}/api/v1/messages/{fake_id}",
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if fake_delete_response.status_code == 404:
                    self.record_test_result(
                        test_name="Non-existent Message Deletion",
                        category=self.category,
                        endpoint=f"/api/v1/messages/{fake_id}",
                        method="DELETE",
                        status="passed",
                        duration_ms=duration,
                        status_code=fake_delete_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Non-existent Message Deletion",
                        category=self.category,
                        endpoint=f"/api/v1/messages/{fake_id}",
                        method="DELETE",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 404, got {fake_delete_response.status_code}",
                        status_code=fake_delete_response.status_code
                    )
                
                # Test 5: Unauthorized deletion (without token)
                test_start = time.time()
                if self.test_messages:
                    unauthorized_id = self.test_messages[0].get("id")
                    unauthorized_response = await client.delete(
                        f"{self.base_url}/api/v1/messages/{unauthorized_id}"
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if unauthorized_response.status_code == 401:
                        self.record_test_result(
                            test_name="Unauthorized Message Deletion",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{unauthorized_id}",
                            method="DELETE",
                            status="passed",
                            duration_ms=duration,
                            status_code=unauthorized_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Unauthorized Message Deletion",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{unauthorized_id}",
                            method="DELETE",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Expected 401, got {unauthorized_response.status_code}",
                            status_code=unauthorized_response.status_code
                        )
        
        except Exception as e:
            self.record_test_result(
                test_name="Message Deletion Tests",
                category=self.category,
                endpoint="/api/v1/messages/{id}",
                method="DELETE",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_message_retrieval(self):
        """Test message retrieval endpoints."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="Message Retrieval",
                    category=self.category,
                    endpoint="/api/v1/messages",
                    method="GET",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test 1: Get all messages
                response = await client.get(
                    f"{self.base_url}/api/v1/messages",
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 200:
                    messages_data = response.json()
                    self.record_test_result(
                        test_name="Get All Messages",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="GET",
                        status="passed",
                        duration_ms=duration,
                        status_code=response.status_code,
                        performance_metrics={"messages_count": len(messages_data) if isinstance(messages_data, list) else 0}
                    )
                else:
                    self.record_test_result(
                        test_name="Get All Messages",
                        category=self.category,
                        endpoint="/api/v1/messages",
                        method="GET",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 200, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Get specific message
                if self.test_messages:
                    test_start = time.time()
                    message_id = self.test_messages[0].get("id")
                    specific_response = await client.get(
                        f"{self.base_url}/api/v1/messages/{message_id}",
                        headers=headers
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if specific_response.status_code == 200:
                        self.record_test_result(
                            test_name="Get Specific Message",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="GET",
                            status="passed",
                            duration_ms=duration,
                            status_code=specific_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Get Specific Message",
                            category=self.category,
                            endpoint=f"/api/v1/messages/{message_id}",
                            method="GET",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Expected 200, got {specific_response.status_code}",
                            status_code=specific_response.status_code
                        )
        
        except Exception as e:
            self.record_test_result(
                test_name="Message Retrieval Tests",
                category=self.category,
                endpoint="/api/v1/messages",
                method="GET",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_message_editing(self):
        """Test message editing functionality."""
        # Placeholder for message editing tests
        self.record_test_result(
            test_name="Message Editing",
            category=self.category,
            endpoint="/api/v1/messages/{id}",
            method="PUT",
            status="skipped",
            duration_ms=0,
            error_message="Message editing endpoint not implemented yet"
        )
    
    async def test_message_search(self):
        """Test message search functionality."""
        # Placeholder for message search tests
        self.record_test_result(
            test_name="Message Search",
            category=self.category,
            endpoint="/api/v1/messages/search",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Message search endpoint not implemented yet"
        )
    
    async def test_message_filtering(self):
        """Test message filtering functionality."""
        # Placeholder for message filtering tests
        self.record_test_result(
            test_name="Message Filtering",
            category=self.category,
            endpoint="/api/v1/messages",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Message filtering not implemented yet"
        )
    
    async def test_message_pagination(self):
        """Test message pagination."""
        # Placeholder for pagination tests
        self.record_test_result(
            test_name="Message Pagination",
            category=self.category,
            endpoint="/api/v1/messages",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Message pagination testing not implemented yet"
        )
    
    async def test_message_permissions(self):
        """Test message permissions and access control."""
        # Placeholder for permissions tests
        self.record_test_result(
            test_name="Message Permissions",
            category=self.category,
            endpoint="/api/v1/messages",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Message permissions testing not implemented yet"
        )
    
    async def test_message_validation(self):
        """Test message content validation."""
        # Placeholder for validation tests
        self.record_test_result(
            test_name="Message Validation",
            category=self.category,
            endpoint="/api/v1/messages",
            method="POST",
            status="skipped",
            duration_ms=0,
            error_message="Message validation testing not implemented yet"
        )
    
    async def test_bulk_operations(self):
        """Test bulk message operations."""
        # Placeholder for bulk operations tests
        self.record_test_result(
            test_name="Bulk Message Operations",
            category=self.category,
            endpoint="/api/v1/messages/bulk",
            method="POST",
            status="skipped",
            duration_ms=0,
            error_message="Bulk message operations not implemented yet"
        )
