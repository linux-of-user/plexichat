"""
User endpoint tests.
Tests user management, profile operations, and account functionality.
"""

import time
import httpx
from typing import Dict, Any

from .test_base import BaseEndpointTest


class UserEndpointTests(BaseEndpointTest):
    """Tests for user management endpoints."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        super().__init__(base_url)
        self.category = "users"
    
    async def _run_endpoint_tests(self):
        """Run all user endpoint tests."""
        await self.test_user_profile_operations()
        await self.test_user_settings()
        await self.test_user_search()
        await self.test_user_permissions()
    
    async def test_user_profile_operations(self):
        """Test user profile CRUD operations."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="User Profile Operations",
                    category=self.category,
                    endpoint="/api/v1/users/me",
                    method="GET",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test get profile
                response = await client.get(f"{self.base_url}/api/v1/users/me", headers=headers)
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 200:
                    self.record_test_result(
                        test_name="Get User Profile",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="passed",
                        duration_ms=duration,
                        status_code=response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Get User Profile",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 200, got {response.status_code}",
                        status_code=response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="User Profile Operations",
                category=self.category,
                endpoint="/api/v1/users/me",
                method="GET",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_user_settings(self):
        """Test user settings management."""
        self.record_test_result(
            test_name="User Settings",
            category=self.category,
            endpoint="/api/v1/users/settings",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="User settings endpoint not implemented yet"
        )
    
    async def test_user_search(self):
        """Test user search functionality."""
        self.record_test_result(
            test_name="User Search",
            category=self.category,
            endpoint="/api/v1/users/search",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="User search endpoint not implemented yet"
        )
    
    async def test_user_permissions(self):
        """Test user permissions and roles."""
        self.record_test_result(
            test_name="User Permissions",
            category=self.category,
            endpoint="/api/v1/users/permissions",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="User permissions endpoint not implemented yet"
        )
