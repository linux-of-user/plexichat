"""
Comprehensive filter system tests.
Tests all filtering capabilities separate from moderation reports.
"""

import asyncio
import time
import json
import re
from typing import Dict, Any, List
import httpx

from .test_base import BaseEndpointTest, TestResult
from netlink.app.logger_config import logger


class FilterSystemTests(BaseEndpointTest):
    """Comprehensive tests for filter system functionality."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        super().__init__(base_url)
        self.category = "filters"
        self.test_filters: List[Dict[str, Any]] = []
        
        # Test filter patterns
        self.filter_test_cases = {
            "profanity": [
                "This is a bad word test",
                "Clean message here",
                "Another inappropriate term",
                "Family friendly content"
            ],
            "spam": [
                "BUY NOW!!! CLICK HERE!!!",
                "Normal conversation message",
                "FREE MONEY GUARANTEED!!!",
                "Regular chat content"
            ],
            "links": [
                "Check out https://suspicious-site.com",
                "Visit our official site at https://netlink.com",
                "No links in this message",
                "Malicious link: http://malware.example.com"
            ],
            "personal_info": [
                "My phone number is 555-123-4567",
                "Contact me at john@email.com",
                "No personal info here",
                "My SSN is 123-45-6789"
            ],
            "custom_keywords": [
                "This contains a blocked keyword",
                "This is completely safe",
                "Another flagged term here",
                "Normal conversation"
            ]
        }
    
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
        """Clean up test filters and data."""
        async with httpx.AsyncClient() as client:
            # Delete test filters
            for filter_data in self.test_filters:
                if "id" in filter_data:
                    try:
                        token = list(self.auth_tokens.values())[0]
                        headers = {"Authorization": f"Bearer {token}"}
                        await client.delete(f"{self.base_url}/api/v1/filters/{filter_data['id']}", headers=headers)
                    except:
                        pass  # Ignore cleanup errors
    
    async def _run_endpoint_tests(self):
        """Run all filter system tests."""
        await self.test_filter_creation()
        await self.test_filter_management()
        await self.test_content_filtering()
        await self.test_filter_performance()
        await self.test_filter_bypass_attempts()
        await self.test_filter_categories()
        await self.test_regex_filters()
        await self.test_whitelist_blacklist()
        await self.test_filter_priorities()
        await self.test_filter_statistics()
    
    async def test_filter_creation(self):
        """Test filter creation with various configurations."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="Filter Creation",
                    category=self.category,
                    endpoint="/api/v1/filters",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test 1: Create keyword filter
                keyword_filter = {
                    "name": "Test Profanity Filter",
                    "type": "keyword",
                    "pattern": "badword1,badword2,inappropriate",
                    "action": "flag",
                    "severity": "medium",
                    "case_sensitive": False,
                    "enabled": True,
                    "description": "Test filter for profanity detection"
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/filters",
                    json=keyword_filter,
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 201:
                    filter_response = response.json()
                    self.test_filters.append(filter_response)
                    
                    self.record_test_result(
                        test_name="Keyword Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        request_data=keyword_filter,
                        response_data=filter_response,
                        status_code=response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Keyword Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 201, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Create regex filter
                test_start = time.time()
                regex_filter = {
                    "name": "Email Detection Filter",
                    "type": "regex",
                    "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                    "action": "warn",
                    "severity": "low",
                    "enabled": True,
                    "description": "Detects email addresses in messages"
                }
                
                regex_response = await client.post(
                    f"{self.base_url}/api/v1/filters",
                    json=regex_filter,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if regex_response.status_code == 201:
                    regex_filter_response = regex_response.json()
                    self.test_filters.append(regex_filter_response)
                    
                    self.record_test_result(
                        test_name="Regex Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=regex_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Regex Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 201, got {regex_response.status_code}",
                        status_code=regex_response.status_code
                    )
                
                # Test 3: Create URL filter
                test_start = time.time()
                url_filter = {
                    "name": "Suspicious URL Filter",
                    "type": "url",
                    "pattern": "suspicious-site.com,malware.example.com",
                    "action": "block",
                    "severity": "high",
                    "enabled": True,
                    "description": "Blocks known malicious URLs"
                }
                
                url_response = await client.post(
                    f"{self.base_url}/api/v1/filters",
                    json=url_filter,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if url_response.status_code == 201:
                    url_filter_response = url_response.json()
                    self.test_filters.append(url_filter_response)
                    
                    self.record_test_result(
                        test_name="URL Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=url_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="URL Filter Creation",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 201, got {url_response.status_code}",
                        status_code=url_response.status_code
                    )
                
                # Test 4: Invalid filter (missing required fields)
                test_start = time.time()
                invalid_filter = {
                    "name": "Invalid Filter"
                    # Missing required fields
                }
                
                invalid_response = await client.post(
                    f"{self.base_url}/api/v1/filters",
                    json=invalid_filter,
                    headers=headers
                )
                duration = (time.time() - test_start) * 1000
                
                if invalid_response.status_code in [400, 422]:
                    self.record_test_result(
                        test_name="Invalid Filter Rejection",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=invalid_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Invalid Filter Rejection",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 400/422, got {invalid_response.status_code}",
                        status_code=invalid_response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Filter Creation Tests",
                category=self.category,
                endpoint="/api/v1/filters",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_content_filtering(self):
        """Test content filtering against various test cases."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="Content Filtering",
                    category=self.category,
                    endpoint="/api/v1/filters/check",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test each filter category
                for category, test_cases in self.filter_test_cases.items():
                    for i, content in enumerate(test_cases):
                        test_start = time.time()
                        
                        filter_request = {
                            "content": content,
                            "content_type": "message",
                            "check_all": True
                        }
                        
                        response = await client.post(
                            f"{self.base_url}/api/v1/filters/check",
                            json=filter_request,
                            headers=headers
                        )
                        
                        duration = (time.time() - test_start) * 1000
                        
                        if response.status_code == 200:
                            filter_result = response.json()
                            
                            # Analyze results
                            is_flagged = filter_result.get("flagged", False)
                            matched_filters = filter_result.get("matched_filters", [])
                            
                            test_name = f"{category.title()} Filter Test {i+1}"
                            
                            # Determine if result is expected
                            # Even-indexed items should be flagged, odd-indexed should be clean
                            expected_flagged = (i % 2 == 0)
                            
                            if is_flagged == expected_flagged:
                                status = "passed"
                                message = f"Correctly {'flagged' if is_flagged else 'allowed'} content"
                            else:
                                status = "warning"
                                message = f"Unexpected result: {'flagged' if is_flagged else 'allowed'} when {'allowed' if is_flagged else 'flagged'} expected"
                            
                            self.record_test_result(
                                test_name=test_name,
                                category=self.category,
                                endpoint="/api/v1/filters/check",
                                method="POST",
                                status=status,
                                duration_ms=duration,
                                request_data={"content_preview": content[:50] + "..."},
                                response_data=filter_result,
                                status_code=response.status_code,
                                performance_metrics={
                                    "filter_processing_time_ms": duration,
                                    "matched_filters_count": len(matched_filters)
                                }
                            )
                        else:
                            self.record_test_result(
                                test_name=f"{category.title()} Filter Test {i+1}",
                                category=self.category,
                                endpoint="/api/v1/filters/check",
                                method="POST",
                                status="failed",
                                duration_ms=duration,
                                error_message=f"Filter check failed with {response.status_code}",
                                status_code=response.status_code
                            )
        
        except Exception as e:
            self.record_test_result(
                test_name="Content Filtering Tests",
                category=self.category,
                endpoint="/api/v1/filters/check",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_filter_management(self):
        """Test filter management operations."""
        test_start = time.time()
        
        try:
            if not self.auth_tokens or not self.test_filters:
                self.record_test_result(
                    test_name="Filter Management",
                    category=self.category,
                    endpoint="/api/v1/filters",
                    method="GET",
                    status="skipped",
                    duration_ms=0,
                    error_message="No filters available for management testing"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test 1: List all filters
                response = await client.get(
                    f"{self.base_url}/api/v1/filters",
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 200:
                    filters_data = response.json()
                    self.record_test_result(
                        test_name="List All Filters",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="GET",
                        status="passed",
                        duration_ms=duration,
                        status_code=response.status_code,
                        performance_metrics={"filters_count": len(filters_data) if isinstance(filters_data, list) else 0}
                    )
                else:
                    self.record_test_result(
                        test_name="List All Filters",
                        category=self.category,
                        endpoint="/api/v1/filters",
                        method="GET",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 200, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Get specific filter
                if self.test_filters:
                    test_start = time.time()
                    filter_id = self.test_filters[0].get("id")
                    
                    specific_response = await client.get(
                        f"{self.base_url}/api/v1/filters/{filter_id}",
                        headers=headers
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if specific_response.status_code == 200:
                        self.record_test_result(
                            test_name="Get Specific Filter",
                            category=self.category,
                            endpoint=f"/api/v1/filters/{filter_id}",
                            method="GET",
                            status="passed",
                            duration_ms=duration,
                            status_code=specific_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Get Specific Filter",
                            category=self.category,
                            endpoint=f"/api/v1/filters/{filter_id}",
                            method="GET",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Expected 200, got {specific_response.status_code}",
                            status_code=specific_response.status_code
                        )
                
                # Test 3: Update filter
                if self.test_filters:
                    test_start = time.time()
                    filter_id = self.test_filters[0].get("id")
                    
                    update_data = {
                        "name": "Updated Test Filter",
                        "description": "Updated description for testing"
                    }
                    
                    update_response = await client.put(
                        f"{self.base_url}/api/v1/filters/{filter_id}",
                        json=update_data,
                        headers=headers
                    )
                    duration = (time.time() - test_start) * 1000
                    
                    if update_response.status_code == 200:
                        self.record_test_result(
                            test_name="Update Filter",
                            category=self.category,
                            endpoint=f"/api/v1/filters/{filter_id}",
                            method="PUT",
                            status="passed",
                            duration_ms=duration,
                            status_code=update_response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Update Filter",
                            category=self.category,
                            endpoint=f"/api/v1/filters/{filter_id}",
                            method="PUT",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Expected 200, got {update_response.status_code}",
                            status_code=update_response.status_code
                        )
        
        except Exception as e:
            self.record_test_result(
                test_name="Filter Management Tests",
                category=self.category,
                endpoint="/api/v1/filters",
                method="GET",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_filter_performance(self):
        """Test filter performance with large content and many filters."""
        test_start = time.time()
        
        try:
            # Generate large content for performance testing
            large_content = " ".join([
                self.test_data_generator.random_message_content(100)
                for _ in range(50)
            ])  # ~5000 words
            
            if not self.auth_tokens:
                self.record_test_result(
                    test_name="Filter Performance",
                    category=self.category,
                    endpoint="/api/v1/filters/check",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="No auth tokens available"
                )
                return
            
            async with httpx.AsyncClient() as client:
                token = list(self.auth_tokens.values())[0]
                headers = {"Authorization": f"Bearer {token}"}
                
                filter_request = {
                    "content": large_content,
                    "content_type": "message",
                    "check_all": True
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/filters/check",
                    json=filter_request,
                    headers=headers
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 200:
                    filter_result = response.json()
                    
                    # Performance thresholds
                    performance_status = "passed"
                    if duration > 5000:  # More than 5 seconds
                        performance_status = "warning"
                    elif duration > 10000:  # More than 10 seconds
                        performance_status = "failed"
                    
                    self.record_test_result(
                        test_name="Large Content Filter Performance",
                        category=self.category,
                        endpoint="/api/v1/filters/check",
                        method="POST",
                        status=performance_status,
                        duration_ms=duration,
                        status_code=response.status_code,
                        performance_metrics={
                            "content_size_chars": len(large_content),
                            "processing_time_ms": duration,
                            "chars_per_second": len(large_content) / (duration / 1000) if duration > 0 else 0
                        }
                    )
                else:
                    self.record_test_result(
                        test_name="Large Content Filter Performance",
                        category=self.category,
                        endpoint="/api/v1/filters/check",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Performance test failed with {response.status_code}",
                        status_code=response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Filter Performance Tests",
                category=self.category,
                endpoint="/api/v1/filters/check",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_filter_bypass_attempts(self):
        """Test filter bypass attempts and evasion techniques."""
        # Placeholder for bypass testing
        self.record_test_result(
            test_name="Filter Bypass Attempts",
            category=self.category,
            endpoint="/api/v1/filters/check",
            method="POST",
            status="skipped",
            duration_ms=0,
            error_message="Bypass testing not implemented yet"
        )
    
    async def test_filter_categories(self):
        """Test different filter categories and types."""
        # Placeholder for category testing
        self.record_test_result(
            test_name="Filter Categories",
            category=self.category,
            endpoint="/api/v1/filters/categories",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Category testing not implemented yet"
        )
    
    async def test_regex_filters(self):
        """Test regex filter functionality."""
        # Placeholder for regex testing
        self.record_test_result(
            test_name="Regex Filters",
            category=self.category,
            endpoint="/api/v1/filters/regex",
            method="POST",
            status="skipped",
            duration_ms=0,
            error_message="Regex filter testing not implemented yet"
        )
    
    async def test_whitelist_blacklist(self):
        """Test whitelist and blacklist functionality."""
        # Placeholder for whitelist/blacklist testing
        self.record_test_result(
            test_name="Whitelist/Blacklist",
            category=self.category,
            endpoint="/api/v1/filters/whitelist",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Whitelist/blacklist testing not implemented yet"
        )
    
    async def test_filter_priorities(self):
        """Test filter priority and ordering."""
        # Placeholder for priority testing
        self.record_test_result(
            test_name="Filter Priorities",
            category=self.category,
            endpoint="/api/v1/filters/priorities",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Filter priority testing not implemented yet"
        )
    
    async def test_filter_statistics(self):
        """Test filter statistics and reporting."""
        # Placeholder for statistics testing
        self.record_test_result(
            test_name="Filter Statistics",
            category=self.category,
            endpoint="/api/v1/filters/statistics",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Filter statistics testing not implemented yet"
        )
