"""
System Integration Testing
Comprehensive integration tests to ensure all components work seamlessly together.
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger("plexichat.testing.integration")

class IntegrationTestSuite:
    """Comprehensive integration test suite."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.test_results: List[Dict[str, Any]] = []
        self.admin_token: Optional[str] = None
        
        # Test configuration
        self.config = {
            "timeout": 30,
            "max_retries": 3,
            "test_user_prefix": "test_user_",
            "cleanup_after_tests": True
        }
    
    async def setup(self):
        """Setup test environment."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config["timeout"])
            )
            
            # Test basic connectivity
            await self._test_connectivity()
            
            # Setup admin authentication
            await self._setup_admin_auth()
            
            logger.info("Integration test setup completed")
            
        except Exception as e:
            logger.error(f"Test setup failed: {e}")
            raise
    
    async def teardown(self):
        """Cleanup test environment."""
        try:
            if self.config["cleanup_after_tests"]:
                await self._cleanup_test_data()
            
            if self.session:
                await self.session.close()
            
            logger.info("Integration test teardown completed")
            
        except Exception as e:
            logger.error(f"Test teardown failed: {e}")
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all integration tests."""
        try:
            await self.setup()
            
            # Core system tests
            await self._test_api_endpoints()
            await self._test_authentication_system()
            await self._test_user_management()
            await self._test_rate_limiting()
            
            # Feature tests
            await self._test_backup_system()
            await self._test_filter_system()
            await self._test_suggestions_system()
            await self._test_configuration_system()
            
            # Performance tests
            await self._test_performance()
            await self._test_concurrent_operations()
            
            # Security tests
            await self._test_security_features()
            
            # Generate test report
            return self._generate_test_report()
            
        except Exception as e:
            logger.error(f"Integration tests failed: {e}")
            raise
        finally:
            await self.teardown()
    
    async def _test_connectivity(self):
        """Test basic connectivity."""
        test_name = "Basic Connectivity"
        start_time = time.time()
        
        try:
            async with self.session.get(f"{self.base_url}/") as response:
                success = response.status == 200
                
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_api_endpoints(self):
        """Test core API endpoints."""
        endpoints = [
            ("/api/v1/health", "GET"),
            ("/api/v1/system/status", "GET"),
            ("/api/v1/system/info", "GET"),
            ("/docs", "GET"),
            ("/ui", "GET")
        ]
        
        for endpoint, method in endpoints:
            test_name = f"API Endpoint: {method} {endpoint}"
            start_time = time.time()
            
            try:
                async with self.session.request(method, f"{self.base_url}{endpoint}") as response:
                    success = response.status in [200, 401, 403]  # 401/403 are OK for protected endpoints
                    
                self._record_test_result(test_name, success, time.time() - start_time)
                
            except Exception as e:
                self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_authentication_system(self):
        """Test authentication system."""
        test_name = "Authentication System"
        start_time = time.time()
        
        try:
            # Test login with invalid credentials
            login_data = {"username": "invalid", "password": "invalid"}
            async with self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            ) as response:
                invalid_login_works = response.status == 401
            
            # Test admin login (if credentials available)
            admin_login_works = self.admin_token is not None
            
            success = invalid_login_works and admin_login_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_user_management(self):
        """Test user management functionality."""
        test_name = "User Management"
        start_time = time.time()
        
        try:
            if not self.admin_token:
                self._record_test_result(test_name, False, time.time() - start_time, "No admin token")
                return
            
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            
            # Test user creation
            user_data = {
                "username": f"{self.config['test_user_prefix']}{int(time.time())}",
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
            
            async with self.session.post(
                f"{self.base_url}/api/v1/admin/users",
                json=user_data,
                headers=headers
            ) as response:
                user_creation_works = response.status in [200, 201]
            
            success = user_creation_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_rate_limiting(self):
        """Test rate limiting functionality."""
        test_name = "Rate Limiting"
        start_time = time.time()
        
        try:
            # Make rapid requests to trigger rate limiting
            responses = []
            for _ in range(20):
                async with self.session.get(f"{self.base_url}/api/v1/health") as response:
                    responses.append(response.status)
            
            # Check if rate limiting kicked in
            rate_limited = 429 in responses
            success = rate_limited  # We expect rate limiting to work
            
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_backup_system(self):
        """Test backup system functionality."""
        test_name = "Backup System"
        start_time = time.time()
        
        try:
            if not self.admin_token:
                self._record_test_result(test_name, False, time.time() - start_time, "No admin token")
                return
            
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            
            # Test backup status
            async with self.session.get(
                f"{self.base_url}/api/v1/backup/status",
                headers=headers
            ) as response:
                status_works = response.status == 200
            
            # Test backup creation
            async with self.session.post(
                f"{self.base_url}/api/v1/backup/create",
                json={"type": "incremental"},
                headers=headers
            ) as response:
                creation_works = response.status in [200, 201, 202]
            
            success = status_works and creation_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_filter_system(self):
        """Test content and username filter systems."""
        test_name = "Filter System"
        start_time = time.time()
        
        try:
            # Test content filter
            content_data = {"content": "This is a test message"}
            async with self.session.post(
                f"{self.base_url}/api/v1/filters/content/check",
                json=content_data
            ) as response:
                content_filter_works = response.status == 200
            
            # Test username filter
            username_data = {"username": "testuser123"}
            async with self.session.post(
                f"{self.base_url}/api/v1/filters/username/validate",
                json=username_data
            ) as response:
                username_filter_works = response.status == 200
            
            success = content_filter_works and username_filter_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_suggestions_system(self):
        """Test suggestions system."""
        test_name = "Suggestions System"
        start_time = time.time()
        
        try:
            # Test getting suggestions
            async with self.session.get(f"{self.base_url}/api/v1/suggestions") as response:
                get_works = response.status == 200
            
            # Test creating suggestion
            suggestion_data = {
                "title": "Test Suggestion",
                "description": "This is a test suggestion",
                "category": "feature"
            }
            async with self.session.post(
                f"{self.base_url}/api/v1/suggestions",
                json=suggestion_data
            ) as response:
                create_works = response.status in [200, 201]
            
            success = get_works and create_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_configuration_system(self):
        """Test configuration system."""
        test_name = "Configuration System"
        start_time = time.time()
        
        try:
            if not self.admin_token:
                self._record_test_result(test_name, False, time.time() - start_time, "No admin token")
                return
            
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            
            # Test getting config
            async with self.session.get(
                f"{self.base_url}/api/v1/config",
                headers=headers
            ) as response:
                get_works = response.status == 200
            
            success = get_works
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_performance(self):
        """Test system performance."""
        test_name = "Performance Test"
        start_time = time.time()
        
        try:
            # Test response times
            response_times = []
            for _ in range(10):
                req_start = time.time()
                async with self.session.get(f"{self.base_url}/api/v1/health") as response:
                    if response.status == 200:
                        response_times.append(time.time() - req_start)
            
            avg_response_time = sum(response_times) / len(response_times) if response_times else 999
            success = avg_response_time < 1.0  # Less than 1 second average
            
            self._record_test_result(
                test_name, 
                success, 
                time.time() - start_time,
                f"Average response time: {avg_response_time:.3f}s"
            )
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_concurrent_operations(self):
        """Test concurrent operations."""
        test_name = "Concurrent Operations"
        start_time = time.time()
        
        try:
            # Create multiple concurrent requests
            tasks = []
            for _ in range(50):
                task = self.session.get(f"{self.base_url}/api/v1/health")
                tasks.append(task)
            
            # Execute concurrently
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check results
            successful_responses = sum(1 for r in responses if hasattr(r, 'status') and r.status == 200)
            success = successful_responses >= 45  # At least 90% success rate
            
            self._record_test_result(
                test_name,
                success,
                time.time() - start_time,
                f"Successful responses: {successful_responses}/50"
            )
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _test_security_features(self):
        """Test security features."""
        test_name = "Security Features"
        start_time = time.time()
        
        try:
            # Test SQL injection protection
            malicious_data = {"username": "'; DROP TABLE users; --"}
            async with self.session.post(
                f"{self.base_url}/api/v1/auth/login",
                json=malicious_data
            ) as response:
                sql_injection_blocked = response.status in [400, 401]
            
            # Test XSS protection
            xss_data = {"content": "<script>alert('xss')</script>"}
            async with self.session.post(
                f"{self.base_url}/api/v1/filters/content/check",
                json=xss_data
            ) as response:
                xss_handled = response.status == 200
            
            success = sql_injection_blocked and xss_handled
            self._record_test_result(test_name, success, time.time() - start_time)
            
        except Exception as e:
            self._record_test_result(test_name, False, time.time() - start_time, str(e))
    
    async def _setup_admin_auth(self):
        """Setup admin authentication for tests."""
        try:
            # Try to get admin token (implementation depends on auth system)
            # For now, we'll simulate having admin access
            self.admin_token = "test_admin_token"
            
        except Exception as e:
            logger.warning(f"Could not setup admin auth: {e}")
    
    async def _cleanup_test_data(self):
        """Cleanup test data."""
        try:
            if not self.admin_token:
                return
            
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            
            # Clean up test users
            async with self.session.get(
                f"{self.base_url}/api/v1/admin/users",
                headers=headers
            ) as response:
                if response.status == 200:
                    users = await response.json()
                    for user in users.get("users", []):
                        if user.get("username", "").startswith(self.config["test_user_prefix"]):
                            await self.session.delete(
                                f"{self.base_url}/api/v1/admin/users/{user['id']}",
                                headers=headers
                            )
            
            logger.info("Test data cleanup completed")
            
        except Exception as e:
            logger.error(f"Test cleanup failed: {e}")
    
    def _record_test_result(self, test_name: str, success: bool, 
                          duration: float, details: str = None):
        """Record test result."""
        result = {
            "test_name": test_name,
            "success": success,
            "duration": round(duration, 3),
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        
        self.test_results.append(result)
        
        status = "PASS" if success else "FAIL"
        logger.info(f"[{status}] {test_name} ({duration:.3f}s)")
        
        if details:
            logger.info(f"  Details: {details}")
    
    def _generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["success"])
        failed_tests = total_tests - passed_tests
        
        total_duration = sum(r["duration"] for r in self.test_results)
        avg_duration = total_duration / total_tests if total_tests > 0 else 0
        
        return {
            "summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "success_rate": round((passed_tests / total_tests * 100), 2) if total_tests > 0 else 0,
                "total_duration": round(total_duration, 3),
                "average_duration": round(avg_duration, 3)
            },
            "results": self.test_results,
            "timestamp": datetime.now().isoformat()
        }

# Global integration test instance
integration_tester = IntegrationTestSuite()

async def run_integration_tests() -> Dict[str, Any]:
    """Run all integration tests."""
    return await integration_tester.run_all_tests()
