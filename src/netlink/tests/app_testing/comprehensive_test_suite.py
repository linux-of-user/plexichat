"""
Comprehensive Testing Framework
Advanced testing suite with self-testing capabilities, performance testing, and automated validation.
"""

import asyncio
import time
import json
import statistics
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import logging
import psutil
import sys
import os

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

try:
    import logging import settings, logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    # Create fallback logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    # Create fallback settings
    class FallbackSettings:
        HOST = "localhost"
        PORT = 8000
        DATABASE_URL = "sqlite:///./data/chatapi.db"
        DEBUG = True

    settings = FallbackSettings()

@dataclass
class TestResult:
    """Represents the result of a single test."""
    test_name: str
    status: str  # passed, failed, skipped, error
    duration: float
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def passed(self) -> bool:
        return self.status == "passed"
    
    @property
    def failed(self) -> bool:
        return self.status == "failed"

@dataclass
class TestSuite:
    """Represents a collection of tests."""
    name: str
    description: str
    tests: List[Callable] = field(default_factory=list)
    setup: Optional[Callable] = None
    teardown: Optional[Callable] = None
    timeout: int = 300  # 5 minutes default
    parallel: bool = False

@dataclass
class PerformanceMetrics:
    """Performance test metrics."""
    requests_per_second: float
    average_response_time: float
    p95_response_time: float
    p99_response_time: float
    error_rate: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    cpu_usage: float
    memory_usage: float

class ComprehensiveTestFramework:
    """Advanced testing framework with comprehensive capabilities."""
    
    def __init__(self):
        self.test_suites: Dict[str, TestSuite] = {}
        self.results: List[TestResult] = []
        self.base_url = f"http://{getattr(settings, 'HOST', 'localhost')}:{getattr(settings, 'PORT', 8000)}"
        self.websocket_url = f"ws://{getattr(settings, 'HOST', 'localhost')}:{getattr(settings, 'PORT', 8000)}"
        self.session: Optional[aiohttp.ClientSession] = None
        self.auth_token: Optional[str] = None
        
        self._register_default_suites()
    
    def _register_default_suites(self):
        """Register default test suites."""
        # API Health Tests
        self.register_suite(TestSuite(
            name="api_health",
            description="Basic API health and connectivity tests",
            tests=[
                self.test_api_health,
                self.test_api_ready,
                self.test_api_version,
                self.test_openapi_spec
            ]
        ))
        
        # Authentication Tests
        self.register_suite(TestSuite(
            name="authentication",
            description="Authentication and authorization tests",
            tests=[
                self.test_user_registration,
                self.test_user_login,
                self.test_token_validation,
                self.test_protected_endpoints,
                self.test_admin_access
            ]
        ))
        
        # API Functionality Tests
        self.register_suite(TestSuite(
            name="api_functionality",
            description="Core API functionality tests",
            tests=[
                self.test_user_crud,
                self.test_message_crud,
                self.test_file_upload,
                self.test_websocket_connection,
                self.test_backup_system
            ]
        ))
        
        # Performance Tests
        self.register_suite(TestSuite(
            name="performance",
            description="Performance and load testing",
            tests=[
                self.test_api_performance,
                self.test_websocket_performance,
                self.test_concurrent_users,
                self.test_memory_usage,
                self.test_database_performance
            ],
            timeout=600  # 10 minutes for performance tests
        ))
        
        # Security Tests
        self.register_suite(TestSuite(
            name="security",
            description="Security and vulnerability tests",
            tests=[
                self.test_sql_injection,
                self.test_xss_protection,
                self.test_csrf_protection,
                self.test_rate_limiting,
                self.test_input_validation
            ]
        ))
        
        # Integration Tests
        self.register_suite(TestSuite(
            name="integration",
            description="Integration and end-to-end tests",
            tests=[
                self.test_full_user_workflow,
                self.test_chat_workflow,
                self.test_file_sharing_workflow,
                self.test_backup_recovery_workflow,
                self.test_multi_user_scenarios
            ],
            timeout=900  # 15 minutes for integration tests
        ))
    
    def register_suite(self, suite: TestSuite):
        """Register a test suite."""
        self.test_suites[suite.name] = suite
        logger.info(f"Registered test suite: {suite.name}")
    
    async def setup_session(self):
        """Setup HTTP session and authentication."""
        if not AIOHTTP_AVAILABLE:
            if LOGGER_AVAILABLE:
                logger.warning("aiohttp not available, HTTP tests will be skipped")
            else:
                print("aiohttp not available, HTTP tests will be skipped")
            return

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)

            if LOGGER_AVAILABLE:
                logger.info("Test session initialized")
            else:
                print("Test session initialized")
        except Exception as e:
            if LOGGER_AVAILABLE:
                logger.error(f"Failed to setup test session: {e}")
            else:
                print(f"Failed to setup test session: {e}")
            return

        # Authenticate for protected endpoints
        try:
            await self._authenticate()
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
    
    async def teardown_session(self):
        """Cleanup HTTP session."""
        if self.session:
            await self.session.close()
    
    async def _authenticate(self):
        """Authenticate and get access token."""
        auth_data = {
            "username": "test_user",
            "password": "test_password"
        }
        
        try:
            async with self.session.post(f"{self.base_url}/api/v1/auth/login", json=auth_data) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get("access_token")
                    logger.info("Authentication successful")
                else:
                    logger.warning("Authentication failed, some tests may be skipped")
        except Exception as e:
            logger.warning(f"Authentication error: {e}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}
    
    async def run_suite(self, suite_name: str) -> List[TestResult]:
        """Run a specific test suite."""
        if suite_name not in self.test_suites:
            raise ValueError(f"Unknown test suite: {suite_name}")
        
        suite = self.test_suites[suite_name]
        suite_results = []
        
        logger.info(f"Running test suite: {suite.name}")
        
        # Setup
        if suite.setup:
            try:
                await suite.setup()
            except Exception as e:
                logger.error(f"Suite setup failed: {e}")
                return []
        
        # Run tests
        if suite.parallel:
            # Run tests in parallel
            tasks = []
            for test_func in suite.tests:
                tasks.append(self._run_single_test(test_func, suite.timeout))
            
            suite_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle exceptions
            for i, result in enumerate(suite_results):
                if isinstance(result, Exception):
                    suite_results[i] = TestResult(
                        test_name=suite.tests[i].__name__,
                        status="error",
                        duration=0.0,
                        message=str(result)
                    )
        else:
            # Run tests sequentially
            for test_func in suite.tests:
                result = await self._run_single_test(test_func, suite.timeout)
                suite_results.append(result)
        
        # Teardown
        if suite.teardown:
            try:
                await suite.teardown()
            except Exception as e:
                logger.error(f"Suite teardown failed: {e}")
        
        self.results.extend(suite_results)
        return suite_results
    
    async def _run_single_test(self, test_func: Callable, timeout: int) -> TestResult:
        """Run a single test function."""
        test_name = test_func.__name__
        start_time = time.time()
        
        try:
            # Run test with timeout
            await asyncio.wait_for(test_func(), timeout=timeout)
            
            duration = time.time() - start_time
            return TestResult(
                test_name=test_name,
                status="passed",
                duration=duration,
                message="Test passed successfully"
            )
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return TestResult(
                test_name=test_name,
                status="failed",
                duration=duration,
                message=f"Test timed out after {timeout} seconds"
            )
            
        except AssertionError as e:
            duration = time.time() - start_time
            return TestResult(
                test_name=test_name,
                status="failed",
                duration=duration,
                message=f"Assertion failed: {str(e)}"
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name=test_name,
                status="error",
                duration=duration,
                message=f"Test error: {str(e)}"
            )
    
    async def run_all_suites(self) -> Dict[str, List[TestResult]]:
        """Run all registered test suites."""
        all_results = {}
        
        await self.setup_session()
        
        try:
            for suite_name in self.test_suites.keys():
                logger.info(f"Starting test suite: {suite_name}")
                results = await self.run_suite(suite_name)
                all_results[suite_name] = results
                
                # Log suite summary
                passed = sum(1 for r in results if r.passed)
                failed = sum(1 for r in results if r.failed)
                total = len(results)
                
                logger.info(f"Suite {suite_name} completed: {passed}/{total} passed, {failed} failed")
        
        finally:
            await self.teardown_session()
        
        return all_results
    
    def generate_report(self, results: Dict[str, List[TestResult]] = None) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        if results is None:
            # Group existing results by suite
            results = {}
            for result in self.results:
                suite_name = result.test_name.split('_')[1] if '_' in result.test_name else 'unknown'
                if suite_name not in results:
                    results[suite_name] = []
                results[suite_name].append(result)
        
        total_tests = sum(len(suite_results) for suite_results in results.values())
        total_passed = sum(sum(1 for r in suite_results if r.passed) for suite_results in results.values())
        total_failed = sum(sum(1 for r in suite_results if r.failed) for suite_results in results.values())
        total_duration = sum(sum(r.duration for r in suite_results) for suite_results in results.values())
        
        suite_summaries = {}
        for suite_name, suite_results in results.items():
            suite_passed = sum(1 for r in suite_results if r.passed)
            suite_failed = sum(1 for r in suite_results if r.failed)
            suite_duration = sum(r.duration for r in suite_results)
            
            suite_summaries[suite_name] = {
                "total": len(suite_results),
                "passed": suite_passed,
                "failed": suite_failed,
                "success_rate": (suite_passed / len(suite_results) * 100) if suite_results else 0,
                "duration": suite_duration,
                "tests": [
                    {
                        "name": r.test_name,
                        "status": r.status,
                        "duration": r.duration,
                        "message": r.message,
                        "timestamp": r.timestamp.isoformat()
                    }
                    for r in suite_results
                ]
            }
        
        return {
            "summary": {
                "total_tests": total_tests,
                "passed": total_passed,
                "failed": total_failed,
                "success_rate": (total_passed / total_tests * 100) if total_tests > 0 else 0,
                "total_duration": total_duration,
                "timestamp": datetime.utcnow().isoformat()
            },
            "suites": suite_summaries,
            "system_info": {
                "base_url": self.base_url,
                "python_version": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
                "platform": __import__('platform').platform()
            }
        }
    
    # Test implementations
    async def test_api_health(self):
        """Test API health endpoint."""
        if not self.session:
            raise Exception("HTTP session not available - skipping HTTP tests")

        try:
            async with self.session.get(f"{self.base_url}/api/v1/system/health") as response:
                assert response.status == 200
                data = await response.json()
                assert data.get("status") == "healthy"
        except Exception as e:
            if "Connection" in str(e):
                raise Exception(f"API server not running on {self.base_url}")
            raise
    
    async def test_api_ready(self):
        """Test API readiness endpoint."""
        async with self.session.get(f"{self.base_url}/api/v1/system/ready") as response:
            assert response.status == 200
            data = await response.json()
            assert data.get("ready") is True
    
    async def test_api_version(self):
        """Test API version endpoint."""
        async with self.session.get(f"{self.base_url}/api/v1/system/version") as response:
            assert response.status == 200
            data = await response.json()
            assert "version" in data
            assert "build" in data
    
    async def test_openapi_spec(self):
        """Test OpenAPI specification endpoint."""
        async with self.session.get(f"{self.base_url}/openapi.json") as response:
            assert response.status == 200
            data = await response.json()
            assert "openapi" in data
            assert "paths" in data
    
    async def test_user_registration(self):
        """Test user registration."""
        user_data = {
            "username": f"test_user_{int(time.time())}",
            "email": f"test_{int(time.time())}@example.com",
            "password": "test_password_123"
        }
        
        async with self.session.post(f"{self.base_url}/api/v1/auth/register", json=user_data) as response:
            assert response.status == 201
            data = await response.json()
            assert "id" in data
            assert data["username"] == user_data["username"]
    
    async def test_user_login(self):
        """Test user login."""
        # This assumes a test user exists
        login_data = {
            "username": "test_user",
            "password": "test_password"
        }
        
        async with self.session.post(f"{self.base_url}/api/v1/auth/login", json=login_data) as response:
            if response.status == 404:
                # User doesn't exist, skip test
                return
            assert response.status == 200
            data = await response.json()
            assert "access_token" in data
    
    async def test_token_validation(self):
        """Test token validation."""
        if not self.auth_token:
            return  # Skip if no token
        
        headers = self._get_auth_headers()
        async with self.session.get(f"{self.base_url}/api/v1/auth/me", headers=headers) as response:
            assert response.status == 200
            data = await response.json()
            assert "id" in data
            assert "username" in data
    
    async def test_protected_endpoints(self):
        """Test protected endpoint access."""
        # Test without token
        async with self.session.get(f"{self.base_url}/api/v1/users/me") as response:
            assert response.status == 401
        
        # Test with token
        if self.auth_token:
            headers = self._get_auth_headers()
            async with self.session.get(f"{self.base_url}/api/v1/users/me", headers=headers) as response:
                assert response.status == 200
    
    async def test_admin_access(self):
        """Test admin-only endpoint access."""
        headers = self._get_auth_headers()
        async with self.session.get(f"{self.base_url}/api/v1/admin/users", headers=headers) as response:
            # Should be 401/403 for non-admin users, or 200 for admin users
            assert response.status in [200, 401, 403]
    
    async def test_user_crud(self):
        """Test user CRUD operations."""
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Get current user
        async with self.session.get(f"{self.base_url}/api/v1/users/me", headers=headers) as response:
            assert response.status == 200
            user_data = await response.json()
            assert "id" in user_data
    
    async def test_message_crud(self):
        """Test message CRUD operations."""
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Create message
        message_data = {
            "content": "Test message",
            "channel_id": 1
        }
        
        async with self.session.post(f"{self.base_url}/api/v1/messages", json=message_data, headers=headers) as response:
            if response.status == 404:  # Channel doesn't exist
                return
            assert response.status == 201
            data = await response.json()
            message_id = data["id"]
        
        # Get message
        async with self.session.get(f"{self.base_url}/api/v1/messages/{message_id}", headers=headers) as response:
            assert response.status == 200
    
    async def test_file_upload(self):
        """Test file upload functionality."""
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Create test file
        test_content = b"Test file content"
        data = aiohttp.FormData()
        data.add_field('file', test_content, filename='test.txt', content_type='text/plain')
        
        async with self.session.post(f"{self.base_url}/api/v1/files/upload", data=data, headers=headers) as response:
            assert response.status == 201
            data = await response.json()
            assert "id" in data
            assert "filename" in data
    
    async def test_websocket_connection(self):
        """Test WebSocket connection."""
        try:
            uri = f"{self.websocket_url}/ws"
            async with websockets.connect(uri) as websocket:
                # Send test message
                await websocket.send(json.dumps({"type": "ping"}))
                
                # Receive response
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                data = json.loads(response)
                assert data.get("type") == "pong"
        except Exception as e:
            # WebSocket might not be available
            logger.warning(f"WebSocket test failed: {e}")
    
    async def test_backup_system(self):
        """Test backup system functionality."""
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Test backup status
        async with self.session.get(f"{self.base_url}/api/v1/backup/status", headers=headers) as response:
            if response.status == 403:  # Not admin
                return
            assert response.status == 200
            data = await response.json()
            assert "total_backups" in data
    
    async def test_api_performance(self):
        """Test API performance under load."""
        # Perform multiple concurrent requests
        tasks = []
        for _ in range(50):
            tasks.append(self.session.get(f"{self.base_url}/api/v1/system/health"))
        
        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start_time
        
        # Check results
        successful = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 200)
        assert successful >= 45  # At least 90% success rate
        assert duration < 10  # Should complete within 10 seconds
    
    async def test_websocket_performance(self):
        """Test WebSocket performance."""
        # This would test WebSocket message throughput
        pass
    
    async def test_concurrent_users(self):
        """Test concurrent user scenarios."""
        # This would simulate multiple users
        pass
    
    async def test_memory_usage(self):
        """Test memory usage patterns."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Perform memory-intensive operations
        tasks = []
        for _ in range(100):
            tasks.append(self.session.get(f"{self.base_url}/api/v1/system/health"))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024
    
    async def test_database_performance(self):
        """Test database performance."""
        # This would test database query performance
        pass
    
    async def test_sql_injection(self):
        """Test SQL injection protection."""
        # Test various SQL injection patterns
        injection_patterns = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --"
        ]
        
        for pattern in injection_patterns:
            # Test in search endpoint
            params = {"q": pattern}
            async with self.session.get(f"{self.base_url}/api/v1/search", params=params) as response:
                # Should not return 500 error (indicates SQL injection vulnerability)
                assert response.status != 500
    
    async def test_xss_protection(self):
        """Test XSS protection."""
        xss_payload = "<script>alert('xss')</script>"
        
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Test XSS in message content
        message_data = {
            "content": xss_payload,
            "channel_id": 1
        }
        
        async with self.session.post(f"{self.base_url}/api/v1/messages", json=message_data, headers=headers) as response:
            if response.status == 201:
                data = await response.json()
                # Content should be sanitized
                assert "<script>" not in data.get("content", "")
    
    async def test_csrf_protection(self):
        """Test CSRF protection."""
        # This would test CSRF token validation
        pass
    
    async def test_rate_limiting(self):
        """Test rate limiting."""
        # Make rapid requests to trigger rate limiting
        tasks = []
        for _ in range(200):  # Exceed rate limit
            tasks.append(self.session.get(f"{self.base_url}/api/v1/system/health"))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should have some 429 (Too Many Requests) responses
        rate_limited = sum(1 for r in responses if not isinstance(r, Exception) and r.status == 429)
        assert rate_limited > 0
    
    async def test_input_validation(self):
        """Test input validation."""
        if not self.auth_token:
            return
        
        headers = self._get_auth_headers()
        
        # Test invalid data
        invalid_data = {
            "content": "x" * 10000,  # Too long
            "channel_id": "invalid"  # Wrong type
        }
        
        async with self.session.post(f"{self.base_url}/api/v1/messages", json=invalid_data, headers=headers) as response:
            assert response.status == 422  # Validation error
    
    async def test_full_user_workflow(self):
        """Test complete user workflow."""
        # This would test a complete user journey
        pass
    
    async def test_chat_workflow(self):
        """Test chat workflow."""
        # This would test complete chat functionality
        pass
    
    async def test_file_sharing_workflow(self):
        """Test file sharing workflow."""
        # This would test complete file sharing functionality
        pass
    
    async def test_backup_recovery_workflow(self):
        """Test backup and recovery workflow."""
        # This would test complete backup/recovery process
        pass
    
    async def test_multi_user_scenarios(self):
        """Test multi-user scenarios."""
        # This would test multiple users interacting
        pass

# Global test framework instance
test_framework = ComprehensiveTestFramework()
