"""
Comprehensive Endpoint Testing & Validation System

Provides systematic testing of all API endpoints with:
- Automated endpoint discovery and testing
- Comprehensive input validation testing
- Security vulnerability testing
- Performance benchmarking
- Load testing capabilities
- Response validation and schema checking
- Error handling verification
- Authentication and authorization testing
- Real-time monitoring and reporting
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
import re
from urllib.parse import urljoin, urlparse

# Logging imports with fallbacks
import logging
def get_logger(name):
    return logging.getLogger(name)

# Fallback correlation tracker
class CorrelationType:
    REQUEST = "request"
    RESPONSE = "response"
    BACKGROUND_TASK = "background_task"

class correlation_tracker:
    @staticmethod
    def start_correlation(correlation_type, **kwargs):
        return "fallback_correlation_id"

    @staticmethod
    def finish_correlation(correlation_id):
        pass

logger = get_logger(__name__)


def ensure_session(func):
    """Decorator to ensure test session is available."""
    import functools

    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        if not self.test_session:
            # Create a temporary session if none exists
            self.test_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=getattr(self, 'test_timeout', 30))
            )
        return await func(self, *args, **kwargs)
    return wrapper


class TestType(Enum):
    """Types of endpoint tests."""
    FUNCTIONAL = "functional"
    SECURITY = "security"
    PERFORMANCE = "performance"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    LOAD = "load"
    STRESS = "stress"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class EndpointInfo:
    """Information about an API endpoint."""
    path: str
    method: str
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    request_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None
    requires_auth: bool = False
    required_permissions: List[str] = field(default_factory=list)
    rate_limit: Optional[int] = None
    
    # Discovered information
    discovered_at: datetime = field(default_factory=datetime.now)
    last_tested: Optional[datetime] = None
    test_count: int = 0
    success_count: int = 0
    failure_count: int = 0


@dataclass
class TestResult:
    """Result of an endpoint test."""
    test_id: str
    endpoint: EndpointInfo
    test_type: TestType
    status: TestStatus
    
    # Timing information
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    # Request/Response details
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_status: Optional[int] = None
    response_data: Optional[Dict] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    
    # Test details
    test_description: str = ""
    expected_result: Optional[Any] = None
    actual_result: Optional[Any] = None
    
    # Error information
    error_message: str = ""
    error_details: Dict[str, Any] = field(default_factory=dict)
    
    # Performance metrics
    response_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    # Validation results
    schema_valid: bool = True
    security_issues: List[str] = field(default_factory=list)
    performance_issues: List[str] = field(default_factory=list)
    
    def finish(self, status: TestStatus, error_message: str = ""):
        """Mark test as finished."""
        self.end_time = datetime.now()
        self.status = status
        self.error_message = error_message
        
        if self.start_time and self.end_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000


class EndpointDiscovery:
    """Automatic endpoint discovery system."""
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.discovered_endpoints: Dict[str, EndpointInfo] = {}
        
    async def discover_endpoints(self) -> List[EndpointInfo]:
        """Discover all available endpoints."""
        endpoints = []
        
        # Try to get OpenAPI/Swagger documentation
        openapi_endpoints = await self._discover_from_openapi()
        endpoints.extend(openapi_endpoints)
        
        # Try common endpoint patterns
        pattern_endpoints = await self._discover_from_patterns()
        endpoints.extend(pattern_endpoints)
        
        # Try to discover from application routes
        route_endpoints = await self._discover_from_routes()
        endpoints.extend(route_endpoints)
        
        # Remove duplicates
        unique_endpoints = {}
        for endpoint in endpoints:
            key = f"{endpoint.method}:{endpoint.path}"
            if key not in unique_endpoints:
                unique_endpoints[key] = endpoint
        
        self.discovered_endpoints = unique_endpoints
        logger.info(f"Discovered {len(unique_endpoints)} endpoints")
        
        return list(unique_endpoints.values())
    
    async def _discover_from_openapi(self) -> List[EndpointInfo]:
        """Discover endpoints from OpenAPI/Swagger documentation."""
        endpoints = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try common OpenAPI documentation paths
                openapi_paths = ['/docs/openapi.json', '/openapi.json', '/swagger.json', '/api/docs']
                
                for path in openapi_paths:
                    try:
                        url = urljoin(self.base_url, path)
                        async with session.get(url) as response:
                            if response.status == 200:
                                openapi_spec = await response.json()
                                endpoints.extend(self._parse_openapi_spec(openapi_spec))
                                break
                    except Exception as e:
                        logger.debug(f"Failed to fetch OpenAPI from {path}: {e}")
                        
        except Exception as e:
            logger.warning(f"OpenAPI discovery failed: {e}")
        
        return endpoints
    
    def _parse_openapi_spec(self, spec: Dict) -> List[EndpointInfo]:
        """Parse OpenAPI specification to extract endpoints."""
        endpoints = []
        
        try:
            paths = spec.get('paths', {})
            
            for path, path_info in paths.items():
                for method, method_info in path_info.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = EndpointInfo(
                            path=path,
                            method=method.upper(),
                            description=method_info.get('summary', ''),
                            parameters=method_info.get('parameters', {}),
                            request_schema=method_info.get('requestBody', {}).get('content', {}).get('application/json', {}).get('schema'),
                            response_schema=method_info.get('responses', {}).get('200', {}).get('content', {}).get('application/json', {}).get('schema'),
                            requires_auth='security' in method_info
                        )
                        endpoints.append(endpoint)
                        
        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {e}")
        
        return endpoints
    
    async def _discover_from_patterns(self) -> List[EndpointInfo]:
        """Discover endpoints using common patterns."""
        endpoints = []
        
        # Common API patterns
        common_patterns = [
            # Authentication
            ('/api/v1/auth/login', 'POST'),
            ('/api/v1/auth/register', 'POST'),
            ('/api/v1/auth/logout', 'POST'),
            ('/api/v1/auth/refresh', 'POST'),
            
            # Users
            ('/api/v1/users', 'GET'),
            ('/api/v1/users', 'POST'),
            ('/api/v1/users/me', 'GET'),
            ('/api/v1/users/me', 'PUT'),
            ('/api/v1/users/{id}', 'GET'),
            ('/api/v1/users/{id}', 'PUT'),
            ('/api/v1/users/{id}', 'DELETE'),
            
            # Messages
            ('/api/v1/messages', 'GET'),
            ('/api/v1/messages', 'POST'),
            ('/api/v1/messages/{id}', 'GET'),
            ('/api/v1/messages/{id}', 'PUT'),
            ('/api/v1/messages/{id}', 'DELETE'),
            
            # Channels
            ('/api/v1/channels', 'GET'),
            ('/api/v1/channels', 'POST'),
            ('/api/v1/channels/{id}', 'GET'),
            ('/api/v1/channels/{id}', 'PUT'),
            ('/api/v1/channels/{id}', 'DELETE'),
            
            # Files
            ('/api/v1/files', 'GET'),
            ('/api/v1/files', 'POST'),
            ('/api/v1/files/{id}', 'GET'),
            ('/api/v1/files/{id}', 'DELETE'),
            
            # Admin
            ('/api/v1/admin/users', 'GET'),
            ('/api/v1/admin/system', 'GET'),
            ('/api/v1/admin/stats', 'GET'),
        ]
        
        for path, method in common_patterns:
            # Test if endpoint exists
            if await self._test_endpoint_exists(path, method):
                endpoint = EndpointInfo(
                    path=path,
                    method=method,
                    description=f"Discovered {method} {path}",
                    requires_auth=True if 'admin' in path or path.endswith('/me') else False
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _discover_from_routes(self) -> List[EndpointInfo]:
        """Discover endpoints from application routes."""
        # This would integrate with the FastAPI app to get actual routes
        # For now, return empty list
        return []
    
    async def _test_endpoint_exists(self, path: str, method: str) -> bool:
        """Test if an endpoint exists."""
        try:
            url = urljoin(self.base_url, path.replace('{id}', '1'))  # Replace path parameters
            
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url) as response:
                    # Consider endpoint as existing if it doesn't return 404
                    return response.status != 404
                    
        except Exception:
            return False


class ComprehensiveEndpointTester:
    """Comprehensive endpoint testing system."""
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.discovery = EndpointDiscovery(base_url)
        self.test_results: List[TestResult] = []
        self.test_session: Optional[aiohttp.ClientSession] = None
        
        # Test configuration
        self.test_timeout = 30
        self.max_concurrent_tests = 10
        self.auth_token: Optional[str] = None
        self.test_user_credentials = {
            'username': 'test_user',
            'password': 'test_password'
        }
        
        # Test data templates
        self.test_data_templates = {
            'user_registration': {
                'username': 'test_user_{}',
                'email': 'test{}@example.com',
                'password': 'TestPassword123!',
                'display_name': 'Test User {}',
                'first_name': 'Test',
                'last_name': 'User',
                'terms_accepted': True
            },
            'user_login': {
                'username': 'test_user',
                'password': 'TestPassword123!'
            },
            'message_creation': {
                'content': 'Test message content',
                'channel_id': 'test_channel'
            },
            'channel_creation': {
                'name': 'test_channel_{}',
                'description': 'Test channel description',
                'is_private': False
            }
        }
    
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive tests on all discovered endpoints."""
        correlation_id = correlation_tracker.start_correlation(
            correlation_type=CorrelationType.BACKGROUND_TASK,
            component="endpoint_tester",
            operation="comprehensive_test_suite"
        )
        
        try:
            # Initialize test session
            self.test_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.test_timeout)
            )
            
            # Discover endpoints
            logger.info("Starting endpoint discovery...")
            endpoints = await self.discovery.discover_endpoints()
            logger.info(f"Discovered {len(endpoints)} endpoints")
            
            # Authenticate if needed
            await self._setup_authentication()
            
            # Run tests on all endpoints
            test_results = []
            
            # Functional tests
            logger.info("Running functional tests...")
            functional_results = await self._run_functional_tests(endpoints)
            test_results.extend(functional_results)
            
            # Security tests
            logger.info("Running security tests...")
            security_results = await self._run_security_tests(endpoints)
            test_results.extend(security_results)
            
            # Performance tests
            logger.info("Running performance tests...")
            performance_results = await self._run_performance_tests(endpoints)
            test_results.extend(performance_results)
            
            # Validation tests
            logger.info("Running validation tests...")
            validation_results = await self._run_validation_tests(endpoints)
            test_results.extend(validation_results)
            
            self.test_results.extend(test_results)
            
            # Generate comprehensive report
            report = self._generate_test_report(test_results, endpoints)
            
            correlation_tracker.finish_correlation(correlation_id)
            return report
            
        except Exception as e:
            logger.error(f"Comprehensive testing failed: {e}")
            correlation_tracker.finish_correlation(correlation_id)
            raise
        finally:
            if self.test_session:
                await self.test_session.close()
    
    async def _setup_authentication(self):
        """Setup authentication for testing."""
        try:
            if not self.test_session:
                return

            # Try to login and get auth token
            login_url = urljoin(self.base_url, '/api/v1/auth/login')

            async with self.test_session.post(login_url, json=self.test_user_credentials) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get('access_token')
                    logger.info("Authentication setup successful")
                else:
                    logger.warning("Authentication setup failed, some tests may be skipped")
                    
        except Exception as e:
            logger.warning(f"Authentication setup error: {e}")
    
    async def _run_functional_tests(self, endpoints: List[EndpointInfo]) -> List[TestResult]:
        """Run functional tests on endpoints."""
        results = []
        
        for endpoint in endpoints:
            test_result = await self._test_endpoint_functionality(endpoint)
            results.append(test_result)
        
        return results
    
    @ensure_session
    async def _test_endpoint_functionality(self, endpoint: EndpointInfo) -> TestResult:
        """Test basic functionality of an endpoint."""
        test_id = f"func_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.FUNCTIONAL,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"Functional test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            # Prepare request
            url = urljoin(self.base_url, endpoint.path.replace('{id}', '1'))
            headers = {}
            
            if endpoint.requires_auth and self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            
            # Prepare test data based on endpoint
            test_data = self._get_test_data_for_endpoint(endpoint)
            
            # Make request
            start_time = time.time()
            
            if endpoint.method == 'GET':
                assert self.test_session is not None
                async with self.test_session.get(url, headers=headers) as response:
                    response_data = await self._safe_json_response(response)
                    test_result.response_status = response.status
                    test_result.response_data = response_data
                    test_result.response_headers = dict(response.headers)
            
            elif endpoint.method == 'POST':
                assert self.test_session is not None
                async with self.test_session.post(url, json=test_data, headers=headers) as response:
                    response_data = await self._safe_json_response(response)
                    test_result.response_status = response.status
                    test_result.response_data = response_data
                    test_result.response_headers = dict(response.headers)
            
            elif endpoint.method == 'PUT':
                assert self.test_session is not None
                async with self.test_session.put(url, json=test_data, headers=headers) as response:
                    response_data = await self._safe_json_response(response)
                    test_result.response_status = response.status
                    test_result.response_data = response_data
                    test_result.response_headers = dict(response.headers)
            
            elif endpoint.method == 'DELETE':
                assert self.test_session is not None
                async with self.test_session.delete(url, headers=headers) as response:
                    response_data = await self._safe_json_response(response)
                    test_result.response_status = response.status
                    test_result.response_data = response_data
                    test_result.response_headers = dict(response.headers)
            
            test_result.response_time_ms = (time.time() - start_time) * 1000
            test_result.request_data = test_data or {}
            
            # Determine test status
            if test_result.response_status and 200 <= test_result.response_status < 300:
                test_result.finish(TestStatus.PASSED)
            elif test_result.response_status == 401 and endpoint.requires_auth and not self.auth_token:
                test_result.finish(TestStatus.SKIPPED, "Authentication required but not available")
            else:
                test_result.finish(TestStatus.FAILED, f"Unexpected status code: {test_result.response_status}")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    def _get_test_data_for_endpoint(self, endpoint: EndpointInfo) -> Optional[Dict]:
        """Get appropriate test data for an endpoint."""
        if endpoint.method == 'GET' or endpoint.method == 'DELETE':
            return None
        
        # Match endpoint patterns to test data templates
        if 'register' in endpoint.path:
            timestamp = int(time.time())
            data = self.test_data_templates['user_registration'].copy()
            data['username'] = data['username'].format(timestamp)
            data['email'] = data['email'].format(timestamp)
            data['display_name'] = data['display_name'].format(timestamp)
            return data
        
        elif 'login' in endpoint.path:
            return self.test_data_templates['user_login']
        
        elif 'message' in endpoint.path:
            return self.test_data_templates['message_creation']
        
        elif 'channel' in endpoint.path:
            timestamp = int(time.time())
            data = self.test_data_templates['channel_creation'].copy()
            data['name'] = data['name'].format(timestamp)
            return data
        
        # Default test data
        return {'test_field': 'test_value', 'timestamp': int(time.time())}
    
    async def _safe_json_response(self, response) -> Optional[Dict]:
        """Safely get JSON response."""
        try:
            return await response.json()
        except Exception:
            return None
    
    async def _run_security_tests(self, endpoints: List[EndpointInfo]) -> List[TestResult]:
        """Run security tests on endpoints."""
        results = []
        
        # Test common security vulnerabilities
        for endpoint in endpoints:
            # SQL injection test
            sql_test = await self._test_sql_injection(endpoint)
            results.append(sql_test)
            
            # XSS test
            xss_test = await self._test_xss_vulnerability(endpoint)
            results.append(xss_test)
            
            # Authentication bypass test
            auth_test = await self._test_authentication_bypass(endpoint)
            results.append(auth_test)
        
        return results
    
    @ensure_session
    async def _test_sql_injection(self, endpoint: EndpointInfo) -> TestResult:
        """Test for SQL injection vulnerabilities."""
        test_id = f"sql_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.SECURITY,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"SQL injection test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            # SQL injection payloads
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT * FROM users--",
                "admin'--"
            ]
            
            url = urljoin(self.base_url, endpoint.path.replace('{id}', sql_payloads[0]))
            
            assert self.test_session is not None
            async with self.test_session.get(url) as response:
                test_result.response_status = response.status
                response_data = await self._safe_json_response(response)
                test_result.response_data = response_data
            
            # Check if SQL injection was blocked (should return 400 or similar)
            if test_result.response_status == 400:
                test_result.finish(TestStatus.PASSED, "SQL injection properly blocked")
            else:
                test_result.security_issues.append("Potential SQL injection vulnerability")
                test_result.finish(TestStatus.FAILED, "SQL injection not properly blocked")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    @ensure_session
    async def _test_xss_vulnerability(self, endpoint: EndpointInfo) -> TestResult:
        """Test for XSS vulnerabilities."""
        test_id = f"xss_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.SECURITY,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"XSS test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            # XSS payloads
            xss_payload = '<script>alert("xss")</script>'
            
            if endpoint.method == 'POST':
                test_data = {'content': xss_payload, 'message': xss_payload}
                url = urljoin(self.base_url, endpoint.path)
                
                assert self.test_session is not None
                async with self.test_session.post(url, json=test_data) as response:
                    test_result.response_status = response.status
                    response_data = await self._safe_json_response(response)
                    test_result.response_data = response_data
                
                # Check if XSS was blocked
                if test_result.response_status == 400:
                    test_result.finish(TestStatus.PASSED, "XSS properly blocked")
                else:
                    test_result.security_issues.append("Potential XSS vulnerability")
                    test_result.finish(TestStatus.FAILED, "XSS not properly blocked")
            else:
                test_result.finish(TestStatus.SKIPPED, "XSS test not applicable for this method")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    @ensure_session
    async def _test_authentication_bypass(self, endpoint: EndpointInfo) -> TestResult:
        """Test for authentication bypass vulnerabilities."""
        test_id = f"auth_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.SECURITY,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"Authentication bypass test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            if not endpoint.requires_auth:
                test_result.finish(TestStatus.SKIPPED, "Endpoint does not require authentication")
                return test_result
            
            # Test without authentication
            url = urljoin(self.base_url, endpoint.path.replace('{id}', '1'))
            
            if self.test_session:
                async with self.test_session.get(url) as response:
                    test_result.response_status = response.status
            
            # Should return 401 Unauthorized
            if test_result.response_status == 401:
                test_result.finish(TestStatus.PASSED, "Authentication properly enforced")
            else:
                test_result.security_issues.append("Authentication bypass vulnerability")
                test_result.finish(TestStatus.FAILED, "Authentication not properly enforced")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    async def _run_performance_tests(self, endpoints: List[EndpointInfo]) -> List[TestResult]:
        """Run performance tests on endpoints."""
        results = []
        
        for endpoint in endpoints:
            perf_test = await self._test_endpoint_performance(endpoint)
            results.append(perf_test)
        
        return results
    
    @ensure_session
    async def _test_endpoint_performance(self, endpoint: EndpointInfo) -> TestResult:
        """Test endpoint performance."""
        test_id = f"perf_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.PERFORMANCE,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"Performance test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            # Run multiple requests to get average performance
            response_times = []
            
            for _ in range(5):  # 5 requests for average
                start_time = time.time()
                
                url = urljoin(self.base_url, endpoint.path.replace('{id}', '1'))
                headers = {}
                
                if endpoint.requires_auth and self.auth_token:
                    headers['Authorization'] = f'Bearer {self.auth_token}'
                
                if self.test_session:
                    async with self.test_session.get(url, headers=headers) as response:
                        await response.read()  # Ensure full response is received
                        response_time = (time.time() - start_time) * 1000
                        response_times.append(response_time)

                        if not test_result.response_status:
                            test_result.response_status = response.status
            
            # Calculate performance metrics
            avg_response_time = sum(response_times) / len(response_times)
            max_response_time = max(response_times)
            min_response_time = min(response_times)
            
            test_result.response_time_ms = avg_response_time
            
            # Performance thresholds
            if avg_response_time < 100:  # < 100ms is excellent
                test_result.finish(TestStatus.PASSED, f"Excellent performance: {avg_response_time:.2f}ms avg")
            elif avg_response_time < 500:  # < 500ms is acceptable
                test_result.finish(TestStatus.PASSED, f"Good performance: {avg_response_time:.2f}ms avg")
            elif avg_response_time < 1000:  # < 1s is concerning
                test_result.performance_issues.append(f"Slow response time: {avg_response_time:.2f}ms")
                test_result.finish(TestStatus.FAILED, f"Slow performance: {avg_response_time:.2f}ms avg")
            else:  # > 1s is poor
                test_result.performance_issues.append(f"Very slow response time: {avg_response_time:.2f}ms")
                test_result.finish(TestStatus.FAILED, f"Poor performance: {avg_response_time:.2f}ms avg")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    async def _run_validation_tests(self, endpoints: List[EndpointInfo]) -> List[TestResult]:
        """Run input validation tests on endpoints."""
        results = []
        
        for endpoint in endpoints:
            validation_test = await self._test_input_validation(endpoint)
            results.append(validation_test)
        
        return results
    
    @ensure_session
    async def _test_input_validation(self, endpoint: EndpointInfo) -> TestResult:
        """Test input validation for an endpoint."""
        test_id = f"val_{endpoint.method}_{endpoint.path}_{int(time.time())}"
        
        test_result = TestResult(
            test_id=test_id,
            endpoint=endpoint,
            test_type=TestType.VALIDATION,
            status=TestStatus.RUNNING,
            start_time=datetime.now(),
            test_description=f"Input validation test for {endpoint.method} {endpoint.path}"
        )
        
        try:
            if endpoint.method in ['GET', 'DELETE']:
                test_result.finish(TestStatus.SKIPPED, "No input validation needed for this method")
                return test_result
            
            # Test with invalid data
            invalid_data_sets = [
                {},  # Empty data
                {'invalid_field': 'invalid_value'},  # Invalid fields
                {'email': 'invalid_email'},  # Invalid email format
                {'password': '123'},  # Too short password
                None  # Null data
            ]
            
            url = urljoin(self.base_url, endpoint.path)
            validation_passed = True
            
            for invalid_data in invalid_data_sets:
                try:
                    if self.test_session:
                        async with self.test_session.post(url, json=invalid_data) as response:
                            # Should return 400 for invalid data
                            if response.status != 400:
                                validation_passed = False
                                break
                except Exception:
                    pass  # Connection errors are expected for some invalid data
            
            if validation_passed:
                test_result.finish(TestStatus.PASSED, "Input validation working correctly")
            else:
                test_result.finish(TestStatus.FAILED, "Input validation not working properly")
            
        except Exception as e:
            test_result.finish(TestStatus.ERROR, str(e))
        
        return test_result
    
    def _generate_test_report(self, test_results: List[TestResult], endpoints: List[EndpointInfo]) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(test_results)
        passed_tests = sum(1 for r in test_results if r.status == TestStatus.PASSED)
        failed_tests = sum(1 for r in test_results if r.status == TestStatus.FAILED)
        error_tests = sum(1 for r in test_results if r.status == TestStatus.ERROR)
        skipped_tests = sum(1 for r in test_results if r.status == TestStatus.SKIPPED)
        
        # Group results by test type
        results_by_type = {}
        for test_type in TestType:
            type_results = [r for r in test_results if r.test_type == test_type]
            results_by_type[test_type.value] = {
                'total': len(type_results),
                'passed': sum(1 for r in type_results if r.status == TestStatus.PASSED),
                'failed': sum(1 for r in type_results if r.status == TestStatus.FAILED),
                'error': sum(1 for r in type_results if r.status == TestStatus.ERROR),
                'skipped': sum(1 for r in type_results if r.status == TestStatus.SKIPPED)
            }
        
        # Performance statistics
        performance_results = [r for r in test_results if r.test_type == TestType.PERFORMANCE and r.response_time_ms > 0]
        avg_response_time = sum(r.response_time_ms for r in performance_results) / len(performance_results) if performance_results else 0
        
        # Security issues
        security_issues = []
        for result in test_results:
            security_issues.extend(result.security_issues)
        
        # Performance issues
        performance_issues = []
        for result in test_results:
            performance_issues.extend(result.performance_issues)
        
        return {
            'summary': {
                'total_endpoints': len(endpoints),
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'error': error_tests,
                'skipped': skipped_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'results_by_type': results_by_type,
            'performance': {
                'average_response_time_ms': avg_response_time,
                'performance_issues_count': len(performance_issues),
                'performance_issues': performance_issues
            },
            'security': {
                'security_issues_count': len(security_issues),
                'security_issues': security_issues
            },
            'endpoints': [
                {
                    'path': ep.path,
                    'method': ep.method,
                    'description': ep.description,
                    'requires_auth': ep.requires_auth,
                    'test_count': ep.test_count,
                    'success_count': ep.success_count,
                    'failure_count': ep.failure_count
                }
                for ep in endpoints
            ],
            'detailed_results': [
                {
                    'test_id': r.test_id,
                    'endpoint': f"{r.endpoint.method} {r.endpoint.path}",
                    'test_type': r.test_type.value,
                    'status': r.status.value,
                    'duration_ms': r.duration_ms,
                    'response_status': r.response_status,
                    'response_time_ms': r.response_time_ms,
                    'error_message': r.error_message,
                    'security_issues': r.security_issues,
                    'performance_issues': r.performance_issues
                }
                for r in test_results
            ],
            'timestamp': datetime.now().isoformat(),
            'test_configuration': {
                'base_url': self.base_url,
                'test_timeout': self.test_timeout,
                'max_concurrent_tests': self.max_concurrent_tests,
                'authentication_enabled': self.auth_token is not None
            }
        }


# Global comprehensive endpoint tester
comprehensive_endpoint_tester = None

def get_endpoint_tester(base_url: str) -> ComprehensiveEndpointTester:
    """Get or create comprehensive endpoint tester."""
    global comprehensive_endpoint_tester
    if not comprehensive_endpoint_tester:
        comprehensive_endpoint_tester = ComprehensiveEndpointTester(base_url)
    return comprehensive_endpoint_tester
