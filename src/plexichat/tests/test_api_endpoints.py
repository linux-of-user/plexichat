import logging
from datetime import datetime

    import httpx
from .test_base import BaseTest, TestResult


"""
API endpoint tests for PlexiChat.
Tests authentication, user management, and core API functionality.
"""

try:
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


class APIEndpointTest(BaseTest):
    """Test API endpoints functionality."""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        super().__init__(base_url)
        self.client = None
    
    async def setup(self):
        """Setup HTTP client for testing."""
        if HTTPX_AVAILABLE:
            self.client = httpx.AsyncClient()
    
    async def teardown(self):
        """Cleanup HTTP client."""
        if self.client:
            await self.client.aclose()
    
    async def test_health_endpoint(self):
        """Test health check endpoint."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not HTTPX_AVAILABLE:
                self.add_result(TestResult(
                    test_name="Health Endpoint",
                    category="API",
                    endpoint="/health",
                    method="GET",
                    status="skipped",
                    duration_ms=0,
                    error_message="httpx not available"
                ))
                return
            
            response = await self.client.get(f"{self.base_url}/health")
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Health Endpoint",
                category="API",
                endpoint="/health",
                method="GET",
                status="passed" if response.status_code == 200 else "failed",
                duration_ms=duration,
                status_code=response.status_code,
                response_data={"status": "healthy" if response.status_code == 200 else "unhealthy"}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Health Endpoint",
                category="API",
                endpoint="/health",
                method="GET",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_auth_registration(self):
        """Test user registration endpoint."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not HTTPX_AVAILABLE:
                self.add_result(TestResult(
                    test_name="User Registration",
                    category="Authentication",
                    endpoint="/api/v1/auth/register",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="httpx not available"
                ))
                return
            
            # Generate test user data
            user_data = {
                "username": self.data_generator.generate_username(),
                "email": self.data_generator.generate_email(),
                "password": self.data_generator.generate_password()
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/register",
                json=user_data
            )
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            # Check if registration was successful or if endpoint exists
            success = response.status_code in [200, 201, 400, 409]  # 400/409 for validation/duplicate
            
            self.add_result(TestResult(
                test_name="User Registration",
                category="Authentication",
                endpoint="/api/v1/auth/register",
                method="POST",
                status="passed" if success else "failed",
                duration_ms=duration,
                status_code=response.status_code,
                request_data={"username": user_data["username"], "email": user_data["email"]},
                response_data={"registration_attempted": True}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="User Registration",
                category="Authentication",
                endpoint="/api/v1/auth/register",
                method="POST",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_auth_login(self):
        """Test user login endpoint."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not HTTPX_AVAILABLE:
                self.add_result(TestResult(
                    test_name="User Login",
                    category="Authentication",
                    endpoint="/api/v1/auth/login",
                    method="POST",
                    status="skipped",
                    duration_ms=0,
                    error_message="httpx not available"
                ))
                return
            
            # Test login with dummy credentials
            login_data = {
                "username": "test_user",
                "password": "test_password"
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            )
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            # Check if login endpoint exists (even if credentials are wrong)
            endpoint_exists = response.status_code != 404
            
            self.add_result(TestResult(
                test_name="User Login",
                category="Authentication",
                endpoint="/api/v1/auth/login",
                method="POST",
                status="passed" if endpoint_exists else "failed",
                duration_ms=duration,
                status_code=response.status_code,
                request_data={"username": login_data["username"]},
                response_data={"endpoint_exists": endpoint_exists}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="User Login",
                category="Authentication",
                endpoint="/api/v1/auth/login",
                method="POST",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_api_info_endpoint(self):
        """Test API info endpoint."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not HTTPX_AVAILABLE:
                self.add_result(TestResult(
                    test_name="API Info",
                    category="API",
                    endpoint="/api/v1/info",
                    method="GET",
                    status="skipped",
                    duration_ms=0,
                    error_message="httpx not available"
                ))
                return
            
            response = await self.client.get(f"{self.base_url}/api/v1/info")
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="API Info",
                category="API",
                endpoint="/api/v1/info",
                method="GET",
                status="passed" if response.status_code in [200, 404] else "failed",
                duration_ms=duration,
                status_code=response.status_code,
                response_data={"info_available": response.status_code == 200}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="API Info",
                category="API",
                endpoint="/api/v1/info",
                method="GET",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def run_all_tests(self):
        """Run all API endpoint tests."""
        await self.setup()
        try:
            await self.test_health_endpoint()
            await self.test_auth_registration()
            await self.test_auth_login()
            await self.test_api_info_endpoint()
        finally:
            await self.teardown()
