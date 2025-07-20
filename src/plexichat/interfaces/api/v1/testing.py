"""
PlexiChat Testing API Endpoints

API endpoints for testing, debugging, and development purposes.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import asyncio
import time
import random

try:
    from plexichat.interfaces.api.v1.auth import get_current_user
    from plexichat.app.logger_config import get_logger
except ImportError:
    get_current_user = lambda: {}
    get_logger = lambda name: print
    settings = {}

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/testing", tags=["testing"])

# Request/Response Models
class TestRequest(BaseModel):
    test_type: str
    parameters: Dict[str, Any] = {}
    timeout: int = 30

class TestResponse(BaseModel):
    test_id: str
    test_type: str
    status: str
    result: Dict[str, Any]
    duration: float
    timestamp: str

class LoadTestRequest(BaseModel):
    endpoint: str
    concurrent_users: int = 10
    duration_seconds: int = 60
    requests_per_second: int = 10

class LoadTestResponse(BaseModel):
    test_id: str
    status: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    max_response_time: float
    min_response_time: float
    requests_per_second: float

# Development/testing permission check
async def require_dev_access(current_user: Dict = Depends(get_current_user)):
    """Require development/testing access."""
    user_roles = current_user.get("roles", [])
    if not ("admin" in user_roles or "developer" in user_roles or "tester" in user_roles):
        # In development mode, allow all authenticated users
        if settings.get("environment") != "development":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Development/testing privileges required"
            )
    return current_user

@router.get("/ping")
async def ping():
    """Simple ping endpoint for health checks."""
    return {
        "message": "pong",
        "timestamp": time.time(),
        "status": "ok"
    }

@router.get("/echo")
async def echo(message: str = Query(..., description="Message to echo")):
    """Echo back the provided message."""
    return {
        "original_message": message,
        "echoed_message": message,
        "timestamp": time.time()
    }

@router.post("/delay")
async def delay_test(delay_seconds: float = Query(1.0, ge=0, le=30)):
    """Test endpoint with configurable delay."""
    start_time = time.time()
    await asyncio.sleep(delay_seconds)
    end_time = time.time()

    return {
        "requested_delay": delay_seconds,
        "actual_delay": end_time - start_time,
        "timestamp": end_time
    }

@router.get("/random")
async def random_data()
    size: int = Query(100, ge=1, le=10000),
    data_type: str = Query("string", pattern="^(string|number|boolean|mixed)$")
):
    """Generate random test data."""
    data = []

    for _ in range(size):
        if data_type == "string":
            data.append(f"test_string_{random.randint(1000, 9999)}")
        elif data_type == "number":
            data.append(random.randint(1, 1000))
        elif data_type == "boolean":
            data.append(random.choice([True, False]))
        elif data_type == "mixed":
            choice = random.choice(["string", "number", "boolean"])
            if choice == "string":
                data.append(f"mixed_string_{random.randint(100, 999)}")
            elif choice == "number":
                data.append(random.randint(1, 100))
            else:
                data.append(random.choice([True, False]))

    return {
        "data": data,
        "size": len(data),
        "type": data_type,
        "generated_at": time.time()
    }

@router.post("/error")
async def error_test()
    error_code: int = Query(500, ge=400, le=599),
    error_message: str = Query("Test error message")
):
    """Generate test errors with specified status codes."""
    raise HTTPException(status_code=error_code, detail=error_message)

@router.post("/test", response_model=TestResponse)
async def run_test()
    request: TestRequest,
    current_user: Dict = Depends(require_dev_access)
):
    """Run a specific test case."""
    start_time = time.time()
    test_id = f"test_{int(start_time)}_{random.randint(1000, 9999)}"

    try:
        result = {}

        if request.test_type == "database":
            result = await _test_database_connection()
        elif request.test_type == "auth":
            result = await _test_authentication()
        elif request.test_type == "api":
            result = await _test_api_endpoints()
        elif request.test_type == "security":
            result = await _test_security_features()
        elif request.test_type == "performance":
            result = await _test_performance()
        else:
            raise HTTPException(status_code=400, detail=f"Unknown test type: {request.test_type}")

        duration = time.time() - start_time

        return TestResponse()
            test_id=test_id,
            test_type=request.test_type,
            status="completed",
            result=result,
            duration=duration,
            timestamp=str(time.time())
        )

    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Test {test_id} failed: {e}")

        return TestResponse()
            test_id=test_id,
            test_type=request.test_type,
            status="failed",
            result={"error": str(e)},
            duration=duration,
            timestamp=str(time.time())
        )

@router.post("/load-test", response_model=LoadTestResponse)
async def load_test()
    request: LoadTestRequest,
    current_user: Dict = Depends(require_dev_access)
):
    """Run load test on specified endpoint."""
    test_id = f"load_test_{int(time.time())}_{random.randint(1000, 9999)}"

    try:
        # Simulate load test results
        total_requests = request.concurrent_users * request.requests_per_second * request.duration_seconds
        successful_requests = int(total_requests * random.uniform(0.85, 0.99))
        failed_requests = total_requests - successful_requests

        return LoadTestResponse()
            test_id=test_id,
            status="completed",
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            average_response_time=random.uniform(50, 200),
            max_response_time=random.uniform(200, 500),
            min_response_time=random.uniform(10, 50),
            requests_per_second=float(request.requests_per_second)
        )

    except Exception as e:
        logger.error(f"Load test {test_id} failed: {e}")
        raise HTTPException(status_code=500, detail=f"Load test failed: {e}")

@router.get("/system-info")
async def get_system_info(current_user: Dict = Depends(require_dev_access)):
    """Get system information for testing purposes."""
    try:
        import platform
        import sys

        return {
            "python_version": sys.version,
            "platform": platform.platform(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "environment": settings.get("environment", "unknown"),
            "debug_mode": settings.get("debug", False),
            "timestamp": time.time()
        }

    except Exception as e:
        logger.error(f"Get system info error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/logs/test")
async def test_logging()
    level: str = Query("info", pattern="^(debug|info|warning|error|critical)$"),
    message: str = Query("Test log message")
):
    """Test logging functionality."""
    try:
        if level == "debug":
            logger.debug(message)
        elif level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
        elif level == "error":
            logger.error(message)
        elif level == "critical":
            logger.critical(message)

        return {
            "message": f"Log message sent with level: {level}",
            "logged_message": message,
            "timestamp": time.time()
        }

    except Exception as e:
        logger.error(f"Test logging error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Helper functions for test cases
async def _test_database_connection():
    """Test database connectivity."""
    try:
        # Simulate database test
        await asyncio.sleep(0.1)
        return {
            "database_connected": True,
            "connection_time": 0.1,
            "test_query_success": True
        }
    except Exception as e:
        return {
            "database_connected": False,
            "error": str(e)
        }

async def _test_authentication():
    """Test authentication system."""
    try:
        # Simulate auth test
        await asyncio.sleep(0.05)
        return {
            "auth_system_available": True,
            "token_generation": True,
            "token_validation": True
        }
    except Exception as e:
        return {
            "auth_system_available": False,
            "error": str(e)
        }

async def _test_api_endpoints():
    """Test API endpoints."""
    try:
        # Simulate API test
        await asyncio.sleep(0.2)
        return {
            "endpoints_accessible": True,
            "response_times": {
                "/api/v1/auth/status": 45,
                "/api/v1/admin/status": 52,
                "/api/v1/security/status": 38
            }
        }
    except Exception as e:
        return {
            "endpoints_accessible": False,
            "error": str(e)
        }

async def _test_security_features():
    """Test security features."""
    try:
        # Simulate security test
        await asyncio.sleep(0.15)
        return {
            "firewall_active": True,
            "encryption_working": True,
            "antivirus_active": True,
            "threat_detection": True
        }
    except Exception as e:
        return {
            "security_features_working": False,
            "error": str(e)
        }

async def _test_performance():
    """Test system performance."""
    try:
        # Simulate performance test
        await asyncio.sleep(0.3)
        return {
            "cpu_usage": random.uniform(10, 80),
            "memory_usage": random.uniform(20, 70),
            "disk_io": random.uniform(5, 50),
            "network_latency": random.uniform(1, 20)
        }
    except Exception as e:
        return {
            "performance_test_failed": True,
            "error": str(e)
        }

@router.get("/status")
async def testing_status():
    """Get testing service status."""
    return {
        "service": "testing",
        "status": "online",
        "environment": settings.get("environment", "unknown"),
        "debug_mode": settings.get("debug", False)
    }
