"""
API Testing Plugin

Comprehensive API testing with request building, response validation, and automated testing suites.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiohttp
import requests
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability

logger = logging.getLogger(__name__)


class APIRequest(BaseModel):
    """API request model."""
    method: str
    url: str
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    data: Optional[Union[Dict[str, Any], str]] = None
    timeout: Optional[int] = None


class TestCase(BaseModel):
    """Test case model."""
    name: str
    request: APIRequest
    expected_status: Optional[int] = None
    expected_headers: Optional[Dict[str, str]] = None
    expected_body: Optional[Dict[str, Any]] = None
    validations: Optional[List[Dict[str, Any]]] = None


class APITestingCore:
    """Core API testing functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('request_timeout', 30)
        self.max_redirects = config.get('max_redirects', 5)
        self.verify_ssl = config.get('verify_ssl', True)
        self.user_agent = config.get('user_agent', 'PlexiChat API Tester/1.0')
        self.environments = config.get('test_environments', {})
        
    async def send_request(self, request: APIRequest) -> Dict[str, Any]:
        """Send HTTP request and return response details."""
        try:
            start_time = time.time()
            
            # Prepare request parameters
            headers = request.headers or {}
            headers.setdefault('User-Agent', self.user_agent)
            
            timeout = request.timeout or self.timeout
            
            # Send request using aiohttp for async support
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            ) as session:
                
                async with session.request(
                    method=request.method.upper(),
                    url=request.url,
                    headers=headers,
                    params=request.params,
                    json=request.data if isinstance(request.data, dict) else None,
                    data=request.data if isinstance(request.data, str) else None
                ) as response:
                    
                    response_time = time.time() - start_time
                    response_text = await response.text()
                    
                    # Try to parse JSON response
                    try:
                        response_json = await response.json()
                    except:
                        response_json = None
                    
                    return {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "body": response_json,
                        "text": response_text,
                        "response_time": response_time,
                        "url": str(response.url),
                        "method": request.method.upper(),
                        "timestamp": datetime.now().isoformat()
                    }
                    
        except Exception as e:
            logger.error(f"Error sending request to {request.url}: {e}")
            return {
                "error": str(e),
                "status_code": None,
                "response_time": time.time() - start_time,
                "timestamp": datetime.now().isoformat()
            }
    
    async def run_test_case(self, test_case: TestCase) -> Dict[str, Any]:
        """Run a single test case."""
        try:
            # Send request
            response = await self.send_request(test_case.request)
            
            # Initialize test result
            test_result = {
                "name": test_case.name,
                "passed": True,
                "response": response,
                "validations": [],
                "errors": []
            }
            
            # Check if request failed
            if "error" in response:
                test_result["passed"] = False
                test_result["errors"].append(f"Request failed: {response['error']}")
                return test_result
            
            # Validate status code
            if test_case.expected_status is not None:
                if response["status_code"] != test_case.expected_status:
                    test_result["passed"] = False
                    test_result["errors"].append(
                        f"Expected status {test_case.expected_status}, got {response['status_code']}"
                    )
                else:
                    test_result["validations"].append("Status code validation passed")
            
            # Validate headers
            if test_case.expected_headers:
                for header, expected_value in test_case.expected_headers.items():
                    actual_value = response["headers"].get(header)
                    if actual_value != expected_value:
                        test_result["passed"] = False
                        test_result["errors"].append(
                            f"Expected header {header}={expected_value}, got {actual_value}"
                        )
                    else:
                        test_result["validations"].append(f"Header {header} validation passed")
            
            # Validate response body
            if test_case.expected_body and response["body"]:
                if not self._validate_json_structure(response["body"], test_case.expected_body):
                    test_result["passed"] = False
                    test_result["errors"].append("Response body validation failed")
                else:
                    test_result["validations"].append("Response body validation passed")
            
            # Run custom validations
            if test_case.validations:
                for validation in test_case.validations:
                    validation_result = self._run_validation(response, validation)
                    if not validation_result["passed"]:
                        test_result["passed"] = False
                        test_result["errors"].append(validation_result["error"])
                    else:
                        test_result["validations"].append(validation_result["message"])
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error running test case {test_case.name}: {e}")
            return {
                "name": test_case.name,
                "passed": False,
                "errors": [str(e)],
                "validations": []
            }
    
    def _validate_json_structure(self, actual: Dict[str, Any], expected: Dict[str, Any]) -> bool:
        """Validate JSON structure matches expected."""
        try:
            for key, expected_value in expected.items():
                if key not in actual:
                    return False
                
                if isinstance(expected_value, dict) and isinstance(actual[key], dict):
                    if not self._validate_json_structure(actual[key], expected_value):
                        return False
                elif actual[key] != expected_value:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _run_validation(self, response: Dict[str, Any], validation: Dict[str, Any]) -> Dict[str, Any]:
        """Run custom validation rule."""
        try:
            validation_type = validation.get("type")
            
            if validation_type == "response_time":
                max_time = validation.get("max_time", 1.0)
                if response["response_time"] <= max_time:
                    return {"passed": True, "message": f"Response time validation passed ({response['response_time']:.3f}s)"}
                else:
                    return {"passed": False, "error": f"Response time too slow: {response['response_time']:.3f}s > {max_time}s"}
            
            elif validation_type == "json_path":
                path = validation.get("path")
                expected_value = validation.get("value")
                actual_value = self._get_json_path_value(response["body"], path)
                
                if actual_value == expected_value:
                    return {"passed": True, "message": f"JSON path validation passed: {path}"}
                else:
                    return {"passed": False, "error": f"JSON path {path}: expected {expected_value}, got {actual_value}"}
            
            elif validation_type == "contains":
                text = validation.get("text")
                if text in response["text"]:
                    return {"passed": True, "message": f"Contains validation passed: '{text}'"}
                else:
                    return {"passed": False, "error": f"Response does not contain: '{text}'"}
            
            else:
                return {"passed": False, "error": f"Unknown validation type: {validation_type}"}
                
        except Exception as e:
            return {"passed": False, "error": f"Validation error: {str(e)}"}
    
    def _get_json_path_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from JSON using dot notation path."""
        try:
            keys = path.split('.')
            current = data
            
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            
            return current
            
        except Exception:
            return None
    
    async def run_test_suite(self, test_cases: List[TestCase]) -> Dict[str, Any]:
        """Run multiple test cases."""
        try:
            start_time = time.time()
            results = []
            
            for test_case in test_cases:
                result = await self.run_test_case(test_case)
                results.append(result)
            
            # Calculate summary
            total_tests = len(results)
            passed_tests = len([r for r in results if r["passed"]])
            failed_tests = total_tests - passed_tests
            
            return {
                "summary": {
                    "total": total_tests,
                    "passed": passed_tests,
                    "failed": failed_tests,
                    "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                    "execution_time": time.time() - start_time
                },
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error running test suite: {e}")
            raise
    
    async def load_test(self, request: APIRequest, concurrent_users: int = 10, 
                       duration: int = 60) -> Dict[str, Any]:
        """Perform load testing on an endpoint."""
        try:
            start_time = time.time()
            results = []
            
            async def worker():
                """Worker function for load testing."""
                worker_results = []
                end_time = start_time + duration
                
                while time.time() < end_time:
                    response = await self.send_request(request)
                    worker_results.append({
                        "status_code": response.get("status_code"),
                        "response_time": response.get("response_time", 0),
                        "error": response.get("error")
                    })
                    
                    # Small delay to prevent overwhelming the server
                    await asyncio.sleep(0.1)
                
                return worker_results
            
            # Run concurrent workers
            tasks = [worker() for _ in range(concurrent_users)]
            worker_results = await asyncio.gather(*tasks)
            
            # Flatten results
            for worker_result in worker_results:
                results.extend(worker_result)
            
            # Calculate statistics
            response_times = [r["response_time"] for r in results if r["response_time"] is not None]
            status_codes = [r["status_code"] for r in results if r["status_code"] is not None]
            errors = [r for r in results if r["error"] is not None]
            
            return {
                "summary": {
                    "total_requests": len(results),
                    "successful_requests": len([r for r in results if r["status_code"] and 200 <= r["status_code"] < 300]),
                    "failed_requests": len(errors),
                    "avg_response_time": sum(response_times) / len(response_times) if response_times else 0,
                    "min_response_time": min(response_times) if response_times else 0,
                    "max_response_time": max(response_times) if response_times else 0,
                    "requests_per_second": len(results) / duration,
                    "concurrent_users": concurrent_users,
                    "duration": duration
                },
                "status_code_distribution": {str(code): status_codes.count(code) for code in set(status_codes)},
                "errors": errors[:10],  # First 10 errors
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error during load test: {e}")
            raise


class APITesterPlugin(PluginInterface):
    """API Testing Plugin."""

    def __init__(self):
        super().__init__("api_tester", "1.0.0")
        self.router = APIRouter()
        self.tester = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="api_tester",
            version="1.0.0",
            description="Comprehensive API testing with request building, response validation, and automated testing suites",
            plugin_type=PluginType.TESTING
        )

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.NETWORK,
                ModuleCapability.FILE_SYSTEM,
                ModuleCapability.WEB_UI
            ],
            network_access=True,
            file_system_access=True,
            database_access=False
        )

    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()

            # Initialize tester core
            self.tester = APITestingCore(self.config)

            # Setup API routes
            self._setup_routes()

            # Register UI pages
            await self._register_ui_pages()

            self.logger.info("API Tester plugin initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize API Tester plugin: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("API Tester plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during API Tester plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.post("/send-request")
        async def send_request(request: APIRequest):
            """Send HTTP request."""
            try:
                result = await self.tester.send_request(request)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/run-test")
        async def run_test(test_case: TestCase):
            """Run single test case."""
            try:
                result = await self.tester.run_test_case(test_case)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/run-suite")
        async def run_test_suite(test_cases: List[TestCase]):
            """Run test suite."""
            try:
                result = await self.tester.run_test_suite(test_cases)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/load-test")
        async def load_test(request: APIRequest, concurrent_users: int = 10, duration: int = 60):
            """Perform load test."""
            try:
                result = await self.tester.load_test(request, concurrent_users, duration)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/api-tester/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="api_tester_static")

    # Self-test methods
    async def test_http_requests(self) -> Dict[str, Any]:
        """Test HTTP request functionality."""
        try:
            # Test GET request to a public API
            request = APIRequest(
                method="GET",
                url="https://httpbin.org/get",
                headers={"Accept": "application/json"}
            )

            response = await self.tester.send_request(request)

            if response.get("status_code") != 200:
                return {"success": False, "error": f"Expected status 200, got {response.get('status_code')}"}

            return {"success": True, "message": "HTTP requests test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_validation(self) -> Dict[str, Any]:
        """Test response validation functionality."""
        try:
            # Test JSON structure validation
            actual = {"status": "ok", "data": {"id": 1, "name": "test"}}
            expected = {"status": "ok", "data": {"id": 1}}

            valid = self.tester._validate_json_structure(actual, expected)
            if not valid:
                return {"success": False, "error": "JSON validation failed"}

            return {"success": True, "message": "Validation test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_automation(self) -> Dict[str, Any]:
        """Test test automation functionality."""
        try:
            # Create test case
            test_case = TestCase(
                name="Test Case",
                request=APIRequest(method="GET", url="https://httpbin.org/status/200"),
                expected_status=200
            )

            result = await self.tester.run_test_case(test_case)

            if not result.get("passed"):
                return {"success": False, "error": "Test case failed"}

            return {"success": True, "message": "Automation test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_load_testing(self) -> Dict[str, Any]:
        """Test load testing functionality."""
        try:
            # Simple load test
            request = APIRequest(method="GET", url="https://httpbin.org/get")
            result = await self.tester.load_test(request, concurrent_users=2, duration=5)

            if result["summary"]["total_requests"] == 0:
                return {"success": False, "error": "No requests completed"}

            return {"success": True, "message": "Load testing test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_reporting(self) -> Dict[str, Any]:
        """Test reporting functionality."""
        try:
            # Test that test results are properly formatted
            test_cases = [
                TestCase(
                    name="Test 1",
                    request=APIRequest(method="GET", url="https://httpbin.org/status/200"),
                    expected_status=200
                )
            ]

            result = await self.tester.run_test_suite(test_cases)

            if "summary" not in result or "results" not in result:
                return {"success": False, "error": "Invalid report format"}

            return {"success": True, "message": "Reporting test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("http_requests", self.test_http_requests),
            ("validation", self.test_validation),
            ("automation", self.test_automation),
            ("load_testing", self.test_load_testing),
            ("reporting", self.test_reporting)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return APITesterPlugin()
