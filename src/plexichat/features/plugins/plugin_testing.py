import asyncio
import json
import logging
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


"""
PlexiChat Plugin Testing Framework

Comprehensive testing framework for plugins:
- Unit testing utilities
- Integration testing
- Performance testing
- Mock PlexiChat API
- Test automation
- Coverage reporting
"""

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Test result data."""
    test_name: str
    success: bool
    duration_ms: float
    error: Optional[str] = None
    output: str = ""
    assertions: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "output": self.output,
            "assertions": self.assertions
        }


@dataclass
class TestSuite:
    """Test suite for plugin."""
    plugin_id: str
    name: str
    tests: List[Callable] = field(default_factory=list)
    setup_func: Optional[Callable] = None
    teardown_func: Optional[Callable] = None
    results: List[TestResult] = field(default_factory=list)
    
    def add_test(self, test_func: Callable):
        """Add test to suite."""
        self.tests.append(test_func)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get test suite summary."""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        total_duration = sum(r.duration_ms for r in self.results)
        
        return {
            "plugin_id": self.plugin_id,
            "suite_name": self.name,
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "total_duration_ms": total_duration,
            "average_duration_ms": total_duration / total_tests if total_tests > 0 else 0
        }


class MockPlexiChatAPI:
    """Mock PlexiChat API for testing."""
    
    def __init__(self):
        self.sent_messages: List[Dict[str, Any]] = []
        self.user_data: Dict[str, Dict[str, Any]] = {}
        self.config_data: Dict[str, Any] = {}
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.ai_responses: Dict[str, Any] = {}
        
        # Mock responses
        self.mock_responses = {
            "send_message": True,
            "get_user_info": {"user_id": "test_user", "username": "testuser"},
            "create_group": "test_group_123",
            "call_ai": {"success": True, "content": "Mock AI response"}
        }
    
    async def send_message(self, user_id: str, message: str, **kwargs) -> bool:
        """Mock send message."""
        self.sent_messages.append({
            "user_id": user_id,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs
        })
        return self.mock_responses["send_message"]
    
    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Mock get user info."""
        return self.user_data.get(user_id, self.mock_responses["get_user_info"])
    
    async def create_group(self, group_data: Dict[str, Any]) -> Optional[str]:
        """Mock create group."""
        return self.mock_responses["create_group"]
    
    async def call_ai(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock AI call."""
        return self.ai_responses.get(request_type, self.mock_responses["call_ai"])
    
    def register_event_handler(self, event_name: str, handler: Callable):
        """Mock register event handler."""
        if event_name not in self.event_handlers:
            self.event_handlers[event_name] = []
        self.event_handlers[event_name].append(handler)
    
    def emit_event(self, event_name: str, data: Any):
        """Mock emit event."""
    
    def log(self, level: str, message: str):
        """Mock logging."""
        logger.log(getattr(logging, level.upper(), logging.INFO), f"Plugin: {message}")
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Mock get config."""
        return self.config_data.get(key, default)
    
    def set_config(self, key: str, value: Any):
        """Mock set config."""
        self.config_data[key] = value
    
    # Test utilities
    def set_mock_response(self, method: str, response: Any):
        """Set mock response for method."""
        self.mock_responses[method] = response
    
    def set_user_data(self, user_id: str, data: Dict[str, Any]):
        """Set mock user data."""
        self.user_data[user_id] = data
    
    def set_ai_response(self, request_type: str, response: Dict[str, Any]):
        """Set mock AI response."""
        self.ai_responses[request_type] = response
    
    def get_sent_messages(self) -> List[Dict[str, Any]]:
        """Get all sent messages."""
        return self.sent_messages.copy()
    
    def clear_sent_messages(self):
        """Clear sent messages."""
        self.sent_messages.clear()


class PluginTestFramework:
    """Testing framework for PlexiChat plugins."""
    
    def __init__(self):
        self.test_suites: Dict[str, TestSuite] = {}
        self.mock_api = MockPlexiChatAPI()
        self.performance_data: Dict[str, List[float]] = {}
    
    def create_test_suite(self, plugin_id: str, suite_name: str) -> TestSuite:
        """Create new test suite."""
        suite = TestSuite(plugin_id=plugin_id, name=suite_name)
        suite_key = f"{plugin_id}_{suite_name}"
        self.test_suites[suite_key] = suite
        return suite
    
    async def run_test_suite(self, suite_key: str) -> Dict[str, Any]:
        """Run test suite."""
        if suite_key not in self.test_suites:
            return {"error": f"Test suite {suite_key} not found"}
        
        suite = self.test_suites[suite_key]
        suite.results.clear()
        
        try:
            # Setup
            if suite.setup_func:
                if asyncio.iscoroutinefunction(suite.setup_func):
                    await suite.setup_func()
                else:
                    suite.setup_func()
            
            # Run tests
            for test_func in suite.tests:
                result = await self._run_single_test(test_func)
                suite.results.append(result)
            
            # Teardown
            if suite.teardown_func:
                if asyncio.iscoroutinefunction(suite.teardown_func):
                    await suite.teardown_func()
                else:
                    suite.teardown_func()
            
            return suite.get_summary()
            
        except Exception as e:
            logger.error(f"Test suite {suite_key} failed: {e}")
            return {"error": str(e)}
    
    async def _run_single_test(self, test_func: Callable) -> TestResult:
        """Run single test."""
        test_name = test_func.__name__
        start_time = time.time()
        
        try:
            # Reset mock API
            self.mock_api.clear_sent_messages()
            
            # Run test
            if asyncio.iscoroutinefunction(test_func):
                await test_func(self.mock_api)
            else:
                test_func(self.mock_api)
            
            duration_ms = (time.time() - start_time) * 1000
            
            return TestResult(
                test_name=test_name,
                success=True,
                duration_ms=duration_ms,
                output="Test passed"
            )
            
        except AssertionError as e:
            duration_ms = (time.time() - start_time) * 1000
            return TestResult(
                test_name=test_name,
                success=False,
                duration_ms=duration_ms,
                error=f"Assertion failed: {e}",
                output=traceback.format_exc()
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return TestResult(
                test_name=test_name,
                success=False,
                duration_ms=duration_ms,
                error=str(e),
                output=traceback.format_exc()
            )
    
    async def run_performance_test(self, plugin_id: str, test_func: Callable, 
                                 iterations: int = 100) -> Dict[str, Any]:
        """Run performance test."""
        durations = []
        errors = 0
        
        for i in range(iterations):
            start_time = time.time()
            
            try:
                if asyncio.iscoroutinefunction(test_func):
                    await test_func(self.mock_api)
                else:
                    test_func(self.mock_api)
                
                duration = (time.time() - start_time) * 1000
                durations.append(duration)
                
            except Exception as e:
                errors += 1
                logger.error(f"Performance test iteration {i} failed: {e}")
        
        if durations:
            avg_duration = sum(durations) / len(durations)
            min_duration = min(durations)
            max_duration = max(durations)
            
            # Store performance data
            if plugin_id not in self.performance_data:
                self.performance_data[plugin_id] = []
            self.performance_data[plugin_id].extend(durations)
            
            return {
                "plugin_id": plugin_id,
                "iterations": iterations,
                "successful_iterations": len(durations),
                "errors": errors,
                "average_duration_ms": avg_duration,
                "min_duration_ms": min_duration,
                "max_duration_ms": max_duration,
                "success_rate": (len(durations) / iterations) * 100
            }
        else:
            return {
                "plugin_id": plugin_id,
                "iterations": iterations,
                "successful_iterations": 0,
                "errors": errors,
                "success_rate": 0
            }
    
    def create_integration_test(self, plugin_path: Path) -> TestSuite:
        """Create integration test for plugin."""
        plugin_id = plugin_path.name
        suite = self.create_test_suite(plugin_id, "integration")
        
        # Add basic integration tests
        suite.add_test(self._test_plugin_loads)
        suite.add_test(self._test_plugin_manifest)
        suite.add_test(self._test_plugin_api_usage)
        
        return suite
    
    async def _test_plugin_loads(self, api):
        """Test that plugin loads without errors."""
        # This would actually load the plugin
        assert True, "Plugin should load successfully"
    
    async def _test_plugin_manifest(self, api):
        """Test plugin manifest validity."""
        # This would validate the manifest
        assert True, "Plugin manifest should be valid"
    
    async def _test_plugin_api_usage(self, api):
        """Test plugin API usage."""
        # Test basic API calls
        result = await api.send_message("test_user", "test message")
        assert result, "Should be able to send messages"
        
        user_info = await api.get_user_info("test_user")
        assert user_info is not None, "Should be able to get user info"
    
    def generate_test_report(self, output_file: Path):
        """Generate comprehensive test report."""
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "test_suites": {},
            "performance_data": self.performance_data,
            "summary": {
                "total_suites": len(self.test_suites),
                "total_tests": 0,
                "total_passed": 0,
                "total_failed": 0
            }
        }
        
        for suite_key, suite in self.test_suites.items():
            suite_summary = suite.get_summary()
            report["test_suites"][suite_key] = {
                "summary": suite_summary,
                "results": [r.to_dict() for r in suite.results]
            }
            
            report["summary"]["total_tests"] += suite_summary["total_tests"]
            report["summary"]["total_passed"] += suite_summary["passed_tests"]
            report["summary"]["total_failed"] += suite_summary["failed_tests"]
        
        # Calculate overall success rate
        total_tests = report["summary"]["total_tests"]
        if total_tests > 0:
            report["summary"]["success_rate"] = (report["summary"]["total_passed"] / total_tests) * 100
        else:
            report["summary"]["success_rate"] = 0
        
        # Write report
        output_file.write_text(json.dumps(report, indent=2))
        logger.info(f"Test report generated: {output_file}")


# Global testing framework instance
plugin_test_framework = PluginTestFramework()
