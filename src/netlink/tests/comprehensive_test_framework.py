"""
NetLink Comprehensive Testing Framework

Unified testing framework that consolidates all test functionality with
enhanced features, performance testing, and comprehensive coverage.
"""

import asyncio
import unittest
import pytest
import time
import json
import logging
import traceback
from typing import Dict, List, Optional, Any, Callable, Type
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import sys
import importlib
import inspect
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class TestType(Enum):
    """Types of tests."""
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    API = "api"
    UI = "ui"
    STRESS = "stress"
    REGRESSION = "regression"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestResult:
    """Individual test result."""
    test_id: str
    test_name: str
    test_type: TestType
    status: TestStatus
    duration: float
    error_message: Optional[str] = None
    traceback: Optional[str] = None
    assertions: int = 0
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TestSuite:
    """Test suite results."""
    suite_id: str
    suite_name: str
    test_type: TestType
    tests: List[TestResult] = field(default_factory=list)
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    error_tests: int = 0
    total_duration: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class PerformanceProfiler:
    """Performance profiling for tests."""
    
    def __init__(self):
        self.metrics = {}
        self.start_time = None
        self.memory_start = None
    
    def start_profiling(self):
        """Start performance profiling."""
        self.start_time = time.perf_counter()
        try:
            import psutil
            process = psutil.Process()
            self.memory_start = process.memory_info().rss
        except ImportError:
            self.memory_start = None
    
    def stop_profiling(self) -> Dict[str, Any]:
        """Stop profiling and return metrics."""
        if self.start_time is None:
            return {}
        
        duration = time.perf_counter() - self.start_time
        metrics = {"duration": duration}
        
        if self.memory_start is not None:
            try:
                import psutil
                process = psutil.Process()
                memory_end = process.memory_info().rss
                metrics["memory_delta"] = memory_end - self.memory_start
                metrics["memory_peak"] = memory_end
            except ImportError:
                pass
        
        return metrics


class TestDiscovery:
    """Automatic test discovery."""
    
    def __init__(self, test_directories: List[str]):
        self.test_directories = [Path(d) for d in test_directories]
        self.discovered_tests = {}
    
    async def discover_tests(self) -> Dict[str, List[Callable]]:
        """Discover all test functions and classes."""
        discovered = {}
        
        for test_dir in self.test_directories:
            if not test_dir.exists():
                continue
            
            for test_file in test_dir.rglob("test_*.py"):
                module_tests = await self._discover_tests_in_file(test_file)
                if module_tests:
                    discovered[str(test_file)] = module_tests
        
        self.discovered_tests = discovered
        return discovered
    
    async def _discover_tests_in_file(self, test_file: Path) -> List[Callable]:
        """Discover tests in a specific file."""
        try:
            # Import the test module
            spec = importlib.util.spec_from_file_location(
                f"test_module_{test_file.stem}",
                test_file
            )
            
            if not spec or not spec.loader:
                return []
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            tests = []
            
            # Find test functions
            for name, obj in inspect.getmembers(module):
                if (inspect.isfunction(obj) and 
                    (name.startswith('test_') or hasattr(obj, '_is_test'))):
                    tests.append(obj)
                elif (inspect.isclass(obj) and 
                      issubclass(obj, unittest.TestCase)):
                    # Find test methods in test classes
                    for method_name, method in inspect.getmembers(obj):
                        if method_name.startswith('test_'):
                            tests.append(getattr(obj(), method_name))
            
            return tests
            
        except Exception as e:
            logger.warning(f"Failed to discover tests in {test_file}: {e}")
            return []


class ComprehensiveTestFramework:
    """Comprehensive testing framework."""
    
    def __init__(self, test_directories: List[str] = None):
        self.test_directories = test_directories or [
            "src/netlink/tests",
            "tests",
            "src/tests"
        ]
        
        # Test discovery
        self.discovery = TestDiscovery(self.test_directories)
        
        # Test execution
        self.test_suites: Dict[str, TestSuite] = {}
        self.test_history: List[TestSuite] = []
        
        # Configuration
        self.config = {
            "parallel_execution": True,
            "max_workers": 4,
            "timeout_seconds": 300,
            "performance_profiling": True,
            "detailed_logging": True,
            "auto_retry_failed": False,
            "retry_count": 1
        }
        
        # Statistics
        self.stats = {
            "total_test_runs": 0,
            "total_tests_executed": 0,
            "total_passed": 0,
            "total_failed": 0,
            "total_skipped": 0,
            "average_duration": 0.0
        }
        
        logger.info("Comprehensive Test Framework initialized")
    
    async def run_all_tests(self) -> TestSuite:
        """Run all discovered tests."""
        # Discover tests
        discovered_tests = await self.discovery.discover_tests()
        
        # Create master test suite
        suite = TestSuite(
            suite_id=f"all_tests_{int(time.time())}",
            suite_name="All Tests",
            test_type=TestType.UNIT,
            started_at=datetime.now(timezone.utc)
        )
        
        # Run tests by type
        for test_file, test_functions in discovered_tests.items():
            file_results = await self._run_test_file(test_file, test_functions)
            suite.tests.extend(file_results)
        
        # Calculate summary
        suite.total_tests = len(suite.tests)
        suite.passed_tests = len([t for t in suite.tests if t.status == TestStatus.PASSED])
        suite.failed_tests = len([t for t in suite.tests if t.status == TestStatus.FAILED])
        suite.skipped_tests = len([t for t in suite.tests if t.status == TestStatus.SKIPPED])
        suite.error_tests = len([t for t in suite.tests if t.status == TestStatus.ERROR])
        suite.total_duration = sum(t.duration for t in suite.tests)
        suite.completed_at = datetime.now(timezone.utc)
        
        # Store results
        self.test_suites[suite.suite_id] = suite
        self.test_history.append(suite)
        
        # Update statistics
        self._update_statistics(suite)
        
        logger.info(f"Test run completed: {suite.passed_tests}/{suite.total_tests} passed")
        return suite
    
    async def run_test_type(self, test_type: TestType) -> TestSuite:
        """Run tests of a specific type."""
        discovered_tests = await self.discovery.discover_tests()
        
        suite = TestSuite(
            suite_id=f"{test_type.value}_tests_{int(time.time())}",
            suite_name=f"{test_type.value.title()} Tests",
            test_type=test_type,
            started_at=datetime.now(timezone.utc)
        )
        
        # Filter tests by type (based on naming convention or decorators)
        filtered_tests = {}
        for test_file, test_functions in discovered_tests.items():
            type_tests = [
                test for test in test_functions
                if self._is_test_type(test, test_type)
            ]
            if type_tests:
                filtered_tests[test_file] = type_tests
        
        # Run filtered tests
        for test_file, test_functions in filtered_tests.items():
            file_results = await self._run_test_file(test_file, test_functions)
            suite.tests.extend(file_results)
        
        # Calculate summary
        suite.total_tests = len(suite.tests)
        suite.passed_tests = len([t for t in suite.tests if t.status == TestStatus.PASSED])
        suite.failed_tests = len([t for t in suite.tests if t.status == TestStatus.FAILED])
        suite.skipped_tests = len([t for t in suite.tests if t.status == TestStatus.SKIPPED])
        suite.error_tests = len([t for t in suite.tests if t.status == TestStatus.ERROR])
        suite.total_duration = sum(t.duration for t in suite.tests)
        suite.completed_at = datetime.now(timezone.utc)
        
        self.test_suites[suite.suite_id] = suite
        return suite
    
    def _is_test_type(self, test_func: Callable, test_type: TestType) -> bool:
        """Determine if a test function is of a specific type."""
        # Check for type decorators or markers
        if hasattr(test_func, '_test_type'):
            return test_func._test_type == test_type
        
        # Check naming conventions
        func_name = getattr(test_func, '__name__', '').lower()
        
        if test_type == TestType.PERFORMANCE:
            return 'performance' in func_name or 'perf' in func_name or 'benchmark' in func_name
        elif test_type == TestType.SECURITY:
            return 'security' in func_name or 'auth' in func_name or 'permission' in func_name
        elif test_type == TestType.INTEGRATION:
            return 'integration' in func_name or 'e2e' in func_name
        elif test_type == TestType.API:
            return 'api' in func_name or 'endpoint' in func_name
        elif test_type == TestType.STRESS:
            return 'stress' in func_name or 'load' in func_name
        
        # Default to unit test
        return test_type == TestType.UNIT
    
    async def _run_test_file(self, test_file: str, test_functions: List[Callable]) -> List[TestResult]:
        """Run all tests in a file."""
        results = []
        
        if self.config["parallel_execution"] and len(test_functions) > 1:
            # Run tests in parallel
            with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
                future_to_test = {
                    executor.submit(self._run_single_test, test_func): test_func
                    for test_func in test_functions
                }
                
                for future in as_completed(future_to_test):
                    test_func = future_to_test[future]
                    try:
                        result = future.result(timeout=self.config["timeout_seconds"])
                        results.append(result)
                    except Exception as e:
                        # Create error result
                        error_result = TestResult(
                            test_id=f"{test_file}::{test_func.__name__}",
                            test_name=test_func.__name__,
                            test_type=TestType.UNIT,
                            status=TestStatus.ERROR,
                            duration=0.0,
                            error_message=str(e),
                            traceback=traceback.format_exc()
                        )
                        results.append(error_result)
        else:
            # Run tests sequentially
            for test_func in test_functions:
                result = await self._run_single_test_async(test_func)
                results.append(result)
        
        return results
    
    def _run_single_test(self, test_func: Callable) -> TestResult:
        """Run a single test function (synchronous)."""
        test_id = f"{test_func.__module__}::{test_func.__name__}"
        
        # Setup profiling
        profiler = PerformanceProfiler()
        if self.config["performance_profiling"]:
            profiler.start_profiling()
        
        start_time = time.perf_counter()
        
        try:
            # Execute test
            if asyncio.iscoroutinefunction(test_func):
                # Run async test
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(test_func())
                finally:
                    loop.close()
            else:
                # Run sync test
                test_func()
            
            duration = time.perf_counter() - start_time
            
            # Get performance metrics
            perf_metrics = {}
            if self.config["performance_profiling"]:
                perf_metrics = profiler.stop_profiling()
            
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.PASSED,
                duration=duration,
                performance_metrics=perf_metrics
            )
            
        except unittest.SkipTest as e:
            duration = time.perf_counter() - start_time
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.SKIPPED,
                duration=duration,
                error_message=str(e)
            )
            
        except Exception as e:
            duration = time.perf_counter() - start_time
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.FAILED,
                duration=duration,
                error_message=str(e),
                traceback=traceback.format_exc()
            )
    
    async def _run_single_test_async(self, test_func: Callable) -> TestResult:
        """Run a single test function (asynchronous)."""
        test_id = f"{test_func.__module__}::{test_func.__name__}"
        
        # Setup profiling
        profiler = PerformanceProfiler()
        if self.config["performance_profiling"]:
            profiler.start_profiling()
        
        start_time = time.perf_counter()
        
        try:
            # Execute test
            if asyncio.iscoroutinefunction(test_func):
                await test_func()
            else:
                test_func()
            
            duration = time.perf_counter() - start_time
            
            # Get performance metrics
            perf_metrics = {}
            if self.config["performance_profiling"]:
                perf_metrics = profiler.stop_profiling()
            
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.PASSED,
                duration=duration,
                performance_metrics=perf_metrics
            )
            
        except unittest.SkipTest as e:
            duration = time.perf_counter() - start_time
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.SKIPPED,
                duration=duration,
                error_message=str(e)
            )
            
        except Exception as e:
            duration = time.perf_counter() - start_time
            return TestResult(
                test_id=test_id,
                test_name=test_func.__name__,
                test_type=TestType.UNIT,
                status=TestStatus.FAILED,
                duration=duration,
                error_message=str(e),
                traceback=traceback.format_exc()
            )
    
    def _update_statistics(self, suite: TestSuite):
        """Update framework statistics."""
        self.stats["total_test_runs"] += 1
        self.stats["total_tests_executed"] += suite.total_tests
        self.stats["total_passed"] += suite.passed_tests
        self.stats["total_failed"] += suite.failed_tests
        self.stats["total_skipped"] += suite.skipped_tests
        
        # Calculate average duration
        if self.stats["total_tests_executed"] > 0:
            total_duration = sum(s.total_duration for s in self.test_history)
            self.stats["average_duration"] = total_duration / self.stats["total_tests_executed"]
    
    def generate_test_report(self, suite_id: str) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        if suite_id not in self.test_suites:
            return {"error": "Test suite not found"}
        
        suite = self.test_suites[suite_id]
        
        # Calculate success rate
        success_rate = (suite.passed_tests / suite.total_tests * 100) if suite.total_tests > 0 else 0
        
        # Group results by status
        results_by_status = {
            "passed": [t for t in suite.tests if t.status == TestStatus.PASSED],
            "failed": [t for t in suite.tests if t.status == TestStatus.FAILED],
            "skipped": [t for t in suite.tests if t.status == TestStatus.SKIPPED],
            "error": [t for t in suite.tests if t.status == TestStatus.ERROR]
        }
        
        # Performance analysis
        durations = [t.duration for t in suite.tests if t.duration > 0]
        performance_summary = {}
        if durations:
            performance_summary = {
                "min_duration": min(durations),
                "max_duration": max(durations),
                "avg_duration": sum(durations) / len(durations),
                "total_duration": suite.total_duration
            }
        
        return {
            "suite_info": {
                "suite_id": suite.suite_id,
                "suite_name": suite.suite_name,
                "test_type": suite.test_type.value,
                "started_at": suite.started_at.isoformat() if suite.started_at else None,
                "completed_at": suite.completed_at.isoformat() if suite.completed_at else None
            },
            "summary": {
                "total_tests": suite.total_tests,
                "passed": suite.passed_tests,
                "failed": suite.failed_tests,
                "skipped": suite.skipped_tests,
                "errors": suite.error_tests,
                "success_rate": success_rate,
                "total_duration": suite.total_duration
            },
            "performance": performance_summary,
            "results_by_status": {
                status: [
                    {
                        "test_name": t.test_name,
                        "duration": t.duration,
                        "error_message": t.error_message
                    }
                    for t in tests
                ]
                for status, tests in results_by_status.items()
            },
            "failed_tests_detail": [
                {
                    "test_id": t.test_id,
                    "test_name": t.test_name,
                    "error_message": t.error_message,
                    "traceback": t.traceback
                }
                for t in results_by_status["failed"]
            ]
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get framework statistics."""
        return self.stats.copy()
    
    def export_results(self, suite_id: str, format: str = "json") -> str:
        """Export test results in specified format."""
        report = self.generate_test_report(suite_id)
        
        if format.lower() == "json":
            return json.dumps(report, indent=2, default=str)
        elif format.lower() == "html":
            return self._generate_html_report(report)
        else:
            return str(report)
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML test report."""
        # Simplified HTML report generation
        html = f"""
        <html>
        <head><title>Test Report - {report['suite_info']['suite_name']}</title></head>
        <body>
        <h1>Test Report: {report['suite_info']['suite_name']}</h1>
        <h2>Summary</h2>
        <p>Total Tests: {report['summary']['total_tests']}</p>
        <p>Passed: {report['summary']['passed']}</p>
        <p>Failed: {report['summary']['failed']}</p>
        <p>Success Rate: {report['summary']['success_rate']:.1f}%</p>
        <p>Duration: {report['summary']['total_duration']:.2f}s</p>
        </body>
        </html>
        """
        return html


# Global test framework instance
comprehensive_test_framework = ComprehensiveTestFramework()

def get_test_framework() -> ComprehensiveTestFramework:
    """Get the global test framework."""
    return comprehensive_test_framework


# Decorators for test marking
def performance_test(func):
    """Mark a test as a performance test."""
    func._test_type = TestType.PERFORMANCE
    func._is_test = True
    return func


def security_test(func):
    """Mark a test as a security test."""
    func._test_type = TestType.SECURITY
    func._is_test = True
    return func


def integration_test(func):
    """Mark a test as an integration test."""
    func._test_type = TestType.INTEGRATION
    func._is_test = True
    return func


def api_test(func):
    """Mark a test as an API test."""
    func._test_type = TestType.API
    func._is_test = True
    return func
