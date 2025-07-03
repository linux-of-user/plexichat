# app/utils/self_tests/test_executor.py
"""
Enhanced test execution framework with comprehensive error handling,
retry logic, timeouts, and detailed reporting.
"""

import asyncio
import time
import traceback
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from functools import wraps

from app.logger_config import settings, selftest_logger
from app.utils.self_tests.results_reporter import (
    TestResult, TestSuiteResult, TestStatus, results_reporter
)


class TestExecutionError(Exception):
    """Custom exception for test execution errors."""
    pass


class TestTimeout(Exception):
    """Custom exception for test timeouts."""
    pass


def with_timeout(timeout_seconds: int):
    """Decorator to add timeout to test functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=timeout_seconds)
                except FutureTimeoutError:
                    raise TestTimeout(f"Test timed out after {timeout_seconds} seconds")
        return wrapper
    return decorator


def with_retry(max_retries: int = None, delay_seconds: int = None):
    """Decorator to add retry logic to test functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = max_retries or settings.SELFTEST_RETRY_COUNT
            delay = delay_seconds or settings.SELFTEST_RETRY_DELAY_SECONDS
            
            last_exception = None
            for attempt in range(retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < retries:
                        selftest_logger.debug("Test %s failed (attempt %d/%d): %s. Retrying in %ds...", 
                                            func.__name__, attempt + 1, retries + 1, e, delay)
                        time.sleep(delay)
                    else:
                        selftest_logger.error("Test %s failed after %d attempts: %s", 
                                            func.__name__, retries + 1, e)
            
            raise last_exception
        return wrapper
    return decorator


class TestExecutor:
    """Enhanced test execution framework."""
    
    def __init__(self):
        self.timeout_seconds = settings.SELFTEST_TIMEOUT_SECONDS
        self.retry_count = settings.SELFTEST_RETRY_COUNT
        self.retry_delay = settings.SELFTEST_RETRY_DELAY_SECONDS
    
    def execute_test_suite(self, suite_name: str, test_functions: Dict[str, Callable]) -> TestSuiteResult:
        """Execute a complete test suite with comprehensive reporting."""
        start_time = datetime.utcnow()
        start_timestamp = start_time.isoformat() + "Z"
        
        selftest_logger.info("Starting test suite: %s", suite_name)
        
        test_results = []
        passed = failed = errors = skipped = timeouts = 0
        
        for test_name, test_func in test_functions.items():
            result = self._execute_single_test(test_name, test_func)
            test_results.append(result)
            
            # Count results
            if result.status == TestStatus.PASS:
                passed += 1
            elif result.status == TestStatus.FAIL:
                failed += 1
            elif result.status == TestStatus.ERROR:
                errors += 1
            elif result.status == TestStatus.SKIP:
                skipped += 1
            elif result.status == TestStatus.TIMEOUT:
                timeouts += 1
        
        end_time = datetime.utcnow()
        end_timestamp = end_time.isoformat() + "Z"
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        suite_result = TestSuiteResult(
            suite_name=suite_name,
            start_time=start_timestamp,
            end_time=end_timestamp,
            duration_ms=duration_ms,
            total_tests=len(test_results),
            passed=passed,
            failed=failed,
            errors=errors,
            skipped=skipped,
            timeouts=timeouts,
            tests=test_results
        )
        
        # Report results
        if settings.SELFTEST_LOG_RESULTS:
            results_reporter.report_suite_results(suite_result)
        
        selftest_logger.info("Test suite %s completed: %d/%d passed (%.1f%%)", 
                           suite_name, passed, len(test_results), 
                           (passed / len(test_results) * 100) if test_results else 0)
        
        return suite_result
    
    def _execute_single_test(self, test_name: str, test_func: Callable) -> TestResult:
        """Execute a single test with comprehensive error handling."""
        start_time = time.time()
        
        try:
            selftest_logger.debug("Executing test: %s", test_name)
            
            # Apply timeout wrapper
            timeout_func = with_timeout(self.timeout_seconds)(test_func)
            
            # Apply retry wrapper if configured
            if self.retry_count > 0:
                retry_func = with_retry(self.retry_count, self.retry_delay)(timeout_func)
                result = retry_func()
            else:
                result = timeout_func()
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Analyze result
            if isinstance(result, dict):
                # Check if any sub-tests failed
                failed_tests = [k for k, v in result.items() 
                              if isinstance(v, dict) and not v.get("ok", True)]
                
                if failed_tests:
                    return TestResult(
                        name=test_name,
                        status=TestStatus.FAIL,
                        duration_ms=duration_ms,
                        message=f"Failed sub-tests: {', '.join(failed_tests)}",
                        details=result
                    )
                else:
                    return TestResult(
                        name=test_name,
                        status=TestStatus.PASS,
                        duration_ms=duration_ms,
                        message="All sub-tests passed",
                        details=result
                    )
            else:
                # Simple boolean or other result
                status = TestStatus.PASS if result else TestStatus.FAIL
                return TestResult(
                    name=test_name,
                    status=status,
                    duration_ms=duration_ms,
                    message="Test completed" if result else "Test failed",
                    details={"result": result}
                )
        
        except TestTimeout as e:
            duration_ms = (time.time() - start_time) * 1000
            selftest_logger.warning("Test %s timed out: %s", test_name, e)
            return TestResult(
                name=test_name,
                status=TestStatus.TIMEOUT,
                duration_ms=duration_ms,
                message=str(e),
                details={"error_type": "timeout"}
            )
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_details = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "traceback": traceback.format_exc()
            }
            
            selftest_logger.error("Test %s failed with error: %s", test_name, e)
            selftest_logger.debug("Test %s error details: %s", test_name, error_details["traceback"])
            
            return TestResult(
                name=test_name,
                status=TestStatus.ERROR,
                duration_ms=duration_ms,
                message=f"{type(e).__name__}: {str(e)}",
                details=error_details
            )
    
    def validate_test_environment(self) -> Tuple[bool, List[str]]:
        """Validate that the test environment is ready."""
        issues = []
        
        try:
            # Check if server is running
            import requests
            response = requests.get(f"{settings.BASE_URL}/v1/status/health", timeout=5)
            if response.status_code != 200:
                issues.append(f"Server health check failed: {response.status_code}")
        except Exception as e:
            issues.append(f"Cannot connect to server: {e}")
        
        # Check database connectivity
        try:
            from app.db import engine
            from sqlalchemy import text
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as e:
            issues.append(f"Database connectivity failed: {e}")
        
        # Check required directories
        try:
            results_dir = Path(settings.SELFTEST_RESULTS_DIR)
            results_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create results directory: {e}")
        
        return len(issues) == 0, issues
    
    def get_test_status_summary(self) -> Dict[str, Any]:
        """Get current test status summary."""
        try:
            summary_file = Path(settings.SELFTEST_RESULTS_DIR) / "latest_summary.json"
            if summary_file.exists():
                import json
                with open(summary_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                return {"status": "NO_DATA", "message": "No test results available"}
        except Exception as e:
            return {"status": "ERROR", "message": f"Failed to read summary: {e}"}


# Global executor instance
test_executor = TestExecutor()
