"""
Plugin Test Manager

Enhanced testing framework for plugins with scheduling, GUI integration, and comprehensive test management.
"""

import asyncio
import json
import logging
import importlib.util
import schedule
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class TestPriority(Enum):
    """Test priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestResult:
    """Test result data structure."""
    test_id: str
    plugin_name: str
    test_name: str
    status: TestStatus
    duration: float
    message: str
    error: Optional[str] = None
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class TestSchedule:
    """Test schedule configuration."""
    test_id: str
    plugin_name: str
    test_name: str
    schedule_expression: str  # Cron-like expression
    enabled: bool = True
    priority: TestPriority = TestPriority.MEDIUM
    timeout: int = 300  # 5 minutes default
    retry_count: int = 0
    last_run: Optional[str] = None
    next_run: Optional[str] = None


class PluginTestManager:
    """Enhanced plugin test manager with scheduling and GUI integration."""
    
    def __init__(self):
        self.test_results: Dict[str, List[TestResult]] = {}
        self.test_schedules: Dict[str, TestSchedule] = {}
        self.running_tests: Dict[str, asyncio.Task] = {}
        self.test_history: List[TestResult] = []
        self.scheduler_thread = None
        self.scheduler_running = False
        
        # Test discovery cache
        self.discovered_tests: Dict[str, Dict[str, Callable]] = {}
        
        # GUI integration callbacks
        self.gui_callbacks: Dict[str, Callable] = {}
        
    async def discover_plugin_tests(self, plugin_name: str, plugin_path: Path) -> Dict[str, Callable]:
        """Discover tests for a specific plugin."""
        try:
            tests_dir = plugin_path / "tests"
            if not tests_dir.exists():
                logger.info(f"No tests directory found for plugin {plugin_name}")
                return {}
            
            discovered_tests = {}
            
            # Look for test files
            for test_file in tests_dir.glob("test_*.py"):
                try:
                    # Load test module
                    spec = importlib.util.spec_from_file_location(
                        f"{plugin_name}_tests_{test_file.stem}", test_file
                    )
                    test_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(test_module)
                    
                    # Find test functions
                    for attr_name in dir(test_module):
                        if attr_name.startswith("test_") and callable(getattr(test_module, attr_name)):
                            test_func = getattr(test_module, attr_name)
                            discovered_tests[attr_name] = test_func
                            
                except Exception as e:
                    logger.error(f"Error loading test file {test_file}: {e}")
            
            self.discovered_tests[plugin_name] = discovered_tests
            logger.info(f"Discovered {len(discovered_tests)} tests for plugin {plugin_name}")
            
            return discovered_tests
            
        except Exception as e:
            logger.error(f"Error discovering tests for plugin {plugin_name}: {e}")
            return {}
    
    async def run_plugin_test(self, plugin_name: str, test_name: str, 
                            timeout: int = 300) -> TestResult:
        """Run a specific test for a plugin."""
        test_id = f"{plugin_name}_{test_name}_{int(time.time())}"
        
        try:
            # Check if test exists
            if plugin_name not in self.discovered_tests:
                raise ValueError(f"No tests discovered for plugin {plugin_name}")
            
            if test_name not in self.discovered_tests[plugin_name]:
                raise ValueError(f"Test {test_name} not found for plugin {plugin_name}")
            
            test_func = self.discovered_tests[plugin_name][test_name]
            
            # Create test result
            result = TestResult(
                test_id=test_id,
                plugin_name=plugin_name,
                test_name=test_name,
                status=TestStatus.RUNNING,
                duration=0.0,
                message="Test started"
            )
            
            # Add to running tests
            start_time = time.time()
            
            try:
                # Run test with timeout
                if asyncio.iscoroutinefunction(test_func):
                    test_result = await asyncio.wait_for(test_func(), timeout=timeout)
                else:
                    test_result = test_func()
                
                # Process result
                duration = time.time() - start_time
                
                if isinstance(test_result, dict):
                    if test_result.get("success", False):
                        result.status = TestStatus.PASSED
                        result.message = test_result.get("message", "Test passed")
                    else:
                        result.status = TestStatus.FAILED
                        result.message = test_result.get("message", "Test failed")
                        result.error = test_result.get("error")
                else:
                    # Assume success if no dict returned
                    result.status = TestStatus.PASSED
                    result.message = "Test completed successfully"
                
                result.duration = duration
                
            except asyncio.TimeoutError:
                result.status = TestStatus.ERROR
                result.message = f"Test timed out after {timeout} seconds"
                result.duration = timeout
                
            except Exception as e:
                result.status = TestStatus.ERROR
                result.message = f"Test execution error: {str(e)}"
                result.error = str(e)
                result.duration = time.time() - start_time
            
            # Store result
            if plugin_name not in self.test_results:
                self.test_results[plugin_name] = []
            
            self.test_results[plugin_name].append(result)
            self.test_history.append(result)
            
            # Limit history size
            if len(self.test_history) > 1000:
                self.test_history = self.test_history[-1000:]
            
            # Notify GUI if callback registered
            if "test_completed" in self.gui_callbacks:
                try:
                    self.gui_callbacks["test_completed"](result)
                except Exception as e:
                    logger.error(f"Error in GUI callback: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error running test {test_name} for plugin {plugin_name}: {e}")
            return TestResult(
                test_id=test_id,
                plugin_name=plugin_name,
                test_name=test_name,
                status=TestStatus.ERROR,
                duration=0.0,
                message=f"Test setup error: {str(e)}",
                error=str(e)
            )
    
    async def run_all_plugin_tests(self, plugin_name: str) -> List[TestResult]:
        """Run all tests for a specific plugin."""
        try:
            if plugin_name not in self.discovered_tests:
                logger.warning(f"No tests found for plugin {plugin_name}")
                return []
            
            results = []
            tests = self.discovered_tests[plugin_name]
            
            for test_name in tests:
                result = await self.run_plugin_test(plugin_name, test_name)
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error running all tests for plugin {plugin_name}: {e}")
            return []
    
    async def run_scheduled_tests(self) -> List[TestResult]:
        """Run all scheduled tests that are due."""
        try:
            results = []
            current_time = datetime.now()
            
            for schedule_id, test_schedule in self.test_schedules.items():
                if not test_schedule.enabled:
                    continue
                
                # Check if test is due
                if test_schedule.next_run:
                    next_run_time = datetime.fromisoformat(test_schedule.next_run)
                    if current_time >= next_run_time:
                        # Run the test
                        result = await self.run_plugin_test(
                            test_schedule.plugin_name,
                            test_schedule.test_name,
                            test_schedule.timeout
                        )
                        results.append(result)
                        
                        # Update schedule
                        test_schedule.last_run = current_time.isoformat()
                        test_schedule.next_run = self._calculate_next_run(
                            test_schedule.schedule_expression, current_time
                        ).isoformat()
            
            return results
            
        except Exception as e:
            logger.error(f"Error running scheduled tests: {e}")
            return []
    
    def schedule_test(self, plugin_name: str, test_name: str, 
                     schedule_expression: str, priority: TestPriority = TestPriority.MEDIUM,
                     timeout: int = 300) -> str:
        """Schedule a test to run automatically."""
        try:
            schedule_id = f"{plugin_name}_{test_name}_schedule"
            
            # Calculate next run time
            next_run = self._calculate_next_run(schedule_expression, datetime.now())
            
            test_schedule = TestSchedule(
                test_id=schedule_id,
                plugin_name=plugin_name,
                test_name=test_name,
                schedule_expression=schedule_expression,
                priority=priority,
                timeout=timeout,
                next_run=next_run.isoformat()
            )
            
            self.test_schedules[schedule_id] = test_schedule
            
            logger.info(f"Scheduled test {test_name} for plugin {plugin_name} with expression {schedule_expression}")
            
            return schedule_id
            
        except Exception as e:
            logger.error(f"Error scheduling test: {e}")
            raise
    
    def unschedule_test(self, schedule_id: str) -> bool:
        """Remove a scheduled test."""
        try:
            if schedule_id in self.test_schedules:
                del self.test_schedules[schedule_id]
                logger.info(f"Unscheduled test {schedule_id}")
                return True
            else:
                logger.warning(f"Schedule {schedule_id} not found")
                return False
                
        except Exception as e:
            logger.error(f"Error unscheduling test: {e}")
            return False
    
    def get_test_results(self, plugin_name: Optional[str] = None, 
                        limit: int = 100) -> List[TestResult]:
        """Get test results, optionally filtered by plugin."""
        try:
            if plugin_name:
                return self.test_results.get(plugin_name, [])[-limit:]
            else:
                return self.test_history[-limit:]
                
        except Exception as e:
            logger.error(f"Error getting test results: {e}")
            return []
    
    def get_test_statistics(self, plugin_name: Optional[str] = None) -> Dict[str, Any]:
        """Get test statistics."""
        try:
            if plugin_name:
                results = self.test_results.get(plugin_name, [])
            else:
                results = self.test_history
            
            if not results:
                return {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "error": 0,
                    "success_rate": 0.0
                }
            
            status_counts = {}
            for result in results:
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            
            total = len(results)
            passed = status_counts.get("passed", 0)
            success_rate = (passed / total * 100) if total > 0 else 0.0
            
            return {
                "total": total,
                "passed": passed,
                "failed": status_counts.get("failed", 0),
                "error": status_counts.get("error", 0),
                "skipped": status_counts.get("skipped", 0),
                "success_rate": success_rate,
                "status_breakdown": status_counts
            }
            
        except Exception as e:
            logger.error(f"Error getting test statistics: {e}")
            return {}
    
    def start_scheduler(self):
        """Start the test scheduler in a background thread."""
        if self.scheduler_running:
            logger.warning("Test scheduler is already running")
            return
        
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.if scheduler_thread and hasattr(scheduler_thread, "start"): scheduler_thread.start()
        logger.info("Test scheduler started")
    
    def stop_scheduler(self):
        """Stop the test scheduler."""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Test scheduler stopped")
    
    def register_gui_callback(self, event_name: str, callback: Callable):
        """Register a GUI callback for test events."""
        self.gui_callbacks[event_name] = callback
        logger.info(f"Registered GUI callback for event: {event_name}")
    
    def _scheduler_loop(self):
        """Background scheduler loop."""
        while self.scheduler_running:
            try:
                # Run scheduled tests
                asyncio.run(self.run_scheduled_tests())
                
                # Sleep for 60 seconds before checking again
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)
    
    def _calculate_next_run(self, schedule_expression: str, current_time: datetime) -> datetime:
        """Calculate next run time based on schedule expression."""
        try:
            # Simple schedule expressions (extend as needed)
            if schedule_expression == "daily":
                return current_time + timedelta(days=1)
            elif schedule_expression == "hourly":
                return current_time + timedelta(hours=1)
            elif schedule_expression == "weekly":
                return current_time + timedelta(weeks=1)
            elif schedule_expression.startswith("every_"):
                # Format: every_30_minutes, every_2_hours, etc.
                parts = schedule_expression.split("_")
                if len(parts) == 3:
                    interval = int(parts[1])
                    unit = parts[2]
                    
                    if unit == "minutes":
                        return current_time + timedelta(minutes=interval)
                    elif unit == "hours":
                        return current_time + timedelta(hours=interval)
                    elif unit == "days":
                        return current_time + timedelta(days=interval)
            
            # Default to 1 hour if expression not recognized
            logger.warning(f"Unknown schedule expression: {schedule_expression}, defaulting to 1 hour")
            return current_time + timedelta(hours=1)
            
        except Exception as e:
            logger.error(f"Error calculating next run time: {e}")
            return current_time + timedelta(hours=1)


# Global test manager instance
_test_manager = None


def get_test_manager() -> PluginTestManager:
    """Get the global test manager instance."""
    global _test_manager
    if _test_manager is None:
        _test_manager = PluginTestManager()
    return _test_manager
