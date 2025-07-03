"""
CLI Testing Framework
Comprehensive testing and validation system for CLI commands and automation.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import re

logger = logging.getLogger(__name__)

class TestStatus(str, Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"

class TestSeverity(str, Enum):
    """Test severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class TestCase:
    """Individual test case definition."""
    id: str
    name: str
    description: str
    command: str
    expected_output: Optional[str] = None
    expected_exit_code: int = 0
    timeout: int = 30
    severity: TestSeverity = TestSeverity.MEDIUM
    tags: List[str] = None
    setup_commands: List[str] = None
    cleanup_commands: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.setup_commands is None:
            self.setup_commands = []
        if self.cleanup_commands is None:
            self.cleanup_commands = []

@dataclass
class TestResult:
    """Test execution result."""
    test_id: str
    status: TestStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: float = 0.0
    output: str = ""
    error: str = ""
    exit_code: Optional[int] = None
    assertion_results: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.assertion_results is None:
            self.assertion_results = []

@dataclass
class TestSuite:
    """Test suite definition."""
    id: str
    name: str
    description: str
    tests: List[TestCase]
    setup_commands: List[str] = None
    cleanup_commands: List[str] = None
    parallel: bool = False
    
    def __post_init__(self):
        if self.setup_commands is None:
            self.setup_commands = []
        if self.cleanup_commands is None:
            self.cleanup_commands = []

class CLITestingFramework:
    """Comprehensive CLI testing framework."""
    
    def __init__(self, cli_executor: Callable = None):
        self.cli_executor = cli_executor
        self.test_suites: Dict[str, TestSuite] = {}
        self.test_results: Dict[str, TestResult] = {}
        
        # Built-in test suites
        self._create_builtin_test_suites()
    
    def _create_builtin_test_suites(self):
        """Create built-in test suites."""
        
        # Basic functionality tests
        basic_tests = [
            TestCase(
                id="test_help",
                name="Help Command",
                description="Test help command functionality",
                command="help",
                expected_output="Available commands:",
                tags=["basic", "help"]
            ),
            TestCase(
                id="test_status",
                name="Status Command",
                description="Test system status command",
                command="status",
                tags=["basic", "status"]
            ),
            TestCase(
                id="test_version",
                name="Version Command",
                description="Test version command",
                command="version",
                tags=["basic", "version"]
            )
        ]
        
        self.test_suites["basic"] = TestSuite(
            id="basic",
            name="Basic Functionality",
            description="Basic CLI command functionality tests",
            tests=basic_tests
        )
        
        # Database tests
        database_tests = [
            TestCase(
                id="test_db_info",
                name="Database Info",
                description="Test database info command",
                command="database info",
                tags=["database", "info"]
            ),
            TestCase(
                id="test_db_backup",
                name="Database Backup",
                description="Test database backup functionality",
                command="database backup",
                tags=["database", "backup"],
                severity=TestSeverity.HIGH
            ),
            TestCase(
                id="test_db_optimize",
                name="Database Optimize",
                description="Test database optimization",
                command="database optimize",
                tags=["database", "optimize"]
            )
        ]
        
        self.test_suites["database"] = TestSuite(
            id="database",
            name="Database Operations",
            description="Database-related command tests",
            tests=database_tests
        )
        
        # Automation tests
        automation_tests = [
            TestCase(
                id="test_automation_list",
                name="Automation List",
                description="Test automation rule listing",
                command="automation list",
                tags=["automation", "list"]
            ),
            TestCase(
                id="test_automation_status",
                name="Automation Status",
                description="Test automation system status",
                command="automation status",
                tags=["automation", "status"]
            ),
            TestCase(
                id="test_logic_variables",
                name="Logic Variables",
                description="Test logic engine variables",
                command="logic variables",
                tags=["logic", "variables"]
            )
        ]
        
        self.test_suites["automation"] = TestSuite(
            id="automation",
            name="Automation System",
            description="Automation and logic engine tests",
            tests=automation_tests
        )
        
        # Performance tests
        performance_tests = [
            TestCase(
                id="test_performance_monitor",
                name="Performance Monitor",
                description="Test performance monitoring",
                command="monitor",
                tags=["performance", "monitor"],
                timeout=60
            ),
            TestCase(
                id="test_performance_benchmark",
                name="Performance Benchmark",
                description="Test performance benchmarking",
                command="benchmark",
                tags=["performance", "benchmark"],
                timeout=120,
                severity=TestSeverity.LOW
            )
        ]
        
        self.test_suites["performance"] = TestSuite(
            id="performance",
            name="Performance Tests",
            description="Performance and monitoring tests",
            tests=performance_tests
        )
        
        # Security tests
        security_tests = [
            TestCase(
                id="test_security_scan",
                name="Security Scan",
                description="Test security scanning functionality",
                command="security scan",
                tags=["security", "scan"],
                severity=TestSeverity.CRITICAL,
                timeout=180
            ),
            TestCase(
                id="test_user_permissions",
                name="User Permissions",
                description="Test user permission validation",
                command="users list",
                tags=["security", "users"]
            )
        ]
        
        self.test_suites["security"] = TestSuite(
            id="security",
            name="Security Tests",
            description="Security-related functionality tests",
            tests=security_tests
        )
    
    def add_test_suite(self, suite: TestSuite):
        """Add test suite."""
        self.test_suites[suite.id] = suite
        logger.info(f"Added test suite: {suite.name}")
    
    def add_test_case(self, suite_id: str, test_case: TestCase):
        """Add test case to suite."""
        if suite_id in self.test_suites:
            self.test_suites[suite_id].tests.append(test_case)
            logger.info(f"Added test case {test_case.name} to suite {suite_id}")
        else:
            logger.error(f"Test suite not found: {suite_id}")
    
    def remove_test_suite(self, suite_id: str) -> bool:
        """Remove test suite."""
        if suite_id in self.test_suites:
            del self.test_suites[suite_id]
            logger.info(f"Removed test suite: {suite_id}")
            return True
        return False
    
    def list_test_suites(self) -> List[TestSuite]:
        """List all test suites."""
        return list(self.test_suites.values())
    
    def get_test_suite(self, suite_id: str) -> Optional[TestSuite]:
        """Get test suite by ID."""
        return self.test_suites.get(suite_id)
    
    async def run_test_case(self, test_case: TestCase) -> TestResult:
        """Run individual test case."""
        result = TestResult(
            test_id=test_case.id,
            status=TestStatus.RUNNING,
            started_at=datetime.now()
        )
        
        try:
            # Run setup commands
            for setup_cmd in test_case.setup_commands:
                if self.cli_executor:
                    await self.cli_executor(setup_cmd)
            
            # Execute main test command
            start_time = time.time()
            
            if self.cli_executor:
                output = await asyncio.wait_for(
                    self.cli_executor(test_case.command),
                    timeout=test_case.timeout
                )
                result.output = str(output) if output else ""
                result.exit_code = 0  # Assume success if no exception
            else:
                # Simulate test execution
                await asyncio.sleep(0.1)
                result.output = f"Simulated output for: {test_case.command}"
                result.exit_code = 0
            
            result.duration = time.time() - start_time
            
            # Validate results
            result.status = self._validate_test_result(test_case, result)
            
        except asyncio.TimeoutError:
            result.status = TestStatus.FAILED
            result.error = f"Test timed out after {test_case.timeout} seconds"
            result.duration = test_case.timeout
            
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error = str(e)
            result.duration = time.time() - start_time if 'start_time' in locals() else 0
        
        finally:
            # Run cleanup commands
            try:
                for cleanup_cmd in test_case.cleanup_commands:
                    if self.cli_executor:
                        await self.cli_executor(cleanup_cmd)
            except Exception as e:
                logger.warning(f"Cleanup failed for test {test_case.id}: {e}")
            
            result.completed_at = datetime.now()
        
        self.test_results[test_case.id] = result
        return result
    
    def _validate_test_result(self, test_case: TestCase, result: TestResult) -> TestStatus:
        """Validate test result against expectations."""
        try:
            # Check exit code
            if result.exit_code != test_case.expected_exit_code:
                result.assertion_results.append({
                    'type': 'exit_code',
                    'expected': test_case.expected_exit_code,
                    'actual': result.exit_code,
                    'passed': False
                })
                return TestStatus.FAILED
            
            # Check expected output
            if test_case.expected_output:
                if test_case.expected_output not in result.output:
                    result.assertion_results.append({
                        'type': 'output_contains',
                        'expected': test_case.expected_output,
                        'actual': result.output,
                        'passed': False
                    })
                    return TestStatus.FAILED
                else:
                    result.assertion_results.append({
                        'type': 'output_contains',
                        'expected': test_case.expected_output,
                        'actual': result.output,
                        'passed': True
                    })
            
            return TestStatus.PASSED
            
        except Exception as e:
            result.error = f"Validation error: {e}"
            return TestStatus.ERROR
    
    async def run_test_suite(self, suite_id: str, tags: List[str] = None) -> Dict[str, Any]:
        """Run test suite."""
        suite = self.get_test_suite(suite_id)
        if not suite:
            return {'error': f'Test suite not found: {suite_id}'}
        
        logger.info(f"Running test suite: {suite.name}")
        
        # Filter tests by tags if specified
        tests_to_run = suite.tests
        if tags:
            tests_to_run = [
                test for test in suite.tests
                if any(tag in test.tags for tag in tags)
            ]
        
        # Run suite setup
        try:
            for setup_cmd in suite.setup_commands:
                if self.cli_executor:
                    await self.cli_executor(setup_cmd)
        except Exception as e:
            logger.error(f"Suite setup failed: {e}")
            return {'error': f'Suite setup failed: {e}'}
        
        # Run tests
        results = []
        start_time = datetime.now()
        
        try:
            if suite.parallel:
                # Run tests in parallel
                tasks = [self.run_test_case(test) for test in tests_to_run]
                results = await asyncio.gather(*tasks, return_exceptions=True)
            else:
                # Run tests sequentially
                for test in tests_to_run:
                    result = await self.run_test_case(test)
                    results.append(result)
        
        finally:
            # Run suite cleanup
            try:
                for cleanup_cmd in suite.cleanup_commands:
                    if self.cli_executor:
                        await self.cli_executor(cleanup_cmd)
            except Exception as e:
                logger.warning(f"Suite cleanup failed: {e}")
        
        end_time = datetime.now()
        
        # Calculate statistics
        passed = len([r for r in results if isinstance(r, TestResult) and r.status == TestStatus.PASSED])
        failed = len([r for r in results if isinstance(r, TestResult) and r.status == TestStatus.FAILED])
        errors = len([r for r in results if isinstance(r, TestResult) and r.status == TestStatus.ERROR])
        
        return {
            'suite_id': suite_id,
            'suite_name': suite.name,
            'started_at': start_time.isoformat(),
            'completed_at': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'total_tests': len(tests_to_run),
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'success_rate': (passed / len(tests_to_run)) * 100 if tests_to_run else 0,
            'results': [asdict(r) if isinstance(r, TestResult) else str(r) for r in results]
        }
    
    async def run_all_tests(self, tags: List[str] = None) -> Dict[str, Any]:
        """Run all test suites."""
        logger.info("Running all test suites")
        
        suite_results = []
        start_time = datetime.now()
        
        for suite_id in self.test_suites.keys():
            result = await self.run_test_suite(suite_id, tags)
            suite_results.append(result)
        
        end_time = datetime.now()
        
        # Calculate overall statistics
        total_tests = sum(r.get('total_tests', 0) for r in suite_results)
        total_passed = sum(r.get('passed', 0) for r in suite_results)
        total_failed = sum(r.get('failed', 0) for r in suite_results)
        total_errors = sum(r.get('errors', 0) for r in suite_results)
        
        return {
            'started_at': start_time.isoformat(),
            'completed_at': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'total_suites': len(suite_results),
            'total_tests': total_tests,
            'passed': total_passed,
            'failed': total_failed,
            'errors': total_errors,
            'success_rate': (total_passed / total_tests) * 100 if total_tests else 0,
            'suite_results': suite_results
        }
    
    def get_test_result(self, test_id: str) -> Optional[TestResult]:
        """Get test result by ID."""
        return self.test_results.get(test_id)
    
    def list_test_results(self, suite_id: str = None, status: TestStatus = None) -> List[TestResult]:
        """List test results with optional filtering."""
        results = list(self.test_results.values())
        
        if suite_id:
            suite = self.get_test_suite(suite_id)
            if suite:
                test_ids = [test.id for test in suite.tests]
                results = [r for r in results if r.test_id in test_ids]
        
        if status:
            results = [r for r in results if r.status == status]
        
        return sorted(results, key=lambda x: x.started_at, reverse=True)
    
    def cleanup_test_results(self, days: int = 30) -> int:
        """Clean up old test results."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        old_results = [
            test_id for test_id, result in self.test_results.items()
            if result.started_at < cutoff_date
        ]
        
        for test_id in old_results:
            del self.test_results[test_id]
        
        logger.info(f"Cleaned up {len(old_results)} old test results")
        return len(old_results)
    
    def export_test_results(self, filepath: str) -> bool:
        """Export test results to file."""
        try:
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'test_suites': [asdict(suite) for suite in self.test_suites.values()],
                'test_results': [asdict(result) for result in self.test_results.values()]
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported test results to: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export test results: {e}")
            return False
