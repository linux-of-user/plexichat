#!/usr/bin/env python3
"""
NetLink Unified Testing Framework - Comprehensive Test Runner

Consolidated test runner combining all NetLink test suites with:
- Unit, Integration, End-to-End, Performance, and Security testing
- Coverage reporting and CI/CD integration
- Parallel test execution and advanced reporting
- Mock services and comprehensive fixtures
"""

import sys
import os
import json
import time
import subprocess
import pytest
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import argparse
import concurrent.futures
from dataclasses import dataclass

# Add src to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

@dataclass
class TestResult:
    """Test result data structure."""
    category: str
    passed: int
    failed: int
    skipped: int
    duration: float
    coverage: float
    details: Dict[str, Any]

class UnifiedTestRunner:
    """Comprehensive test runner for all NetLink test suites."""
    
    def __init__(self):
        self.results = {}
        self.start_time = None
        self.tests_dir = Path(__file__).parent
        self.project_root = project_root
        
    async def run_all_tests(self, args: argparse.Namespace) -> Dict[str, Any]:
        """Run all test categories based on arguments."""
        print("🧪 NetLink Unified Test Suite")
        print("=" * 60)
        print(f"📁 Test Directory: {self.tests_dir}")
        print(f"🏠 Project Root: {self.project_root}")
        print()
        
        self.start_time = time.time()
        
        # Test categories to run
        test_categories = []
        if not args.skip_unit:
            test_categories.append(("unit", "📋 Unit Tests", self.run_unit_tests))
        if not args.skip_integration:
            test_categories.append(("integration", "🔗 Integration Tests", self.run_integration_tests))
        if not args.skip_e2e:
            test_categories.append(("e2e", "🎯 End-to-End Tests", self.run_e2e_tests))
        if not args.skip_performance:
            test_categories.append(("performance", "🚀 Performance Tests", self.run_performance_tests))
        if not args.skip_security:
            test_categories.append(("security", "🔒 Security Tests", self.run_security_tests))
        
        # Run tests
        if args.parallel and len(test_categories) > 1:
            await self.run_tests_parallel(test_categories, args)
        else:
            await self.run_tests_sequential(test_categories, args)
        
        # Generate coverage report
        if not args.skip_coverage:
            print("\n📊 Generating Coverage Report...")
            await self.generate_coverage_report(args)
        
        # Generate final report
        await self.generate_final_report(args)
        
        return self.results
    
    async def run_tests_sequential(self, test_categories: List, args: argparse.Namespace):
        """Run tests sequentially."""
        for category, description, test_func in test_categories:
            print(f"\n{description}")
            print("-" * 50)
            result = await test_func(args)
            self.results[category] = result
    
    async def run_tests_parallel(self, test_categories: List, args: argparse.Namespace):
        """Run tests in parallel."""
        print("🔄 Running tests in parallel...")
        
        tasks = []
        for category, description, test_func in test_categories:
            print(f"  • Queuing {description}")
            task = asyncio.create_task(test_func(args))
            tasks.append((category, task))
        
        # Wait for all tasks to complete
        for category, task in tasks:
            try:
                result = await task
                self.results[category] = result
                print(f"  ✅ {category.title()} tests completed")
            except Exception as e:
                print(f"  ❌ {category.title()} tests failed: {e}")
                self.results[category] = {"error": str(e), "passed": False}
    
    async def run_unit_tests(self, args: argparse.Namespace) -> TestResult:
        """Run unit tests."""
        return await self.run_pytest_category("unit", args)
    
    async def run_integration_tests(self, args: argparse.Namespace) -> TestResult:
        """Run integration tests."""
        return await self.run_pytest_category("integration", args)
    
    async def run_e2e_tests(self, args: argparse.Namespace) -> TestResult:
        """Run end-to-end tests."""
        return await self.run_pytest_category("e2e", args)
    
    async def run_performance_tests(self, args: argparse.Namespace) -> TestResult:
        """Run performance tests."""
        return await self.run_pytest_category("performance", args)
    
    async def run_security_tests(self, args: argparse.Namespace) -> TestResult:
        """Run security tests."""
        # Run both pytest security tests and custom security audit
        pytest_result = await self.run_pytest_category("security", args)
        
        # Run comprehensive security audit
        try:
            from .comprehensive_security_tests import run_security_audit
            audit_result = await run_security_audit()
            pytest_result.details["security_audit"] = audit_result
        except ImportError:
            print("  ⚠️  Security audit module not found, running pytest only")
        
        return pytest_result
    
    async def run_pytest_category(self, category: str, args: argparse.Namespace) -> TestResult:
        """Run pytest for a specific category."""
        start_time = time.time()
        
        # Build pytest command
        cmd = [
            sys.executable, "-m", "pytest",
            f"-m", category,
            "--tb=short",
            "-v" if args.verbose else "-q",
        ]
        
        # Add parallel execution if requested
        if args.parallel:
            cmd.extend(["-n", "auto"])
        
        # Add coverage if requested
        if not args.skip_coverage:
            cmd.extend([
                "--cov=src/netlink",
                "--cov-report=term-missing",
                f"--cov-report=html:tests/results/coverage/{category}"
            ])
        
        # Set working directory and run
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=args.timeout
            )
            
            duration = time.time() - start_time
            
            # Parse pytest output for statistics
            output_lines = result.stdout.split('\n')
            passed, failed, skipped = self.parse_pytest_output(output_lines)
            
            return TestResult(
                category=category,
                passed=passed,
                failed=failed,
                skipped=skipped,
                duration=duration,
                coverage=0.0,  # Will be updated by coverage report
                details={
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
            )
            
        except subprocess.TimeoutExpired:
            return TestResult(
                category=category,
                passed=0,
                failed=1,
                skipped=0,
                duration=args.timeout,
                coverage=0.0,
                details={"error": "Test timeout"}
            )
        except Exception as e:
            return TestResult(
                category=category,
                passed=0,
                failed=1,
                skipped=0,
                duration=time.time() - start_time,
                coverage=0.0,
                details={"error": str(e)}
            )
    
    def parse_pytest_output(self, lines: List[str]) -> tuple:
        """Parse pytest output to extract test statistics."""
        passed, failed, skipped = 0, 0, 0
        
        for line in lines:
            if "passed" in line and "failed" in line:
                # Parse line like "5 passed, 2 failed, 1 skipped"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "passed" and i > 0:
                        passed = int(parts[i-1])
                    elif part == "failed" and i > 0:
                        failed = int(parts[i-1])
                    elif part == "skipped" and i > 0:
                        skipped = int(parts[i-1])
                break
        
        return passed, failed, skipped
    
    async def generate_coverage_report(self, args: argparse.Namespace):
        """Generate comprehensive coverage report."""
        try:
            # Generate HTML coverage report
            cmd = [
                sys.executable, "-m", "pytest",
                "--cov=src/netlink",
                "--cov-report=html:tests/results/coverage/html",
                "--cov-report=xml:tests/results/coverage/coverage.xml",
                "--cov-report=json:tests/results/coverage/coverage.json",
                "--cov-only"
            ]
            
            subprocess.run(cmd, cwd=self.project_root, check=True)
            print("  ✅ Coverage reports generated")
            
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Coverage generation failed: {e}")
    
    async def generate_final_report(self, args: argparse.Namespace):
        """Generate final test report."""
        total_duration = time.time() - self.start_time
        
        # Calculate totals
        total_passed = sum(r.passed for r in self.results.values() if isinstance(r, TestResult))
        total_failed = sum(r.failed for r in self.results.values() if isinstance(r, TestResult))
        total_skipped = sum(r.skipped for r in self.results.values() if isinstance(r, TestResult))
        
        # Generate summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "duration": total_duration,
            "total_tests": total_passed + total_failed + total_skipped,
            "passed": total_passed,
            "failed": total_failed,
            "skipped": total_skipped,
            "success_rate": (total_passed / (total_passed + total_failed)) * 100 if (total_passed + total_failed) > 0 else 0,
            "categories": {k: v.__dict__ if isinstance(v, TestResult) else v for k, v in self.results.items()}
        }
        
        # Save report
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            print(f"📄 Test report saved to: {output_path}")
        
        # Display summary
        print("\n" + "=" * 60)
        print("🏁 TEST SUMMARY")
        print("=" * 60)
        print(f"⏱️  Duration: {total_duration:.2f}s")
        print(f"📊 Total Tests: {summary['total_tests']}")
        print(f"✅ Passed: {total_passed}")
        print(f"❌ Failed: {total_failed}")
        print(f"⏭️  Skipped: {total_skipped}")
        print(f"📈 Success Rate: {summary['success_rate']:.1f}%")
        
        # Category breakdown
        for category, result in self.results.items():
            if isinstance(result, TestResult):
                status = "✅" if result.failed == 0 else "❌"
                print(f"  {status} {category.title()}: {result.passed}P/{result.failed}F/{result.skipped}S ({result.duration:.1f}s)")
        
        print("=" * 60)
        
        # Exit with appropriate code
        if total_failed > 0:
            print("❌ Some tests failed!")
            sys.exit(1)
        else:
            print("✅ All tests passed!")
            sys.exit(0)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="NetLink Unified Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Test categories
    parser.add_argument("--skip-unit", action="store_true", help="Skip unit tests")
    parser.add_argument("--skip-integration", action="store_true", help="Skip integration tests")
    parser.add_argument("--skip-e2e", action="store_true", help="Skip end-to-end tests")
    parser.add_argument("--skip-performance", action="store_true", help="Skip performance tests")
    parser.add_argument("--skip-security", action="store_true", help="Skip security tests")
    parser.add_argument("--skip-coverage", action="store_true", help="Skip coverage reporting")
    
    # Execution options
    parser.add_argument("--parallel", action="store_true", help="Run tests in parallel")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=300, help="Test timeout in seconds")
    
    # Output options
    parser.add_argument("--output", "-o", help="Output file for test results")
    
    return parser


async def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    runner = UnifiedTestRunner()
    await runner.run_all_tests(args)


if __name__ == "__main__":
    asyncio.run(main())
