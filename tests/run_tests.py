#!/usr/bin/env python3
"""
Comprehensive test runner for PlexiChat application.
Runs all test suites and generates reports.
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_pytest_suite(test_pattern="test_*.py", verbose=False):
    """Run pytest test suite."""
    print("\n=== Running Pytest Test Suite ===")

    cmd = ["python", "-m", "pytest"]
    if verbose:
        cmd.append("-v")
    cmd.extend(["--tb=short", f"tests/{test_pattern}"])

    try:
        result = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running pytest: {e}")
        return False

def run_manual_api_tests(base_url="http://localhost:8000"):
    """Run manual API tests using curl."""
    print("\n=== Running Manual API Tests ===")

    tests = [
        {
            "name": "Health Check",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/health',
            "expected": "200"
        },
        {
            "name": "API Documentation",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/docs',
            "expected": "200"
        },
        {
            "name": "OpenAPI Schema",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/openapi.json',
            "expected": "200"
        },
        {
            "name": "System Info",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/api/v1/system/info',
            "expected": "200"
        },
        {
            "name": "Users List",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/api/v1/users/',
            "expected": "200"
        },
        {
            "name": "Database Status",
            "command": f'curl -s -o /dev/null -w "%{{http_code}}" {base_url}/api/v1/database/status',
            "expected": "200"
        }
    ]

    passed = 0
    failed = 0

    for test in tests:
        print(f"Testing {test['name']}...", end=" ")
        try:
            result = subprocess.run(test['command'], shell=True, capture_output=True, text=True)
            status_code = result.stdout.strip()

            if status_code == test['expected']:
                print(f"✓ PASS (HTTP {status_code})")
                passed += 1
            else:
                print(f"✗ FAIL (Expected {test['expected']}, got {status_code})")
                failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            failed += 1

    print(f"\nAPI Tests: {passed} passed, {failed} failed")
    return failed == 0

def run_security_tests():
    """Run security-focused tests."""
    print("\n=== Running Security Tests ===")

    # Test for common security vulnerabilities
    security_tests = [
        "test_security.py::TestInputSanitizer::test_sql_injection_detection",
        "test_security.py::TestInputSanitizer::test_xss_detection",
        "test_security.py::TestInputSanitizer::test_path_traversal_detection",
        "test_security.py::TestSecuritySystem::test_threat_detection_sql_injection",
        "test_security.py::TestSecuritySystem::test_threat_detection_xss"
    ]

    passed = 0
    failed = 0

    for test in security_tests:
        print(f"Running {test}...", end=" ")
        try:
            result = subprocess.run([
                "python", "-m", "pytest",
                f"tests/{test}",
                "-v", "--tb=line"
            ], cwd=project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print("✓ PASS")
                passed += 1
            else:
                print("✗ FAIL")
                print(result.stdout)
                print(result.stderr)
                failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            failed += 1

    print(f"\nSecurity Tests: {passed} passed, {failed} failed")
    return failed == 0

def run_backup_tests():
    """Run backup system tests."""
    print("\n=== Running Backup System Tests ===")

    backup_tests = [
        "test_backup_system.py::TestBackupManager::test_backup_creation",
        "test_backup_system.py::TestBackupManager::test_backup_recovery",
        "test_backup_system.py::TestBackupManager::test_partial_recovery",
        "test_backup_system.py::TestEncryptionManager::test_data_encryption",
        "test_backup_system.py::TestShardManager::test_data_sharding"
    ]

    passed = 0
    failed = 0

    for test in backup_tests:
        print(f"Running {test}...", end=" ")
        try:
            result = subprocess.run([
                "python", "-m", "pytest",
                f"tests/{test}",
                "-v", "--tb=line"
            ], cwd=project_root, capture_output=True, text=True)

            if result.returncode == 0:
                print("✓ PASS")
                passed += 1
            else:
                print("✗ FAIL")
                print(result.stdout)
                print(result.stderr)
                failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            failed += 1

    print(f"\nBackup Tests: {passed} passed, {failed} failed")
    return failed == 0

def run_load_tests(base_url="http://localhost:8000", requests=100):
    """Run basic load tests."""
    print(f"\n=== Running Load Tests ({requests} requests) ===")

    # Simple load test using curl
    import concurrent.futures
    import time

    def make_request(url):
        try:
            result = subprocess.run([
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', url
            ], capture_output=True, text=True)
            return result.stdout.strip() == '200'
        except:
            return False

    urls = [f"{base_url}/health"] * requests

    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(make_request, urls))

    end_time = time.time()
    duration = end_time - start_time

    successful = sum(results)
    failed = len(results) - successful

    print(".2f")
    print(f"Requests per second: {requests / duration:.2f}")

    return failed == 0

def generate_report(results, output_file=None):
    """Generate test report."""
    print("\n=== Test Report ===")

    total_passed = sum(1 for result in results.values() if result)
    total_failed = len(results) - total_passed

    print(f"Total test suites: {len(results)}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    for suite, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {suite}: {status}")

    if output_file:
        with open(output_file, 'w') as f:
            f.write(f"PlexiChat Test Report - {datetime.now()}\n")
            f.write(f"Total suites: {len(results)}\n")
            f.write(f"Passed: {total_passed}\n")
            f.write(f"Failed: {total_failed}\n\n")

            for suite, passed in results.items():
                f.write(f"{suite}: {'PASS' if passed else 'FAIL'}\n")

    return total_failed == 0

def main():
    parser = argparse.ArgumentParser(description="PlexiChat Test Runner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Base API URL for tests")
    parser.add_argument("--load-test-requests", type=int, default=100, help="Number of requests for load test")
    parser.add_argument("--report", help="Output report file")
    parser.add_argument("--skip-api", action="store_true", help="Skip API tests")
    parser.add_argument("--skip-security", action="store_true", help="Skip security tests")
    parser.add_argument("--skip-backup", action="store_true", help="Skip backup tests")
    parser.add_argument("--skip-load", action="store_true", help="Skip load tests")

    args = parser.parse_args()

    print("PlexiChat Comprehensive Test Suite")
    print("=" * 40)
    print(f"Started at: {datetime.now()}")
    print(f"API URL: {args.api_url}")

    results = {}

    # Run pytest suite
    results["Pytest Suite"] = run_pytest_suite(verbose=args.verbose)

    # Run API tests
    if not args.skip_api:
        results["API Tests"] = run_manual_api_tests(args.api_url)

    # Run security tests
    if not args.skip_security:
        results["Security Tests"] = run_security_tests()

    # Run backup tests
    if not args.skip_backup:
        results["Backup Tests"] = run_backup_tests()

    # Run load tests
    if not args.skip_load:
        results["Load Tests"] = run_load_tests(args.api_url, args.load_test_requests)

    # Generate report
    success = generate_report(results, args.report)

    print(f"\nTest run completed at: {datetime.now()}")

    if success:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()