#!/usr/bin/env python3
"""
Comprehensive Test Runner for NetLink
Runs all test suites and generates combined reports.
"""

import sys
import os
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

class TestRunner:
    """Comprehensive test runner for all NetLink test suites."""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = None
        self.tests_dir = Path(__file__).parent
        
    def run_test_suite(self, test_file: str, description: str) -> Dict[str, Any]:
        """Run a specific test suite."""
        print(f"\n🔍 Running {description}...")
        print("-" * 50)
        
        test_path = self.tests_dir / test_file
        if not test_path.exists():
            return {
                "success": False,
                "error": f"Test file not found: {test_file}",
                "duration": 0
            }
        
        start_time = time.time()
        try:
            # Run test as subprocess to isolate imports
            result = subprocess.run(
                [sys.executable, str(test_path)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=project_root
            )
            
            duration = time.time() - start_time
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "duration": duration
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Test timed out after 5 minutes",
                "duration": time.time() - start_time
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Exception running test: {e}",
                "duration": time.time() - start_time
            }
    
    def run_security_tests(self):
        """Run comprehensive security tests."""
        return self.run_test_suite("comprehensive_security_tests.py", "Security Tests")
    
    def run_api_tests(self):
        """Run API endpoint tests."""
        return self.run_test_suite("api_endpoint_tests.py", "API Endpoint Tests")
    
    def run_import_tests(self):
        """Run import and module tests."""
        print(f"\n🔍 Running Import Tests...")
        print("-" * 50)
        
        start_time = time.time()
        results = []
        
        # Test critical imports
        critical_modules = [
            "netlink.app.logger_config",
            "netlink.core.security.government_auth",
            "netlink.app.core.system_resilience",
            "netlink.app.db.database_manager",
            "netlink.backup.core.backup_manager",
            "netlink.clustering.core.cluster_manager",
            "netlink.antivirus.core.antivirus_manager",
            "netlink.plugins.core.plugin_manager"
        ]
        
        for module in critical_modules:
            try:
                print(f"Testing import: {module}...", end=" ", flush=True)
                __import__(module)
                print("✅ OK")
                results.append({"module": module, "success": True})
            except Exception as e:
                print(f"❌ FAILED: {e}")
                results.append({"module": module, "success": False, "error": str(e)})
        
        duration = time.time() - start_time
        success_count = sum(1 for r in results if r["success"])
        
        return {
            "success": success_count == len(critical_modules),
            "results": results,
            "success_count": success_count,
            "total_count": len(critical_modules),
            "duration": duration
        }
    
    def run_file_structure_tests(self):
        """Run file structure validation tests."""
        print(f"\n🔍 Running File Structure Tests...")
        print("-" * 50)
        
        start_time = time.time()
        results = []
        
        # Check critical directories
        critical_dirs = [
            "src/netlink",
            "src/netlink/app",
            "src/netlink/core",
            "src/netlink/cli",
            "src/netlink/backup",
            "src/netlink/clustering",
            "src/netlink/antivirus",
            "src/netlink/plugins",
            "config",
            "logs",
            "data",
            "backups",
            "tests"
        ]
        
        for dir_path in critical_dirs:
            full_path = project_root / dir_path
            exists = full_path.exists()
            print(f"Checking directory: {dir_path}...", end=" ", flush=True)
            if exists:
                print("✅ OK")
                results.append({"path": dir_path, "type": "directory", "success": True})
            else:
                print("❌ MISSING")
                results.append({"path": dir_path, "type": "directory", "success": False})
        
        # Check critical files
        critical_files = [
            "src/netlink/app/main.py",
            "src/netlink/app/logger_config.py",
            "src/netlink/core/security/government_auth.py",
            "src/netlink/app/core/system_resilience.py",
            "run.py",
            "requirements.txt",
            ".gitignore"
        ]
        
        for file_path in critical_files:
            full_path = project_root / file_path
            exists = full_path.exists()
            print(f"Checking file: {file_path}...", end=" ", flush=True)
            if exists:
                print("✅ OK")
                results.append({"path": file_path, "type": "file", "success": True})
            else:
                print("❌ MISSING")
                results.append({"path": file_path, "type": "file", "success": False})
        
        duration = time.time() - start_time
        success_count = sum(1 for r in results if r["success"])
        
        return {
            "success": success_count == len(critical_dirs) + len(critical_files),
            "results": results,
            "success_count": success_count,
            "total_count": len(critical_dirs) + len(critical_files),
            "duration": duration
        }
    
    def generate_comprehensive_report(self):
        """Generate comprehensive test report."""
        end_time = time.time()
        total_duration = end_time - self.start_time if self.start_time else 0
        
        # Calculate overall statistics
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        for test_name, result in self.test_results.items():
            if result["success"]:
                passed_tests += 1
            else:
                failed_tests += 1
            total_tests += 1
        
        report = {
            "overall_summary": {
                "total_test_suites": len(self.test_results),
                "passed_suites": passed_tests,
                "failed_suites": failed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "total_duration": total_duration,
                "timestamp": datetime.utcnow().isoformat()
            },
            "test_suite_results": self.test_results
        }
        
        # Save comprehensive report
        report_file = self.tests_dir / f"comprehensive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 Comprehensive Test Report Generated: {report_file}")
        return report
    
    def run_all_tests(self):
        """Run all test suites."""
        print("🚀 NetLink Comprehensive Test Suite Runner")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Run all test categories
        self.test_results["file_structure"] = self.run_file_structure_tests()
        self.test_results["imports"] = self.run_import_tests()
        self.test_results["security"] = self.run_security_tests()
        self.test_results["api_endpoints"] = self.run_api_tests()
        
        # Generate comprehensive report
        report = self.generate_comprehensive_report()
        
        print("\n" + "=" * 60)
        print(f"🎯 Overall Test Summary:")
        print(f"   Test Suites: {report['overall_summary']['total_test_suites']}")
        print(f"   Passed: {report['overall_summary']['passed_suites']}")
        print(f"   Failed: {report['overall_summary']['failed_suites']}")
        print(f"   Success Rate: {report['overall_summary']['success_rate']:.1f}%")
        print(f"   Total Duration: {report['overall_summary']['total_duration']:.2f}s")
        
        # Print individual suite results
        print(f"\n📋 Individual Suite Results:")
        for suite_name, result in self.test_results.items():
            status = "✅ PASSED" if result["success"] else "❌ FAILED"
            duration = result.get("duration", 0)
            print(f"   {suite_name}: {status} ({duration:.2f}s)")
        
        return report['overall_summary']['failed_suites'] == 0

def main():
    """Main test runner function."""
    runner = TestRunner()
    success = runner.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
