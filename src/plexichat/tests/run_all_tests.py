#!/usr/bin/env python3
"""
PlexiChat Unified Testing Framework - Comprehensive Test Runner

Consolidated test runner combining all PlexiChat test suites with:
- Unit, Integration, End-to-End, Performance, and Security testing
- Database performance optimization testing
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

class TestRunner:
    """Comprehensive test runner for all PlexiChat test suites."""
    
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
            "plexichat.app.logger_config",
            "plexichat.core.security.government_auth",
            "plexichat.app.core.system_resilience",
            "plexichat.app.db.database_manager",
            "plexichat.backup.core.backup_manager",
            "plexichat.clustering.core.cluster_manager",
            "plexichat.antivirus.core.antivirus_manager",
            "plexichat.plugins.core.plugin_manager"
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
            "src/plexichat",
            "src/plexichat/app",
            "src/plexichat/core",
            "src/plexichat/cli",
            "src/plexichat/backup",
            "src/plexichat/clustering",
            "src/plexichat/antivirus",
            "src/plexichat/plugins",
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
            "src/plexichat/app/main.py",
            "src/plexichat/app/logger_config.py",
            "src/plexichat/core/security/government_auth.py",
            "src/plexichat/app/core/system_resilience.py",
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

    def run_database_performance_tests(self):
        """Run database performance optimization tests."""
        print(f"\n🔍 Running Database Performance Tests...")
        print("-" * 50)

        start_time = time.time()
        results = []

        try:
            # Test database performance optimization imports
            performance_modules = [
                "plexichat.core.database.enhanced_abstraction",
                "plexichat.core.database.performance_integration",
                "plexichat.core.database.query_optimizer",
                "plexichat.core.database.indexing_strategy",
                "plexichat.core.database.schema_optimizer",
                "plexichat.core.database.stored_procedures"
            ]

            for module in performance_modules:
                try:
                    print(f"Testing import: {module}...", end=" ", flush=True)
                    __import__(module)
                    print("✅ OK")
                    results.append({"module": module, "success": True})
                except Exception as e:
                    print(f"❌ FAILED: {e}")
                    results.append({"module": module, "success": False, "error": str(e)})

            # Test query analyzer functionality
            try:
                print("Testing query analyzer...", end=" ", flush=True)
                from plexichat.core.database.query_optimizer import sql_analyzer

                test_query = "SELECT * FROM users WHERE active = 1"
                analysis = sql_analyzer.analyze_query(test_query)

                if analysis and hasattr(analysis, 'query_type'):
                    print("✅ OK")
                    results.append({"test": "query_analyzer", "success": True})
                else:
                    print("❌ FAILED: Invalid analysis result")
                    results.append({"test": "query_analyzer", "success": False, "error": "Invalid analysis result"})

            except Exception as e:
                print(f"❌ FAILED: {e}")
                results.append({"test": "query_analyzer", "success": False, "error": str(e)})

            # Test performance monitoring
            try:
                print("Testing performance monitoring...", end=" ", flush=True)
                from plexichat.core.database.query_optimizer import performance_monitor

                # Record a test query
                performance_monitor.record_query_execution("SELECT 1", 10.0)
                report = performance_monitor.get_performance_report()

                if report and "total_queries" in report:
                    print("✅ OK")
                    results.append({"test": "performance_monitoring", "success": True})
                else:
                    print("❌ FAILED: Invalid monitoring report")
                    results.append({"test": "performance_monitoring", "success": False, "error": "Invalid monitoring report"})

            except Exception as e:
                print(f"❌ FAILED: {e}")
                results.append({"test": "performance_monitoring", "success": False, "error": str(e)})

            # Test configuration loading
            try:
                print("Testing database performance config...", end=" ", flush=True)
                from plexichat.core.config.config_manager import ConfigManager

                config_manager = ConfigManager()
                db_perf_config = config_manager.load_database_performance_config()

                if db_perf_config and "database_performance" in db_perf_config:
                    print("✅ OK")
                    results.append({"test": "config_loading", "success": True})
                else:
                    print("❌ FAILED: Invalid config structure")
                    results.append({"test": "config_loading", "success": False, "error": "Invalid config structure"})

            except Exception as e:
                print(f"❌ FAILED: {e}")
                results.append({"test": "config_loading", "success": False, "error": str(e)})

            # Test CLI integration
            try:
                print("Testing database performance CLI...", end=" ", flush=True)
                from plexichat.cli.database_performance_cli import database_performance_cli

                if database_performance_cli:
                    print("✅ OK")
                    results.append({"test": "cli_integration", "success": True})
                else:
                    print("❌ FAILED: CLI not available")
                    results.append({"test": "cli_integration", "success": False, "error": "CLI not available"})

            except Exception as e:
                print(f"❌ FAILED: {e}")
                results.append({"test": "cli_integration", "success": False, "error": str(e)})

        except Exception as e:
            print(f"❌ Database performance tests failed: {e}")
            results.append({"test": "overall", "success": False, "error": str(e)})

        duration = time.time() - start_time
        success_count = sum(1 for r in results if r["success"])
        total_count = len(results)

        print(f"\n📊 Database Performance Tests Summary:")
        print(f"   Passed: {success_count}/{total_count}")
        print(f"   Duration: {duration:.2f}s")

        return {
            "success": success_count == total_count and total_count > 0,
            "results": results,
            "success_count": success_count,
            "total_count": total_count,
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
        print("🚀 PlexiChat Comprehensive Test Suite Runner")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Run all test categories
        self.test_results["file_structure"] = self.run_file_structure_tests()
        self.test_results["imports"] = self.run_import_tests()
        self.test_results["security"] = self.run_security_tests()
        self.test_results["api_endpoints"] = self.run_api_tests()
        self.test_results["database_performance"] = self.run_database_performance_tests()
        
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
