#!/usr/bin/env python3
"""
Simple Test Runner for Enhanced Chat API
Lightweight test runner that works without external dependencies.
"""

import sys
import os
import time
import json
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class SimpleTestResult:
    """Simple test result container."""
    
    def __init__(self, name: str, passed: bool, message: str = "", duration: float = 0.0):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration
        self.timestamp = datetime.utcnow()

class SimpleTestRunner:
    """Simple test runner for basic system validation."""
    
    def __init__(self):
        self.results = []
        self.base_url = "http://localhost:8000"
        
    def run_all_tests(self) -> List[SimpleTestResult]:
        """Run all available tests."""
        self.results = []
        
        # System tests
        self.test_python_environment()
        self.test_file_structure()
        self.test_database_file()
        self.test_configuration()
        self.test_imports()
        self.test_cli_availability()
        
        # Optional network tests
        try:
            import urllib.request
            self.test_api_server()
        except ImportError:
            self.results.append(SimpleTestResult(
                "API Server Test", False, "urllib not available", 0.0
            ))
        
        return self.results
    
    def test_python_environment(self):
        """Test Python environment."""
        start_time = time.time()
        try:
            version = sys.version_info
            if version.major >= 3 and version.minor >= 8:
                self.results.append(SimpleTestResult(
                    "Python Version", True, f"Python {version.major}.{version.minor}.{version.micro}", 
                    time.time() - start_time
                ))
            else:
                self.results.append(SimpleTestResult(
                    "Python Version", False, f"Python {version.major}.{version.minor} < 3.8", 
                    time.time() - start_time
                ))
        except Exception as e:
            self.results.append(SimpleTestResult(
                "Python Version", False, str(e), time.time() - start_time
            ))
    
    def test_file_structure(self):
        """Test essential file structure."""
        start_time = time.time()
        
        essential_files = [
            "src/plexichat/app/main.py",
            "src/plexichat/app/logger_config.py",
            "run.py",
            "requirements.txt"
        ]
        
        missing_files = []
        for file_path in essential_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        if not missing_files:
            self.results.append(SimpleTestResult(
                "File Structure", True, "All essential files present", 
                time.time() - start_time
            ))
        else:
            self.results.append(SimpleTestResult(
                "File Structure", False, f"Missing files: {', '.join(missing_files)}", 
                time.time() - start_time
            ))
    
    def test_database_file(self):
        """Test database file and basic connectivity."""
        start_time = time.time()
        
        try:
            # Create data directory if it doesn't exist
            data_dir = Path("data")
            data_dir.mkdir(exist_ok=True)
            
            # Test SQLite connection
            db_path = data_dir / "chatapi.db"
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            
            self.results.append(SimpleTestResult(
                "Database Connection", True, f"SQLite database accessible at {db_path}", 
                time.time() - start_time
            ))
        except Exception as e:
            self.results.append(SimpleTestResult(
                "Database Connection", False, str(e), time.time() - start_time
            ))
    
    def test_configuration(self):
        """Test configuration loading."""
        start_time = time.time()
        
        try:
            # Check for .env file
            env_file = Path(".env")
            if env_file.exists():
                config_status = "Configuration file found"
                passed = True
            else:
                config_status = "No .env file found (using defaults)"
                passed = True  # Not critical
            
            # Try to load settings
            try:
                import logging import settings
                config_status += f", Settings loaded successfully"
            except ImportError:
                config_status += ", Settings import failed"
                passed = False
            
            self.results.append(SimpleTestResult(
                "Configuration", passed, config_status, time.time() - start_time
            ))
        except Exception as e:
            self.results.append(SimpleTestResult(
                "Configuration", False, str(e), time.time() - start_time
            ))
    
    def test_imports(self):
        """Test critical imports."""
        start_time = time.time()
        
        critical_imports = [
            ("fastapi", "FastAPI framework"),
            ("sqlmodel", "Database ORM"),
            ("uvicorn", "ASGI server"),
        ]
        
        failed_imports = []
        for module, description in critical_imports:
            try:
                __import__(module)
            except ImportError:
                failed_imports.append(f"{module} ({description})")
        
        if not failed_imports:
            self.results.append(SimpleTestResult(
                "Critical Imports", True, "All critical modules available", 
                time.time() - start_time
            ))
        else:
            self.results.append(SimpleTestResult(
                "Critical Imports", False, f"Missing: {', '.join(failed_imports)}", 
                time.time() - start_time
            ))
    
    def test_cli_availability(self):
        """Test CLI availability."""
        start_time = time.time()
        
        try:
            # Test if CLI can be imported
            import cli
            self.results.append(SimpleTestResult(
                "CLI Availability", True, "CLI module can be imported", 
                time.time() - start_time
            ))
        except ImportError as e:
            self.results.append(SimpleTestResult(
                "CLI Availability", False, f"CLI import failed: {e}", 
                time.time() - start_time
            ))
    
    def test_api_server(self):
        """Test if API server is running."""
        start_time = time.time()
        
        try:
            import urllib.request
            import urllib.error
            
            # Try to connect to health endpoint
            try:
                with urllib.request.urlopen(f"{self.base_url}/api/v1/system/health", timeout=5) as response:
                    if response.status == 200:
                        self.results.append(SimpleTestResult(
                            "API Server", True, f"Server running on {self.base_url}", 
                            time.time() - start_time
                        ))
                    else:
                        self.results.append(SimpleTestResult(
                            "API Server", False, f"Server returned status {response.status}", 
                            time.time() - start_time
                        ))
            except urllib.error.URLError:
                self.results.append(SimpleTestResult(
                    "API Server", False, f"Server not running on {self.base_url}", 
                    time.time() - start_time
                ))
        except ImportError:
            self.results.append(SimpleTestResult(
                "API Server", False, "urllib not available", time.time() - start_time
            ))
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate test report."""
        passed_tests = [r for r in self.results if r.passed]
        failed_tests = [r for r in self.results if not r.passed]
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tests": len(self.results),
            "passed": len(passed_tests),
            "failed": len(failed_tests),
            "success_rate": (len(passed_tests) / len(self.results) * 100) if self.results else 0,
            "duration": sum(r.duration for r in self.results),
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                    "duration": r.duration,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.results
            ]
        }
    
    def print_report(self):
        """Print test report to console."""
        print("\n" + "="*60)
        print("ENHANCED CHAT API - SYSTEM TEST REPORT")
        print("="*60)
        
        passed_count = sum(1 for r in self.results if r.passed)
        total_count = len(self.results)
        
        print(f"Total Tests: {total_count}")
        print(f"Passed: {passed_count}")
        print(f"Failed: {total_count - passed_count}")
        print(f"Success Rate: {(passed_count/total_count*100):.1f}%")
        print()
        
        for result in self.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"{status} {result.name}")
            if result.message:
                print(f"    {result.message}")
            print(f"    Duration: {result.duration:.3f}s")
            print()
        
        if passed_count == total_count:
            print("🎉 All tests passed! System is ready.")
        else:
            print("⚠️  Some tests failed. Check the issues above.")
        
        print("="*60)

def main():
    """Main test runner entry point."""
    print("Starting Enhanced Chat API System Tests...")
    
    runner = SimpleTestRunner()
    results = runner.run_all_tests()
    
    # Print console report
    runner.print_report()
    
    # Save JSON report
    report = runner.generate_report()
    report_file = Path("logs") / "test_report.json"
    report_file.parent.mkdir(exist_ok=True)
    
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")
    
    # Exit with appropriate code
    failed_count = len([r for r in results if not r.passed])
    sys.exit(failed_count)

if __name__ == "__main__":
    main()
