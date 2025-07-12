#!/usr/bin/env python3
"""
PlexiChat Security Testing CLI Script

This script provides a command-line interface for running comprehensive
security tests on PlexiChat, including integration with CI/CD pipelines.
"""

import argparse
import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from plexichat.core_system.security.automated_security_testing import (
    get_automated_security_tester, 
    TestCategory,
    SeverityLevel
)
from plexichat.core_system.logging import get_logger

logger = get_logger(__name__)


class SecurityTestRunner:
    """Security test runner with CLI interface."""
    
    def __init__(self):
        self.tester = get_automated_security_tester()
        self.results = {}
    
    async def run_full_security_audit(self, 
                                    target_url: str = "http://localhost:8000",
                                    output_file: str = None,
                                    fail_on_critical: bool = True) -> Dict[str, Any]:
        """Run comprehensive security audit."""
        print("🔒 Starting PlexiChat Security Audit...")
        print(f"🎯 Target: {target_url}")
        
        # Initialize tester
        await self.tester.initialize()
        self.tester.base_url = target_url
        
        # Run all test categories
        test_categories = [
            TestCategory.API_SECURITY,
            TestCategory.AUTHENTICATION,
            TestCategory.INPUT_VALIDATION,
            TestCategory.WEB_APPLICATION,
            TestCategory.CONFIGURATION,
            TestCategory.ENCRYPTION,
            TestCategory.DEPENDENCY_SCAN
        ]
        
        print(f"📋 Running {len(test_categories)} test categories...")
        
        # Generate test ID
        commit_hash = self._get_git_commit_hash()
        test_id = await self.tester.run_ci_cd_security_tests(
            commit_hash=commit_hash,
            branch=self._get_git_branch(),
            test_categories=test_categories
        )
        
        # Get results
        result = self.tester.get_test_result(test_id)
        
        if not result:
            print("❌ Security test failed - no results generated")
            return {"success": False, "error": "No results generated"}
        
        # Print summary
        self._print_test_summary(result)
        
        # Generate detailed report
        report = self._generate_detailed_report(result)
        
        # Save report if requested
        if output_file:
            self._save_report(report, output_file)
            print(f"📄 Report saved to: {output_file}")
        
        # Check for critical vulnerabilities
        if fail_on_critical and result.critical_count > 0:
            print(f"❌ CRITICAL VULNERABILITIES FOUND: {result.critical_count}")
            print("🚫 Security audit FAILED")
            return {"success": False, "critical_vulnerabilities": result.critical_count}
        
        print("✅ Security audit completed successfully")
        return {"success": True, "report": report}
    
    async def run_dependency_scan(self) -> Dict[str, Any]:
        """Run dependency vulnerability scan."""
        print("📦 Running dependency vulnerability scan...")
        
        try:
            # Run safety check
            result = subprocess.run(
                ["python", "-m", "safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                vulnerabilities = json.loads(result.stdout)
                print(f"🔍 Found {len(vulnerabilities)} vulnerable dependencies")
                
                for vuln in vulnerabilities:
                    severity = "🚨 CRITICAL" if "critical" in vuln.get("advisory", "").lower() else "⚠️  HIGH"
                    print(f"  {severity}: {vuln.get('package_name')} {vuln.get('installed_version')}")
                    print(f"    Advisory: {vuln.get('advisory', 'N/A')}")
                    if vuln.get('cve'):
                        print(f"    CVE: {vuln.get('cve')}")
                
                return {"success": True, "vulnerabilities": vulnerabilities}
            else:
                print("✅ No vulnerable dependencies found")
                return {"success": True, "vulnerabilities": []}
                
        except subprocess.TimeoutExpired:
            print("⏰ Dependency scan timed out")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            print(f"❌ Dependency scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def run_static_analysis(self) -> Dict[str, Any]:
        """Run static code analysis."""
        print("🔍 Running static code analysis...")
        
        try:
            # Run bandit
            result = subprocess.run(
                ["bandit", "-r", "src/plexichat/", "-f", "json"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.stdout:
                analysis = json.loads(result.stdout)
                issues = analysis.get("results", [])
                
                print(f"🔍 Found {len(issues)} potential security issues")
                
                severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for issue in issues:
                    severity = issue.get("issue_severity", "LOW")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    if severity == "HIGH":
                        print(f"  🚨 HIGH: {issue.get('test_name')} in {issue.get('filename')}")
                        print(f"    Line {issue.get('line_number')}: {issue.get('issue_text')}")
                
                print(f"📊 Severity breakdown: {severity_counts}")
                return {"success": True, "analysis": analysis}
            else:
                print("✅ No security issues found in static analysis")
                return {"success": True, "analysis": {"results": []}}
                
        except subprocess.TimeoutExpired:
            print("⏰ Static analysis timed out")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            print(f"❌ Static analysis failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _print_test_summary(self, result):
        """Print test result summary."""
        print("\n" + "="*60)
        print("🔒 SECURITY AUDIT SUMMARY")
        print("="*60)
        print(f"Test ID: {result.test_id}")
        print(f"Target: {result.target}")
        print(f"Duration: {result.duration:.2f}s" if result.duration else "Duration: N/A")
        print(f"Status: {result.status.value.upper()}")
        
        print(f"\n📊 VULNERABILITY BREAKDOWN:")
        print(f"  🚨 Critical: {result.critical_count}")
        print(f"  ⚠️  High: {result.high_count}")
        print(f"  🟡 Medium: {len([v for v in result.vulnerabilities if v.severity == SeverityLevel.MEDIUM])}")
        print(f"  🔵 Low: {len([v for v in result.vulnerabilities if v.severity == SeverityLevel.LOW])}")
        print(f"  ℹ️  Info: {len([v for v in result.vulnerabilities if v.severity == SeverityLevel.INFO])}")
        print(f"  📈 Total: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            print(f"\n🔍 VULNERABILITY DETAILS:")
            for vuln in result.vulnerabilities:
                severity_icon = {
                    SeverityLevel.CRITICAL: "🚨",
                    SeverityLevel.HIGH: "⚠️",
                    SeverityLevel.MEDIUM: "🟡",
                    SeverityLevel.LOW: "🔵",
                    SeverityLevel.INFO: "ℹ️"
                }.get(vuln.severity, "❓")
                
                print(f"  {severity_icon} {vuln.severity.name}: {vuln.title}")
                print(f"    Component: {vuln.affected_component}")
                print(f"    Category: {vuln.category.value}")
                if vuln.cve_id:
                    print(f"    CVE: {vuln.cve_id}")
                print()
    
    def _generate_detailed_report(self, result) -> Dict[str, Any]:
        """Generate detailed security report."""
        return {
            "metadata": {
                "test_id": result.test_id,
                "target": result.target,
                "timestamp": result.start_time.isoformat(),
                "duration": result.duration,
                "git_commit": self._get_git_commit_hash(),
                "git_branch": self._get_git_branch()
            },
            "summary": {
                "total_vulnerabilities": len(result.vulnerabilities),
                "critical_count": result.critical_count,
                "high_count": result.high_count,
                "medium_count": len([v for v in result.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                "low_count": len([v for v in result.vulnerabilities if v.severity == SeverityLevel.LOW]),
                "info_count": len([v for v in result.vulnerabilities if v.severity == SeverityLevel.INFO])
            },
            "vulnerabilities": [vuln.to_dict() for vuln in result.vulnerabilities],
            "test_config": result.test_config,
            "status": result.status.value
        }
    
    def _save_report(self, report: Dict[str, Any], output_file: str):
        """Save report to file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _get_git_commit_hash(self) -> str:
        """Get current git commit hash."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"
    
    def _get_git_branch(self) -> str:
        """Get current git branch."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"


async def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="PlexiChat Security Testing CLI")
    parser.add_argument("--target", default="http://localhost:8000", help="Target URL to test")
    parser.add_argument("--output", help="Output file for security report")
    parser.add_argument("--fail-on-critical", action="store_true", default=True, help="Fail if critical vulnerabilities found")
    parser.add_argument("--deps-only", action="store_true", help="Run dependency scan only")
    parser.add_argument("--static-only", action="store_true", help="Run static analysis only")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    runner = SecurityTestRunner()
    
    try:
        if args.deps_only:
            result = await runner.run_dependency_scan()
        elif args.static_only:
            result = await runner.run_static_analysis()
        else:
            result = await runner.run_full_security_audit(
                target_url=args.target,
                output_file=args.output,
                fail_on_critical=args.fail_on_critical
            )
        
        if not result.get("success", False):
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Security test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
