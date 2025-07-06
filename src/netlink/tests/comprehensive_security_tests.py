#!/usr/bin/env python3
"""
Comprehensive Security Testing Suite for NetLink
Tests all security features, authentication, and system components.
"""

import sys
import os
import asyncio
import json
import time
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

class SecurityTestSuite:
    """Comprehensive security testing suite."""
    
    def __init__(self):
        self.test_results = []
        self.passed_tests = 0
        self.failed_tests = 0
        self.start_time = None
        
    def log_test(self, test_name: str, passed: bool, message: str = "", details: Dict = None):
        """Log test result."""
        result = {
            "test_name": test_name,
            "passed": passed,
            "message": message,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        self.test_results.append(result)
        
        if passed:
            self.passed_tests += 1
            print(f"✅ {test_name}: {message}")
        else:
            self.failed_tests += 1
            print(f"❌ {test_name}: {message}")
    
    def test_government_auth_system(self):
        """Test government authentication system."""
        print("\n🔐 Testing Government Authentication System...")
        
        try:
            from netlink.core.security.government_auth import get_government_auth
            auth_system = get_government_auth()
            
            if not auth_system:
                self.log_test("Auth System Initialization", False, "Failed to initialize auth system")
                return
            
            self.log_test("Auth System Initialization", True, "Successfully initialized")
            
            # Test security policy
            policy = auth_system.security_policy
            self.log_test("Security Policy", True, f"Min password length: {policy.min_password_length}")
            
            # Test password generation
            password = auth_system._generate_secure_password()
            self.log_test("Password Generation", len(password) >= policy.min_password_length, 
                         f"Generated password length: {len(password)}")
            
            # Test encryption/decryption
            test_data = "test_encryption_data"
            encrypted = auth_system._encrypt_data(test_data)
            decrypted = auth_system._decrypt_data(encrypted)
            self.log_test("Encryption/Decryption", decrypted == test_data, 
                         "Data encryption/decryption cycle")
            
        except Exception as e:
            self.log_test("Government Auth System", False, f"Exception: {e}")
    
    def test_system_resilience(self):
        """Test system resilience manager."""
        print("\n🛡️ Testing System Resilience Manager...")
        
        try:
            from netlink.app.core.system_resilience import get_system_resilience
            resilience = get_system_resilience()
            
            if not resilience:
                self.log_test("Resilience System Initialization", False, "Failed to initialize")
                return
            
            self.log_test("Resilience System Initialization", True, "Successfully initialized")
            
            # Test component types
            expected_components = ["DATABASE", "API", "WEBSOCKET", "AUTHENTICATION", 
                                 "FILESYSTEM", "NETWORK", "MEMORY", "CPU", "PLUGINS", 
                                 "BACKUP", "CLUSTERING"]
            
            for component in expected_components:
                has_component = hasattr(resilience, f"check_{component.lower()}")
                self.log_test(f"Component Check - {component}", has_component, 
                             f"Has check method for {component}")
            
        except Exception as e:
            self.log_test("System Resilience", False, f"Exception: {e}")
    
    def test_logger_system(self):
        """Test logging system."""
        print("\n📝 Testing Logger System...")
        
        try:
            from netlink.app.logger_config import logger, Settings
            
            self.log_test("Logger Import", True, "Successfully imported logger")
            
            # Test log levels
            logger.debug("Test debug message")
            logger.info("Test info message")
            logger.warning("Test warning message")
            logger.error("Test error message")
            
            self.log_test("Logger Functionality", True, "All log levels working")
            
            # Test settings
            settings = Settings()
            self.log_test("Logger Settings", True, f"Log level: {settings.LOG_LEVEL}")
            
        except Exception as e:
            self.log_test("Logger System", False, f"Exception: {e}")
    
    def test_database_security(self):
        """Test database security features."""
        print("\n🗄️ Testing Database Security...")
        
        try:
            from netlink.app.db.database_manager import DatabaseManager
            
            # Test database manager initialization
            db_manager = DatabaseManager()
            self.log_test("Database Manager", True, "Successfully initialized")
            
            # Test encryption capabilities
            if hasattr(db_manager, 'encryption_enabled'):
                self.log_test("Database Encryption", db_manager.encryption_enabled, 
                             "Encryption status checked")
            else:
                self.log_test("Database Encryption", False, "No encryption attribute found")
            
        except Exception as e:
            self.log_test("Database Security", False, f"Exception: {e}")
    
    def test_backup_system_security(self):
        """Test backup system security."""
        print("\n💾 Testing Backup System Security...")
        
        try:
            from netlink.backup.core.backup_manager import BackupManager
            
            backup_manager = BackupManager()
            self.log_test("Backup Manager", True, "Successfully initialized")
            
            # Test shard encryption
            test_data = b"test_shard_data"
            if hasattr(backup_manager, 'encrypt_shard'):
                encrypted_shard = backup_manager.encrypt_shard(test_data, "test_key")
                self.log_test("Shard Encryption", len(encrypted_shard) > len(test_data), 
                             "Shard encryption working")
            else:
                self.log_test("Shard Encryption", False, "No shard encryption method found")
            
        except Exception as e:
            self.log_test("Backup System Security", False, f"Exception: {e}")
    
    def test_clustering_security(self):
        """Test clustering system security."""
        print("\n🔗 Testing Clustering Security...")
        
        try:
            from netlink.clustering.core.cluster_manager import ClusterManager
            
            cluster_manager = ClusterManager()
            self.log_test("Cluster Manager", True, "Successfully initialized")
            
            # Test node authentication
            if hasattr(cluster_manager, 'authenticate_node'):
                self.log_test("Node Authentication", True, "Node authentication method exists")
            else:
                self.log_test("Node Authentication", False, "No node authentication found")
            
        except Exception as e:
            self.log_test("Clustering Security", False, f"Exception: {e}")
    
    def test_antivirus_system(self):
        """Test antivirus system."""
        print("\n🦠 Testing Antivirus System...")
        
        try:
            from netlink.antivirus.core.antivirus_manager import AntivirusManager
            
            av_manager = AntivirusManager()
            self.log_test("Antivirus Manager", True, "Successfully initialized")
            
            # Test file scanning
            if hasattr(av_manager, 'scan_file'):
                self.log_test("File Scanning", True, "File scanning method exists")
            else:
                self.log_test("File Scanning", False, "No file scanning method found")
            
        except Exception as e:
            self.log_test("Antivirus System", False, f"Exception: {e}")
    
    def test_plugin_system_security(self):
        """Test plugin system security."""
        print("\n🔌 Testing Plugin System Security...")
        
        try:
            from netlink.plugins.core.plugin_manager import PluginManager
            
            plugin_manager = PluginManager()
            self.log_test("Plugin Manager", True, "Successfully initialized")
            
            # Test plugin validation
            if hasattr(plugin_manager, 'validate_plugin'):
                self.log_test("Plugin Validation", True, "Plugin validation method exists")
            else:
                self.log_test("Plugin Validation", False, "No plugin validation found")
            
        except Exception as e:
            self.log_test("Plugin System Security", False, f"Exception: {e}")
    
    def test_rate_limiting(self):
        """Test rate limiting system."""
        print("\n⏱️ Testing Rate Limiting System...")
        
        try:
            from netlink.app.core.rate_limiter import RateLimiter
            
            rate_limiter = RateLimiter()
            self.log_test("Rate Limiter", True, "Successfully initialized")
            
            # Test rate limiting functionality
            if hasattr(rate_limiter, 'check_rate_limit'):
                self.log_test("Rate Limit Check", True, "Rate limit check method exists")
            else:
                self.log_test("Rate Limit Check", False, "No rate limit check found")
            
        except Exception as e:
            self.log_test("Rate Limiting System", False, f"Exception: {e}")
    
    def generate_report(self):
        """Generate comprehensive test report."""
        end_time = time.time()
        duration = end_time - self.start_time if self.start_time else 0
        
        report = {
            "test_summary": {
                "total_tests": len(self.test_results),
                "passed": self.passed_tests,
                "failed": self.failed_tests,
                "success_rate": (self.passed_tests / len(self.test_results) * 100) if self.test_results else 0,
                "duration_seconds": duration,
                "timestamp": datetime.utcnow().isoformat()
            },
            "test_results": self.test_results
        }
        
        # Save report
        report_file = Path(__file__).parent / f"security_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 Test Report Generated: {report_file}")
        return report
    
    def run_all_tests(self):
        """Run all security tests."""
        print("🚀 NetLink Comprehensive Security Test Suite")
        print("=" * 60)
        
        self.start_time = time.time()
        
        # Run all test categories
        self.test_government_auth_system()
        self.test_system_resilience()
        self.test_logger_system()
        self.test_database_security()
        self.test_backup_system_security()
        self.test_clustering_security()
        self.test_antivirus_system()
        self.test_plugin_system_security()
        self.test_rate_limiting()
        
        # Generate report
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print(f"🎯 Test Summary:")
        print(f"   Total Tests: {report['test_summary']['total_tests']}")
        print(f"   Passed: {report['test_summary']['passed']}")
        print(f"   Failed: {report['test_summary']['failed']}")
        print(f"   Success Rate: {report['test_summary']['success_rate']:.1f}%")
        print(f"   Duration: {report['test_summary']['duration_seconds']:.2f}s")
        
        return report['test_summary']['failed'] == 0

def main():
    """Main test function."""
    test_suite = SecurityTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
