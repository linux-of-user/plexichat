"""
PlexiChat Security Test Suite

This package contains comprehensive security tests for PlexiChat's security controls,
cryptographic implementations, and threat mitigation measures.

Test Categories:
- Authentication & Authorization Security
- Input Validation & Sanitization
- Cryptographic Operations
- Access Control & Permissions
- Session Management
- API Security
- File Upload Security
- P2P Shard System Security
- Backup Security
- WAF Effectiveness
- Rate Limiting
- Audit Logging

Usage:
    python -m pytest tests/security/ -v
    python -m pytest tests/security/test_authentication.py::TestAuthenticationSecurity::test_brute_force_protection -v
"""

__version__ = "1.0.0"
__all__ = [
    "test_authentication",
    "test_input_validation",
    "test_cryptography"
]