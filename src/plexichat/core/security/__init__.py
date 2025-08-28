# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Core Security System - SINGLE SOURCE OF TRUTH

Consolidates ALL security functionality from:
- core/security/security_manager.py - INTEGRATED
- core/security/unified_security_manager.py - INTEGRATED
- features/security/ (all modules) - INTEGRATED
- Related security components - INTEGRATED

Provides a single, unified interface for all security operations.
"""

import warnings
import logging
from typing import Any, Dict, Optional, List

from plexichat.src.plexichat.core.security.security_manager import (
    UnifiedSecurityManager,
    unified_security_manager,
    PasswordManager,
    TokenManager,
    RateLimiter,
    InputSanitizer,
    SecurityMetrics,
    SecurityEvent,
    SecurityRequest,
    SecurityResponse,
    SecurityLevel,
    ThreatLevel,
    SecurityEventType,
    AttackType,
    hash_password,
    verify_password,
    generate_token,
    verify_token,
    check_rate_limit,
    sanitize_input,
    process_security_request,
    get_security_manager,
    SecurityError,
    AuthenticationError,
    AuthorizationError,
)

# Backward compatibility aliases
security_manager = unified_security_manager
SecurityManager = UnifiedSecurityManager

# Export all the main classes and functions
__all__ = [
    # Unified security system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedSecurityManager",
    "unified_security_manager",
    "PasswordManager",
    "TokenManager",
    "RateLimiter",
    "InputSanitizer",
    "SecurityMetrics",

    # Data classes
    "SecurityEvent",
    "SecurityRequest",
    "SecurityResponse",
    "SecurityLevel",
    "ThreatLevel",
    "SecurityEventType",
    "AttackType",

    # Main functions
    "hash_password",
    "verify_password",
    "generate_token",
    "verify_token",
    "check_rate_limit",
    "sanitize_input",
    "process_security_request",
    "get_security_manager",

    # Backward compatibility aliases
    "security_manager",
    "SecurityManager",

    # Exceptions
    "SecurityError",
    "AuthenticationError",
    "AuthorizationError",
]
