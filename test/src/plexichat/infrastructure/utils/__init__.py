# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

import logging

from .common_utils import *
from .ip_security import *
from .monitoring.error_handler import *
from .performance import *
from .rate_limiting import *
from .scheduling import *
from .security import *
from .shutdown import *
from .snowflake import *
from .utilities import *
from typing import Optional

"""
PlexiChat Infrastructure Utilities

Consolidated utility functions from common and utils modules.
This module provides centralized access to all utility functions used throughout the application.
"""

# Re-export for backward compatibility
__all__ = [
    # From utilities
    'config_manager',
    'DateTimeUtils',
    'StringUtils',

    # From enhanced_logging
    'setup_logging',
    'get_logger',

    # From common_utils
    'validate_input',
    'sanitize_string',

    # From performance
    'PerformanceMonitor',
    'performance_timer',

    # From security
    'SecurityUtils',
    'hash_password',
    'verify_password',

    # From ip_security
    'IPSecurityManager',
    'is_ip_allowed',

    # From rate_limiting
    'RateLimiter',
    'rate_limit',

    # From scheduling
    'TaskScheduler',
    'schedule_task',

    # From shutdown
    'GracefulShutdown',
    'register_shutdown_handler',

    # From snowflake
    'SnowflakeGenerator',
    'generate_id',
]
