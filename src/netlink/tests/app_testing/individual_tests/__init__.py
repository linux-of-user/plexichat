"""
Individual test files for comprehensive endpoint testing.
Each test file focuses on specific functionality with detailed coverage.
"""

from .test_auth_endpoints import AuthEndpointTests
from .test_user_endpoints import UserEndpointTests
from .test_message_endpoints import MessageEndpointTests
from .test_file_endpoints import FileEndpointTests
from .test_backup_endpoints import BackupEndpointTests
from .test_device_endpoints import DeviceEndpointTests
from .test_admin_endpoints import AdminEndpointTests
from .test_moderation_endpoints import ModerationEndpointTests
from .test_filter_system import FilterSystemTests
from .test_security_features import SecurityFeatureTests

__all__ = [
    "AuthEndpointTests",
    "UserEndpointTests",
    "MessageEndpointTests",
    "FileEndpointTests",
    "BackupEndpointTests",
    "DeviceEndpointTests",
    "AdminEndpointTests",
    "ModerationEndpointTests",
    "FilterSystemTests",
    "SecurityFeatureTests"
]

__all__ = [
    "AuthEndpointTests",
    "UserEndpointTests", 
    "MessageEndpointTests",
    "FileEndpointTests",
    "BackupEndpointTests",
    "DeviceEndpointTests",
    "AdminEndpointTests",
    "ModerationEndpointTests",
    "FilterSystemTests",
    "SecurityFeatureTests"
]
