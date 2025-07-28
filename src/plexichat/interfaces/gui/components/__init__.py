"""
PlexiChat GUI Components
Modern PyQt6-based interface components.
"""

# Export PyQt6 components
from .login_screen_pyqt import LoginScreenPyQt
from .main_dashboard_pyqt import MainDashboardPyQt
from .plugin_manager_pyqt import PluginManagerPyQt
from .settings_panel_pyqt import SettingsPanelPyQt
from .theme_manager_pyqt import ThemeManagerPyQt
from .notification_system_pyqt import NotificationSystemPyQt

# Keep old Tkinter components for backward compatibility
try:
    from .login_screen import LoginScreen
    from .main_dashboard import MainDashboard
    from .plugin_manager import PluginManager
    from .settings_panel import SettingsPanel
except ImportError:
    # Tkinter components may not be available
    pass

__all__ = [
    'LoginScreenPyQt',
    'MainDashboardPyQt',
    'PluginManagerPyQt',
    'SettingsPanelPyQt',
    'ThemeManagerPyQt',
    'NotificationSystemPyQt',
    'LoginScreen',
    'MainDashboard',
    'PluginManager',
    'SettingsPanel'
]