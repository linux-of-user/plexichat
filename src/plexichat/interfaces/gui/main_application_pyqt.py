"""
PlexiChat Advanced PyQt6 GUI Application
The most sophisticated and feature-rich PyQt6 interface for PlexiChat.
"""

import sys
import os
import json
import logging
import asyncio
import threading
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QStackedWidget, QMessageBox, QSplashScreen, QSystemTrayIcon,
    QMenu, QMenuBar, QStatusBar, QToolBar, QTabWidget, QFrame,
    QLabel, QPushButton, QLineEdit, QTextEdit, QScrollArea,
    QGridLayout, QFormLayout, QGroupBox, QSplitter
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSettings, QSize,
    QPropertyAnimation, QEasingCurve, QRect, QPoint
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QPainter, QFont, QFontMetrics, QPalette,
    QColor, QLinearGradient, QBrush, QPen, QAction
)

# Import PyQt6 components (we'll create these)
from .components.login_screen_pyqt import LoginScreenPyQt
from .components.main_dashboard_pyqt import MainDashboardPyQt
from .components.plugin_manager_pyqt import PluginManagerPyQt
from .components.settings_panel_pyqt import SettingsPanelPyQt
from .components.theme_manager_pyqt import ThemeManagerPyQt
from .components.notification_system_pyqt import NotificationSystemPyQt

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


class PlexiChatGUIPyQt(QMainWindow):
    """
    The most advanced PyQt6 GUI application for PlexiChat.
    Features:
    - Modern, sleek design with custom themes
    - Full integration with all PlexiChat systems
    - Plugin system with custom language support
    - Advanced chat interface with rich text
    - Real-time notifications and status updates
    - Multi-window support
    - Customizable layouts and workspaces
    - Advanced user management
    - System monitoring and analytics
    """

    # Signals
    user_authenticated = pyqtSignal(dict)
    user_logged_out = pyqtSignal()
    theme_changed = pyqtSignal(str)
    plugin_loaded = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        
        # Core attributes
        self.current_user: Optional[Dict[str, Any]] = None
        self.is_authenticated: bool = False
        self.settings = QSettings('PlexiChat', 'GUI')
        
        # Component references
        self.login_screen: Optional[LoginScreenPyQt] = None
        self.main_dashboard: Optional[MainDashboardPyQt] = None
        self.plugin_manager: Optional[PluginManagerPyQt] = None
        self.settings_panel: Optional[SettingsPanelPyQt] = None
        self.theme_manager: Optional[ThemeManagerPyQt] = None
        self.notification_system: Optional[NotificationSystemPyQt] = None
        
        # UI components
        self.central_widget: Optional[QWidget] = None
        self.stacked_widget: Optional[QStackedWidget] = None
        self.status_bar: Optional[QStatusBar] = None
        self.menu_bar: Optional[QMenuBar] = None
        self.tool_bar: Optional[QToolBar] = None
        
        # State management
        self.windows = {}
        self.active_plugins = {}
        self.user_preferences = {}
        self.session_data = {}
        
        # Event system
        self.event_handlers = {}
        self.async_loop = None
        
        self.initialize_application()

    def initialize_application(self):
        """Initialize the main application."""
        try:
            logger.info("Initializing PlexiChat Advanced PyQt6 GUI...")
            
            # Setup main window
            self.setup_main_window()
            
            # Initialize theme system
            self.theme_manager = ThemeManagerPyQt(self)
            self.theme_manager.apply_theme("dark_modern")

            # Theme manager signals will be connected after UI setup
            
            # Initialize notification system
            self.notification_system = NotificationSystemPyQt(self)

            # Setup UI components (plugin manager will be created after login)
            self.setup_ui_components()
            
            # Setup async event loop
            self.setup_async_loop()
            
            # Connect signals
            self.connect_signals()
            
            # Show login screen
            self.show_login_screen()
            
            logger.info("PlexiChat PyQt6 GUI initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize GUI: {e}")
            QMessageBox.critical(self, "Initialization Error", 
                               f"Failed to start PlexiChat GUI: {e}")
            sys.exit(1)

    def setup_main_window(self):
        """Setup the main window properties."""
        self.setWindowTitle("PlexiChat Management Interface")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 800)
        
        # Set application icon
        self.set_application_icon()
        
        # Create central widget and stacked widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)
        
        # Setup menu bar
        self.setup_menu_bar()
        
        # Setup status bar
        self.setup_status_bar()
        
        # Setup toolbar
        self.setup_toolbar()

    def setup_ui_components(self):
        """Setup all UI components."""
        # Create login screen
        self.login_screen = LoginScreenPyQt(self)
        self.stacked_widget.addWidget(self.login_screen)

        # Initialize other components as None (will be created after login)
        self.main_dashboard = None
        self.plugin_manager = None
        self.settings_panel = None

        # Connect all signals after components are created
        self.connect_signals()

    def setup_menu_bar(self):
        """Setup the menu bar."""
        self.menu_bar = self.menuBar()
        
        # File menu
        file_menu = self.menu_bar.addMenu("&File")
        
        # Add actions
        login_action = QAction("&Login", self)
        login_action.setShortcut("Ctrl+L")
        login_action.triggered.connect(self.show_login_screen)
        file_menu.addAction(login_action)
        
        logout_action = QAction("Log&out", self)
        logout_action.setShortcut("Ctrl+O")
        logout_action.triggered.connect(self.logout_user)
        file_menu.addAction(logout_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = self.menu_bar.addMenu("&View")
        
        dashboard_action = QAction("&Dashboard", self)
        dashboard_action.triggered.connect(self.show_dashboard)
        view_menu.addAction(dashboard_action)
        
        plugins_action = QAction("&Plugins", self)
        plugins_action.triggered.connect(self.show_plugin_manager)
        view_menu.addAction(plugins_action)
        
        settings_action = QAction("&Settings", self)
        settings_action.triggered.connect(self.show_settings)
        view_menu.addAction(settings_action)
        
        # Help menu
        help_menu = self.menu_bar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        docs_action = QAction("&Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)

    def setup_status_bar(self):
        """Setup the status bar."""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")

    def setup_toolbar(self):
        """Setup the toolbar."""
        self.tool_bar = self.addToolBar("Main")
        
        # Add toolbar actions
        login_action = QAction("Login", self)
        login_action.triggered.connect(self.show_login_screen)
        self.tool_bar.addAction(login_action)
        
        dashboard_action = QAction("Dashboard", self)
        dashboard_action.triggered.connect(self.show_dashboard)
        self.tool_bar.addAction(dashboard_action)
        
        plugins_action = QAction("Plugins", self)
        plugins_action.triggered.connect(self.show_plugin_manager)
        self.tool_bar.addAction(plugins_action)
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        self.tool_bar.addAction(settings_action)

    def set_application_icon(self):
        """Set the application icon."""
        try:
            icon_path = Path(__file__).parent / "assets" / "plexichat_icon.png"
            if icon_path.exists():
                self.setWindowIcon(QIcon(str(icon_path)))
            else:
                # Create default icon
                self.create_default_icon()
        except Exception as e:
            logger.warning(f"Could not set application icon: {e}")

    def create_default_icon(self):
        """Create a default icon programmatically."""
        try:
            # Create a simple icon using QPainter
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.GlobalColor.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Draw a simple "P" for PlexiChat
            painter.setPen(QPen(QColor("#4A90E2"), 4))
            painter.setFont(QFont("Arial", 32, QFont.Weight.Bold))
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "P")
            
            painter.end()
            
            self.setWindowIcon(QIcon(pixmap))
        except Exception as e:
            logger.warning(f"Could not create default icon: {e}")

    def setup_async_loop(self):
        """Setup async event loop integration."""
        try:
            # Create event loop for async operations
            self.async_loop = asyncio.new_event_loop()
            
            # Start async loop in separate thread
            async_thread = threading.Thread(
                target=self._run_async_loop,
                daemon=True
            )
            async_thread.start()
            
            logger.info("Async event loop initialized")
        except Exception as e:
            logger.error(f"Failed to setup async loop: {e}")

    def _run_async_loop(self):
        """Run the async event loop."""
        asyncio.set_event_loop(self.async_loop)
        self.async_loop.run_forever()

    def connect_signals(self):
        """Connect all signals."""
        try:
            # Connect login screen signals using lambda to avoid method reference issues
            if hasattr(self, 'login_screen') and self.login_screen:
                if hasattr(self.login_screen, 'login_success'):
                    self.login_screen.login_success.connect(lambda user_data: self.handle_user_login(user_data))
                    logger.info("Connected login screen signals")

            # Settings panel signals will be connected after login when it's created
            logger.info("Signal connections initialized")
        except Exception as e:
            logger.error(f"Error connecting signals: {e}")
            import traceback
            traceback.print_exc()

    def show_login_screen(self):
        """Show the login screen."""
        if self.login_screen:
            self.stacked_widget.setCurrentWidget(self.login_screen)
            self.status_bar.showMessage("Please log in")

    def show_dashboard(self):
        """Show the main dashboard."""
        if not self.is_authenticated:
            self.show_login_screen()
            return

        if self.main_dashboard:
            if self.main_dashboard not in [self.stacked_widget.widget(i)
                                         for i in range(self.stacked_widget.count())]:
                self.stacked_widget.addWidget(self.main_dashboard)
            self.stacked_widget.setCurrentWidget(self.main_dashboard)
            self.status_bar.showMessage("Dashboard")
        else:
            self.status_bar.showMessage("Please log in first")

    def show_plugin_manager(self):
        """Show the plugin manager."""
        if not self.is_authenticated:
            self.show_login_screen()
            return

        if self.plugin_manager:
            # Create plugin manager window or tab
            self.plugin_manager.show()
        else:
            self.status_bar.showMessage("Please log in first")

    def show_settings(self):
        """Show the settings panel."""
        if not self.is_authenticated:
            self.show_login_screen()
            return

        if self.settings_panel:
            self.settings_panel.show()
        else:
            self.status_bar.showMessage("Please log in first")

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About PlexiChat",
                         "PlexiChat Management Interface\n"
                         "Advanced PyQt6 GUI Application\n"
                         "Version: a.1.1-144")

    def handle_user_login(self, user_data: dict):
        """Handle user login from signal."""
        # Create dashboard components after successful login
        if not self.main_dashboard:
            self.main_dashboard = MainDashboardPyQt(self)
            self.stacked_widget.addWidget(self.main_dashboard)

        if not self.plugin_manager:
            self.plugin_manager = PluginManagerPyQt(self)
            self.plugin_manager.hide()  # Hide initially

        if not self.settings_panel:
            self.settings_panel = SettingsPanelPyQt(self)
            self.settings_panel.hide()  # Hide initially
            # Connect settings panel signals now that it exists
            if hasattr(self.settings_panel, 'theme_changed'):
                self.settings_panel.theme_changed.connect(lambda theme: self.handle_theme_change(theme))
                logger.info("Connected settings panel theme signals")

        self.on_user_authenticated(user_data)

    def handle_theme_change(self, theme_name: str):
        """Handle theme change from signal."""
        self.on_theme_changed(theme_name)

    def on_user_authenticated(self, user_data: dict):
        """Handle user authentication."""
        self.current_user = user_data
        self.is_authenticated = True
        self.show_dashboard()
        self.status_bar.showMessage(f"Welcome, {user_data.get('username', 'User')}")

    def on_user_logged_out(self):
        """Handle user logout."""
        self.current_user = None
        self.is_authenticated = False
        self.show_login_screen()
        self.status_bar.showMessage("Logged out")

    def on_theme_changed(self, theme_name: str):
        """Handle theme change."""
        if self.theme_manager:
            # Apply theme without triggering signals to avoid circular calls
            theme = self.theme_manager.themes.get(theme_name)
            if theme:
                self.setStyleSheet(theme["stylesheet"])
                self.theme_manager.current_theme = theme_name
                logger.info(f"Applied theme: {theme['name']}")

    def logout_user(self):
        """Logout the current user."""
        self.user_logged_out.emit()

    def show_plugin_manager(self):
        """Show plugin manager."""
        try:
            if self.plugin_manager:
                self.plugin_manager.show()
                self.plugin_manager.raise_()
                self.plugin_manager.activateWindow()
            else:
                logger.warning("Plugin manager not initialized")
        except Exception as e:
            logger.error(f"Failed to show plugin manager: {e}")

    def show_settings(self):
        """Show settings panel."""
        try:
            if self.settings_panel:
                self.settings_panel.show()
                self.settings_panel.raise_()
                self.settings_panel.activateWindow()
            else:
                logger.warning("Settings panel not initialized")
        except Exception as e:
            logger.error(f"Failed to show settings: {e}")

    def show_about(self):
        """Show about dialog."""
        try:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.about(self, "About PlexiChat",
                            """<h2>PlexiChat Management Interface</h2>
                            <p>Version 1.1.1</p>
                            <p>Advanced chat and collaboration platform</p>
                            <p>Built with PyQt6 and modern design principles</p>
                            <p><b>Features:</b></p>
                            <ul>
                            <li>Real-time messaging</li>
                            <li>Plugin system</li>
                            <li>Advanced security</li>
                            <li>Modern UI/UX</li>
                            </ul>
                            <p>© 2024 PlexiChat Team</p>""")
        except Exception as e:
            logger.error(f"Failed to show about dialog: {e}")

    def show_documentation(self):
        """Show documentation."""
        try:
            import webbrowser
            webbrowser.open("http://localhost/docs")
        except Exception as e:
            logger.error(f"Failed to open documentation: {e}")
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Documentation",
                                  "Documentation is available at: http://localhost/docs")

    def closeEvent(self, event):
        """Handle application close event."""
        # Save settings
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())

        # Close async loop
        if self.async_loop:
            self.async_loop.call_soon_threadsafe(self.async_loop.stop)

        event.accept()

    def run(self):
        """Run the application."""
        self.show()


def main():
    """Main entry point for PyQt6 GUI."""
    app = QApplication(sys.argv)
    app.setApplicationName("PlexiChat")
    app.setApplicationVersion("a.1.1-144")
    app.setOrganizationName("PlexiChat")
    
    # Create and run GUI
    gui = PlexiChatGUIPyQt()
    gui.run()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
