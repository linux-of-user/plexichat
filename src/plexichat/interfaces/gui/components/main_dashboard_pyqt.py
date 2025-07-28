"""
PlexiChat PyQt6 Main Dashboard
Modern dashboard interface with comprehensive system management.
"""

import logging
from typing import Dict, Any, Optional, List
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QTabWidget, QTextEdit,
    QProgressBar, QGroupBox, QSplitter, QListWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QIcon, QPixmap, QPainter, QColor

logger = logging.getLogger(__name__)


class SystemStatsWidget(QFrame):
    """Widget displaying system statistics."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_timer()
    
    def setup_ui(self):
        """Setup the UI components."""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("System Statistics")
        title.setFont(QFont("Inter", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Stats grid
        stats_layout = QGridLayout()
        
        # CPU Usage
        self.cpu_label = QLabel("CPU Usage:")
        self.cpu_value = QLabel("0%")
        self.cpu_bar = QProgressBar()
        stats_layout.addWidget(self.cpu_label, 0, 0)
        stats_layout.addWidget(self.cpu_value, 0, 1)
        stats_layout.addWidget(self.cpu_bar, 0, 2)
        
        # Memory Usage
        self.memory_label = QLabel("Memory:")
        self.memory_value = QLabel("0 MB")
        self.memory_bar = QProgressBar()
        stats_layout.addWidget(self.memory_label, 1, 0)
        stats_layout.addWidget(self.memory_value, 1, 1)
        stats_layout.addWidget(self.memory_bar, 1, 2)
        
        # Active Users
        self.users_label = QLabel("Active Users:")
        self.users_value = QLabel("0")
        stats_layout.addWidget(self.users_label, 2, 0)
        stats_layout.addWidget(self.users_value, 2, 1)
        
        # Messages Today
        self.messages_label = QLabel("Messages Today:")
        self.messages_value = QLabel("0")
        stats_layout.addWidget(self.messages_label, 3, 0)
        stats_layout.addWidget(self.messages_value, 3, 1)
        
        layout.addLayout(stats_layout)
        layout.addStretch()
    
    def setup_timer(self):
        """Setup timer for updating stats."""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(5000)  # Update every 5 seconds
    
    def update_stats(self):
        """Update system statistics."""
        try:
            import psutil
            
            # CPU Usage
            cpu_percent = psutil.cpu_percent()
            self.cpu_value.setText(f"{cpu_percent:.1f}%")
            self.cpu_bar.setValue(int(cpu_percent))
            
            # Memory Usage
            memory = psutil.virtual_memory()
            memory_mb = memory.used // (1024 * 1024)
            memory_percent = memory.percent
            self.memory_value.setText(f"{memory_mb} MB")
            self.memory_bar.setValue(int(memory_percent))
            
            # Simulate other stats
            import random
            self.users_value.setText(str(random.randint(10, 50)))
            self.messages_value.setText(str(random.randint(100, 1000)))
            
        except ImportError:
            # Fallback if psutil not available
            import random
            self.cpu_value.setText(f"{random.randint(10, 80)}%")
            self.cpu_bar.setValue(random.randint(10, 80))
            self.memory_value.setText(f"{random.randint(500, 2000)} MB")
            self.memory_bar.setValue(random.randint(30, 90))


class QuickActionsWidget(QFrame):
    """Widget with quick action buttons."""
    
    action_triggered = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the UI components."""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Quick Actions")
        title.setFont(QFont("Inter", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Action buttons
        actions = [
            ("🔌 Manage Plugins", "plugins"),
            ("⚙️ Settings", "settings"),
            ("👥 User Management", "users"),
            ("📊 Analytics", "analytics"),
            ("🔧 System Tools", "tools"),
            ("📝 Logs", "logs")
        ]
        
        for text, action in actions:
            btn = QPushButton(text)
            btn.clicked.connect(lambda checked, a=action: self.action_triggered.emit(a))
            layout.addWidget(btn)
        
        layout.addStretch()


class RecentActivityWidget(QFrame):
    """Widget showing recent system activity."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.populate_activity()
    
    def setup_ui(self):
        """Setup the UI components."""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Recent Activity")
        title.setFont(QFont("Inter", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Activity list
        self.activity_list = QListWidget()
        layout.addWidget(self.activity_list)
    
    def populate_activity(self):
        """Populate with sample activity data."""
        activities = [
            "🔐 User 'admin' logged in",
            "🔌 Plugin 'TestPlugin' loaded",
            "📝 System configuration updated",
            "👤 New user 'john_doe' registered",
            "🔄 Database backup completed",
            "⚠️ High memory usage detected",
            "📊 Analytics report generated",
            "🔧 System maintenance completed"
        ]
        
        for activity in activities:
            self.activity_list.addItem(activity)


class MainDashboardPyQt(QWidget):
    """
    Main dashboard for PlexiChat management interface.
    Features:
    - System statistics and monitoring
    - Quick action buttons
    - Recent activity feed
    - Plugin management overview
    - User management tools
    - System health indicators
    """
    
    # Signals
    action_requested = pyqtSignal(str)
    plugin_action = pyqtSignal(str, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setup_ui()
        self.setup_connections()
        
        logger.info("Main dashboard initialized")
    
    def setup_ui(self):
        """Setup the main dashboard UI."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Header
        self.create_header(main_layout)
        
        # Main content area
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(content_splitter)
        
        # Left panel
        left_panel = self.create_left_panel()
        content_splitter.addWidget(left_panel)
        
        # Center panel
        center_panel = self.create_center_panel()
        content_splitter.addWidget(center_panel)
        
        # Right panel
        right_panel = self.create_right_panel()
        content_splitter.addWidget(right_panel)
        
        # Set splitter proportions
        content_splitter.setSizes([300, 600, 300])
    
    def create_header(self, layout):
        """Create dashboard header."""
        header_layout = QHBoxLayout()
        
        # Welcome message
        welcome_label = QLabel("Welcome to PlexiChat Dashboard")
        welcome_label.setFont(QFont("Inter", 20, QFont.Weight.Bold))
        header_layout.addWidget(welcome_label)
        
        header_layout.addStretch()
        
        # Status indicator
        status_label = QLabel("🟢 System Online")
        status_label.setFont(QFont("Inter", 12))
        header_layout.addWidget(status_label)
        
        layout.addLayout(header_layout)
    
    def create_left_panel(self) -> QWidget:
        """Create left panel with system stats."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # System statistics
        self.stats_widget = SystemStatsWidget()
        layout.addWidget(self.stats_widget)
        
        # Quick actions
        self.actions_widget = QuickActionsWidget()
        layout.addWidget(self.actions_widget)
        
        return panel
    
    def create_center_panel(self) -> QWidget:
        """Create center panel with main content."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Overview tab
        overview_tab = self.create_overview_tab()
        self.tab_widget.addTab(overview_tab, "📊 Overview")
        
        # Plugins tab
        plugins_tab = self.create_plugins_tab()
        self.tab_widget.addTab(plugins_tab, "🔌 Plugins")
        
        # Users tab
        users_tab = self.create_users_tab()
        self.tab_widget.addTab(users_tab, "👥 Users")
        
        # Logs tab
        logs_tab = self.create_logs_tab()
        self.tab_widget.addTab(logs_tab, "📝 Logs")
        
        layout.addWidget(self.tab_widget)
        
        return panel
    
    def create_right_panel(self) -> QWidget:
        """Create right panel with activity feed."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Recent activity
        self.activity_widget = RecentActivityWidget()
        layout.addWidget(self.activity_widget)
        
        return panel
    
    def create_overview_tab(self) -> QWidget:
        """Create overview tab content."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # System overview
        overview_group = QGroupBox("System Overview")
        overview_layout = QGridLayout(overview_group)
        
        # Add overview widgets
        overview_layout.addWidget(QLabel("Server Status:"), 0, 0)
        overview_layout.addWidget(QLabel("🟢 Running"), 0, 1)
        
        overview_layout.addWidget(QLabel("Database:"), 1, 0)
        overview_layout.addWidget(QLabel("🟢 Connected"), 1, 1)
        
        overview_layout.addWidget(QLabel("Plugins:"), 2, 0)
        overview_layout.addWidget(QLabel("5 Active"), 2, 1)
        
        overview_layout.addWidget(QLabel("Uptime:"), 3, 0)
        overview_layout.addWidget(QLabel("2 days, 14 hours"), 3, 1)
        
        layout.addWidget(overview_group)
        layout.addStretch()
        
        return tab
    
    def create_plugins_tab(self) -> QWidget:
        """Create plugins tab content."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Plugin management
        plugins_group = QGroupBox("Plugin Management")
        plugins_layout = QVBoxLayout(plugins_group)
        
        # Plugin table
        self.plugins_table = QTableWidget(0, 4)
        self.plugins_table.setHorizontalHeaderLabels(["Name", "Version", "Status", "Actions"])
        self.plugins_table.horizontalHeader().setStretchLastSection(True)
        
        # Add sample plugins
        self.populate_plugins_table()
        
        plugins_layout.addWidget(self.plugins_table)
        
        # Plugin actions
        actions_layout = QHBoxLayout()
        
        install_btn = QPushButton("📦 Install Plugin")
        install_btn.clicked.connect(lambda: self.plugin_action.emit("install", ""))
        actions_layout.addWidget(install_btn)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_plugins)
        actions_layout.addWidget(refresh_btn)
        
        actions_layout.addStretch()
        
        plugins_layout.addLayout(actions_layout)
        layout.addWidget(plugins_group)
        
        return tab
    
    def create_users_tab(self) -> QWidget:
        """Create users tab content."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # User management
        users_group = QGroupBox("User Management")
        users_layout = QVBoxLayout(users_group)
        
        # User table
        self.users_table = QTableWidget(0, 4)
        self.users_table.setHorizontalHeaderLabels(["Username", "Role", "Last Login", "Status"])
        self.users_table.horizontalHeader().setStretchLastSection(True)
        
        # Add sample users
        self.populate_users_table()
        
        users_layout.addWidget(self.users_table)
        layout.addWidget(users_group)
        
        return tab
    
    def create_logs_tab(self) -> QWidget:
        """Create logs tab content."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Log viewer
        logs_group = QGroupBox("System Logs")
        logs_layout = QVBoxLayout(logs_group)
        
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setFont(QFont("Courier New", 10))
        
        # Add sample log entries
        sample_logs = [
            "[2025-01-27 20:58:00] INFO: PlexiChat server started",
            "[2025-01-27 20:58:01] INFO: Database connection established",
            "[2025-01-27 20:58:02] INFO: Plugin system initialized",
            "[2025-01-27 20:58:03] INFO: Web interface started on port 8000",
            "[2025-01-27 20:58:04] INFO: GUI interface initialized",
            "[2025-01-27 20:58:05] INFO: System ready for connections"
        ]
        
        self.log_viewer.setText("\n".join(sample_logs))
        
        logs_layout.addWidget(self.log_viewer)
        layout.addWidget(logs_group)
        
        return tab
    
    def populate_plugins_table(self):
        """Populate plugins table with sample data."""
        plugins = [
            ("TestPlugin", "1.0.0", "🟢 Active", "Disable"),
            ("ChatBot", "2.1.0", "🟢 Active", "Disable"),
            ("FileManager", "1.5.0", "🔴 Inactive", "Enable"),
            ("Analytics", "3.0.0", "🟢 Active", "Disable"),
            ("Backup", "1.2.0", "🟡 Loading", "Stop")
        ]
        
        self.plugins_table.setRowCount(len(plugins))
        for row, (name, version, status, action) in enumerate(plugins):
            self.plugins_table.setItem(row, 0, QTableWidgetItem(name))
            self.plugins_table.setItem(row, 1, QTableWidgetItem(version))
            self.plugins_table.setItem(row, 2, QTableWidgetItem(status))
            
            action_btn = QPushButton(action)
            action_btn.clicked.connect(lambda checked, n=name: self.plugin_action.emit("toggle", n))
            self.plugins_table.setCellWidget(row, 3, action_btn)
    
    def populate_users_table(self):
        """Populate users table with sample data."""
        users = [
            ("admin", "Administrator", "2025-01-27 20:58", "🟢 Online"),
            ("john_doe", "User", "2025-01-27 18:30", "🔴 Offline"),
            ("jane_smith", "Moderator", "2025-01-27 19:45", "🟢 Online"),
            ("bob_wilson", "User", "2025-01-26 15:20", "🔴 Offline")
        ]
        
        self.users_table.setRowCount(len(users))
        for row, (username, role, last_login, status) in enumerate(users):
            self.users_table.setItem(row, 0, QTableWidgetItem(username))
            self.users_table.setItem(row, 1, QTableWidgetItem(role))
            self.users_table.setItem(row, 2, QTableWidgetItem(last_login))
            self.users_table.setItem(row, 3, QTableWidgetItem(status))
    
    def setup_connections(self):
        """Setup signal connections."""
        if self.actions_widget:
            self.actions_widget.action_triggered.connect(self.handle_action)
    
    def handle_action(self, action: str):
        """Handle quick action button clicks."""
        self.action_requested.emit(action)
        
        # Switch to appropriate tab
        if action == "plugins":
            self.tab_widget.setCurrentIndex(1)
        elif action == "users":
            self.tab_widget.setCurrentIndex(2)
        elif action == "logs":
            self.tab_widget.setCurrentIndex(3)
    
    def refresh_plugins(self):
        """Refresh plugins table."""
        # In a real implementation, this would reload plugin data
        self.populate_plugins_table()
    
    def update_user_info(self, user_data: Dict[str, Any]):
        """Update dashboard with user information."""
        if user_data:
            username = user_data.get('username', 'User')
            # Update welcome message or user-specific content
            pass
