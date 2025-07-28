"""
PlexiChat PyQt6 Settings Panel
Comprehensive settings management interface.
"""

import logging
from typing import Dict, Any, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QTabWidget, QTextEdit,
    QLineEdit, QComboBox, QCheckBox, QSpinBox, QSlider,
    QGroupBox, QFormLayout, QColorDialog, QFontDialog,
    QFileDialog, QMessageBox, QButtonGroup, QRadioButton
)
from PyQt6.QtCore import Qt, pyqtSignal, QSettings
from PyQt6.QtGui import QFont, QColor, QPalette

logger = logging.getLogger(__name__)


class SettingsPanelPyQt(QWidget):
    """
    Comprehensive settings management interface.
    Features:
    - General application settings
    - Theme and appearance customization
    - User preferences
    - Security settings
    - Plugin configuration
    - System settings
    """
    
    # Signals
    settings_changed = pyqtSignal(str, object)  # setting_name, value
    theme_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.settings = QSettings('PlexiChat', 'GUI')
        self.setup_ui()
        self.load_settings()
        
        logger.info("Settings panel initialized")
    
    def setup_ui(self):
        """Setup the settings panel UI."""
        self.setWindowTitle("Settings")
        self.setGeometry(300, 300, 800, 600)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        self.create_header(main_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # General settings tab
        general_tab = self.create_general_tab()
        self.tab_widget.addTab(general_tab, "⚙️ General")
        
        # Appearance tab
        appearance_tab = self.create_appearance_tab()
        self.tab_widget.addTab(appearance_tab, "🎨 Appearance")
        
        # Privacy tab
        privacy_tab = self.create_privacy_tab()
        self.tab_widget.addTab(privacy_tab, "🔒 Privacy")
        
        # Advanced tab
        advanced_tab = self.create_advanced_tab()
        self.tab_widget.addTab(advanced_tab, "🔧 Advanced")
        
        main_layout.addWidget(self.tab_widget)
        
        # Buttons
        self.create_buttons(main_layout)
    
    def create_header(self, layout):
        """Create settings header."""
        header_layout = QHBoxLayout()
        
        # Title
        title = QLabel("Settings")
        title.setFont(QFont("Inter", 18, QFont.Weight.Bold))
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Reset button
        reset_btn = QPushButton("🔄 Reset to Defaults")
        reset_btn.clicked.connect(self.reset_to_defaults)
        header_layout.addWidget(reset_btn)
        
        layout.addLayout(header_layout)
    
    def create_general_tab(self) -> QWidget:
        """Create general settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Application settings
        app_group = QGroupBox("Application Settings")
        app_layout = QFormLayout(app_group)
        
        # Auto-start
        self.auto_start_check = QCheckBox("Start with system")
        app_layout.addRow("Startup:", self.auto_start_check)
        
        # Minimize to tray
        self.minimize_tray_check = QCheckBox("Minimize to system tray")
        app_layout.addRow("Minimize:", self.minimize_tray_check)
        
        # Auto-save interval
        self.auto_save_spin = QSpinBox()
        self.auto_save_spin.setRange(1, 60)
        self.auto_save_spin.setSuffix(" minutes")
        app_layout.addRow("Auto-save interval:", self.auto_save_spin)
        
        # Language
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Spanish", "French", "German", "Chinese"])
        app_layout.addRow("Language:", self.language_combo)
        
        layout.addWidget(app_group)
        
        # Notification settings
        notif_group = QGroupBox("Notifications")
        notif_layout = QFormLayout(notif_group)
        
        # Enable notifications
        self.notifications_check = QCheckBox("Enable notifications")
        notif_layout.addRow("Notifications:", self.notifications_check)
        
        # Sound notifications
        self.sound_notif_check = QCheckBox("Play notification sounds")
        notif_layout.addRow("Sound:", self.sound_notif_check)
        
        # Desktop notifications
        self.desktop_notif_check = QCheckBox("Show desktop notifications")
        notif_layout.addRow("Desktop:", self.desktop_notif_check)
        
        layout.addWidget(notif_group)
        layout.addStretch()
        
        return tab
    
    def create_appearance_tab(self) -> QWidget:
        """Create appearance settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Theme settings
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QFormLayout(theme_group)
        
        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([
            "Dark Modern", "Light Modern", "Cyberpunk",
            "Neon Blue", "Forest Green", "Sunset Orange", "Royal Purple"
        ])
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        theme_layout.addRow("Theme:", self.theme_combo)
        
        # Custom colors
        color_layout = QHBoxLayout()
        
        self.primary_color_btn = QPushButton("Primary Color")
        self.primary_color_btn.clicked.connect(lambda: self.choose_color("primary"))
        color_layout.addWidget(self.primary_color_btn)
        
        self.accent_color_btn = QPushButton("Accent Color")
        self.accent_color_btn.clicked.connect(lambda: self.choose_color("accent"))
        color_layout.addWidget(self.accent_color_btn)
        
        theme_layout.addRow("Custom Colors:", color_layout)
        
        layout.addWidget(theme_group)
        
        # Font settings
        font_group = QGroupBox("Font Settings")
        font_layout = QFormLayout(font_group)
        
        # Font family
        self.font_btn = QPushButton("Choose Font")
        self.font_btn.clicked.connect(self.choose_font)
        font_layout.addRow("Font:", self.font_btn)
        
        # Font size
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        font_layout.addRow("Font Size:", self.font_size_spin)
        
        layout.addWidget(font_group)
        
        # UI settings
        ui_group = QGroupBox("Interface Settings")
        ui_layout = QFormLayout(ui_group)
        
        # Window opacity
        self.opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.opacity_slider.setRange(50, 100)
        self.opacity_slider.setValue(100)
        ui_layout.addRow("Window Opacity:", self.opacity_slider)
        
        # Animation speed
        self.animation_combo = QComboBox()
        self.animation_combo.addItems(["Slow", "Normal", "Fast", "Disabled"])
        ui_layout.addRow("Animations:", self.animation_combo)
        
        layout.addWidget(ui_group)
        layout.addStretch()
        
        return tab
    
    def create_privacy_tab(self) -> QWidget:
        """Create privacy settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Privacy settings
        privacy_group = QGroupBox("Privacy Settings")
        privacy_layout = QFormLayout(privacy_group)
        
        # Friend-only messaging
        self.friend_only_check = QCheckBox("Restrict messaging to friends only")
        privacy_layout.addRow("Messaging:", self.friend_only_check)
        
        # Online status
        self.show_online_check = QCheckBox("Show online status to others")
        privacy_layout.addRow("Online Status:", self.show_online_check)
        
        # Read receipts
        self.read_receipts_check = QCheckBox("Send read receipts")
        privacy_layout.addRow("Read Receipts:", self.read_receipts_check)
        
        # Typing indicators
        self.typing_check = QCheckBox("Show typing indicators")
        privacy_layout.addRow("Typing:", self.typing_check)
        
        layout.addWidget(privacy_group)
        
        # Data settings
        data_group = QGroupBox("Data Settings")
        data_layout = QFormLayout(data_group)
        
        # Analytics
        self.analytics_check = QCheckBox("Allow anonymous usage analytics")
        data_layout.addRow("Analytics:", self.analytics_check)
        
        # Crash reports
        self.crash_reports_check = QCheckBox("Send crash reports")
        data_layout.addRow("Crash Reports:", self.crash_reports_check)
        
        # Auto-updates
        self.auto_updates_check = QCheckBox("Check for updates automatically")
        data_layout.addRow("Updates:", self.auto_updates_check)
        
        layout.addWidget(data_group)
        
        # Security settings
        security_group = QGroupBox("Security Settings")
        security_layout = QFormLayout(security_group)
        
        # Session timeout
        self.session_timeout_spin = QSpinBox()
        self.session_timeout_spin.setRange(5, 480)
        self.session_timeout_spin.setSuffix(" minutes")
        security_layout.addRow("Session Timeout:", self.session_timeout_spin)
        
        # Two-factor auth
        self.two_factor_check = QCheckBox("Enable two-factor authentication")
        security_layout.addRow("2FA:", self.two_factor_check)
        
        layout.addWidget(security_group)
        layout.addStretch()
        
        return tab
    
    def create_advanced_tab(self) -> QWidget:
        """Create advanced settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Performance settings
        perf_group = QGroupBox("Performance Settings")
        perf_layout = QFormLayout(perf_group)
        
        # Hardware acceleration
        self.hw_accel_check = QCheckBox("Enable hardware acceleration")
        perf_layout.addRow("Hardware Acceleration:", self.hw_accel_check)
        
        # Memory limit
        self.memory_limit_spin = QSpinBox()
        self.memory_limit_spin.setRange(256, 8192)
        self.memory_limit_spin.setSuffix(" MB")
        perf_layout.addRow("Memory Limit:", self.memory_limit_spin)
        
        # Cache size
        self.cache_size_spin = QSpinBox()
        self.cache_size_spin.setRange(50, 1000)
        self.cache_size_spin.setSuffix(" MB")
        perf_layout.addRow("Cache Size:", self.cache_size_spin)
        
        layout.addWidget(perf_group)
        
        # Developer settings
        dev_group = QGroupBox("Developer Settings")
        dev_layout = QFormLayout(dev_group)
        
        # Debug mode
        self.debug_check = QCheckBox("Enable debug mode")
        dev_layout.addRow("Debug Mode:", self.debug_check)
        
        # Console logging
        self.console_log_check = QCheckBox("Enable console logging")
        dev_layout.addRow("Console Logging:", self.console_log_check)
        
        # Log level
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        dev_layout.addRow("Log Level:", self.log_level_combo)
        
        layout.addWidget(dev_group)
        
        # Backup settings
        backup_group = QGroupBox("Backup Settings")
        backup_layout = QFormLayout(backup_group)
        
        # Auto backup
        self.auto_backup_check = QCheckBox("Enable automatic backups")
        backup_layout.addRow("Auto Backup:", self.auto_backup_check)
        
        # Backup location
        backup_location_layout = QHBoxLayout()
        self.backup_path_edit = QLineEdit()
        backup_location_layout.addWidget(self.backup_path_edit)
        
        browse_backup_btn = QPushButton("Browse")
        browse_backup_btn.clicked.connect(self.choose_backup_location)
        backup_location_layout.addWidget(browse_backup_btn)
        
        backup_layout.addRow("Backup Location:", backup_location_layout)
        
        layout.addWidget(backup_group)
        layout.addStretch()
        
        return tab
    
    def create_buttons(self, layout):
        """Create action buttons."""
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        # Cancel button
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.close)
        buttons_layout.addWidget(cancel_btn)
        
        # Apply button
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_settings)
        buttons_layout.addWidget(apply_btn)
        
        # OK button
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.save_and_close)
        buttons_layout.addWidget(ok_btn)
        
        layout.addLayout(buttons_layout)
    
    def load_settings(self):
        """Load settings from storage."""
        # General settings
        self.auto_start_check.setChecked(self.settings.value("auto_start", False, type=bool))
        self.minimize_tray_check.setChecked(self.settings.value("minimize_tray", True, type=bool))
        self.auto_save_spin.setValue(self.settings.value("auto_save_interval", 5, type=int))
        self.language_combo.setCurrentText(self.settings.value("language", "English"))
        
        # Notifications
        self.notifications_check.setChecked(self.settings.value("notifications", True, type=bool))
        self.sound_notif_check.setChecked(self.settings.value("sound_notifications", True, type=bool))
        self.desktop_notif_check.setChecked(self.settings.value("desktop_notifications", True, type=bool))
        
        # Appearance
        self.theme_combo.setCurrentText(self.settings.value("theme", "Dark Modern"))
        self.font_size_spin.setValue(self.settings.value("font_size", 12, type=int))
        self.opacity_slider.setValue(self.settings.value("opacity", 100, type=int))
        self.animation_combo.setCurrentText(self.settings.value("animations", "Normal"))
        
        # Privacy
        self.friend_only_check.setChecked(self.settings.value("friend_only_messaging", False, type=bool))
        self.show_online_check.setChecked(self.settings.value("show_online_status", True, type=bool))
        self.read_receipts_check.setChecked(self.settings.value("read_receipts", True, type=bool))
        self.typing_check.setChecked(self.settings.value("typing_indicators", True, type=bool))
        
        # Data
        self.analytics_check.setChecked(self.settings.value("analytics", True, type=bool))
        self.crash_reports_check.setChecked(self.settings.value("crash_reports", True, type=bool))
        self.auto_updates_check.setChecked(self.settings.value("auto_updates", True, type=bool))
        
        # Security
        self.session_timeout_spin.setValue(self.settings.value("session_timeout", 60, type=int))
        self.two_factor_check.setChecked(self.settings.value("two_factor", False, type=bool))
        
        # Advanced
        self.hw_accel_check.setChecked(self.settings.value("hardware_acceleration", True, type=bool))
        self.memory_limit_spin.setValue(self.settings.value("memory_limit", 1024, type=int))
        self.cache_size_spin.setValue(self.settings.value("cache_size", 200, type=int))
        self.debug_check.setChecked(self.settings.value("debug_mode", False, type=bool))
        self.console_log_check.setChecked(self.settings.value("console_logging", False, type=bool))
        self.log_level_combo.setCurrentText(self.settings.value("log_level", "INFO"))
        self.auto_backup_check.setChecked(self.settings.value("auto_backup", True, type=bool))
        self.backup_path_edit.setText(self.settings.value("backup_path", ""))
    
    def save_settings(self):
        """Save settings to storage."""
        # General settings
        self.settings.setValue("auto_start", self.auto_start_check.isChecked())
        self.settings.setValue("minimize_tray", self.minimize_tray_check.isChecked())
        self.settings.setValue("auto_save_interval", self.auto_save_spin.value())
        self.settings.setValue("language", self.language_combo.currentText())
        
        # Notifications
        self.settings.setValue("notifications", self.notifications_check.isChecked())
        self.settings.setValue("sound_notifications", self.sound_notif_check.isChecked())
        self.settings.setValue("desktop_notifications", self.desktop_notif_check.isChecked())
        
        # Appearance
        self.settings.setValue("theme", self.theme_combo.currentText())
        self.settings.setValue("font_size", self.font_size_spin.value())
        self.settings.setValue("opacity", self.opacity_slider.value())
        self.settings.setValue("animations", self.animation_combo.currentText())
        
        # Privacy
        self.settings.setValue("friend_only_messaging", self.friend_only_check.isChecked())
        self.settings.setValue("show_online_status", self.show_online_check.isChecked())
        self.settings.setValue("read_receipts", self.read_receipts_check.isChecked())
        self.settings.setValue("typing_indicators", self.typing_check.isChecked())
        
        # Data
        self.settings.setValue("analytics", self.analytics_check.isChecked())
        self.settings.setValue("crash_reports", self.crash_reports_check.isChecked())
        self.settings.setValue("auto_updates", self.auto_updates_check.isChecked())
        
        # Security
        self.settings.setValue("session_timeout", self.session_timeout_spin.value())
        self.settings.setValue("two_factor", self.two_factor_check.isChecked())
        
        # Advanced
        self.settings.setValue("hardware_acceleration", self.hw_accel_check.isChecked())
        self.settings.setValue("memory_limit", self.memory_limit_spin.value())
        self.settings.setValue("cache_size", self.cache_size_spin.value())
        self.settings.setValue("debug_mode", self.debug_check.isChecked())
        self.settings.setValue("console_logging", self.console_log_check.isChecked())
        self.settings.setValue("log_level", self.log_level_combo.currentText())
        self.settings.setValue("auto_backup", self.auto_backup_check.isChecked())
        self.settings.setValue("backup_path", self.backup_path_edit.text())
    
    def on_theme_changed(self, theme_name: str):
        """Handle theme change."""
        theme_map = {
            "Dark Modern": "dark_modern",
            "Light Modern": "light_modern",
            "Cyberpunk": "cyberpunk",
            "Neon Blue": "neon_blue",
            "Forest Green": "forest_green",
            "Sunset Orange": "sunset_orange",
            "Royal Purple": "royal_purple"
        }
        theme_key = theme_map.get(theme_name, "dark_modern")

        # Apply theme through parent if available
        if self.parent_app and hasattr(self.parent_app, 'theme_manager'):
            self.parent_app.theme_manager.apply_theme(theme_key)

        self.theme_changed.emit(theme_key)
    
    def choose_color(self, color_type: str):
        """Choose custom color."""
        color = QColorDialog.getColor(Qt.GlobalColor.blue, self)
        if color.isValid():
            # Apply color (implementation would depend on theme system)
            pass
    
    def choose_font(self):
        """Choose font."""
        font, ok = QFontDialog.getFont(QFont("Inter", 12), self)
        if ok:
            self.font_btn.setText(f"{font.family()} {font.pointSize()}pt")
    
    def choose_backup_location(self):
        """Choose backup location."""
        directory = QFileDialog.getExistingDirectory(self, "Select Backup Directory")
        if directory:
            self.backup_path_edit.setText(directory)
    
    def apply_settings(self):
        """Apply settings without closing."""
        self.save_settings()
        QMessageBox.information(self, "Settings", "Settings applied successfully.")
    
    def save_and_close(self):
        """Save settings and close dialog."""
        self.save_settings()
        self.close()
    
    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        reply = QMessageBox.question(self, "Reset Settings",
                                   "Are you sure you want to reset all settings to defaults?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.settings.clear()
            self.load_settings()
            QMessageBox.information(self, "Settings", "Settings reset to defaults.")
