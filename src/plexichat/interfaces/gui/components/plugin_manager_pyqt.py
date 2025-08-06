"""
PlexiChat PyQt6 Plugin Manager
Advanced plugin management interface with marketplace integration.


import logging
from typing import Dict, Any, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QFrame, QScrollArea, QTabWidget, QTextEdit,
    QListWidget, QListWidgetItem, QGroupBox, QLineEdit,
    QComboBox, QCheckBox, QProgressBar, QSplitter, QDialog,
    QDialogButtonBox, QFormLayout, QSpinBox, QFileDialog,
    QMessageBox, QTableWidget, QTableWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QFont, QIcon, QPixmap

logger = logging.getLogger(__name__)


class PluginCard(QFrame):
    """Individual plugin card widget."""
        action_requested = pyqtSignal(str, str)  # action, plugin_name
    
    def __init__(self, plugin_data: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.plugin_data = plugin_data
        self.setup_ui()
    
    def setup_ui(self):
        Setup the plugin card UI."""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setFixedSize(300, 200)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Plugin name and version
        name_layout = QHBoxLayout()
        name_label = QLabel(self.plugin_data.get('name', 'Unknown'))
        name_label.setFont(QFont("Inter", 14, QFont.Weight.Bold))
        name_layout.addWidget(name_label)
        
        name_layout.addStretch()
        
        version_label = QLabel(f"v{self.plugin_data.get('version', '1.0.0')}")
        version_label.setStyleSheet("color: #666666;")
        name_layout.addWidget(version_label)
        
        layout.addLayout(name_layout)
        
        # Description
        desc_label = QLabel(self.plugin_data.get('description', 'No description available'))
        desc_label.setWordWrap(True)
        desc_label.setMaximumHeight(60)
        layout.addWidget(desc_label)
        
        # Status
        status = self.plugin_data.get('status', 'inactive')
        status_label = QLabel(f"Status: {'? Active' if status == 'active' else '? Inactive'}")
        layout.addWidget(status_label)
        
        layout.addStretch()
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        
        if status == 'active':
            disable_btn = QPushButton("Disable")
            disable_btn.clicked.connect(lambda: self.action_requested.emit("disable", self.plugin_data['name']))
            buttons_layout.addWidget(disable_btn)
        else:
            enable_btn = QPushButton("Enable")
            enable_btn.clicked.connect(lambda: self.action_requested.emit("enable", self.plugin_data['name']))
            buttons_layout.addWidget(enable_btn)
        
        config_btn = QPushButton("Configure")
        config_btn.clicked.connect(lambda: self.action_requested.emit("configure", self.plugin_data['name']))
        buttons_layout.addWidget(config_btn)
        
        layout.addLayout(buttons_layout)


class PluginInstallDialog(QDialog):
    """Dialog for installing new plugins."""
        def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Install Plugin")
        self.setModal(True)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Installation methods
        methods_group = QGroupBox("Installation Method")
        methods_layout = QVBoxLayout(methods_group)
        
        self.file_radio = QCheckBox("Install from file")
        self.file_radio.setChecked(True)
        methods_layout.addWidget(self.file_radio)
        
        self.url_radio = QCheckBox("Install from URL")
        methods_layout.addWidget(self.url_radio)
        
        layout.addWidget(methods_group)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select plugin file...")
        file_layout.addWidget(self.file_path)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        
        layout.addLayout(file_layout)
        
        # URL input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter plugin URL...")
        self.url_input.setEnabled(False)
        layout.addWidget(self.url_input)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # Connect radio buttons
        self.file_radio.toggled.connect(self.toggle_method)
        self.url_radio.toggled.connect(self.toggle_method)
    
    def toggle_method(self):
        """Toggle between installation methods.
        file_method = self.file_radio.isChecked()
        self.file_path.setEnabled(file_method)
        self.url_input.setEnabled(not file_method)
    
    def browse_file(self):
        """Browse for plugin file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Plugin File", "", "Plugin Files (*.zip *.tar.gz);;All Files (*)"
        )
        if file_path:
            self.file_path.setText(file_path)


class PluginManagerPyQt(QDialog):
    """
    Advanced plugin management interface.
    Features:
    - Plugin installation and removal
    - Plugin configuration
    - Plugin marketplace integration
    - Plugin development tools
    - Plugin security scanning
    """
        # Signals
    plugin_action = pyqtSignal(str, str)  # action, plugin_name

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.plugins_data = []

        # Make window movable and resizable
        self.setWindowTitle("Plugin Manager")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint |
                        Qt.WindowType.WindowMinMaxButtonsHint)
        self.setModal(False)  # Allow interaction with other windows
        self.resize(900, 700)

        self.setup_ui()
        self.load_plugins()

        logger.info("Plugin manager initialized")
    
    def setup_ui(self):
        """Setup the plugin manager UI."""
        self.setWindowTitle("Plugin Manager")
        self.setGeometry(200, 200, 1000, 700)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        self.create_header(main_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Installed plugins tab
        installed_tab = self.create_installed_tab()
        self.tab_widget.addTab(installed_tab, "[PACKAGE] Installed")
        
        # Marketplace tab
        marketplace_tab = self.create_marketplace_tab()
        self.tab_widget.addTab(marketplace_tab, "? Marketplace")
        
        # Development tab
        dev_tab = self.create_development_tab()
        self.tab_widget.addTab(dev_tab, "[SETUP] Development")
        
        main_layout.addWidget(self.tab_widget)
    
    def create_header(self, layout):
        """Create header with search and actions."""
        header_layout = QHBoxLayout()
        
        # Title
        title = QLabel("Plugin Manager")
        title.setFont(QFont("Inter", 18, QFont.Weight.Bold))
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search plugins...")
        self.search_input.textChanged.connect(self.filter_plugins)
        header_layout.addWidget(self.search_input)
        
        # Install button
        install_btn = QPushButton("[DOWNLOAD] Install Plugin")
        install_btn.clicked.connect(self.show_install_dialog)
        header_layout.addWidget(install_btn)
        
        # Refresh button
        refresh_btn = QPushButton("[UPDATE] Refresh")
        refresh_btn.clicked.connect(self.refresh_plugins)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
    
    def create_installed_tab(self) -> QWidget:
        """Create installed plugins tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Filter options
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Active", "Inactive"])
        self.status_filter.currentTextChanged.connect(self.filter_plugins)
        filter_layout.addWidget(self.status_filter)
        
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Plugins scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.plugins_container = QWidget()
        self.plugins_layout = QGridLayout(self.plugins_container)
        self.plugins_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        scroll_area.setWidget(self.plugins_container)
        layout.addWidget(scroll_area)
        
        return tab
    
    def create_marketplace_tab(self) -> QWidget:
        """Create marketplace tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Marketplace info
        info_label = QLabel("? Plugin Marketplace")
        info_label.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(info_label)
        
        desc_label = QLabel("Discover and install new plugins from the community.")
        layout.addWidget(desc_label)
        
        # Categories
        categories_layout = QHBoxLayout()
        categories = ["All", "Chat", "Utilities", "Security", "Analytics", "Fun"]
        
        for category in categories:
            btn = QPushButton(category)
            btn.setCheckable(True)
            if category == "All":
                btn.setChecked(True)
            categories_layout.addWidget(btn)
        
        categories_layout.addStretch()
        layout.addLayout(categories_layout)
        
        # Marketplace plugins (placeholder)
        marketplace_label = QLabel("Marketplace integration coming soon...")
        marketplace_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        marketplace_label.setStyleSheet("color: #666666; font-style: italic;")
        layout.addWidget(marketplace_label)
        
        layout.addStretch()
        
        return tab
    
    def create_development_tab(self) -> QWidget:
        """Create development tools tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Development tools
        dev_group = QGroupBox("Plugin Development Tools")
        dev_layout = QVBoxLayout(dev_group)
        
        # Create new plugin
        create_btn = QPushButton("[NEW] Create New Plugin")
        create_btn.clicked.connect(self.create_new_plugin)
        dev_layout.addWidget(create_btn)
        
        # Plugin template
        template_btn = QPushButton("[LIST] Generate Template")
        template_btn.clicked.connect(self.generate_template)
        dev_layout.addWidget(template_btn)
        
        # Test plugin
        test_btn = QPushButton("[TEST] Test Plugin")
        test_btn.clicked.connect(self.test_plugin)
        dev_layout.addWidget(test_btn)
        
        # Package plugin
        package_btn = QPushButton("[PACKAGE] Package Plugin")
        package_btn.clicked.connect(self.package_plugin)
        dev_layout.addWidget(package_btn)
        
        layout.addWidget(dev_group)
        
        # Documentation
        docs_group = QGroupBox("Documentation")
        docs_layout = QVBoxLayout(docs_group)
        
        docs_text = QTextEdit()
        docs_text.setReadOnly(True)
        docs_text.setMaximumHeight(200)
        docs_text.setText("""
Plugin Development Guide:

1. Create a new plugin using the template generator
2. Implement your plugin logic in the main class
3. Test your plugin using the test tools
4. Package your plugin for distribution

For detailed documentation, visit: localhost/docs/plugins
        )
        docs_layout.addWidget(docs_text)
        
        layout.addWidget(docs_group)
        layout.addStretch()
        
        return tab
    
    def load_plugins(self):
        """Load plugin data."""
        # Sample plugin data
        self.plugins_data = [
            {
                "name": "TestPlugin",
                "version": "1.0.0",
                "description": "A simple test plugin for demonstration purposes.",
                "status": "active",
                "author": "PlexiChat Team"
            },
            {
                "name": "ChatBot",
                "version": "2.1.0", 
                "description": "AI-powered chatbot integration with multiple providers.",
                "status": "active",
                "author": "AI Team"
            },
            {
                "name": "FileManager",
                "version": "1.5.0",
                "description": "Advanced file management and sharing capabilities.",
                "status": "inactive",
                "author": "Utils Team"
            },
            {
                "name": "Analytics",
                "version": "3.0.0",
                "description": "Comprehensive analytics and reporting dashboard.",
                "status": "active",
                "author": "Data Team"
            },
            {
                "name": "Backup",
                "version": "1.2.0",
                "description": "Automated backup and restore functionality.",
                "status": "inactive",
                "author": "System Team"
            }
        ]
        
        self.display_plugins()
    
    def display_plugins(self):
        """Display plugins in the grid layout.
        # Clear existing widgets
        for i in reversed(range(self.plugins_layout.count())):
            self.plugins_layout.itemAt(i).widget().setParent(None)
        
        # Add plugin cards
        row, col = 0, 0
        for plugin_data in self.plugins_data:
            if self.should_show_plugin(plugin_data):
                card = PluginCard(plugin_data)
                card.action_requested.connect(self.handle_plugin_action)
                self.plugins_layout.addWidget(card, row, col)
                
                col += 1
                if col >= 3:  # 3 cards per row
                    col = 0
                    row += 1
    
    def should_show_plugin(self, plugin_data: Dict[str, Any]) -> bool:
        """Check if plugin should be shown based on filters."""
        # Status filter
        status_filter = self.status_filter.currentText().lower()
        if status_filter != "all" and plugin_data.get("status") != status_filter:
            return False
        
        # Search filter
        search_text = self.search_input.text().lower()
        if search_text:
            name = plugin_data.get("name", "").lower()
            desc = plugin_data.get("description", "").lower()
            if search_text not in name and search_text not in desc:
                return False
        
        return True
    
    def filter_plugins(self):
        """Filter plugins based on search and status.
        self.display_plugins()
    
    def handle_plugin_action(self, action: str, plugin_name: str):
        """Handle plugin actions."""
        self.plugin_action.emit(action, plugin_name)
        
        if action in ["enable", "disable"]:
            # Update plugin status
            for plugin in self.plugins_data:
                if plugin["name"] == plugin_name:
                    plugin["status"] = "active" if action == "enable" else "inactive"
                    break
            self.display_plugins()
        elif action == "configure":
            self.configure_plugin(plugin_name)
    
    def configure_plugin(self, plugin_name: str):
        """Open plugin configuration dialog."""
        try:
            # Find plugin data
            plugin_data = None
            for plugin in self.plugins_data:
                if plugin["name"] == plugin_name:
                    plugin_data = plugin
                    break

            if not plugin_data:
                QMessageBox.warning(self, "Plugin Not Found",
                                f"Plugin '{plugin_name}' not found.")
                return

            # Create configuration dialog
            config_dialog = PluginConfigDialog(plugin_data, self)
            config_dialog.exec()

        except Exception as e:
            logger.error(f"Failed to open plugin configuration: {e}")
            QMessageBox.critical(self, "Configuration Error",
                            f"Failed to open configuration for {plugin_name}:\n{str(e)}")
    
    def show_install_dialog(self):
        """Show plugin installation dialog."""
        dialog = PluginInstallDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Handle plugin installation
            QMessageBox.information(self, "Plugin Installation",
                                "Plugin installation would be processed here.")
    
    def refresh_plugins(self):
        """Refresh plugin list.
        self.load_plugins()
    
    def create_new_plugin(self):
        """Create new plugin."""
        QMessageBox.information(self, "Create Plugin",
                            "Plugin creation wizard would open here.")
    
    def generate_template(self):
        """Generate plugin template."""
        QMessageBox.information(self, "Generate Template",
                            "Plugin template generator would run here.")
    
    def test_plugin(self):
        """Test plugin."""
        QMessageBox.information(self, "Test Plugin",
                            "Plugin testing interface would open here.")
    
    def package_plugin(self):
        """Package plugin for distribution."""
        QMessageBox.information(self, "Package Plugin",
                            "Plugin packaging tool would run here.")


class PluginConfigDialog(QDialog):
    """Plugin configuration dialog with dynamic form generation."""
        def __init__(self, plugin_data: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.plugin_data = plugin_data
        self.config_widgets = {}

        self.setWindowTitle(f"Configure {plugin_data.get('name', 'Plugin')}")
        self.setModal(True)
        self.resize(600, 500)

        self.setup_ui()
        self.load_current_config()

    def setup_ui(self):
        """Setup the configuration dialog UI."""
        layout = QVBoxLayout(self)

        # Header
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)

        title_label = QLabel(f"Configure {self.plugin_data.get('name', 'Plugin')}")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4A90E2;")
        header_layout.addWidget(title_label)

        version_label = QLabel(f"v{self.plugin_data.get('version', '1.0.0')}")
        version_label.setStyleSheet("color: #666; font-size: 12px;")
        header_layout.addWidget(version_label)
        header_layout.addStretch()

        layout.addWidget(header_frame)

        # Scroll area for configuration options
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        self.config_layout = QFormLayout(scroll_widget)

        # Generate configuration form
        self.generate_config_form()

        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)

        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel |
            QDialogButtonBox.StandardButton.RestoreDefaults
        )
        button_box.accepted.connect(self.save_config)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(self.restore_defaults)

        layout.addWidget(button_box)

    def generate_config_form(self):
        """Generate configuration form based on plugin schema."""
        try:
            # Get plugin configuration schema
            config_schema = self.plugin_data.get('config_schema', {})
            if not config_schema:
                # Create basic configuration options
                self.add_basic_config_options()
                return

            # Generate form from schema
            properties = config_schema.get('properties', {})
            for key, schema in properties.items():
                self.add_config_field(key, schema)

        except Exception as e:
            logger.error(f"Failed to generate config form: {e}")
            self.add_basic_config_options()

    def add_basic_config_options(self):
        """Add basic configuration options when no schema is available."""
        # Enabled checkbox
        enabled_checkbox = QCheckBox()
        enabled_checkbox.setChecked(self.plugin_data.get('enabled', True))
        self.config_widgets['enabled'] = enabled_checkbox
        self.config_layout.addRow("Enabled:", enabled_checkbox)

        # Auto-start checkbox
        auto_start_checkbox = QCheckBox()
        auto_start_checkbox.setChecked(self.plugin_data.get('auto_start', True))
        self.config_widgets['auto_start'] = auto_start_checkbox
        self.config_layout.addRow("Auto Start:", auto_start_checkbox)

        # Priority spinner
        priority_spinner = QSpinBox()
        priority_spinner.setRange(1, 10)
        priority_spinner.setValue(self.plugin_data.get('priority', 5))
        self.config_widgets['priority'] = priority_spinner
        self.config_layout.addRow("Priority:", priority_spinner)

        # Description (read-only)
        description_text = QTextEdit()
        description_text.setPlainText(self.plugin_data.get('description', 'No description available'))
        description_text.setMaximumHeight(80)
        description_text.setReadOnly(True)
        self.config_layout.addRow("Description:", description_text)

    def add_config_field(self, key: str, schema: Dict[str, Any]):
        """Add a configuration field based on schema."""
        field_type = schema.get('type', 'string')
        title = schema.get('title', key.replace('_', ' ').title())
        description = schema.get('description', '')
        default_value = schema.get('default')

        if field_type == 'boolean':
            widget = QCheckBox()
            if default_value is not None:
                widget.setChecked(default_value)
        elif field_type == 'integer':
            widget = QSpinBox()
            widget.setRange(schema.get('minimum', -999999), schema.get('maximum', 999999))
            if default_value is not None:
                widget.setValue(default_value)
        elif field_type == 'number':
            widget = QSpinBox()  # Could use QDoubleSpinBox for floats
            widget.setRange(int(schema.get('minimum', -999999)), int(schema.get('maximum', 999999)))
            if default_value is not None:
                widget.setValue(int(default_value))
        elif field_type == 'string':
            if 'enum' in schema:
                widget = QComboBox()
                widget.addItems(schema['enum'])
                if default_value and default_value in schema['enum']:
                    widget.setCurrentText(default_value)
            else:
                widget = QLineEdit()
                if default_value is not None:
                    widget.setText(str(default_value))
        else:
            # Default to text input
            widget = QLineEdit()
            if default_value is not None:
                widget.setText(str(default_value))

        # Add tooltip if description exists
        if description:
            widget.setToolTip(description)

        self.config_widgets[key] = widget
        self.config_layout.addRow(f"{title}:", widget)

    def load_current_config(self):
        """Load current plugin configuration."""
        try:
            current_config = self.plugin_data.get('config', {})
            for key, widget in self.config_widgets.items():
                if key in current_config:
                    value = current_config[key]
                    if isinstance(widget, QCheckBox):
                        widget.setChecked(bool(value))
                    elif isinstance(widget, QSpinBox):
                        widget.setValue(int(value))
                    elif isinstance(widget, QLineEdit):
                        widget.setText(str(value))
                    elif isinstance(widget, QComboBox):
                        widget.setCurrentText(str(value))
        except Exception as e:
            logger.error(f"Failed to load current config: {e}")

    def save_config(self):
        """Save plugin configuration."""
        try:
            new_config = {}
            for key, widget in self.config_widgets.items():
                if isinstance(widget, QCheckBox):
                    new_config[key] = widget.isChecked()
                elif isinstance(widget, QSpinBox):
                    new_config[key] = widget.value()
                elif isinstance(widget, QLineEdit):
                    new_config[key] = widget.text()
                elif isinstance(widget, QComboBox):
                    new_config[key] = widget.currentText()

            # Update plugin data
            self.plugin_data['config'] = new_config

            # Here you would typically save to file or send to plugin manager
            logger.info(f"Saved configuration for {self.plugin_data.get('name')}: {new_config}")

            QMessageBox.information(self, "Configuration Saved",
                                f"Configuration for {self.plugin_data.get('name')} has been saved.")

            self.accept()

        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            QMessageBox.critical(self, "Save Error", f"Failed to save configuration:\n{str(e)}")

    def restore_defaults(self):
        """Restore default configuration values."""
        try:
            # Reset all widgets to their default values
            config_schema = self.plugin_data.get('config_schema', {})
            properties = config_schema.get('properties', {})

            for key, widget in self.config_widgets.items():
                if key in properties:
                    default_value = properties[key].get('default')
                    if default_value is not None:
                        if isinstance(widget, QCheckBox):
                            widget.setChecked(bool(default_value))
                        elif isinstance(widget, QSpinBox):
                            widget.setValue(int(default_value))
                        elif isinstance(widget, QLineEdit):
                            widget.setText(str(default_value))
                        elif isinstance(widget, QComboBox):
                            widget.setCurrentText(str(default_value))
                else:
                    # Basic defaults
                    if key == 'enabled':
                        widget.setChecked(True)
                    elif key == 'auto_start':
                        widget.setChecked(True)
                    elif key == 'priority':
                        widget.setValue(5)

            QMessageBox.information(self, "Defaults Restored",
                                "Configuration has been reset to default values.")

        except Exception as e:
            logger.error(f"Failed to restore defaults: {e}")
            QMessageBox.critical(self, "Restore Error", f"Failed to restore defaults:\n{str(e)}")
