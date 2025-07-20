"""
Menu System Component for PlexiChat GUI
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class MenuSystem:
    """Advanced menu system with CLI integration."""

    def __init__(self, root, app_instance):
        self.root = root
        self.app = app_instance
        self.create_menu()

    def create_menu(self):
        """Create the main menu bar."""
        try:
            # Create menu bar
            self.menubar = tk.Menu(self.root)
            self.root.config(menu=self.menubar)

            # File menu
            self.file_menu = tk.Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="File", menu=self.file_menu)
            self.file_menu.add_command(label="New Chat", command=self.new_chat)
            self.file_menu.add_command(label="Open Settings", command=self.open_settings)
            self.file_menu.add_separator()
            self.file_menu.add_command(label="Exit", command=self.exit_app)

            # Tools menu
            self.tools_menu = tk.Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="Tools", menu=self.tools_menu)
            self.tools_menu.add_command(label="CLI Terminal", command=self.open_cli_terminal)
            self.tools_menu.add_command(label="Plugin Manager", command=self.open_plugin_manager)
            self.tools_menu.add_command(label="System Monitor", command=self.open_system_monitor)
            self.tools_menu.add_separator()
            self.tools_menu.add_command(label="Run Tests", command=self.run_tests)
            self.tools_menu.add_command(label="System Cleanup", command=self.run_cleanup)

            # Admin menu
            self.admin_menu = tk.Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="Admin", menu=self.admin_menu)
            self.admin_menu.add_command(label="User Management", command=self.open_user_management)
            self.admin_menu.add_command(label="Server Status", command=self.show_server_status)
            self.admin_menu.add_command(label="Database Tools", command=self.open_database_tools)

            # Help menu
            self.help_menu = tk.Menu(self.menubar, tearoff=0)
            self.menubar.add_cascade(label="Help", menu=self.help_menu)
            self.help_menu.add_command(label="Documentation", command=self.open_docs)
            self.help_menu.add_command(label="About", command=self.show_about)

            logger.info("Menu system created successfully")

        except Exception as e:
            logger.error(f"Failed to create menu: {e}")

    def new_chat(self):
        """Start a new chat."""
        try:
            # Implement new chat functionality
            logger.info("Starting new chat")
        except Exception as e:
            logger.error(f"Failed to start new chat: {e}")

    def open_settings(self):
        """Open settings panel."""
        try:
            if hasattr(self.app, 'settings_panel'):
                self.app.settings_panel.show()
        except Exception as e:
            logger.error(f"Failed to open settings: {e}")

    def open_cli_terminal(self):
        """Open CLI terminal."""
        try:
            if hasattr(self.app, 'open_cli_terminal'):
                self.app.open_cli_terminal()
            else:
                logger.warning("CLI terminal not available")
        except Exception as e:
            logger.error(f"Failed to open CLI terminal: {e}")

    def open_plugin_manager(self):
        """Open plugin manager."""
        try:
            if hasattr(self.app, 'plugin_manager'):
                self.app.plugin_manager.show()
        except Exception as e:
            logger.error(f"Failed to open plugin manager: {e}")

    def open_system_monitor(self):
        """Open system monitor."""
        try:
            # Implement system monitor
            logger.info("Opening system monitor")
        except Exception as e:
            logger.error(f"Failed to open system monitor: {e}")

    def run_tests(self):
        """Run system tests via CLI."""
        try:
            if hasattr(self.app, 'run_gui_command'):
                self.app.run_gui_command('test')
        except Exception as e:
            logger.error(f"Failed to run tests: {e}")

    def run_cleanup(self):
        """Run system cleanup via CLI."""
        try:
            if hasattr(self.app, 'run_gui_command'):
                self.app.run_gui_command('clean')
        except Exception as e:
            logger.error(f"Failed to run cleanup: {e}")

    def open_user_management(self):
        """Open user management."""
        try:
            if hasattr(self.app, 'run_gui_command'):
                self.app.run_gui_command('admin users')
        except Exception as e:
            logger.error(f"Failed to open user management: {e}")

    def show_server_status(self):
        """Show server status."""
        try:
            if hasattr(self.app, 'run_gui_command'):
                self.app.run_gui_command('status')
        except Exception as e:
            logger.error(f"Failed to show server status: {e}")

    def open_database_tools(self):
        """Open database tools."""
        try:
            if hasattr(self.app, 'run_gui_command'):
                self.app.run_gui_command('admin database')
        except Exception as e:
            logger.error(f"Failed to open database tools: {e}")

    def open_docs(self):
        """Open documentation."""
        try:
            import webbrowser
            webbrowser.open("http://localhost:8000/docs")
        except Exception as e:
            logger.error(f"Failed to open docs: {e}")

    def show_about(self):
        """Show about dialog."""
        try:
            from tkinter import messagebox
            messagebox.showinfo("About PlexiChat",
                              "PlexiChat - Advanced AI-Powered Chat Platform\n"
                              "Version: 1.0.0\n"
                              "Built with Python and Tkinter")
        except Exception as e:
            logger.error(f"Failed to show about: {e}")

    def exit_app(self):
        """Exit the application."""
        try:
            self.root.quit()
        except Exception as e:
            logger.error(f"Failed to exit app: {e}")
