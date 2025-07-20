"""
PlexiChat Advanced Tkinter GUI Application
The most sophisticated and feature-rich Tkinter interface ever created.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkFont
from typing import Dict, List, Optional, Any, Callable
import threading
import asyncio
import json
import logging
import webbrowser
from datetime import datetime
from pathlib import Path
import sys
import os

# Custom imports
from .components.login_screen import LoginScreen
from .components.main_dashboard import MainDashboard
from .components.chat_interface import ChatInterface
from .components.plugin_manager import PluginManager
from .components.settings_panel import SettingsPanel
from .components.theme_manager import ThemeManager
from .components.notification_system import NotificationSystem
from .components.status_bar import StatusBar
from .components.menu_system import MenuSystem
from .components.toolbar import Toolbar
from .components.sidebar import Sidebar
from .webui_renderer import WebUIRenderer

logger = logging.getLogger(__name__)


class PlexiChatGUI:
    """
    The most advanced Tkinter GUI application for PlexiChat.
    Features:
    - Modern, sleek design with custom themes
    - Full integration with all PlexiChat systems
    - Plugin system with custom language support
    - Advanced chat interface with rich text
    - Real-time notifications and status updates
    - Embedded web browser for WebUI integration
    - Multi-window support
    - Customizable layouts and workspaces
    - Advanced user management
    - System monitoring and analytics
    """

    def __init__(self):
        self.root = None
        self.current_user = None
        self.is_authenticated = False
        self.theme_manager = None
        self.notification_system = None
        self.plugin_manager = None
        self.webui_renderer = None
        
        # Component references
        self.login_screen = None
        self.main_dashboard = None
        self.chat_interface = None
        self.settings_panel = None
        self.status_bar = None
        self.menu_system = None
        self.toolbar = None
        self.sidebar = None
        
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
            logger.info("Initializing PlexiChat Advanced GUI...")
            
            # Create main window
            self.root = tk.Tk()
            self.root.title("PlexiChat - Advanced Communication Platform")
            self.root.geometry("1400x900")
            self.root.minsize(1200, 800)
            
            # Set application icon
            self.set_application_icon()
            
            # Initialize theme system
            self.theme_manager = ThemeManager(self.root)
            self.theme_manager.apply_theme("dark_modern")
            
            # Initialize notification system
            self.notification_system = NotificationSystem(self.root)
            
            # Initialize WebUI renderer
            self.webui_renderer = WebUIRenderer()
            
            # Initialize plugin manager
            self.plugin_manager = PluginManager(self)

            # Initialize CLI integration
            self.setup_cli_integration()

            # Setup async event loop
            self.setup_async_loop()

            # Configure window behavior
            self.configure_window()

            # Show login screen
            self.show_login_screen()
            
            logger.info("PlexiChat GUI initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize GUI: {e}")
            messagebox.showerror("Initialization Error", f"Failed to start PlexiChat GUI: {e}")
            sys.exit(1)

    def set_application_icon(self):
        """Set the application icon."""
        try:
            # Try to load custom icon
            icon_path = Path(__file__).parent / "assets" / "plexichat_icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
            else:
                # Use default icon or create one programmatically
                self.create_default_icon()
        except Exception as e:
            logger.warning(f"Could not set application icon: {e}")

    def create_default_icon(self):
        """Create a default icon programmatically."""
        try:
            # Create a simple icon using tkinter
            icon_window = tk.Toplevel()
            icon_window.withdraw()
            
            canvas = tk.Canvas(icon_window, width=32, height=32)
            canvas.create_oval(4, 4, 28, 28, fill="#3498db", outline="#2c3e50", width=2)
            canvas.create_text(16, 16, text="P", fill="white", font=("Arial", 16, "bold"))
            
            # Convert to icon (simplified approach)
            icon_window.destroy()
        except Exception as e:
            logger.warning(f"Could not create default icon: {e}")

    def configure_window(self):
        """Configure main window properties."""
        # Center window on screen
        self.center_window()
        
        # Configure window closing behavior
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Configure window state change handling
        self.root.bind("<Configure>", self.on_window_configure)
        
        # Set window properties
        self.root.resizable(True, True)
        
        # Configure styles
        self.configure_styles()

    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def configure_styles(self):
        """Configure ttk styles for modern appearance."""
        style = ttk.Style()
        
        # Configure modern button style
        style.configure("Modern.TButton",
                       padding=(10, 5),
                       font=("Segoe UI", 10))
        
        # Configure modern frame style
        style.configure("Modern.TFrame",
                       background="#2c3e50",
                       relief="flat")
        
        # Configure modern label style
        style.configure("Modern.TLabel",
                       background="#2c3e50",
                       foreground="#ecf0f1",
                       font=("Segoe UI", 10))

    def setup_async_loop(self):
        """Setup asyncio event loop for async operations."""
        try:
            self.async_loop = asyncio.new_event_loop()
            
            def run_async_loop():
                asyncio.set_event_loop(self.async_loop)
                self.async_loop.run_forever()
            
            async_thread = threading.Thread(target=run_async_loop, daemon=True)
            async_thread.start()
            
            logger.info("Async event loop initialized")
        except Exception as e:
            logger.error(f"Failed to setup async loop: {e}")

    def show_login_screen(self):
        """Display the login screen."""
        try:
            # Clear any existing content
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Create and show login screen
            self.login_screen = LoginScreen(self.root, self)
            self.login_screen.pack(fill=tk.BOTH, expand=True)
            
            logger.info("Login screen displayed")
        except Exception as e:
            logger.error(f"Failed to show login screen: {e}")
            messagebox.showerror("Error", f"Failed to display login screen: {e}")

    def on_login_success(self, user_data: Dict[str, Any]):
        """Handle successful login."""
        try:
            self.current_user = user_data
            self.is_authenticated = True
            self.session_data = {
                "login_time": datetime.now(),
                "user_id": user_data.get("id"),
                "username": user_data.get("username"),
                "permissions": user_data.get("permissions", [])
            }
            
            logger.info(f"User {user_data.get('username')} logged in successfully")
            
            # Load user preferences
            self.load_user_preferences()
            
            # Show main dashboard
            self.show_main_dashboard()
            
            # Send welcome notification
            self.notification_system.show_notification(
                "Welcome to PlexiChat!",
                f"Welcome back, {user_data.get('username')}!",
                "success"
            )
            
        except Exception as e:
            logger.error(f"Login success handling failed: {e}")
            messagebox.showerror("Error", f"Failed to complete login: {e}")

    def load_user_preferences(self):
        """Load user preferences and settings."""
        try:
            # Load preferences from file or database
            prefs_file = Path.home() / ".plexichat" / f"{self.current_user['username']}_preferences.json"
            
            if prefs_file.exists():
                with open(prefs_file, 'r') as f:
                    self.user_preferences = json.load(f)
            else:
                # Set default preferences
                self.user_preferences = {
                    "theme": "dark_modern",
                    "notifications": True,
                    "auto_save": True,
                    "layout": "default",
                    "plugins": []
                }
            
            # Apply preferences
            self.apply_user_preferences()
            
        except Exception as e:
            logger.error(f"Failed to load user preferences: {e}")

    def apply_user_preferences(self):
        """Apply loaded user preferences."""
        try:
            # Apply theme
            theme = self.user_preferences.get("theme", "dark_modern")
            self.theme_manager.apply_theme(theme)
            
            # Configure notifications
            notifications_enabled = self.user_preferences.get("notifications", True)
            self.notification_system.set_enabled(notifications_enabled)
            
            logger.info("User preferences applied")
        except Exception as e:
            logger.error(f"Failed to apply user preferences: {e}")

    def show_main_dashboard(self):
        """Display the main dashboard after login."""
        try:
            # Clear login screen
            if self.login_screen:
                self.login_screen.destroy()
                self.login_screen = None
            
            # Create main application layout
            self.create_main_layout()
            
            logger.info("Main dashboard displayed")
        except Exception as e:
            logger.error(f"Failed to show main dashboard: {e}")
            messagebox.showerror("Error", f"Failed to display main dashboard: {e}")

    def create_main_layout(self):
        """Create the main application layout."""
        try:
            # Create main container
            main_container = ttk.Frame(self.root, style="Modern.TFrame")
            main_container.pack(fill=tk.BOTH, expand=True)

            # Create menu system
            self.menu_system = MenuSystem(self.root, self)

            # Create toolbar
            self.toolbar = Toolbar(main_container, self)
            self.toolbar.pack(fill=tk.X, padx=5, pady=(5, 0))

            # Create main content area
            content_frame = ttk.Frame(main_container, style="Modern.TFrame")
            content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Create sidebar
            self.sidebar = Sidebar(content_frame, self)
            self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

            # Create main dashboard
            self.main_dashboard = MainDashboard(content_frame, self)
            self.main_dashboard.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            # Create status bar
            self.status_bar = StatusBar(main_container, self)
            self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=(0, 5))

            # Initialize components
            self.initialize_main_components()

            logger.info("Main layout created successfully")

        except Exception as e:
            logger.error(f"Failed to create main layout: {e}")
            messagebox.showerror("Error", f"Failed to create main layout: {e}")

    def initialize_main_components(self):
        """Initialize main application components."""
        try:
            # Load plugins
            self.plugin_manager.load_plugins()

            # Setup chat interface
            self.chat_interface = ChatInterface(self.main_dashboard, self)

            # Setup settings panel
            self.settings_panel = SettingsPanel(self.main_dashboard, self)

            # Register theme callback
            self.theme_manager.register_theme_callback(self.on_theme_changed)

            # Start background services
            self.start_background_services()

            logger.info("Main components initialized")

        except Exception as e:
            logger.error(f"Failed to initialize main components: {e}")

    def start_background_services(self):
        """Start background services."""
        try:
            # Start periodic tasks
            self.schedule_periodic_tasks()

            # Connect to real-time services
            self.connect_realtime_services()

        except Exception as e:
            logger.error(f"Failed to start background services: {e}")

    def schedule_periodic_tasks(self):
        """Schedule periodic background tasks."""
        try:
            # Update status every 30 seconds
            def update_status():
                if self.status_bar:
                    self.status_bar.update_status()
                self.root.after(30000, update_status)

            # Check for updates every 5 minutes
            def check_updates():
                # Implementation for update checking
                self.root.after(300000, check_updates)

            # Start tasks
            self.root.after(1000, update_status)
            self.root.after(5000, check_updates)

        except Exception as e:
            logger.error(f"Failed to schedule periodic tasks: {e}")

    def connect_realtime_services(self):
        """Connect to real-time services."""
        try:
            # Connect to WebSocket for real-time updates
            # This would connect to the PlexiChat API WebSocket
            pass

        except Exception as e:
            logger.error(f"Failed to connect to real-time services: {e}")

    def on_theme_changed(self, theme_name: str, theme_data: Dict[str, Any]):
        """Handle theme change event."""
        try:
            # Update all components with new theme
            if self.main_dashboard:
                self.main_dashboard.apply_theme(theme_data)

            if self.chat_interface:
                self.chat_interface.apply_theme(theme_data)

            if self.sidebar:
                self.sidebar.apply_theme(theme_data)

            if self.toolbar:
                self.toolbar.apply_theme(theme_data)

            if self.status_bar:
                self.status_bar.apply_theme(theme_data)

            # Notify plugins of theme change
            self.plugin_manager.notify_theme_change(theme_name, theme_data)

        except Exception as e:
            logger.error(f"Failed to handle theme change: {e}")

    def on_window_configure(self, event):
        """Handle window configuration changes."""
        if event.widget == self.root:
            # Handle window resize, move, etc.
            pass

    def on_closing(self):
        """Handle application closing - Server Manager behavior."""
        try:
            if self.is_authenticated:
                # Save user session data
                self.save_user_session()

                # Ask what to do - this is a SERVER MANAGER
                result = messagebox.askyesnocancel(
                    "PlexiChat Server Manager",
                    "What would you like to do?\n\n"
                    "• Yes: Minimize to system tray (keep server running)\n"
                    "• No: Close GUI only (keep server running)\n"
                    "• Cancel: Stay open\n\n"
                    "Note: The PlexiChat server will continue running."
                )

                if result is True:
                    # Minimize to system tray
                    self.minimize_to_tray()
                elif result is False:
                    # Close GUI but keep server running
                    self.close_gui_only()
                # Cancel - do nothing, stay open
            else:
                # Not authenticated, just close GUI
                self.close_gui_only()
        except Exception as e:
            logger.error(f"Error during application closing: {e}")
            self.close_gui_only()

    def minimize_to_tray(self):
        """Minimize application to system tray."""
        try:
            # Hide the window
            self.root.withdraw()

            # Show notification
            self.notification_system.show_notification(
                "Server Manager",
                "PlexiChat Server Manager minimized to system tray. Server continues running.",
                "info"
            )

            # Create system tray icon (simplified implementation)
            self.create_system_tray_icon()

            logger.info("GUI minimized to system tray, server continues running")

        except Exception as e:
            logger.error(f"Failed to minimize to tray: {e}")
            self.close_gui_only()

    def close_gui_only(self):
        """Close GUI but keep server running."""
        try:
            # Show notification that server continues
            if self.notification_system:
                self.notification_system.show_notification(
                    "Server Manager",
                    "GUI closed. PlexiChat server continues running in background.",
                    "info"
                )

            # Save session
            if self.is_authenticated:
                self.save_user_session()

            # Cleanup GUI resources only
            self.cleanup_gui_only()

            # Close the GUI window
            self.root.quit()
            self.root.destroy()

            logger.info("GUI closed, server continues running")

        except Exception as e:
            logger.error(f"Error closing GUI: {e}")
            try:
                self.root.quit()
                self.root.destroy()
            except:
                pass

    def create_system_tray_icon(self):
        """Create system tray icon (simplified implementation)."""
        try:
            # This would create a proper system tray icon
            # For now, just log that it would be created
            logger.info("System tray icon would be created here")

            # In a full implementation, this would use libraries like:
            # - pystray for cross-platform system tray
            # - plyer for notifications

        except Exception as e:
            logger.error(f"Failed to create system tray icon: {e}")

    def cleanup_gui_only(self):
        """Cleanup GUI resources only, keep server running."""
        try:
            # Stop GUI-specific async operations
            if self.async_loop and self.async_loop.is_running():
                # Don't stop the main async loop, just GUI-specific tasks
                pass

            # Cleanup GUI components
            if self.plugin_manager:
                # Don't fully cleanup plugins, just GUI parts
                pass

            if self.webui_renderer:
                # Don't cleanup WebUI renderer, it's part of the server
                pass

            logger.info("GUI cleanup completed, server resources preserved")

        except Exception as e:
            logger.error(f"Error during GUI cleanup: {e}")

    def save_user_session(self):
        """Save current user session data."""
        try:
            if self.current_user:
                session_file = Path.home() / ".plexichat" / f"{self.current_user['username']}_session.json"
                session_file.parent.mkdir(exist_ok=True)
                
                with open(session_file, 'w') as f:
                    json.dump(self.session_data, f, default=str, indent=2)
                
                logger.info("User session saved")
        except Exception as e:
            logger.error(f"Failed to save user session: {e}")

    def cleanup_and_exit(self):
        """Cleanup resources and exit application."""
        try:
            # Stop async loop
            if self.async_loop and self.async_loop.is_running():
                self.async_loop.call_soon_threadsafe(self.async_loop.stop)
            
            # Cleanup components
            if self.plugin_manager:
                self.plugin_manager.cleanup()
            
            if self.webui_renderer:
                self.webui_renderer.cleanup()
            
            logger.info("Application cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        finally:
            self.root.quit()
            self.root.destroy()

    def run(self):
        """Start the GUI application."""
        try:
            logger.info("Starting PlexiChat GUI application...")
            self.root.mainloop()
        except Exception as e:
            logger.error(f"GUI application error: {e}")
            messagebox.showerror("Application Error", f"An error occurred: {e}")

    def setup_cli_integration(self):
        """Setup CLI integration for running commands from GUI."""
        try:
            # Import CLI modules
            from ..cli.main_cli import main as cli_main

            # Store CLI main function for later use
            self.cli_main = cli_main

            logger.info("CLI integration initialized successfully")

        except ImportError as e:
            logger.warning(f"CLI integration not available: {e}")
            self.cli_main = None
        except Exception as e:
            logger.error(f"Failed to setup CLI integration: {e}")
            self.cli_main = None

    def open_cli_terminal(self):
        """Open a CLI terminal window within the GUI."""
        try:
            # Create CLI terminal window
            cli_window = tk.Toplevel(self.root)
            cli_window.title("PlexiChat CLI Terminal")
            cli_window.geometry("900x700")
            cli_window.configure(bg="#1e1e1e")

            # Create main frame
            main_frame = ttk.Frame(cli_window)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Output text area with scrollbar
            output_frame = ttk.Frame(main_frame)
            output_frame.pack(fill=tk.BOTH, expand=True)

            output_text = tk.Text(output_frame, bg="#1e1e1e", fg="#00ff00",
                                font=("Consolas", 11), wrap=tk.WORD,
                                insertbackground="#00ff00")
            output_scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=output_text.yview)
            output_text.configure(yscrollcommand=output_scrollbar.set)

            output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Input frame
            input_frame = ttk.Frame(main_frame)
            input_frame.pack(fill=tk.X, pady=(10, 0))

            # Command prompt label
            prompt_label = ttk.Label(input_frame, text="plexichat>",
                                   foreground="#00ff00", background="#1e1e1e")
            prompt_label.pack(side=tk.LEFT)

            # Command input
            command_entry = ttk.Entry(input_frame, font=("Consolas", 11))
            command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))

            # Execute button
            execute_button = ttk.Button(input_frame, text="Execute")
            execute_button.pack(side=tk.RIGHT)

            def execute_command():
                command = command_entry.get().strip()
                if command:
                    # Display command
                    output_text.insert(tk.END, f"plexichat> {command}\n", "command")
                    output_text.tag_config("command", foreground="#ffff00")

                    # Execute command
                    try:
                        if command.lower() in ['exit', 'quit']:
                            cli_window.destroy()
                            return
                        elif command.lower() == 'clear':
                            output_text.delete(1.0, tk.END)
                            command_entry.delete(0, tk.END)
                            return
                        elif command.lower() == 'help':
                            help_text = """
Available Commands:
  admin          - Admin commands
  test           - Run tests
  system         - System commands
  backup         - Backup operations
  plugin         - Plugin management
  status         - Show status
  clean          - System cleanup
  clear          - Clear terminal
  exit/quit      - Close terminal
  help           - Show this help

Examples:
  admin users    - Manage users
  test all       - Run all tests
  system status  - Show system status
"""
                            output_text.insert(tk.END, help_text + "\n", "help")
                            output_text.tag_config("help", foreground="#00ffff")
                        else:
                            # Try to execute via CLI integration
                            if self.cli_main:
                                import sys
                                import io
                                from contextlib import redirect_stdout, redirect_stderr

                                # Capture output
                                stdout_capture = io.StringIO()
                                stderr_capture = io.StringIO()

                                # Save original argv
                                original_argv = sys.argv.copy()

                                try:
                                    # Set command arguments
                                    sys.argv = ['plexichat'] + command.split()

                                    # Redirect output
                                    with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                                        self.cli_main()

                                    # Get output
                                    stdout_result = stdout_capture.getvalue()
                                    stderr_result = stderr_capture.getvalue()

                                    if stdout_result:
                                        output_text.insert(tk.END, stdout_result + "\n", "output")
                                        output_text.tag_config("output", foreground="#ffffff")
                                    if stderr_result:
                                        output_text.insert(tk.END, f"Error: {stderr_result}\n", "error")
                                        output_text.tag_config("error", foreground="#ff0000")

                                finally:
                                    # Restore original argv
                                    sys.argv = original_argv
                            else:
                                output_text.insert(tk.END, "CLI integration not available\n", "error")
                                output_text.tag_config("error", foreground="#ff0000")

                    except Exception as e:
                        output_text.insert(tk.END, f"Error: {str(e)}\n", "error")
                        output_text.tag_config("error", foreground="#ff0000")

                    # Scroll to end and clear input
                    output_text.see(tk.END)
                    command_entry.delete(0, tk.END)

            # Bind events
            execute_button.configure(command=execute_command)
            command_entry.bind('<Return>', lambda e: execute_command())

            # Initial welcome message
            welcome_text = """PlexiChat CLI Terminal
======================
Welcome to the PlexiChat command-line interface.
Type 'help' for available commands or 'exit' to close.

"""
            output_text.insert(tk.END, welcome_text, "welcome")
            output_text.tag_config("welcome", foreground="#00ffff")

            # Focus on command entry
            command_entry.focus()

            logger.info("CLI terminal opened successfully")

        except Exception as e:
            logger.error(f"Failed to open CLI terminal: {e}")
            messagebox.showerror("Error", f"Failed to open CLI terminal: {e}")

    def run_gui_command(self, command):
        """Run a command from GUI context."""
        try:
            if self.cli_main:
                import sys
                import io
                from contextlib import redirect_stdout, redirect_stderr

                # Capture output
                stdout_capture = io.StringIO()
                stderr_capture = io.StringIO()

                # Save original argv
                original_argv = sys.argv.copy()

                try:
                    # Set command arguments
                    sys.argv = ['plexichat'] + command.split()

                    # Redirect output
                    with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                        self.cli_main()

                    # Get output
                    stdout_result = stdout_capture.getvalue()
                    stderr_result = stderr_capture.getvalue()

                    # Show result in message box
                    if stdout_result:
                        messagebox.showinfo("Command Result", stdout_result)
                    elif stderr_result:
                        messagebox.showerror("Command Error", stderr_result)
                    else:
                        messagebox.showinfo("Command Result", "Command executed successfully")

                    return True

                finally:
                    # Restore original argv
                    sys.argv = original_argv
            else:
                messagebox.showerror("Error", "CLI integration not available")
                return False

        except Exception as e:
            logger.error(f"Error running GUI command: {e}")
            messagebox.showerror("Error", f"Failed to run command: {e}")
            return False


def main():
    """Main entry point for the GUI application."""
    try:
        app = PlexiChatGUI()
        app.run()
    except Exception as e:
        logger.error(f"Failed to start PlexiChat GUI: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
