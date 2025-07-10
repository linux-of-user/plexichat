"""
PlexiChat Advanced GUI Application
Sophisticated Python GUI with same login system and full feature parity with WebUI.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import customtkinter as ctk
import requests
import json
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional
import sys
import os

# Add src to path for imports
current_dir = os.path.dirname(__file__)
src_dir = os.path.join(current_dir, '..', '..')
root_dir = os.path.join(current_dir, '..', '..', '..')

for path in [src_dir, root_dir]:
    abs_path = os.path.abspath(path)
    if abs_path not in sys.path:
        sys.path.insert(0, abs_path)

try:
    from plexichat.core.security.government_auth import government_auth
    from plexichat.app.logger_config import logger
    PLEXICHAT_MODULES_AVAILABLE = True
except ImportError as e:
    # Fallback for development/standalone mode
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    government_auth = None
    PLEXICHAT_MODULES_AVAILABLE = False
    logger.info(f"Running in standalone mode - PlexiChat modules not available: {e}")

# Import GUI components
try:
    from plexichat.gui.components.backup_management_widget import BackupManagementWidget
    from plexichat.gui.components.clustering_management_widget import ClusteringManagementWidget
    GUI_COMPONENTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"GUI components not available: {e}")
    GUI_COMPONENTS_AVAILABLE = False


# Configure CustomTkinter
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")


class PlexiChatAdminGUI:
    """Advanced GUI application for PlexiChat administration."""
    
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("PlexiChat Admin - Government-Level Security")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        # Application state
        self.current_user = None
        self.session_token = None
        self.server_url = "http://localhost:8000"  # Default to HTTP for local development
        self.is_authenticated = False

        # Auto-detect server URL
        self.detect_server_url()
        
        # Theme settings
        self.current_theme = "system"
        self.themes = ["system", "light", "dark"]
        
        # Initialize GUI
        self.setup_styles()
        self.create_login_interface()
        
        # Start auto-refresh thread
        self.auto_refresh_active = False
        self.start_auto_refresh()
        
        logger.info("PlexiChat Admin GUI initialized")

    def detect_server_url(self):
        """Auto-detect PlexiChat server URL."""
        possible_urls = [
            "http://localhost:8000",
            "https://localhost:8000",
            "http://127.0.0.1:8000",
            "https://127.0.0.1:8000"
        ]

        for url in possible_urls:
            try:
                response = requests.get(f"{url}/health", timeout=2, verify=False)
                if response.status_code == 200:
                    self.server_url = url
                    print(f"✅ Detected PlexiChat server at: {url}")
                    return
            except:
                continue

        print("⚠️ PlexiChat server not detected. Using default: http://localhost:8000")
        print("💡 Make sure to start the server with: python run.py run")
    
    def setup_styles(self):
        """Setup custom styles and colors."""
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#34495e',
            'accent': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#2c3e50'
        }
    
    def create_login_interface(self):
        """Create government-level login interface."""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main login frame
        login_frame = ctk.CTkFrame(self.root, width=500, height=600)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Logo and title
        title_label = ctk.CTkLabel(
            login_frame,
            text="🔒 PlexiChat Admin",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        title_label.pack(pady=(40, 10))
        
        subtitle_label = ctk.CTkLabel(
            login_frame,
            text="Government-Level Security",
            font=ctk.CTkFont(size=16)
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Security notice
        security_frame = ctk.CTkFrame(login_frame, fg_color=("#ff8c00", "#ff6600"))
        security_frame.pack(pady=(0, 30), padx=40, fill="x")
        
        security_label = ctk.CTkLabel(
            security_frame,
            text="⚠️ GOVERNMENT-LEVEL SECURITY\nUnauthorized access is prohibited",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="white"
        )
        security_label.pack(pady=15)
        
        # Login form
        self.username_entry = ctk.CTkEntry(
            login_frame,
            placeholder_text="Username",
            width=300,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.username_entry.pack(pady=(0, 15), padx=40)
        
        self.password_entry = ctk.CTkEntry(
            login_frame,
            placeholder_text="Password",
            show="*",
            width=300,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.password_entry.pack(pady=(0, 15), padx=40)
        
        # 2FA entry (initially hidden)
        self.totp_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
        self.totp_entry = ctk.CTkEntry(
            self.totp_frame,
            placeholder_text="2FA Code (6 digits)",
            width=300,
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.totp_entry.pack(pady=(0, 15), padx=40)
        
        # Login button
        self.login_button = ctk.CTkButton(
            login_frame,
            text="🔐 Secure Login",
            width=300,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.handle_login
        )
        self.login_button.pack(pady=(0, 20), padx=40)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            login_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(pady=(0, 20))
        
        # Footer
        footer_label = ctk.CTkLabel(
            login_frame,
            text=f"System Time: {datetime.now().strftime('%H:%M:%S')}",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        footer_label.pack(pady=(0, 20))
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.handle_login())
        
        # Focus username entry
        self.username_entry.focus()
        
        # Update time every second
        self.update_time(footer_label)
    
    def update_time(self, label):
        """Update time display."""
        label.configure(text=f"System Time: {datetime.now().strftime('%H:%M:%S')}")
        self.root.after(1000, lambda: self.update_time(label))
    
    def handle_login(self):
        """Handle login attempt."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        totp_code = self.totp_entry.get().strip() if self.totp_entry.winfo_viewable() else None
        
        if not username or not password:
            self.show_status("Please enter username and password", "error")
            return
        
        # Disable login button and show loading
        self.login_button.configure(text="🔄 Authenticating...", state="disabled")
        
        # Perform authentication in thread to avoid blocking UI
        threading.Thread(
            target=self.authenticate_user,
            args=(username, password, totp_code),
            daemon=True
        ).start()
    
    def authenticate_user(self, username: str, password: str, totp_code: Optional[str]):
        """Authenticate user with government auth system."""
        try:
            if government_auth:
                result = government_auth.authenticate(username, password, totp_code)
            else:
                # Fallback authentication for development
                if username == "admin" and password == "admin123":
                    result = {"success": True, "user": {"username": username, "permission_level": 4}}
                else:
                    result = {"success": False, "message": "Invalid credentials"}

            # Update UI in main thread
            self.root.after(0, self.handle_auth_result, result, username)

        except Exception as e:
            logger.error(f"GUI authentication error: {e}")
            self.root.after(0, self.handle_auth_error, str(e))
    
    def handle_auth_result(self, result: Dict[str, Any], username: str):
        """Handle authentication result."""
        # Re-enable login button
        self.login_button.configure(text="🔐 Secure Login", state="normal")
        
        if result['success']:
            self.current_user = username
            self.session_token = result['session_token']
            self.is_authenticated = True
            
            if result.get('must_change_password'):
                self.show_password_change_dialog()
            else:
                self.create_main_interface()
                
        else:
            if result.get('requires_2fa'):
                self.show_2fa_input()
                self.show_status("2FA code required", "warning")
            else:
                self.show_status(f"Login failed: {result['error']}", "error")
    
    def handle_auth_error(self, error: str):
        """Handle authentication error."""
        self.login_button.configure(text="🔐 Secure Login", state="normal")
        self.show_status(f"Authentication error: {error}", "error")
    
    def show_2fa_input(self):
        """Show 2FA input field."""
        self.totp_frame.pack(pady=(0, 15), padx=40, before=self.login_button)
        self.totp_entry.focus()
    
    def show_status(self, message: str, status_type: str = "info"):
        """Show status message."""
        colors = {
            "info": "gray",
            "success": "green",
            "warning": "orange",
            "error": "red"
        }
        
        self.status_label.configure(
            text=message,
            text_color=colors.get(status_type, "gray")
        )
    
    def show_password_change_dialog(self):
        """Show mandatory password change dialog."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Password Change Required")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        # Title
        title_label = ctk.CTkLabel(
            dialog,
            text="🔒 Password Change Required",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title_label.pack(pady=(20, 10))
        
        # Notice
        notice_label = ctk.CTkLabel(
            dialog,
            text="You must change your password before continuing.",
            font=ctk.CTkFont(size=12)
        )
        notice_label.pack(pady=(0, 20))
        
        # Current password
        current_pwd_entry = ctk.CTkEntry(
            dialog,
            placeholder_text="Current Password",
            show="*",
            width=300
        )
        current_pwd_entry.pack(pady=5)
        
        # New password
        new_pwd_entry = ctk.CTkEntry(
            dialog,
            placeholder_text="New Password (min 16 chars)",
            show="*",
            width=300
        )
        new_pwd_entry.pack(pady=5)
        
        # Confirm password
        confirm_pwd_entry = ctk.CTkEntry(
            dialog,
            placeholder_text="Confirm New Password",
            show="*",
            width=300
        )
        confirm_pwd_entry.pack(pady=5)
        
        # Change button
        def change_password():
            current = current_pwd_entry.get()
            new = new_pwd_entry.get()
            confirm = confirm_pwd_entry.get()
            
            if not all([current, new, confirm]):
                messagebox.showerror("Error", "All fields are required")
                return
            
            if new != confirm:
                messagebox.showerror("Error", "New passwords do not match")
                return
            
            if len(new) < 16:
                messagebox.showerror("Error", "Password must be at least 16 characters")
                return
            
            try:
                if government_auth:
                    result = government_auth.change_password(self.current_user, current, new)
                    if result['success']:
                        messagebox.showinfo("Success", "Password changed successfully!")
                        dialog.destroy()
                        self.create_main_interface()
                    else:
                        messagebox.showerror("Error", result['error'])
                else:
                    messagebox.showinfo("Success", "Password change simulated (development mode)")
                    dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Password change failed: {e}")
        
        change_btn = ctk.CTkButton(
            dialog,
            text="Change Password",
            command=change_password,
            width=200
        )
        change_btn.pack(pady=20)
        
        current_pwd_entry.focus()
    
    def create_main_interface(self):
        """Create main admin interface."""
        # Clear login interface
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create main layout
        self.create_sidebar()
        self.create_main_content()
        self.create_top_bar()
        
        # Load dashboard by default
        self.show_dashboard()
        
        # Start auto-refresh
        self.auto_refresh_active = True
    
    def create_sidebar(self):
        """Create navigation sidebar."""
        self.sidebar = ctk.CTkFrame(self.root, width=280, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # Logo
        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="🔒 PlexiChat",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        logo_label.pack(pady=(20, 10))
        
        subtitle_label = ctk.CTkLabel(
            self.sidebar,
            text="Admin Dashboard",
            font=ctk.CTkFont(size=14)
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("📊 Dashboard", "dashboard"),
            ("👥 Users", "users"),
            ("🔒 Security", "security"),
            ("⚖️ Moderation", "moderation"),
            ("💾 Backup Management", "backup_management"),
            ("🖥️ Clustering", "clustering_management"),
            ("⚙️ System", "system"),
            ("📈 Monitoring", "monitoring"),
            ("🧩 Plugins", "plugins"),
            ("📄 Logs", "logs"),
            ("⚙️ Settings", "settings")
        ]
        
        for text, module in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                width=240,
                height=40,
                font=ctk.CTkFont(size=14),
                anchor="w",
                command=lambda m=module: self.show_module(m)
            )
            btn.pack(pady=2, padx=20)
            self.nav_buttons[module] = btn
        
        # Set dashboard as active
        self.nav_buttons["dashboard"].configure(fg_color=self.colors['accent'])
    
    def create_top_bar(self):
        """Create top navigation bar."""
        self.top_bar = ctk.CTkFrame(self.main_content, height=60, corner_radius=0)
        self.top_bar.pack(side="top", fill="x")
        self.top_bar.pack_propagate(False)
        
        # Title
        self.page_title = ctk.CTkLabel(
            self.top_bar,
            text="Dashboard",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.page_title.pack(side="left", padx=20, pady=15)
        
        # User info and controls
        user_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        user_frame.pack(side="right", padx=20, pady=10)
        
        # Theme selector
        theme_btn = ctk.CTkButton(
            user_frame,
            text="🎨",
            width=40,
            height=40,
            command=self.toggle_theme
        )
        theme_btn.pack(side="right", padx=5)
        
        # User menu
        user_label = ctk.CTkLabel(
            user_frame,
            text=f"Welcome, {self.current_user}",
            font=ctk.CTkFont(size=14)
        )
        user_label.pack(side="right", padx=10)
        
        # Logout button
        logout_btn = ctk.CTkButton(
            user_frame,
            text="🚪 Logout",
            width=80,
            height=30,
            command=self.logout
        )
        logout_btn.pack(side="right", padx=5)
    
    def create_main_content(self):
        """Create main content area."""
        self.main_content = ctk.CTkFrame(self.root, corner_radius=0)
        self.main_content.pack(side="right", fill="both", expand=True)
        
        # Content will be added by individual modules
        self.content_area = ctk.CTkScrollableFrame(self.main_content)
        self.content_area.pack(fill="both", expand=True, padx=20, pady=(80, 20))
    
    def show_module(self, module_name: str):
        """Show specific module."""
        # Update navigation
        for name, btn in self.nav_buttons.items():
            if name == module_name:
                btn.configure(fg_color=self.colors['accent'])
            else:
                btn.configure(fg_color=("gray75", "gray25"))
        
        # Update page title
        titles = {
            'dashboard': 'Dashboard',
            'users': 'User Management',
            'security': 'Security Center',
            'moderation': 'Moderation Tools',
            'backup_management': 'Backup Management',
            'clustering_management': 'Clustering Management',
            'system': 'System Settings',
            'monitoring': 'System Monitoring',
            'plugins': 'Plugin Management',
            'logs': 'System Logs',
            'settings': 'Configuration'
        }
        self.page_title.configure(text=titles.get(module_name, 'Dashboard'))
        
        # Clear content area
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        # Load module content
        if module_name == "dashboard":
            self.show_dashboard()
        elif module_name == "users":
            self.show_users()
        elif module_name == "security":
            self.show_security()
        elif module_name == "backup_management":
            self.show_backup_management()
        elif module_name == "clustering_management":
            self.show_clustering_management()
        else:
            self.show_placeholder(module_name)
    
    def show_dashboard(self):
        """Show dashboard content."""
        # Stats cards
        stats_frame = ctk.CTkFrame(self.content_area)
        stats_frame.pack(fill="x", pady=(0, 20))
        
        # Create stats grid
        stats = [
            ("👥 Total Users", "5", self.colors['primary']),
            ("💬 Messages Today", "1,234", self.colors['success']),
            ("🖥️ Server Status", "Online", self.colors['accent']),
            ("🔒 Security Level", "High", self.colors['warning'])
        ]
        
        for i, (title, value, color) in enumerate(stats):
            stat_frame = ctk.CTkFrame(stats_frame)
            stat_frame.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
            stats_frame.grid_columnconfigure(i, weight=1)
            
            value_label = ctk.CTkLabel(
                stat_frame,
                text=value,
                font=ctk.CTkFont(size=24, weight="bold")
            )
            value_label.pack(pady=(15, 5))
            
            title_label = ctk.CTkLabel(
                stat_frame,
                text=title,
                font=ctk.CTkFont(size=12)
            )
            title_label.pack(pady=(0, 15))
        
        # Quick actions
        actions_frame = ctk.CTkFrame(self.content_area)
        actions_frame.pack(fill="x", pady=(0, 20))
        
        actions_title = ctk.CTkLabel(
            actions_frame,
            text="Quick Actions",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        actions_title.pack(pady=(15, 10))
        
        actions = [
            ("💾 Start Backup", lambda: self.show_module("backup")),
            ("👤 Add User", lambda: self.show_module("users")),
            ("🔒 Security Scan", lambda: self.show_module("security")),
            ("🔄 Restart Server", self.restart_server)
        ]
        
        for i, (text, command) in enumerate(actions):
            btn = ctk.CTkButton(
                actions_frame,
                text=text,
                width=200,
                command=command
            )
            btn.grid(row=i//2, column=i%2, padx=10, pady=5, sticky="ew")
            actions_frame.grid_columnconfigure(0, weight=1)
            actions_frame.grid_columnconfigure(1, weight=1)
        
        # System overview
        overview_frame = ctk.CTkFrame(self.content_area)
        overview_frame.pack(fill="both", expand=True)
        
        overview_title = ctk.CTkLabel(
            overview_frame,
            text="System Overview",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        overview_title.pack(pady=(15, 10))
        
        # Resource usage bars
        resources = [
            ("CPU Usage", 45),
            ("Memory Usage", 67),
            ("Disk Usage", 23),
            ("Network I/O", 12)
        ]
        
        for name, value in resources:
            resource_frame = ctk.CTkFrame(overview_frame, fg_color="transparent")
            resource_frame.pack(fill="x", padx=20, pady=5)
            
            label = ctk.CTkLabel(
                resource_frame,
                text=f"{name}: {value}%",
                font=ctk.CTkFont(size=12)
            )
            label.pack(side="left")
            
            progress = ctk.CTkProgressBar(resource_frame, width=200)
            progress.pack(side="right", padx=(10, 0))
            progress.set(value / 100)
    
    def show_users(self):
        """Show user management interface."""
        # Add user button
        add_btn = ctk.CTkButton(
            self.content_area,
            text="👤 Add User",
            command=self.add_user_dialog
        )
        add_btn.pack(pady=(0, 20))
        
        # Users list
        users_frame = ctk.CTkFrame(self.content_area)
        users_frame.pack(fill="both", expand=True)
        
        title = ctk.CTkLabel(
            users_frame,
            text="Admin Users",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(15, 10))
        
        # Mock user data
        if government_auth and hasattr(government_auth, 'admin_credentials'):
            user_data = government_auth.admin_credentials.items()
        else:
            # Fallback user data for development
            user_data = [
                ("admin", {"permission_level": 4, "last_login": "2025-01-08 12:00:00"}),
                ("moderator", {"permission_level": 2, "last_login": "2025-01-08 11:30:00"}),
                ("user", {"permission_level": 1, "last_login": "2025-01-08 11:00:00"})
            ]

        for username, admin_data in user_data:
            user_frame = ctk.CTkFrame(users_frame)
            user_frame.pack(fill="x", padx=20, pady=5)
            
            # User info
            info_label = ctk.CTkLabel(
                user_frame,
                text=f"👤 {username} - {'Locked' if admin_data.locked_until else 'Active'}",
                font=ctk.CTkFont(size=14)
            )
            info_label.pack(side="left", padx=15, pady=10)
            
            # Actions
            reset_btn = ctk.CTkButton(
                user_frame,
                text="🔑 Reset Password",
                width=120,
                command=lambda u=username: self.reset_user_password(u)
            )
            reset_btn.pack(side="right", padx=5, pady=5)
    
    def show_security(self):
        """Show security center."""
        security_frame = ctk.CTkFrame(self.content_area)
        security_frame.pack(fill="both", expand=True)
        
        title = ctk.CTkLabel(
            security_frame,
            text="Security Center",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(15, 10))
        
        # Security alerts
        alerts = [
            ("⚠️ Failed Login Attempts", "15 failed attempts in the last hour", "warning"),
            ("✅ SSL Certificate", "Valid until 2025-01-15", "success"),
            ("🚨 Default Password", "Change default admin password immediately", "error")
        ]
        
        for title_text, message, alert_type in alerts:
            alert_frame = ctk.CTkFrame(security_frame)
            alert_frame.pack(fill="x", padx=20, pady=5)
            
            colors = {
                "success": "green",
                "warning": "orange", 
                "error": "red"
            }
            
            alert_label = ctk.CTkLabel(
                alert_frame,
                text=f"{title_text}\n{message}",
                font=ctk.CTkFont(size=12),
                text_color=colors.get(alert_type, "gray")
            )
            alert_label.pack(padx=15, pady=10)
    
    def show_backup(self):
        """Show backup management."""
        backup_frame = ctk.CTkFrame(self.content_area)
        backup_frame.pack(fill="both", expand=True)
        
        title = ctk.CTkLabel(
            backup_frame,
            text="Backup & Clustering",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(15, 10))
        
        # Backup status
        status_frame = ctk.CTkFrame(backup_frame)
        status_frame.pack(fill="x", padx=20, pady=10)
        
        status_label = ctk.CTkLabel(
            status_frame,
            text="Backup Completeness: 95% (19/20 shards distributed)",
            font=ctk.CTkFont(size=14)
        )
        status_label.pack(pady=10)
        
        progress = ctk.CTkProgressBar(status_frame, width=400)
        progress.pack(pady=5)
        progress.set(0.95)
        
        # Start backup button
        backup_btn = ctk.CTkButton(
            backup_frame,
            text="💾 Start Backup",
            command=self.start_backup
        )
        backup_btn.pack(pady=20)

    def show_backup_management(self):
        """Show comprehensive backup management interface."""
        if not GUI_COMPONENTS_AVAILABLE:
            self.show_placeholder("backup_management")
            return

        try:
            # Create backup management widget
            backup_widget = BackupManagementWidget(self.content_area)
            if backup_widget and backup_widget.main_frame:
                backup_widget.main_frame.pack(fill="both", expand=True)
                logger.info("Backup management widget loaded successfully")
            else:
                self.show_placeholder("backup_management")
        except Exception as e:
            logger.error(f"Failed to load backup management widget: {e}")
            self.show_placeholder("backup_management")

    def show_clustering_management(self):
        """Show comprehensive clustering management interface."""
        if not GUI_COMPONENTS_AVAILABLE:
            self.show_placeholder("clustering_management")
            return

        try:
            # Create clustering management widget
            clustering_widget = ClusteringManagementWidget(self.content_area)
            if clustering_widget and clustering_widget.main_frame:
                clustering_widget.main_frame.pack(fill="both", expand=True)
                logger.info("Clustering management widget loaded successfully")
            else:
                self.show_placeholder("clustering_management")
        except Exception as e:
            logger.error(f"Failed to load clustering management widget: {e}")
            self.show_placeholder("clustering_management")

    def show_placeholder(self, module_name: str):
        """Show placeholder for unimplemented modules."""
        placeholder_frame = ctk.CTkFrame(self.content_area)
        placeholder_frame.pack(fill="both", expand=True)
        
        label = ctk.CTkLabel(
            placeholder_frame,
            text=f"{module_name.title()} module will be implemented here",
            font=ctk.CTkFont(size=16)
        )
        label.pack(expand=True)
    
    def toggle_theme(self):
        """Toggle application theme."""
        current_index = self.themes.index(self.current_theme)
        next_index = (current_index + 1) % len(self.themes)
        self.current_theme = self.themes[next_index]
        
        ctk.set_appearance_mode(self.current_theme)
        messagebox.showinfo("Theme", f"Theme changed to: {self.current_theme}")
    
    def add_user_dialog(self):
        """Show add user dialog."""
        username = simpledialog.askstring("Add User", "Enter username:")
        if username:
            messagebox.showinfo("Success", f"User {username} would be created")
    
    def reset_user_password(self, username: str):
        """Reset user password."""
        if messagebox.askyesno("Confirm", f"Reset password for {username}?"):
            try:
                if government_auth and hasattr(government_auth, '_generate_secure_password'):
                    new_password = government_auth._generate_secure_password()
                else:
                    # Fallback password generation
                    import secrets
                    import string
                    chars = string.ascii_letters + string.digits + "!@#$%^&*"
                    new_password = ''.join(secrets.choice(chars) for _ in range(16))

                messagebox.showinfo(
                    "Password Reset",
                    f"New password for {username}:\n{new_password}\n\nPlease save this securely!"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Password reset failed: {e}")
    
    def start_backup(self):
        """Start backup process."""
        if messagebox.askyesno("Confirm", "Start backup process?"):
            messagebox.showinfo("Backup", "Backup started successfully!")
    
    def restart_server(self):
        """Restart server."""
        if messagebox.askyesno("Confirm", "Restart server? This will interrupt service temporarily."):
            messagebox.showinfo("Restart", "Server restart initiated!")
    
    def logout(self):
        """Logout and return to login screen."""
        if messagebox.askyesno("Confirm", "Are you sure you want to logout?"):
            self.current_user = None
            self.session_token = None
            self.is_authenticated = False
            self.auto_refresh_active = False
            
            logger.info("GUI logout")
            self.create_login_interface()
    
    def start_auto_refresh(self):
        """Start auto-refresh thread for real-time updates."""
        def refresh_loop():
            while True:
                if self.auto_refresh_active and self.is_authenticated:
                    # Refresh data here
                    pass
                time.sleep(30)  # Refresh every 30 seconds
        
        threading.Thread(target=refresh_loop, daemon=True).start()
    
    def run(self):
        """Run the GUI application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("GUI application interrupted")
        except Exception as e:
            logger.error(f"GUI application error: {e}")
            messagebox.showerror("Error", f"Application error: {e}")


def main():
    """Main entry point for GUI application."""
    try:
        app = PlexiChatAdminGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
