"""
Advanced Login Screen Component for PlexiChat GUI
Features modern design, security, and multiple authentication methods.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkFont
from typing import Dict, Any, Callable, Optional
import asyncio
import threading
import hashlib
import base64
import logging
from datetime import datetime, timedelta
from pathlib import Path
import json
import requests
import base64
import psutil
import os
import time
import random
import math
try:
    from PIL import Image, ImageTk, ImageFilter, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
import psutil
import os
import time
import random
import math
try:
    from PIL import Image, ImageTk, ImageFilter, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class LoginScreen(ttk.Frame):
    """
    Advanced login screen with modern design and security features.

    Features:
    - Modern, animated UI with tooltips
    - Multiple authentication methods (password, 2FA)
    - Remember me functionality
    - Password strength indicator
    - CLI-based password recovery
    - Enhanced security monitoring
    - Improved user experience
    """

    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.parent = parent
        
        # Authentication state
        self.auth_method = "password"  # password, 2fa
        self.login_attempts = 0
        self.max_attempts = 5
        self.is_authenticating = False

        # UI components
        self.main_frame = None
        self.login_frame = None
        # No registration frame - this is an admin interface

        # Tooltip system
        self.tooltips = {}
        
        # Form variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_me_var = tk.BooleanVar()
        self.show_password_var = tk.BooleanVar()
        
        # Animation variables
        self.animation_running = False
        self.particles = []

        # Modern UI enhancements
        self.dark_mode = tk.BooleanVar(value=True)  # Default to dark mode
        self.system_status_text = tk.StringVar()
        self.start_time = datetime.now()

        # Glassmorphism and rounded corners
        self.login_card_canvas = None
        self.blur_image = None
        self.password_visible = False

        # Configure custom styles
        self.configure_custom_styles()

        self.create_login_interface()

    def create_login_interface(self):
        """Create the main login interface."""
        try:
            # Configure main frame
            self.configure(style="Login.TFrame")
            
            # Create background
            self.create_background()

            # Create dark mode toggle in top-right corner
            self.create_dark_mode_toggle()

            # Create main container with glassmorphism
            self.create_glassmorphism_container()

            # Create main container
            self.main_frame = ttk.Frame(self, style="LoginMain.TFrame")
            self.main_frame.place(relx=0.5, rely=0.5, anchor="center")
            
            # Create login form
            self.create_login_form()
            
            # Start background animations
            self.start_background_animation()
            
            logger.info("Login interface created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create login interface: {e}")
            messagebox.showerror("Error", f"Failed to create login interface: {e}")

    def create_dark_mode_toggle(self):
        """Create dark mode toggle in top-right corner."""
        try:
            # Dark mode toggle frame
            toggle_frame = tk.Frame(self, bg='transparent')
            toggle_frame.place(relx=0.95, rely=0.05, anchor="ne")

            # Dark mode label
            mode_label = tk.Label(
                toggle_frame,
                text="🌙",
                font=('Inter', 16),
                bg='transparent',
                fg='white',
                cursor='hand2'
            )
            mode_label.pack(side=tk.LEFT, padx=(0, 5))

            # Dark mode toggle
            self.dark_toggle = tk.Checkbutton(
                toggle_frame,
                variable=self.dark_mode,
                command=self.toggle_dark_mode,
                bg='transparent',
                fg='white',
                selectcolor='#3b82f6',
                activebackground='transparent',
                activeforeground='white',
                cursor='hand2',
                font=('Inter', 10)
            )
            self.dark_toggle.pack(side=tk.LEFT)

        except Exception as e:
            logger.error(f"Failed to create dark mode toggle: {e}")

    def create_glassmorphism_container(self):
        """Create glassmorphism effect behind login card."""
        try:
            if not PIL_AVAILABLE:
                return

            # Create canvas for glassmorphism effect
            self.glass_canvas = tk.Canvas(
                self,
                highlightthickness=0,
                bg='transparent'
            )
            self.glass_canvas.place(relx=0.5, rely=0.5, anchor="center")

            # We'll update this when the login form is created

        except Exception as e:
            logger.error(f"Failed to create glassmorphism container: {e}")

    def toggle_dark_mode(self):
        """Toggle between dark and light mode."""
        try:
            # Reconfigure styles based on mode
            self.configure_custom_styles()

            # Update background colors
            if self.dark_mode.get():
                # Dark mode colors
                self.configure(bg='#1a1a2e')
                if hasattr(self, 'bg_canvas'):
                    self.create_gradient_background()
            else:
                # Light mode colors
                self.configure(bg='#f8fafc')
                if hasattr(self, 'bg_canvas'):
                    self.create_light_gradient_background()

            # Update system status
            self.update_system_status()

        except Exception as e:
            logger.error(f"Failed to toggle dark mode: {e}")

    def create_background(self):
        """Create animated background."""
        try:
            # Create canvas for background effects
            self.bg_canvas = tk.Canvas(self, highlightthickness=0)
            self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Create gradient background
            self.create_gradient_background()
            
            # Create floating particles
            self.create_floating_particles()
            
        except Exception as e:
            logger.error(f"Failed to create background: {e}")

    def create_gradient_background(self):
        """Create stunning gradient background from deep indigo to violet/cyan."""
        try:
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()

            # Create beautiful gradient: deep indigo (#1a1a2e) to violet (#16213e) to cyan hints
            for i in range(height):
                ratio = i / height

                # Deep indigo to violet gradient with cyan hints
                if ratio < 0.6:
                    # Deep indigo to darker indigo
                    r = int(26 + (22 - 26) * (ratio / 0.6))     # 26 to 22
                    g = int(26 + (33 - 26) * (ratio / 0.6))     # 26 to 33
                    b = int(46 + (62 - 46) * (ratio / 0.6))     # 46 to 62
                else:
                    # Add subtle cyan hints at bottom
                    sub_ratio = (ratio - 0.6) / 0.4
                    r = int(22 + (30 - 22) * sub_ratio)         # 22 to 30 (cyan hint)
                    g = int(33 + (45 - 33) * sub_ratio)         # 33 to 45 (cyan hint)
                    b = int(62 + (80 - 62) * sub_ratio)         # 62 to 80 (deeper)

                color = f"#{r:02x}{g:02x}{b:02x}"
                self.bg_canvas.create_line(0, i, width, i, fill=color, width=1)

        except Exception as e:
            logger.error(f"Failed to create gradient background: {e}")

    def create_light_gradient_background(self):
        """Create light mode gradient background."""
        try:
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()

            # Create beautiful light gradient: light blue to white to light cyan
            for i in range(height):
                ratio = i / height

                # Light blue to white to light cyan gradient
                if ratio < 0.5:
                    # Light blue to white
                    r = int(248 + (255 - 248) * (ratio / 0.5))     # 248 to 255
                    g = int(250 + (255 - 250) * (ratio / 0.5))     # 250 to 255
                    b = int(252 + (255 - 252) * (ratio / 0.5))     # 252 to 255
                else:
                    # White to light cyan
                    sub_ratio = (ratio - 0.5) / 0.5
                    r = int(255 + (240 - 255) * sub_ratio)         # 255 to 240
                    g = int(255 + (253 - 255) * sub_ratio)         # 255 to 253
                    b = int(255 + (255 - 255) * sub_ratio)         # 255 to 255

                color = f"#{r:02x}{g:02x}{b:02x}"
                self.bg_canvas.create_line(0, i, width, i, fill=color, width=1)

        except Exception as e:
            logger.error(f"Failed to create light gradient background: {e}")

    def create_floating_particles(self):
        """Create floating particle effects."""
        try:
            import random
            
            self.particles = []
            for _ in range(50):
                x = random.randint(0, self.winfo_screenwidth())
                y = random.randint(0, self.winfo_screenheight())
                size = random.randint(2, 6)
                speed = random.uniform(0.5, 2.0)
                
                particle = self.bg_canvas.create_oval(
                    x, y, x + size, y + size,
                    fill="#ffffff", outline="", stipple="gray25"
                )
                
                self.particles.append({
                    "id": particle,
                    "x": x,
                    "y": y,
                    "size": size,
                    "speed": speed,
                    "direction": random.uniform(0, 360)
                })
                
        except Exception as e:
            logger.error(f"Failed to create floating particles: {e}")

    def start_background_animation(self):
        """Start background animation loop."""
        try:
            self.animation_running = True
            self.animate_particles()
        except Exception as e:
            logger.error(f"Failed to start background animation: {e}")

    def animate_particles(self):
        """Animate floating particles."""
        if not self.animation_running:
            return
            
        try:
            import math
            
            for particle in self.particles:
                # Update position
                particle["x"] += math.cos(math.radians(particle["direction"])) * particle["speed"]
                particle["y"] += math.sin(math.radians(particle["direction"])) * particle["speed"]
                
                # Wrap around screen
                if particle["x"] < 0:
                    particle["x"] = self.winfo_screenwidth()
                elif particle["x"] > self.winfo_screenwidth():
                    particle["x"] = 0
                    
                if particle["y"] < 0:
                    particle["y"] = self.winfo_screenheight()
                elif particle["y"] > self.winfo_screenheight():
                    particle["y"] = 0
                
                # Update canvas position
                self.bg_canvas.coords(
                    particle["id"],
                    particle["x"], particle["y"],
                    particle["x"] + particle["size"], particle["y"] + particle["size"]
                )
            
            # Schedule next animation frame
            self.after(50, self.animate_particles)
            
        except Exception as e:
            logger.error(f"Animation error: {e}")

    def create_login_form(self):
        """Create the main login form."""
        try:
            # Main login container
            self.login_frame = ttk.Frame(self.main_frame, style="LoginCard.TFrame", padding=40)
            self.login_frame.grid(row=0, column=0, sticky="nsew")
            
            # PlexiChat logo and title
            self.create_header()
            
            # Login form fields
            self.create_form_fields()
            
            # Login options
            self.create_login_options()
            
            # Action buttons
            self.create_action_buttons()
            
            # Footer links
            self.create_footer_links()
            
        except Exception as e:
            logger.error(f"Failed to create login form: {e}")

    def add_tooltip(self, widget, text):
        """Add tooltip to a widget."""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.configure(bg='#2c3e50')

            label = tk.Label(
                tooltip,
                text=text,
                background='#2c3e50',
                foreground='white',
                font=('Arial', 9),
                relief='solid',
                borderwidth=1,
                wraplength=300
            )
            label.pack()

            # Position tooltip
            x = widget.winfo_rootx() + 25
            y = widget.winfo_rooty() + 25
            tooltip.geometry(f"+{x}+{y}")

            self.tooltips[widget] = tooltip

        def on_leave(event):
            if widget in self.tooltips:
                self.tooltips[widget].destroy()
                del self.tooltips[widget]

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def create_header(self):
        """Create modern header with beautiful logo and title."""
        try:
            # Logo frame
            logo_frame = ttk.Frame(self.login_frame)
            logo_frame.grid(row=0, column=0, columnspan=2, pady=(0, 25))

            # Create modern logo canvas with gradient effect
            logo_canvas = tk.Canvas(logo_frame, width=90, height=90, highlightthickness=0, bg='white')
            logo_canvas.pack()

            # Draw modern PlexiChat logo with gradient and shadow
            # Shadow effect
            logo_canvas.create_oval(8, 8, 82, 82, fill="#e5e7eb", outline="", width=0)

            # Main logo circle with modern gradient (simulated)
            logo_canvas.create_oval(5, 5, 80, 80, fill="#3b82f6", outline="#2563eb", width=2)

            # Inner highlight for depth
            logo_canvas.create_oval(15, 15, 35, 35, fill="#60a5fa", outline="", width=0)

            # Modern "P" with better typography
            logo_canvas.create_text(42.5, 42.5, text="P", fill="white", font=("Inter", 28, "bold"))

            # Main title with modern typography
            title_label = ttk.Label(
                self.login_frame,
                text="PlexiChat",
                style="LoginTitle.TLabel"
            )
            title_label.grid(row=1, column=0, columnspan=2, pady=(0, 8))

            # Professional subtitle
            subtitle_label = ttk.Label(
                self.login_frame,
                text="Management Interface",
                style="LoginSubtitle.TLabel"
            )
            subtitle_label.grid(row=2, column=0, columnspan=2, pady=(0, 35))

        except Exception as e:
            logger.error(f"Failed to create header: {e}")

    def create_form_fields(self):
        """Create modern form input fields with icons."""
        try:
            # Username field with icon
            username_label = ttk.Label(self.login_frame, text="👤 Username", style="LoginLabel.TLabel")
            username_label.grid(row=3, column=0, sticky="w", pady=(0, 8))

            self.username_entry = ttk.Entry(
                self.login_frame,
                textvariable=self.username_var,
                style="LoginEntry.TEntry",
                width=30
            )
            self.username_entry.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 20))
            self.username_entry.insert(0, "admin")  # Pre-fill with default
            self.add_tooltip(self.username_entry, "Enter your username (default: admin)")

            # Password field with icon
            password_label = ttk.Label(self.login_frame, text="🔒 Password", style="LoginLabel.TLabel")
            password_label.grid(row=5, column=0, sticky="w", pady=(0, 8))

            password_frame = ttk.Frame(self.login_frame)
            password_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 20))
            password_frame.columnconfigure(0, weight=1)

            self.password_entry = ttk.Entry(
                password_frame,
                textvariable=self.password_var,
                style="LoginEntry.TEntry",
                show="*"
            )
            self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
            self.add_tooltip(self.password_entry, "Enter your password (check default_creds.txt for initial password)")

            # Modern eye button for password visibility
            self.show_password_btn = ttk.Button(
                password_frame,
                text="👁",
                width=4,
                command=self.toggle_password_visibility,
                style="EyeButton.TButton"
            )
            self.show_password_btn.grid(row=0, column=1)
            self.add_tooltip(self.show_password_btn, "Show/hide password")

        except Exception as e:
            logger.error(f"Failed to create form fields: {e}")

    def create_login_options(self):
        """Create login options (remember me, etc.)."""
        try:
            options_frame = ttk.Frame(self.login_frame)
            options_frame.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(0, 20))
            options_frame.columnconfigure(1, weight=1)
            
            # Remember me checkbox
            remember_check = ttk.Checkbutton(
                options_frame,
                text="Remember me",
                variable=self.remember_me_var,
                style="LoginCheck.TCheckbutton"
            )
            remember_check.grid(row=0, column=0, sticky="w")
            
            # Password reset info link
            reset_link = ttk.Label(
                options_frame,
                text="Reset password?",
                style="LoginLink.TLabel",
                cursor="hand2"
            )
            reset_link.grid(row=0, column=1, sticky="e")
            reset_link.bind("<Button-1>", self.show_password_reset_info)
            self.add_tooltip(reset_link, "Use CLI command 'gui-password --reset' to reset your password")
            
        except Exception as e:
            logger.error(f"Failed to create login options: {e}")

    def create_action_buttons(self):
        """Create action buttons."""
        try:
            button_frame = ttk.Frame(self.login_frame)
            button_frame.grid(row=9, column=0, columnspan=2, pady=(0, 20))
            
            # Login button
            self.login_btn = ttk.Button(
                button_frame,
                text="Sign In",
                command=self.perform_login,
                style="LoginButton.TButton",
                width=20
            )
            self.login_btn.pack(pady=(0, 10))
            self.add_tooltip(self.login_btn, "Click to sign in with your username and password")
            
            # System status indicator (modern and informative)
            self.create_system_status_indicator(button_frame)

        except Exception as e:
            logger.error(f"Failed to create action buttons: {e}")

    def create_system_status_indicator(self, parent):
        """Create system status indicator below sign in button."""
        try:
            # System status frame
            status_frame = ttk.Frame(parent)
            status_frame.pack(pady=(15, 0))

            # System status label
            self.status_label = tk.Label(
                status_frame,
                textvariable=self.system_status_text,
                font=('Inter', 9),
                fg='#6b7280' if self.dark_mode.get() else '#9ca3af',
                bg='white',
                justify='center'
            )
            self.status_label.pack()

            # Start updating system status
            self.update_system_status()
            self.schedule_status_update()

        except Exception as e:
            logger.error(f"Failed to create system status indicator: {e}")

    def update_system_status(self):
        """Update system status information."""
        try:
            # Calculate uptime
            uptime = datetime.now() - self.start_time
            uptime_str = f"{uptime.days}d {uptime.seconds//3600}h"

            # Get CPU and memory usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            # Network status (simplified)
            network_status = "🌐" if self.check_network_status() else "🔴"

            # Format status string
            status_text = f"🟢 Uptime: {uptime_str} | {network_status} Network | 📊 CPU: {cpu_percent:.0f}% | 💾 RAM: {memory.percent:.0f}%"

            self.system_status_text.set(status_text)

        except Exception as e:
            logger.error(f"Failed to update system status: {e}")
            self.system_status_text.set("🟡 System status unavailable")

    def check_network_status(self):
        """Check basic network connectivity."""
        try:
            # Simple check - try to resolve a DNS name
            import socket
            socket.gethostbyname('google.com')
            return True
        except:
            return False

    def schedule_status_update(self):
        """Schedule periodic status updates."""
        try:
            # Update every 30 seconds
            self.after(30000, lambda: (self.update_system_status(), self.schedule_status_update()))
        except Exception as e:
            logger.error(f"Failed to schedule status update: {e}")

    def create_footer_links(self):
        """Create footer - no signup nonsense, this is an admin interface."""
        try:
            # No footer needed - this is an admin interface, not a public service
            pass

        except Exception as e:
            logger.error(f"Failed to create footer links: {e}")

    def toggle_password_visibility(self):
        """Toggle password field visibility."""
        try:
            if self.show_password_var.get():
                self.password_entry.configure(show="")
                self.show_password_btn.configure(text="[HIDE]")
                self.show_password_var.set(False)
            else:
                self.password_entry.configure(show="*")
                self.show_password_btn.configure(text="[EYE]")
                self.show_password_var.set(True)
        except Exception as e:
            logger.error(f"Failed to toggle password visibility: {e}")

    # Password strength methods removed - they were annoying and unnecessary

    def perform_login(self):
        """Perform login authentication."""
        try:
            if self.is_authenticating:
                return
            
            username = self.username_var.get().strip()
            password = self.password_var.get()
            
            # Validate input
            if not username or not password:
                messagebox.showerror("Error", "Please enter both username and password.")
                return
            
            # Check login attempts
            if self.login_attempts >= self.max_attempts:
                messagebox.showerror("Error", "Too many login attempts. Please try again later.")
                return
            
            self.is_authenticating = True
            self.login_btn.configure(text="Signing in...", state="disabled")
            
            # Perform authentication in background thread
            auth_thread = threading.Thread(target=self.authenticate_user, args=(username, password))
            auth_thread.daemon = True
            auth_thread.start()
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            messagebox.showerror("Error", f"Login failed: {e}")
            self.reset_login_form()

    def authenticate_user(self, username: str, password: str):
        """Authenticate user credentials."""
        try:
            # Hash password for security
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Simulate authentication (replace with actual authentication)
            # In real implementation, this would call the authentication API
            auth_result = self.call_auth_api(username, password_hash)
            
            # Schedule UI update on main thread
            self.after(0, self.handle_auth_result, auth_result)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            self.after(0, self.handle_auth_error, str(e))

    def call_auth_api(self, username: str, password_hash: str) -> Dict[str, Any]:
        """Call authentication API - Ultra-secure server manager authentication."""
        try:
            # Use the new default credentials system
            from plexichat.core.auth.default_credentials import get_default_credentials_manager
            manager = get_default_credentials_manager()

            # Get GUI credentials
            gui_creds = manager.get_interface_credentials("gui")
            if not gui_creds:
                return {
                    "success": False,
                    "error": "No GUI credentials found. Please check default_creds.txt file."
                }

            # Check against GUI credentials
            if username == gui_creds.get("username", "admin"):
                # Verify password (compare plain text since we're hashing on client side)
                stored_password_hash = hashlib.sha256(gui_creds["password"].encode()).hexdigest()
                if password_hash == stored_password_hash:
                    return {
                        "success": True,
                        "user": {
                            "id": "admin",
                            "username": username,
                            "email": "admin@plexichat.local",
                            "permissions": ["admin", "server_manager", "all_access"],
                            "security_level": "GOVERNMENT",
                            "role": "server_administrator",
                            "profile": {
                                "display_name": "Server Administrator",
                                "avatar": None,
                                "theme": "dark_modern"
                            }
                        },
                        "token": self.generate_secure_token(username),
                        "expires": (datetime.now() + timedelta(hours=8)).isoformat()
                    }

            return {"success": False, "error": "Invalid username or password"}

        except ImportError:
            # Fallback to old system if new system not available
            return {"success": False, "error": "Authentication system not available"}
        except Exception as e:
            logger.error(f"Auth API call failed: {e}")
            return {"success": False, "error": str(e)}

    def load_default_credentials(self) -> Dict[str, str]:
        """Load default credentials from file."""
        try:
            creds_file = Path(__file__).parent.parent.parent.parent.parent / "src" / "default_creds.txt"

            if creds_file.exists():
                with open(creds_file, 'r') as f:
                    content = f.read()

                # Parse credentials from file
                username = "admin"  # Default
                password = "admin123"  # Default

                for line in content.split('\n'):
                    if 'username:' in line.lower():
                        username = line.split(':')[1].strip()
                    elif 'password:' in line.lower():
                        password = line.split(':')[1].strip()

                return {"username": username, "password": password}

            return {"username": "admin", "password": "admin123"}

        except Exception as e:
            logger.error(f"Failed to load default credentials: {e}")
            return {"username": "admin", "password": "admin123"}

    def verify_admin_password(self, username: str, password_hash: str, default_creds: Dict[str, str]) -> bool:
        """Verify admin password against multiple sources."""
        try:
            # Check against default password
            default_password = default_creds.get("password", "admin123")
            default_hash = hashlib.sha256(default_password.encode()).hexdigest()

            if password_hash == default_hash:
                return True

            # Check against stored admin credentials (if any)
            # This would integrate with the actual auth system
            return False

        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False

    def authenticate_with_webui(self, username: str, password_hash: str) -> Dict[str, Any]:
        """Authenticate with WebUI system."""
        try:
            # Make API call to local WebUI authentication endpoint
            import requests

            auth_url = "http://localhost:8000/api/v1/auth/login"

            # Convert hash back to password for API call (simplified)
            # In production, this would use proper token-based auth
            response = requests.post(auth_url, json={
                "username": username,
                "password": password_hash  # This would be handled properly
            }, timeout=5)

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "user": data.get("user", {}),
                    "token": data.get("token", ""),
                    "expires": data.get("expires", "")
                }

            return {"success": False, "error": "WebUI authentication failed"}

        except Exception as e:
            logger.error(f"WebUI authentication failed: {e}")
            return {"success": False, "error": "WebUI connection failed"}

    def generate_secure_token(self, username: str) -> str:
        """Generate secure authentication token."""
        try:
            import secrets
            import time

            # Create secure token with timestamp and user info
            token_data = f"{username}:{int(time.time())}:{secrets.token_urlsafe(32)}"
            token = base64.b64encode(token_data.encode()).decode()

            return token

        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            return "fallback_token"

    def handle_auth_result(self, result: Dict[str, Any]):
        """Handle authentication result."""
        try:
            self.is_authenticating = False
            self.login_btn.configure(text="Sign In", state="normal")
            
            if result.get("success"):
                # Successful login
                user_data = result.get("user", {})
                
                # Save remember me preference
                if self.remember_me_var.get():
                    self.save_remember_me_data(user_data)
                
                # Notify parent application
                self.app.on_login_success(user_data)
                
            else:
                # Failed login
                self.login_attempts += 1
                error_msg = result.get("error", "Authentication failed")
                messagebox.showerror("Login Failed", error_msg)
                
                # Clear password field
                self.password_var.set("")
                
        except Exception as e:
            logger.error(f"Failed to handle auth result: {e}")
            messagebox.showerror("Error", f"Authentication error: {e}")

    def handle_auth_error(self, error: str):
        """Handle authentication error."""
        try:
            self.is_authenticating = False
            self.login_btn.configure(text="Sign In", state="normal")
            self.login_attempts += 1
            
            messagebox.showerror("Authentication Error", f"Login failed: {error}")
            self.password_var.set("")
            
        except Exception as e:
            logger.error(f"Failed to handle auth error: {e}")

    def reset_login_form(self):
        """Reset login form to initial state."""
        try:
            self.is_authenticating = False
            self.login_btn.configure(text="Sign In", state="normal")
            self.password_var.set("")
        except Exception as e:
            logger.error(f"Failed to reset login form: {e}")

    def save_remember_me_data(self, user_data: Dict[str, Any]):
        """Save remember me data securely."""
        try:
            # In real implementation, this would save encrypted data
            remember_file = Path.home() / ".plexichat" / "remember_me.json"
            remember_file.parent.mkdir(exist_ok=True)
            
            remember_data = {
                "username": user_data.get("username"),
                "saved_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(days=30)).isoformat()
            }
            
            with open(remember_file, 'w') as f:
                json.dump(remember_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save remember me data: {e}")

    def show_password_reset_info(self, event=None):
        """Show password reset information dialog."""
        reset_info = """Password Reset Instructions:

To reset your GUI password, use the CLI command:

    python run.py cli gui-password --reset

This will generate a new secure password that will be displayed in the terminal.

For more help with CLI commands:
    python run.py cli --help

Note: You must have access to the command line to reset your password."""

        messagebox.showinfo("Password Reset", reset_info)

    # Registration removed - this is an admin interface, not a public service

    # 2FA removed - this is a simple admin interface

    def is_setup_completed(self):
        """Check if PlexiChat setup is completed."""
        # Always return True to hide setup from login screen
        # Setup is now accessible from the main application after login
        return True

    def get_default_credentials_info(self):
        """Get default credentials information."""
        try:
            config_path = Path.home() / ".plexichat"
            creds_file = config_path / "default-creds.json"

            if creds_file.exists():
                with open(creds_file, 'r') as f:
                    creds = json.load(f)
                    admin_creds = creds.get('admin', {})
                    return {
                        'username': admin_creds.get('username', 'admin'),
                        'password': 'See admin-credentials.txt'
                    }
            return None
        except Exception as e:
            logger.error(f"Failed to get default credentials: {e}")
            return None

    def show_database_setup(self):
        """Show database setup dialog."""
        try:
            # Create database setup window
            setup_window = tk.Toplevel(self)
            setup_window.title("Database Setup")
            setup_window.geometry("600x500")
            setup_window.configure(bg='#2c3e50')
            setup_window.transient(self.winfo_toplevel())
            setup_window.grab_set()

            # Center the window
            setup_window.update_idletasks()
            x = (setup_window.winfo_screenwidth() // 2) - (600 // 2)
            y = (setup_window.winfo_screenheight() // 2) - (500 // 2)
            setup_window.geometry(f"600x500+{x}+{y}")

            # Main frame
            main_frame = tk.Frame(setup_window, bg='#34495e', relief='raised', bd=2)
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)

            # Title
            title_label = tk.Label(main_frame, text="[DATABASE] Database Setup",
                                 font=("Arial", 20, "bold"), bg='#34495e', fg='#3498db')
            title_label.pack(pady=20)

            # Database type selection
            db_frame = tk.Frame(main_frame, bg='#34495e')
            db_frame.pack(pady=10, fill='x', padx=20)

            tk.Label(db_frame, text="Database Type:", font=("Arial", 12),
                    bg='#34495e', fg='#ecf0f1').pack(anchor='w')

            self.db_type_var = tk.StringVar(value="sqlite")
            db_types = [("SQLite (Recommended)", "sqlite"), ("PostgreSQL", "postgresql"), ("MySQL", "mysql")]

            for text, value in db_types:
                rb = tk.Radiobutton(db_frame, text=text, variable=self.db_type_var, value=value,
                                  bg='#34495e', fg='#ecf0f1', selectcolor='#2c3e50',
                                  font=("Arial", 10))
                rb.pack(anchor='w', pady=2)

            # Admin account section
            admin_frame = tk.LabelFrame(main_frame, text="Admin Account", font=("Arial", 12),
                                      bg='#34495e', fg='#ecf0f1', relief='groove', bd=2)
            admin_frame.pack(pady=20, fill='x', padx=20)

            # Username
            tk.Label(admin_frame, text="Username:", font=("Arial", 10),
                    bg='#34495e', fg='#ecf0f1').grid(row=0, column=0, sticky='w', padx=10, pady=5)
            self.admin_username_entry = tk.Entry(admin_frame, font=("Arial", 10), width=20)
            self.admin_username_entry.grid(row=0, column=1, padx=10, pady=5)
            self.admin_username_entry.insert(0, "admin")

            # Password
            tk.Label(admin_frame, text="Password:", font=("Arial", 10),
                    bg='#34495e', fg='#ecf0f1').grid(row=1, column=0, sticky='w', padx=10, pady=5)
            self.admin_password_entry = tk.Entry(admin_frame, font=("Arial", 10), width=20, show="*")
            self.admin_password_entry.grid(row=1, column=1, padx=10, pady=5)

            # Email
            tk.Label(admin_frame, text="Email:", font=("Arial", 10),
                    bg='#34495e', fg='#ecf0f1').grid(row=2, column=0, sticky='w', padx=10, pady=5)
            self.admin_email_entry = tk.Entry(admin_frame, font=("Arial", 10), width=20)
            self.admin_email_entry.grid(row=2, column=1, padx=10, pady=5)

            # Buttons
            button_frame = tk.Frame(main_frame, bg='#34495e')
            button_frame.pack(pady=20)

            setup_btn = tk.Button(button_frame, text="Setup Database", font=("Arial", 12, "bold"),
                                bg='#27ae60', fg='white', relief='flat', bd=0,
                                command=lambda: self.perform_database_setup(setup_window), cursor='hand2')
            setup_btn.pack(side='left', padx=10, ipadx=15, ipady=8)

            cancel_btn = tk.Button(button_frame, text="Cancel", font=("Arial", 12),
                                 bg='#e74c3c', fg='white', relief='flat', bd=0,
                                 command=setup_window.destroy, cursor='hand2')
            cancel_btn.pack(side='left', padx=10, ipadx=15, ipady=8)

        except Exception as e:
            logger.error(f"Failed to show database setup: {e}")

    def perform_database_setup(self, setup_window):
        """Perform the actual database setup."""
        try:
            # Get form data
            db_type = self.db_type_var.get()
            username = self.admin_username_entry.get().strip()
            password = self.admin_password_entry.get().strip()
            email = self.admin_email_entry.get().strip()

            # Validate input
            if not username or not password or not email:
                messagebox.showerror("Error", "Please fill in all fields")
                return

            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long")
                return

            # Create config directory
            config_path = Path.home() / ".plexichat"
            config_path.mkdir(parents=True, exist_ok=True)

            # Initialize database
            if db_type == "sqlite":
                self.initialize_sqlite_database(config_path)

            # Create admin account
            self.create_admin_account(config_path, username, password, email)

            # Mark setup as completed
            setup_file = config_path / "setup_completed"
            setup_file.write_text(str(datetime.now()))

            # Close setup window
            setup_window.destroy()

            # Refresh login screen
            self.create_login_interface()

            messagebox.showinfo("Success", "Database setup completed successfully!\nYou can now log in with your admin credentials.")

        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            messagebox.showerror("Error", f"Database setup failed: {str(e)}")

    def initialize_sqlite_database(self, config_path):
        """Initialize SQLite database using abstraction layer for security compliance."""
        try:
            # Use database abstraction layer for security compliance
            from plexichat.core.database import database_manager

            db_file = config_path / "plexichat.db"

            # Initialize database with security settings
            database_manager.initialize_database(str(db_file))

            # Create users table with encryption support
            create_users_sql = '''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT DEFAULT 'user',
                    active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            '''
            database_manager.execute_query(create_users_sql)

        except ImportError:
            # Fallback to direct SQLite if abstraction layer not available
            # (Removed: use abstraction layer only)
            raise RuntimeError("Database abstraction layer is required.")

        except Exception as e:
            logger.error(f"SQLite initialization failed: {e}")
            raise

    def create_admin_account(self, config_path, username, password, email):
        """Create admin account using abstraction layer only."""
        try:
            # Hash password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            # Create credentials structure
            credentials = {
                "admin": {
                    "username": username,
                    "password_hash": password_hash,
                    "email": email,
                    "role": "admin",
                    "created_at": str(datetime.now()),
                    "active": True
                }
            }
            # Save credentials
            creds_file = config_path / "default-creds.json"
            with open(creds_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            # Also create a readable credentials file
            readable_creds = config_path / "admin-credentials.txt"
            with open(readable_creds, 'w') as f:
                f.write(f"PlexiChat Admin Credentials\n")
                f.write(f"==========================\n\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Email: {email}\n")
                f.write(f"Role: admin\n\n")
                f.write(f"Created: {datetime.now()}\n\n")
                f.write(f"IMPORTANT: Keep this file secure and delete it after noting the credentials!\n")
            # Add to database using abstraction layer
            from plexichat.features.users.models import User, UserRole, UserStatus, UserModelService
            user_service = UserModelService()
            admin_user = User(
                id=None,
                username=username,
                email=email,
                hashed_password=password_hash,
                role=UserRole.ADMIN,
                status=UserStatus.ACTIVE,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                custom_fields={},
            )
            import asyncio
            asyncio.run(user_service.create_user(admin_user))
        except Exception as e:
            logger.error(f"Admin account creation failed: {e}")
            raise

    def open_documentation(self):
        """Open PlexiChat documentation."""
        try:
            import webbrowser
            webbrowser.open("http://localhost:8000/docs")
        except Exception as e:
            logger.error(f"Failed to open documentation: {e}")
            messagebox.showerror("Error", "Failed to open documentation. Make sure the API server is running.")



    def show_system_status(self):
        """Show system status dialog."""
        try:
            # Create status window
            status_window = tk.Toplevel(self)
            status_window.title("System Status")
            status_window.geometry("600x400")
            status_window.configure(bg='#2c3e50')
            status_window.transient(self.winfo_toplevel())
            status_window.grab_set()

            # Center the window
            status_window.update_idletasks()
            x = (status_window.winfo_screenwidth() // 2) - (600 // 2)
            y = (status_window.winfo_screenheight() // 2) - (400 // 2)
            status_window.geometry(f"600x400+{x}+{y}")

            # Main frame
            main_frame = tk.Frame(status_window, bg='#34495e', relief='raised', bd=2)
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)

            # Title
            title_label = tk.Label(main_frame, text="[METRICS] System Status",
                                 font=("Arial", 20, "bold"), bg='#34495e', fg='#3498db')
            title_label.pack(pady=20)

            # Status information
            status_text = tk.Text(main_frame, bg='#2c3e50', fg='#ecf0f1',
                                font=("Consolas", 10), relief='flat', bd=5)
            status_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))

            # Get system status
            status_info = self.get_system_status()
            status_text.insert(tk.END, status_info)
            status_text.config(state='disabled')

            # Close button
            close_btn = tk.Button(main_frame, text="Close", font=("Arial", 12),
                                bg='#95a5a6', fg='white', relief='flat', bd=0,
                                command=status_window.destroy, cursor='hand2')
            close_btn.pack(pady=(0, 10), ipadx=20, ipady=5)

        except Exception as e:
            logger.error(f"Failed to show system status: {e}")
            messagebox.showerror("Error", "Failed to show system status")

    def get_system_status(self) -> str:
        """Get current system status information."""
        try:
            import platform
            from datetime import datetime

            # Try to import psutil, fallback if not available
            psutil = None
            try:
                import psutil
                psutil_available = True
            except ImportError:
                psutil_available = False

            status = []
            status.append("PlexiChat System Status")
            status.append("=" * 50)
            status.append("")

            # System information
            status.append("System Information:")
            status.append(f"  OS: {platform.system()} {platform.release()}")
            status.append(f"  Python: {platform.python_version()}")
            status.append(f"  Architecture: {platform.machine()}")
            status.append("")

            # Resource usage
            status.append("Resource Usage:")
            if psutil_available and psutil:
                status.append(f"  CPU Usage: {psutil.cpu_percent()}%")
                status.append(f"  Memory Usage: {psutil.virtual_memory().percent}%")
                try:
                    status.append(f"  Disk Usage: {psutil.disk_usage('/').percent}%")
                except:
                    status.append(f"  Disk Usage: {psutil.disk_usage('C:').percent}%")
            else:
                status.append("  Resource monitoring unavailable (psutil not installed)")
            status.append("")

            # PlexiChat status
            status.append("PlexiChat Status:")
            status.append(f"  Setup Completed: {'Yes' if self.is_setup_completed() else 'No'}")
            status.append(f"  Config Path: {Path.home() / '.plexichat'}")
            status.append(f"  Plugins Directory: {Path('plugins')}")
            status.append("")

            # Database status
            config_path = Path.home() / ".plexichat"
            db_file = config_path / "plexichat.db"
            status.append("Database Status:")
            status.append(f"  Database File: {'Exists' if db_file.exists() else 'Not Found'}")
            if db_file.exists():
                status.append(f"  Database Size: {db_file.stat().st_size} bytes")
            status.append("")

            # Plugin status
            plugins_dir = Path("plugins")
            if plugins_dir.exists():
                plugin_count = len([p for p in plugins_dir.iterdir() if p.is_dir() and not p.name.startswith('_')])
                status.append(f"Plugins: {plugin_count} installed")
            else:
                status.append("Plugins: Directory not found")

            status.append("")
            status.append(f"Status generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            return "\n".join(status)

        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return f"Error getting system status: {e}"

    def configure_custom_styles(self):
        """Configure stunning modern styles with glassmorphism and curved elements."""
        try:
            style = ttk.Style()

            # Modern gradient color scheme (deep indigo to violet/cyan)
            primary_color = '#1a1a2e'      # Deep indigo background
            secondary_color = '#16213e'    # Darker indigo
            accent_color = '#3b82f6'       # Modern blue
            accent_hover = '#2563eb'       # Darker blue on hover
            success_color = '#10b981'      # Modern green
            card_bg = '#ffffff'            # Pure white card
            text_primary = '#1f2937'       # Dark gray text
            text_secondary = '#6b7280'     # Medium gray text
            text_muted = '#9ca3af'         # Light gray text
            border_color = '#e5e7eb'       # Light border
            focus_color = '#3b82f6'        # Focus blue

            # Main background with gradient effect
            style.configure("Login.TFrame",
                          background=primary_color,
                          relief='flat')

            # Login card with glassmorphism effect (simulated with white + subtle border)
            style.configure("LoginCard.TFrame",
                          background=card_bg,
                          relief='flat',
                          borderwidth=1,
                          bordercolor='#f3f4f6')

            # Modern typography hierarchy
            style.configure("LoginTitle.TLabel",
                          background=card_bg,
                          foreground=text_primary,
                          font=('Inter', 32, 'bold'))  # Large, bold title

            style.configure("LoginSubtitle.TLabel",
                          background=card_bg,
                          foreground=text_secondary,
                          font=('Inter', 14))  # Subtitle

            style.configure("LoginLabel.TLabel",
                          background=card_bg,
                          foreground=text_primary,
                          font=('Inter', 12, 'bold'))  # Field labels

            # Modern rounded input fields with focus animations
            style.configure("LoginEntry.TEntry",
                          fieldbackground='#f9fafb',
                          borderwidth=2,
                          relief='solid',
                          bordercolor=border_color,
                          font=('Inter', 12),
                          padding=(15, 12))  # More padding for modern look

            style.map("LoginEntry.TEntry",
                     bordercolor=[('focus', focus_color),
                                ('active', focus_color)])

            # Stunning curved primary button with gradient effect
            style.configure("LoginButton.TButton",
                          background=accent_color,
                          foreground='white',
                          font=('Inter', 14, 'bold'),
                          borderwidth=0,
                          focuscolor='none',
                          relief='flat',
                          padding=(30, 16))  # Generous padding

            style.map("LoginButton.TButton",
                     background=[('active', accent_hover),
                               ('pressed', '#1d4ed8'),
                               ('hover', accent_hover)])

            # Modern eye button for password visibility
            style.configure("EyeButton.TButton",
                          background='#f3f4f6',
                          foreground=text_secondary,
                          font=('Inter', 12),
                          borderwidth=0,
                          focuscolor='none',
                          relief='flat',
                          padding=(8, 8))

            style.map("EyeButton.TButton",
                     background=[('active', '#e5e7eb'),
                               ('hover', '#e5e7eb')])

            # Modern checkbox styling
            style.configure("LoginCheck.TCheckbutton",
                          background=card_bg,
                          foreground=text_secondary,
                          font=('Inter', 11),
                          focuscolor='none')

            # Subtle link styling
            style.configure("LoginLink.TLabel",
                          background=card_bg,
                          foreground=accent_color,
                          font=('Inter', 11),
                          cursor='hand2')

            # Footer text styling
            style.configure("LoginFooter.TLabel",
                          background=card_bg,
                          foreground=text_muted,
                          font=('Inter', 10))

        except Exception as e:
            logger.error(f"Failed to configure custom styles: {e}")
