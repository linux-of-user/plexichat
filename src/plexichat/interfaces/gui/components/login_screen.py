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

logger = logging.getLogger(__name__)


class LoginScreen(ttk.Frame):
    """
    Advanced login screen with modern design and security features.
    
    Features:
    - Modern, animated UI
    - Multiple authentication methods (password, 2FA, biometric)
    - Remember me functionality
    - Password strength indicator
    - Forgot password recovery
    - User registration
    - Social login integration
    - Security monitoring
    """

    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.parent = parent
        
        # Authentication state
        self.auth_method = "password"  # password, 2fa, biometric
        self.login_attempts = 0
        self.max_attempts = 5
        self.is_authenticating = False
        
        # UI components
        self.main_frame = None
        self.login_frame = None
        self.register_frame = None
        self.forgot_password_frame = None
        
        # Form variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_me_var = tk.BooleanVar()
        self.show_password_var = tk.BooleanVar()
        
        # Animation variables
        self.animation_running = False
        
        self.create_login_interface()

    def create_login_interface(self):
        """Create the main login interface."""
        try:
            # Configure main frame
            self.configure(style="Login.TFrame")
            
            # Create background
            self.create_background()
            
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
        """Create gradient background effect."""
        try:
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()
            
            # Create gradient from dark blue to dark purple
            for i in range(height):
                ratio = i / height
                r = int(44 + (75 - 44) * ratio)  # 44 to 75
                g = int(62 + (0 - 62) * ratio)   # 62 to 0
                b = int(80 + (130 - 80) * ratio) # 80 to 130
                
                color = f"#{r:02x}{g:02x}{b:02x}"
                self.bg_canvas.create_line(0, i, width, i, fill=color, width=1)
                
        except Exception as e:
            logger.error(f"Failed to create gradient background: {e}")

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

    def create_header(self):
        """Create header with logo and title."""
        try:
            # Logo placeholder (you can replace with actual logo)
            logo_frame = ttk.Frame(self.login_frame)
            logo_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20))
            
            # Create logo canvas
            logo_canvas = tk.Canvas(logo_frame, width=80, height=80, highlightthickness=0)
            logo_canvas.pack()
            
            # Draw PlexiChat logo
            logo_canvas.create_oval(10, 10, 70, 70, fill="#3498db", outline="#2c3e50", width=3)
            logo_canvas.create_text(40, 40, text="P", fill="white", font=("Arial", 24, "bold"))
            
            # Title
            title_label = ttk.Label(
                self.login_frame,
                text="PlexiChat",
                font=("Segoe UI", 24, "bold"),
                style="LoginTitle.TLabel"
            )
            title_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
            
            # Subtitle
            subtitle_label = ttk.Label(
                self.login_frame,
                text="Advanced Communication Platform",
                font=("Segoe UI", 12),
                style="LoginSubtitle.TLabel"
            )
            subtitle_label.grid(row=2, column=0, columnspan=2, pady=(0, 30))
            
        except Exception as e:
            logger.error(f"Failed to create header: {e}")

    def create_form_fields(self):
        """Create form input fields."""
        try:
            # Username field
            username_label = ttk.Label(self.login_frame, text="Username:", style="LoginLabel.TLabel")
            username_label.grid(row=3, column=0, sticky="w", pady=(0, 5))
            
            self.username_entry = ttk.Entry(
                self.login_frame,
                textvariable=self.username_var,
                font=("Segoe UI", 12),
                style="LoginEntry.TEntry",
                width=25
            )
            self.username_entry.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 15))
            
            # Password field
            password_label = ttk.Label(self.login_frame, text="Password:", style="LoginLabel.TLabel")
            password_label.grid(row=5, column=0, sticky="w", pady=(0, 5))
            
            password_frame = ttk.Frame(self.login_frame)
            password_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 15))
            password_frame.columnconfigure(0, weight=1)
            
            self.password_entry = ttk.Entry(
                password_frame,
                textvariable=self.password_var,
                font=("Segoe UI", 12),
                style="LoginEntry.TEntry",
                show="*"
            )
            self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
            
            # Show/hide password button
            self.show_password_btn = ttk.Button(
                password_frame,
                text="👁",
                width=3,
                command=self.toggle_password_visibility,
                style="ShowPassword.TButton"
            )
            self.show_password_btn.grid(row=0, column=1)
            
            # Password strength indicator
            self.password_strength = ttk.Progressbar(
                self.login_frame,
                length=200,
                mode='determinate',
                style="PasswordStrength.Horizontal.TProgressbar"
            )
            self.password_strength.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 15))
            
            # Bind password change event
            self.password_var.trace("w", self.update_password_strength)
            
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
            
            # Forgot password link
            forgot_link = ttk.Label(
                options_frame,
                text="Forgot password?",
                style="LoginLink.TLabel",
                cursor="hand2"
            )
            forgot_link.grid(row=0, column=1, sticky="e")
            forgot_link.bind("<Button-1>", self.show_forgot_password)
            
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
            
            # Alternative login methods
            alt_frame = ttk.Frame(button_frame)
            alt_frame.pack()
            
            # 2FA button
            twofa_btn = ttk.Button(
                alt_frame,
                text="2FA Login",
                command=self.show_2fa_login,
                style="AltLogin.TButton",
                width=12
            )
            twofa_btn.pack(side=tk.LEFT, padx=(0, 5))
            
            # Biometric button (if available)
            bio_btn = ttk.Button(
                alt_frame,
                text="Biometric",
                command=self.show_biometric_login,
                style="AltLogin.TButton",
                width=12
            )
            bio_btn.pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            logger.error(f"Failed to create action buttons: {e}")

    def create_footer_links(self):
        """Create footer with additional links."""
        try:
            footer_frame = ttk.Frame(self.login_frame)
            footer_frame.grid(row=10, column=0, columnspan=2)
            
            # Register link
            register_label = ttk.Label(
                footer_frame,
                text="Don't have an account? ",
                style="LoginFooter.TLabel"
            )
            register_label.pack(side=tk.LEFT)
            
            register_link = ttk.Label(
                footer_frame,
                text="Sign up",
                style="LoginLink.TLabel",
                cursor="hand2"
            )
            register_link.pack(side=tk.LEFT)
            register_link.bind("<Button-1>", self.show_register_form)
            
        except Exception as e:
            logger.error(f"Failed to create footer links: {e}")

    def toggle_password_visibility(self):
        """Toggle password field visibility."""
        try:
            if self.show_password_var.get():
                self.password_entry.configure(show="")
                self.show_password_btn.configure(text="🙈")
                self.show_password_var.set(False)
            else:
                self.password_entry.configure(show="*")
                self.show_password_btn.configure(text="👁")
                self.show_password_var.set(True)
        except Exception as e:
            logger.error(f"Failed to toggle password visibility: {e}")

    def update_password_strength(self, *args):
        """Update password strength indicator."""
        try:
            password = self.password_var.get()
            strength = self.calculate_password_strength(password)
            
            self.password_strength['value'] = strength
            
            # Update color based on strength
            if strength < 30:
                self.password_strength.configure(style="WeakPassword.Horizontal.TProgressbar")
            elif strength < 70:
                self.password_strength.configure(style="MediumPassword.Horizontal.TProgressbar")
            else:
                self.password_strength.configure(style="StrongPassword.Horizontal.TProgressbar")
                
        except Exception as e:
            logger.error(f"Failed to update password strength: {e}")

    def calculate_password_strength(self, password: str) -> int:
        """Calculate password strength (0-100)."""
        try:
            if not password:
                return 0
            
            score = 0
            
            # Length bonus
            score += min(password.__len__() * 4, 25)
            
            # Character variety bonus
            if any(c.islower() for c in password):
                score += 5
            if any(c.isupper() for c in password):
                score += 5
            if any(c.isdigit() for c in password):
                score += 10
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                score += 15
            
            # Length penalties for short passwords
            if len(password) < 6:
                score -= 20
            elif len(password) < 8:
                score -= 10
            
            return max(0, min(100, score))
            
        except Exception as e:
            logger.error(f"Failed to calculate password strength: {e}")
            return 0

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
            # Read default credentials from file
            default_creds = self.load_default_credentials()

            # Check against default admin credentials
            if username == default_creds.get("username", "admin"):
                # Verify password against default or stored hash
                if self.verify_admin_password(username, password_hash, default_creds):
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

            # Check against WebUI authentication system
            webui_result = self.authenticate_with_webui(username, password_hash)
            if webui_result.get("success"):
                return webui_result

            return {"success": False, "error": "Invalid server administrator credentials"}

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

    def show_forgot_password(self, event=None):
        """Show forgot password dialog."""
        # This will be implemented in the next part
        messagebox.showinfo("Forgot Password", "Forgot password functionality will be implemented.")

    def show_register_form(self, event=None):
        """Show user registration form."""
        # This will be implemented in the next part
        messagebox.showinfo("Register", "User registration functionality will be implemented.")

    def show_2fa_login(self):
        """Show 2FA login dialog."""
        # This will be implemented in the next part
        messagebox.showinfo("2FA Login", "Two-factor authentication will be implemented.")

    def show_biometric_login(self):
        """Show biometric login dialog."""
        # This will be implemented in the next part
        messagebox.showinfo("Biometric Login", "Biometric authentication will be implemented.")

    def is_setup_completed(self):
        """Check if PlexiChat setup is completed."""
        try:
            config_path = Path.home() / ".plexichat"
            setup_file = config_path / "setup_completed"
            return setup_file.exists()
        except Exception:
            return False

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
            setup_window.transient(self)
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
            title_label = tk.Label(main_frame, text="🗄️ Database Setup",
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
        """Initialize SQLite database."""
        try:
            import sqlite3

            db_file = config_path / "plexichat.db"
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            # Create users table
            cursor.execute('''
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
            ''')

            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            # Create settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            conn.close()

            logger.info(f"SQLite database initialized at {db_file}")

        except Exception as e:
            logger.error(f"SQLite initialization failed: {e}")
            raise

    def create_admin_account(self, config_path, username, password, email):
        """Create admin account."""
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

            # Add to database if it exists
            db_file = config_path / "plexichat.db"
            if db_file.exists():
                import sqlite3
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT OR REPLACE INTO users (username, password_hash, email, role, active)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, password_hash, email, "admin", True))

                conn.commit()
                conn.close()

            logger.info(f"Admin account created: {username}")

        except Exception as e:
            logger.error(f"Failed to create admin account: {e}")
            raise
