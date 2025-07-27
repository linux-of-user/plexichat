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
        self.remember_var = tk.BooleanVar()  # Fixed variable name
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
        """Create modern dark mode toggle switch in top-right corner."""
        try:
            # Create modern toggle switch using Canvas
            canvas_bg = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
            self.toggle_canvas = tk.Canvas(
                self,
                width=80, height=40,
                highlightthickness=0,
                bg=canvas_bg
            )
            self.toggle_canvas.place(relx=0.95, rely=0.05, anchor="ne")

            # Draw the toggle switch
            self.draw_toggle_switch()

            # Bind click event
            self.toggle_canvas.bind("<Button-1>", lambda e: self.toggle_dark_mode())
            self.toggle_canvas.configure(cursor='hand2')

        except Exception as e:
            logger.error(f"Failed to create dark mode toggle: {e}")

    def draw_toggle_switch(self):
        """Draw the modern toggle switch."""
        try:
            self.toggle_canvas.delete("all")

            # Toggle switch dimensions
            switch_width = 50
            switch_height = 25
            switch_x = 15
            switch_y = 7

            # Colors based on mode
            if self.dark_mode.get():
                # Dark mode - switch is ON
                track_color = '#3b82f6'  # Blue when on
                thumb_color = '#ffffff'  # White thumb
                icon = '🌙'
                thumb_x = switch_x + switch_width - 15  # Right position
            else:
                # Light mode - switch is OFF
                track_color = '#d1d5db'  # Gray when off
                thumb_color = '#ffffff'  # White thumb
                icon = '☀️'
                thumb_x = switch_x + 5  # Left position

            # Draw track (rounded rectangle)
            self.draw_rounded_rect(
                self.toggle_canvas,
                switch_x, switch_y,
                switch_x + switch_width, switch_y + switch_height,
                12, track_color
            )

            # Draw thumb (circle)
            thumb_radius = 10
            self.toggle_canvas.create_oval(
                thumb_x - thumb_radius, switch_y + 2,
                thumb_x + thumb_radius, switch_y + switch_height - 2,
                fill=thumb_color, outline='#e5e7eb', width=1
            )

            # Add icon
            self.toggle_canvas.create_text(
                5, 20, text=icon, font=('Inter', 12), anchor='w'
            )

        except Exception as e:
            logger.error(f"Failed to draw toggle switch: {e}")

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
            # Toggle the mode
            self.dark_mode.set(not self.dark_mode.get())

            # Redraw toggle switch with updated background
            if hasattr(self, 'toggle_canvas'):
                canvas_bg = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
                self.toggle_canvas.configure(bg=canvas_bg)
                self.draw_toggle_switch()

            # Reconfigure styles based on mode
            self.configure_custom_styles()

            # Update background gradient
            if hasattr(self, 'bg_canvas'):
                if self.dark_mode.get():
                    self.create_gradient_background()
                else:
                    self.create_light_gradient_background()

            # Store current form values before recreating
            current_username = self.username_var.get() if hasattr(self, 'username_var') else ""
            current_password = self.password_var.get() if hasattr(self, 'password_var') else ""
            current_remember = self.remember_var.get() if hasattr(self, 'remember_var') else False

            # Recreate the login form with new colors
            if hasattr(self, 'card_canvas'):
                self.card_canvas.destroy()
                self.create_glassmorphic_login_card()

            # Restore form values
            if current_username and hasattr(self, 'username_var'):
                self.username_var.set(current_username)
            if current_password and hasattr(self, 'password_var'):
                self.password_var.set(current_password)
            if hasattr(self, 'remember_var'):
                self.remember_var.set(current_remember)

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
        """Create the main login form with proper rounded corners and glassmorphism."""
        try:
            # Create the glassmorphic login card using Canvas
            self.create_glassmorphic_login_card()

        except Exception as e:
            logger.error(f"Failed to create login form: {e}")

    def create_glassmorphic_login_card(self):
        """Create a beautiful glassmorphic login card with rounded corners."""
        try:
            # Card dimensions
            card_width = 420
            card_height = 580
            corner_radius = 25

            # Create main canvas for the entire card
            canvas_bg = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
            self.card_canvas = tk.Canvas(
                self.main_frame,
                width=card_width,
                height=card_height,
                highlightthickness=0,
                bg=canvas_bg,
                bd=0
            )
            self.card_canvas.grid(row=0, column=0, padx=20, pady=20)

            # Draw glassmorphic background with blur effect
            self.draw_glassmorphic_card(card_width, card_height, corner_radius)

            # Create TRANSPARENT content frame - match the glass background
            if self.dark_mode.get():
                content_bg = '#8a8aaa'  # Match the EXTREME glass color exactly
            else:
                content_bg = '#9090b0'  # Match the EXTREME light glass exactly

            self.content_frame = tk.Frame(
                self.card_canvas,
                bg=content_bg,  # Transparent background
                bd=0,
                highlightthickness=0,
                relief='flat'
            )

            # Fill the entire card - no borders, no margins
            self.card_canvas.create_window(
                card_width // 2, card_height // 2,
                window=self.content_frame,
                anchor='center',
                width=card_width - 10,  # Just enough padding to not touch edges
                height=card_height - 10
            )

            # Add all the login elements
            self.create_card_content()

        except Exception as e:
            logger.error(f"Failed to create glassmorphic login card: {e}")

    def draw_glassmorphic_card(self, width, height, radius):
        """Draw REAL glassmorphic card - transparent, frosted glass effect."""
        try:
            # Clear the canvas first
            self.card_canvas.delete("all")

            # STEP 1: Draw shadow FIRST (behind everything)
            if self.dark_mode.get():
                shadow_color = '#0a0a15'  # Very dark shadow
            else:
                shadow_color = '#cbd5e1'  # Light shadow

            self.draw_rounded_rect(
                self.card_canvas,
                4, 4, width + 4, height + 4,
                radius, shadow_color
            )

            # STEP 2: Draw the ACTUAL glassmorphic card
            if self.dark_mode.get():
                # EXTREME GLASSMORPHISM: Make it SUPER visible
                # Background is #1a1a2e (very dark), make glass EXTREMELY light
                glass_bg = '#8a8aaa'  # EXTREMELY visible - almost white
                glass_border = '#aaaacc'  # Very bright border
                glass_highlight = '#ffffff'  # Pure white highlights
                glass_shadow = '#000000'  # Deep shadow

            else:
                # Light mode: EXTREME glass effect
                # Background is #f8fafc (very light), make glass much darker
                glass_bg = '#9090b0'  # Much darker glass - very visible
                glass_border = '#7070a0'  # Dark prominent border
                glass_highlight = '#ffffff'  # White highlights
                glass_shadow = '#00000080'  # Very visible shadow

            # Draw main glass card
            self.draw_rounded_rect(
                self.card_canvas, 0, 0, width, height, radius, glass_bg
            )

            # STEP 3: Add MORE VISIBLE glass effects
            if self.dark_mode.get():
                # BRIGHTER glass highlight on top edge (like light reflection)
                self.card_canvas.create_line(
                    radius//2, 2, width - radius//2, 2,
                    fill=glass_highlight, width=2
                )

                # BRIGHTER glass highlight on left edge
                self.card_canvas.create_line(
                    2, radius//2, 2, height - radius//2,
                    fill=glass_highlight, width=2
                )

                # Add inner glow effect
                self.card_canvas.create_rectangle(
                    3, 3, width-3, height-3,
                    outline='#6a6a80', width=1
                )

                # DRAMATIC frosted glass texture
                import random
                random.seed(42)  # Consistent pattern
                for i in range(8, width-8, 10):
                    for j in range(8, height-8, 10):
                        if random.random() < 0.5:  # 50% chance for texture dot
                            self.card_canvas.create_oval(
                                i, j, i+3, j+3,  # Even bigger dots
                                fill='#6a6a8a', outline=''  # Much more visible
                            )

            else:
                # Light mode glass effects
                # Glass highlight on top edge
                self.card_canvas.create_line(
                    radius//2, 2, width - radius//2, 2,
                    fill=glass_highlight, width=2
                )

                # Glass highlight on left edge
                self.card_canvas.create_line(
                    2, radius//2, 2, height - radius//2,
                    fill=glass_highlight, width=2
                )

                # Light mode DRAMATIC frosted texture
                import random
                random.seed(42)
                for i in range(8, width-8, 10):
                    for j in range(8, height-8, 10):
                        if random.random() < 0.4:
                            self.card_canvas.create_oval(
                                i, j, i+2, j+2,  # Bigger dots
                                fill='#b8c8d8', outline=''  # More visible
                            )

            # STEP 4: Glass border (very subtle)
            self.draw_rounded_rect_outline(
                self.card_canvas, 0, 0, width, height, radius, glass_border
            )

        except Exception as e:
            logger.error(f"Failed to draw glassmorphic card: {e}")

    def draw_rounded_rect(self, canvas, x1, y1, x2, y2, radius, color, alpha=100):
        """Draw a rounded rectangle (Tkinter compatible - no alpha)."""
        try:
            # Use solid colors only - Tkinter doesn't support alpha transparency
            fill_color = color

            # Draw rounded rectangle using arcs and rectangles
            # Main rectangles
            canvas.create_rectangle(x1 + radius, y1, x2 - radius, y2, fill=fill_color, outline='')
            canvas.create_rectangle(x1, y1 + radius, x2, y2 - radius, fill=fill_color, outline='')

            # Corner arcs
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, fill=fill_color, outline='')
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, fill=fill_color, outline='')
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, fill=fill_color, outline='')
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, fill=fill_color, outline='')

        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle: {e}")

    def draw_rounded_rect_outline(self, canvas, x1, y1, x2, y2, radius, color, alpha=100):
        """Draw a rounded rectangle outline (Tkinter compatible)."""
        try:
            outline_color = color

            # Draw rounded outline using arcs and lines
            # Top line
            canvas.create_line(x1 + radius, y1, x2 - radius, y1, fill=outline_color, width=2)
            # Right line
            canvas.create_line(x2, y1 + radius, x2, y2 - radius, fill=outline_color, width=2)
            # Bottom line
            canvas.create_line(x2 - radius, y2, x1 + radius, y2, fill=outline_color, width=2)
            # Left line
            canvas.create_line(x1, y2 - radius, x1, y1 + radius, fill=outline_color, width=2)

            # Corner arcs
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, outline=outline_color, width=2, style='arc')
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, outline=outline_color, width=2, style='arc')
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, outline=outline_color, width=2, style='arc')
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, outline=outline_color, width=2, style='arc')

        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle outline: {e}")
            
        except Exception as e:
            logger.error(f"Failed to create login form: {e}")

    def create_card_content(self):
        """Create the content inside the glassmorphic card."""
        try:
            # Modern logo and title
            self.create_modern_header()

            # Stylish form fields with rounded inputs
            self.create_modern_form_fields()

            # Clean login options
            self.create_modern_login_options()

            # Beautiful rounded buttons
            self.create_modern_action_buttons()

            # System status indicator
            self.create_modern_system_status()

        except Exception as e:
            logger.error(f"Failed to create card content: {e}")

    def create_modern_header(self):
        """Create modern header with beautiful logo."""
        try:
            # Logo frame with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            logo_frame = tk.Frame(self.content_frame, bg=content_bg, bd=0, highlightthickness=0)
            logo_frame.pack(pady=(30, 20))

            # Create modern logo with glassmorphic effect
            logo_canvas = tk.Canvas(logo_frame, width=100, height=100, highlightthickness=0, bg=content_bg, bd=0)
            logo_canvas.pack()

            # Draw modern glassmorphic logo
            self.draw_modern_logo(logo_canvas)

            # Modern title
            title_color = '#ffffff' if self.dark_mode.get() else '#1f2937'
            title_label = tk.Label(
                self.content_frame,
                text="PlexiChat",
                font=('Inter', 28, 'bold'),
                fg=title_color,
                bg=content_bg,
                bd=0
            )
            title_label.pack(pady=(10, 5))

            # Subtitle
            subtitle_color = '#d1d5db' if self.dark_mode.get() else '#6b7280'
            subtitle_label = tk.Label(
                self.content_frame,
                text="Management Interface",
                font=('Inter', 14),
                fg=subtitle_color,
                bg=content_bg,
                bd=0
            )
            subtitle_label.pack(pady=(0, 30))

        except Exception as e:
            logger.error(f"Failed to create modern header: {e}")

    def draw_modern_logo(self, canvas):
        """Draw a modern logo with proper Tkinter colors."""
        try:
            if self.dark_mode.get():
                # Dark mode: simple clean design
                # Main logo circle
                canvas.create_oval(15, 15, 85, 85, fill='#3b82f6', outline='#60a5fa', width=2)
                # Inner highlight
                canvas.create_oval(25, 25, 45, 45, fill='#60a5fa', outline='')
            else:
                # Light mode: clean with shadow
                # Shadow
                canvas.create_oval(17, 17, 87, 87, fill='#d1d5db', outline='')
                # Main circle
                canvas.create_oval(15, 15, 85, 85, fill='#3b82f6', outline='#2563eb', width=2)
                # Inner highlight
                canvas.create_oval(25, 25, 45, 45, fill='#60a5fa', outline='')

            # Modern "P" letter
            canvas.create_text(50, 50, text="P", fill="white", font=("Inter", 32, "bold"))

        except Exception as e:
            logger.error(f"Failed to draw modern logo: {e}")

    def create_modern_form_fields(self):
        """Create modern form fields with rounded inputs."""
        try:
            # Username field
            self.create_modern_input_field(
                self.content_frame,
                "👤 Username",
                self.username_var,
                "admin"
            )

            # Password field
            self.create_modern_password_field(
                self.content_frame,
                "🔒 Password",
                self.password_var
            )

        except Exception as e:
            logger.error(f"Failed to create modern form fields: {e}")

    def create_modern_input_field(self, parent, label_text, text_var, placeholder=""):
        """Create a modern rounded input field."""
        try:
            # Field container with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            field_frame = tk.Frame(parent, bg=content_bg, bd=0, highlightthickness=0)
            field_frame.pack(fill='x', padx=40, pady=(0, 20))

            # Label
            label_color = '#ffffff' if self.dark_mode.get() else '#374151'
            label = tk.Label(
                field_frame,
                text=label_text,
                font=('Inter', 12, 'bold'),
                fg=label_color,
                bg=content_bg,
                anchor='w'
            )
            label.pack(fill='x', pady=(0, 8))

            # Create rounded input using Canvas
            input_canvas = tk.Canvas(field_frame, height=50, highlightthickness=0, bg=content_bg, bd=0)
            input_canvas.pack(fill='x')

            # Draw rounded input background
            def draw_input_bg():
                input_canvas.delete("input_bg")
                width = input_canvas.winfo_width()
                if width > 1:  # Only draw if canvas is properly sized
                    if self.dark_mode.get():
                        # Glass input fields - subtle and transparent
                        bg_color = '#3a3a4e'  # Slightly darker glass
                        border_color = '#5a5a6e'  # Subtle border
                    else:
                        # Light glass inputs
                        bg_color = '#f8fafc'  # Very light glass
                        border_color = '#e2e8f0'  # Subtle border

                    self.draw_rounded_rect(input_canvas, 2, 2, width-2, 48, 12, bg_color)
                    self.draw_rounded_rect_outline(input_canvas, 1, 1, width-1, 49, 12, border_color)

            # Bind canvas resize to redraw background
            input_canvas.bind('<Configure>', lambda e: draw_input_bg())

            # Create actual entry widget
            entry_color = '#ffffff' if self.dark_mode.get() else '#111827'
            entry_bg = '#374151' if self.dark_mode.get() else '#f9fafb'

            entry = tk.Entry(
                input_canvas,
                textvariable=text_var,
                font=('Inter', 13),
                fg=entry_color,
                bg=entry_bg,
                bd=0,
                highlightthickness=0,
                insertbackground=entry_color
            )

            # Bind Enter key to login (for username field)
            entry.bind('<Return>', lambda e: self.perform_login())

            # Place entry in canvas
            input_canvas.create_window(20, 25, window=entry, anchor='w', width=300)

            # Set placeholder only if field is empty
            if placeholder and not entry.get():
                entry.insert(0, placeholder)

            return entry

        except Exception as e:
            logger.error(f"Failed to create modern input field: {e}")
            return None

    def create_modern_password_field(self, parent, label_text, text_var):
        """Create a modern password field with eye toggle."""
        try:
            # Field container with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            field_frame = tk.Frame(parent, bg=content_bg, bd=0, highlightthickness=0)
            field_frame.pack(fill='x', padx=40, pady=(0, 20))

            # Label
            label_color = '#ffffff' if self.dark_mode.get() else '#374151'
            label = tk.Label(
                field_frame,
                text=label_text,
                font=('Inter', 12, 'bold'),
                fg=label_color,
                bg=content_bg,
                anchor='w'
            )
            label.pack(fill='x', pady=(0, 8))

            # Create rounded input using Canvas
            input_canvas = tk.Canvas(field_frame, height=50, highlightthickness=0, bg=content_bg, bd=0)
            input_canvas.pack(fill='x')

            # Draw rounded input background
            def draw_password_bg():
                input_canvas.delete("password_bg")
                width = input_canvas.winfo_width()
                if width > 1:
                    if self.dark_mode.get():
                        # Glass password field
                        bg_color = '#3a3a4e'  # Slightly darker glass
                        border_color = '#5a5a6e'  # Subtle border
                    else:
                        # Light glass password field
                        bg_color = '#f8fafc'  # Very light glass
                        border_color = '#e2e8f0'  # Subtle border

                    self.draw_rounded_rect(input_canvas, 2, 2, width-2, 48, 12, bg_color)
                    self.draw_rounded_rect_outline(input_canvas, 1, 1, width-1, 49, 12, border_color)

            input_canvas.bind('<Configure>', lambda e: draw_password_bg())

            # Create password entry
            entry_color = '#ffffff' if self.dark_mode.get() else '#111827'
            entry_bg = '#374151' if self.dark_mode.get() else '#f9fafb'

            self.password_entry = tk.Entry(
                input_canvas,
                textvariable=text_var,
                font=('Inter', 13),
                fg=entry_color,
                bg=entry_bg,
                bd=0,
                highlightthickness=0,
                show='*',
                insertbackground=entry_color
            )

            # Bind Enter key to login
            self.password_entry.bind('<Return>', lambda e: self.perform_login())

            # Place password entry in canvas
            input_canvas.create_window(20, 25, window=self.password_entry, anchor='w', width=260)

            # Eye toggle button
            eye_btn = tk.Button(
                input_canvas,
                text="👁",
                font=('Inter', 14),
                fg=entry_color,
                bg=entry_bg,
                bd=0,
                highlightthickness=0,
                command=self.toggle_password_visibility,
                cursor='hand2'
            )
            input_canvas.create_window(320, 25, window=eye_btn, anchor='center')

        except Exception as e:
            logger.error(f"Failed to create modern password field: {e}")

    def create_modern_login_options(self):
        """Create modern login options with proper spacing."""
        try:
            # Options container with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            options_frame = tk.Frame(self.content_frame, bg=content_bg, bd=0, highlightthickness=0)
            options_frame.pack(fill='x', padx=40, pady=(0, 25))

            # Remember me (left side)
            remember_frame = tk.Frame(options_frame, bg=content_bg, bd=0, highlightthickness=0)
            remember_frame.pack(side='left')

            text_color = '#ffffff' if self.dark_mode.get() else '#374151'
            remember_check = tk.Checkbutton(
                remember_frame,
                text="☑ Remember me",
                variable=self.remember_var,
                font=('Inter', 11),
                fg=text_color,
                bg=content_bg,
                selectcolor='#3b82f6',
                activebackground=content_bg,
                activeforeground=text_color,
                bd=0,
                highlightthickness=0
            )
            remember_check.pack()

            # Reset password (right side)
            reset_frame = tk.Frame(options_frame, bg=content_bg, bd=0, highlightthickness=0)
            reset_frame.pack(side='right')

            link_color = '#3b82f6' if self.dark_mode.get() else '#2563eb'
            reset_link = tk.Label(
                reset_frame,
                text="🔁 Reset password?",
                font=('Inter', 11),
                fg=link_color,
                bg=content_bg,
                cursor='hand2'
            )
            reset_link.pack()
            reset_link.bind("<Button-1>", self.show_password_reset_info)

        except Exception as e:
            logger.error(f"Failed to create modern login options: {e}")

    def create_modern_action_buttons(self):
        """Create beautiful rounded action buttons."""
        try:
            # Button container with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            button_frame = tk.Frame(self.content_frame, bg=content_bg, bd=0, highlightthickness=0)
            button_frame.pack(fill='x', padx=40, pady=(0, 20))

            # Create rounded sign in button
            self.create_rounded_button(
                button_frame,
                "Sign In",
                self.perform_login,
                width=320,
                height=50,
                bg_color='#3b82f6',
                hover_color='#2563eb',
                text_color='#ffffff'
            )

        except Exception as e:
            logger.error(f"Failed to create modern action buttons: {e}")

    def create_rounded_button(self, parent, text, command, width=200, height=40,
                            bg_color='#3b82f6', hover_color='#2563eb', text_color='#ffffff'):
        """Create a beautiful rounded button with hover effects."""
        try:
            # Button canvas with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            btn_canvas = tk.Canvas(parent, width=width, height=height,
                                 highlightthickness=0, bg=content_bg, bd=0)
            btn_canvas.pack(pady=10)

            # Draw button background - FIXED VERSION
            def draw_button(color=bg_color):
                btn_canvas.delete("all")  # Clear everything
                # Draw shadow first
                shadow_color = '#d1d5db' if not self.dark_mode.get() else '#1f2937'
                btn_canvas.create_rectangle(3, 3, width-1, height-1, fill=shadow_color, outline='')
                # Draw main button
                btn_canvas.create_rectangle(0, 0, width-3, height-3, fill=color, outline='')
                # Redraw text on top
                btn_canvas.create_text(
                    width//2, height//2,
                    text=text,
                    fill=text_color,
                    font=('Inter', 14, 'bold')
                )

            # Initial draw
            draw_button()

            # Hover effects
            def on_enter(event):
                draw_button(hover_color)
                btn_canvas.configure(cursor='hand2')

            def on_leave(event):
                draw_button(bg_color)
                btn_canvas.configure(cursor='')

            def on_click(event):
                # Button press animation
                btn_canvas.delete("all")
                btn_canvas.create_rectangle(1, 1, width-2, height-2, fill='#1d4ed8', outline='')
                btn_canvas.create_text(width//2, height//2, text=text, fill=text_color, font=('Inter', 14, 'bold'))
                btn_canvas.after(100, lambda: draw_button(hover_color))
                # Execute command
                if command:
                    command()

            # Bind events
            btn_canvas.bind("<Enter>", on_enter)
            btn_canvas.bind("<Leave>", on_leave)
            btn_canvas.bind("<Button-1>", on_click)

            return btn_canvas

        except Exception as e:
            logger.error(f"Failed to create rounded button: {e}")
            return None

    def create_modern_system_status(self):
        """Create modern system status indicator."""
        try:
            # Status container with frosted glass background
            content_bg = '#9090b0' if not self.dark_mode.get() else '#8a8aaa'
            status_frame = tk.Frame(self.content_frame, bg=content_bg, bd=0, highlightthickness=0)
            status_frame.pack(fill='x', padx=40, pady=(10, 20))

            # System status label
            status_color = '#9ca3af' if self.dark_mode.get() else '#6b7280'
            self.status_label = tk.Label(
                status_frame,
                textvariable=self.system_status_text,
                font=('Inter', 9),
                fg=status_color,
                bg=content_bg,
                justify='center'
            )
            self.status_label.pack()

            # Start updating system status
            self.update_system_status()
            self.schedule_status_update()

        except Exception as e:
            logger.error(f"Failed to create modern system status: {e}")

    def create_rounded_login_card(self):
        """Create rounded login card with drop shadow and glassmorphism effect."""
        try:
            # Card dimensions
            card_width = 450
            card_height = 600
            corner_radius = 20

            # Create canvas for the card
            self.login_card_canvas = tk.Canvas(
                self.main_frame,
                width=card_width,
                height=card_height,
                highlightthickness=0,
                bg='transparent'
            )
            self.login_card_canvas.grid(row=0, column=0, sticky="nsew")

            # Draw drop shadow (offset rounded rectangle)
            shadow_offset = 5
            shadow_color = '#00000020' if self.dark_mode.get() else '#00000015'
            self.draw_rounded_rectangle(
                self.login_card_canvas,
                shadow_offset, shadow_offset,
                card_width + shadow_offset, card_height + shadow_offset,
                corner_radius, shadow_color
            )

            # Draw main card (glassmorphism effect)
            card_color = '#ffffff' if not self.dark_mode.get() else '#ffffff10'
            self.draw_rounded_rectangle(
                self.login_card_canvas,
                0, 0,
                card_width, card_height,
                corner_radius, card_color
            )

            # Add subtle border for glassmorphism
            border_color = '#e5e7eb' if not self.dark_mode.get() else '#ffffff20'
            self.draw_rounded_rectangle_border(
                self.login_card_canvas,
                1, 1,
                card_width - 1, card_height - 1,
                corner_radius, border_color
            )

        except Exception as e:
            logger.error(f"Failed to create rounded login card: {e}")

    def draw_rounded_rectangle(self, canvas, x1, y1, x2, y2, radius, fill_color):
        """Draw a rounded rectangle on canvas."""
        try:
            # Create rounded rectangle using arcs and rectangles
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, fill=fill_color, outline="")
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, fill=fill_color, outline="")
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, fill=fill_color, outline="")
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, fill=fill_color, outline="")

            # Fill the middle areas
            canvas.create_rectangle(x1 + radius, y1, x2 - radius, y2,
                                  fill=fill_color, outline="")
            canvas.create_rectangle(x1, y1 + radius, x2, y2 - radius,
                                  fill=fill_color, outline="")

        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle: {e}")

    def draw_rounded_rectangle_border(self, canvas, x1, y1, x2, y2, radius, border_color):
        """Draw a rounded rectangle border on canvas."""
        try:
            # Draw border arcs
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, outline=border_color, width=1, style='arc')
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, outline=border_color, width=1, style='arc')
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, outline=border_color, width=1, style='arc')
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, outline=border_color, width=1, style='arc')

            # Draw border lines
            canvas.create_line(x1 + radius, y1, x2 - radius, y1, fill=border_color, width=1)
            canvas.create_line(x1 + radius, y2, x2 - radius, y2, fill=border_color, width=1)
            canvas.create_line(x1, y1 + radius, x1, y2 - radius, fill=border_color, width=1)
            canvas.create_line(x2, y1 + radius, x2, y2 - radius, fill=border_color, width=1)

        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle border: {e}")

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

            # Dynamic color scheme based on dark mode
            if self.dark_mode.get():
                # Dark mode colors
                primary_color = '#1a1a2e'      # Deep indigo background
                card_bg = '#ffffff15'          # Semi-transparent white for glassmorphism
                text_primary = '#ffffff'       # White text
                text_secondary = '#d1d5db'     # Light gray text
                text_muted = '#9ca3af'         # Medium gray text
                border_color = '#374151'       # Dark border
                input_bg = '#374151'           # Dark input background
            else:
                # Light mode colors
                primary_color = '#f8fafc'      # Light background
                card_bg = '#ffffff'            # Pure white card
                text_primary = '#1f2937'       # Dark gray text
                text_secondary = '#6b7280'     # Medium gray text
                text_muted = '#9ca3af'         # Light gray text
                border_color = '#e5e7eb'       # Light border
                input_bg = '#f9fafb'           # Light input background

            # Universal colors
            accent_color = '#3b82f6'       # Modern blue
            accent_hover = '#2563eb'       # Darker blue on hover
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
                          fieldbackground=input_bg,
                          borderwidth=2,
                          relief='solid',
                          bordercolor=border_color,
                          font=('Inter', 13),
                          padding=(18, 14),  # Extra padding for modern look
                          foreground=text_primary)

            style.map("LoginEntry.TEntry",
                     bordercolor=[('focus', focus_color),
                                ('active', focus_color)],
                     fieldbackground=[('focus', card_bg)])

            # Stunning curved primary button with gradient effect and hover animations
            style.configure("LoginButton.TButton",
                          background=accent_color,
                          foreground='white',
                          font=('Inter', 16, 'bold'),
                          borderwidth=0,
                          focuscolor='none',
                          relief='flat',
                          padding=(35, 18))  # Extra generous padding for modern look

            style.map("LoginButton.TButton",
                     background=[('active', accent_hover),
                               ('pressed', '#1d4ed8'),
                               ('hover', accent_hover)],
                     relief=[('pressed', 'sunken'),
                           ('hover', 'raised')])

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
