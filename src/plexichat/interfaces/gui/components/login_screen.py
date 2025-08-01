"""
Modern Glassmorphic Login Screen for PlexiChat GUI
Features stunning glassmorphism, dark/light modes, and premium UX design.
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

logger = logging.getLogger(__name__)


class LoginScreen(tk.Frame):
    """
    Modern glassmorphic login screen with premium design and UX.
    
    Features:
    - True glassmorphism with frosted glass effects
    - Smooth dark/light mode toggle with animations
    - Modern rounded input fields with focus states
    - Animated starry background
    - Premium button design with hover effects
    - Responsive layout and professional typography
    """

    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.parent = parent
        
        # Authentication state
        self.auth_method = "password"
        self.login_attempts = 0
        self.max_attempts = 5
        self.is_authenticating = False

        # Form variables
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.remember_var = tk.BooleanVar()
        self.show_password_var = tk.BooleanVar()
        
        # Animation variables
        self.animation_running = False
        self.particles = []
        self.hover_animations = {}

        # Modern theme system
        self.dark_mode = tk.BooleanVar(value=True)
        self.system_status_text = tk.StringVar()
        self.start_time = datetime.now()

        # Load saved theme preference
        self.load_theme_preference()

        # Initialize the modern interface
        self.setup_modern_interface()

    def get_bg_color(self):
        """Get appropriate background color based on theme."""
        return '#1a1a2e' if self.dark_mode.get() else '#f8fafc'

    def setup_modern_interface(self):
        """Initialize the complete modern interface."""
        try:
            # Configure main container
            self.pack(fill='both', expand=True)
            
            # Create animated background
            self.create_animated_background()
            
            # Create modern dark mode toggle
            self.create_modern_toggle()
            
            # Create glassmorphic login panel
            self.create_glassmorphic_panel()
            
            # Start background animations
            self.start_animations()
            
            logger.info("Modern login interface initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup modern interface: {e}")
            messagebox.showerror("Error", f"Failed to initialize interface: {e}")

    def create_animated_background(self):
        """Create stunning animated starry background with gradients."""
        try:
            # Full-screen background canvas
            self.bg_canvas = tk.Canvas(
                self,
                highlightthickness=0,
                bd=0,
                relief='flat',
                bg='#1a1a2e'
            )
            self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
            
            # Create dynamic gradient background
            self.create_dynamic_gradient()
            
            # Initialize animated stars
            self.create_animated_stars()
            
        except Exception as e:
            logger.error(f"Failed to create animated background: {e}")

    def create_dynamic_gradient(self):
        """Create beautiful dynamic gradient background."""
        try:
            # Get screen dimensions
            self.update_idletasks()
            width = self.winfo_width() or self.winfo_screenwidth()
            height = self.winfo_height() or self.winfo_screenheight()

            if self.dark_mode.get():
                # Dark mode: Deep space gradient
                colors = [
                    (0.0, '#0a0a1a'),    # Deep space black
                    (0.3, '#1a1a2e'),    # Dark indigo
                    (0.6, '#16213e'),    # Deeper blue
                    (1.0, '#0f172a')     # Slate black
                ]
            else:
                # Light mode: Ethereal sky gradient
                colors = [
                    (0.0, '#f0f9ff'),    # Sky blue white
                    (0.4, '#e0f2fe'),    # Light cyan
                    (0.7, '#f0f9ff'),    # Back to white
                    (1.0, '#fafafa')     # Pure white
                ]

            # Draw gradient lines
            for i in range(height):
                ratio = i / height
                color = self.interpolate_gradient_color(colors, ratio)
                self.bg_canvas.create_line(0, i, width, i, fill=color, width=1)

        except Exception as e:
            logger.error(f"Failed to create dynamic gradient: {e}")

    def interpolate_gradient_color(self, colors, ratio):
        """Interpolate between gradient colors."""
        try:
            # Find the two colors to interpolate between
            for i in range(len(colors) - 1):
                if ratio <= colors[i + 1][0]:
                    # Interpolate between colors[i] and colors[i + 1]
                    t = (ratio - colors[i][0]) / (colors[i + 1][0] - colors[i][0])
                    
                    # Extract RGB values
                    c1 = colors[i][1].lstrip('#')
                    c2 = colors[i + 1][1].lstrip('#')
                    
                    r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
                    r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
                    
                    # Interpolate
                    r = int(r1 + (r2 - r1) * t)
                    g = int(g1 + (g2 - g1) * t)
                    b = int(b1 + (b2 - b1) * t)
                    
                    return f"#{r:02x}{g:02x}{b:02x}"
            
            return colors[-1][1]  # Return last color if ratio > 1
            
        except Exception as e:
            return '#1a1a2e'  # Fallback color

    def create_animated_stars(self):
        """Create beautiful animated floating stars."""
        try:
            self.particles = []
            star_count = 80 if self.dark_mode.get() else 40
            
            # Get canvas dimensions
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()
            
            for _ in range(star_count):
                x = random.randint(0, width)
                y = random.randint(0, height)
                size = random.randint(1, 4)
                speed = random.uniform(0.2, 1.0)
                opacity = random.uniform(0.3, 1.0)
                twinkle_speed = random.uniform(0.01, 0.05)
                
                # Create star colors based on theme
                if self.dark_mode.get():
                    colors = ['#ffffff', '#e0e7ff', '#c7d2fe', '#a5b4fc']
                else:
                    colors = ['#cbd5e1', '#94a3b8', '#64748b', '#475569']
                
                color = random.choice(colors)
                
                # Create star on canvas
                if size <= 2:
                    # Small stars as dots
                    star_id = self.bg_canvas.create_oval(
                        x, y, x + size, y + size,
                        fill=color, outline='', width=0
                    )
                else:
                    # Larger stars with sparkle effect
                    star_id = self.bg_canvas.create_polygon(
                        x, y-size, x+size//2, y-size//2, x+size, y,
                        x+size//2, y+size//2, x, y+size, x-size//2, y+size//2,
                        x-size, y, x-size//2, y-size//2,
                        fill=color, outline='', smooth=True
                    )
                
                self.particles.append({
                    'id': star_id,
                    'x': x, 'y': y,
                    'size': size,
                    'speed': speed,
                    'direction': random.uniform(0, 360),
                    'opacity': opacity,
                    'twinkle_speed': twinkle_speed,
                    'twinkle_phase': random.uniform(0, 2 * math.pi),
                    'color': color,
                    'base_color': color
                })
                
        except Exception as e:
            logger.error(f"Failed to create animated stars: {e}")

    def create_modern_toggle(self):
        """Create premium dark mode toggle with smooth animations."""
        try:
            # Toggle container with glassmorphic background
            bg_color = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
            toggle_container = tk.Frame(self, bg=bg_color)
            toggle_container.place(relx=0.95, rely=0.05, anchor='ne')

            # Toggle label
            theme_color = '#ffffff' if self.dark_mode.get() else '#1f2937'
            self.toggle_label = tk.Label(
                toggle_container,
                text="Dark Mode",
                font=('Inter', 11, 'normal'),
                fg=theme_color,
                bg=bg_color
            )
            self.toggle_label.pack(side='right', padx=(0, 12))

            # Modern toggle switch canvas
            self.toggle_canvas = tk.Canvas(
                toggle_container,
                width=60, height=32,
                highlightthickness=0,
                bg=bg_color,
                cursor='hand2'
            )
            self.toggle_canvas.pack(side='right')
            
            # Draw initial toggle state
            self.draw_modern_toggle()
            
            # Bind click events
            self.toggle_canvas.bind('<Button-1>', lambda e: self.animate_theme_toggle())
            self.toggle_canvas.bind('<Enter>', lambda e: self.on_toggle_hover(True))
            self.toggle_canvas.bind('<Leave>', lambda e: self.on_toggle_hover(False))
            
        except Exception as e:
            logger.error(f"Failed to create modern toggle: {e}")

    def draw_modern_toggle(self, hover=False):
        """Draw the premium toggle switch with smooth gradients."""
        try:
            self.toggle_canvas.delete('all')
            
            # Toggle dimensions
            track_width, track_height = 50, 24
            thumb_size = 20
            track_x, track_y = 5, 4
            
            # Colors based on state and theme
            if self.dark_mode.get():
                # Dark mode ON
                track_color = '#3b82f6' if not hover else '#2563eb'
                thumb_color = '#ffffff'
                thumb_shadow = '#1e40af'
                thumb_x = track_x + track_width - thumb_size - 2
                glow_color = '#3b82f6'
            else:
                # Light mode ON (toggle OFF visually)
                track_color = '#d1d5db' if not hover else '#9ca3af'
                thumb_color = '#ffffff'
                thumb_shadow = '#000000'
                thumb_x = track_x + 2
                glow_color = '#d1d5db'

            # Draw glow effect when enabled
            if self.dark_mode.get():
                self.toggle_canvas.create_oval(
                    track_x - 2, track_y - 2,
                    track_x + track_width + 2, track_y + track_height + 2,
                    fill='', outline=glow_color, width=2
                )

            # Draw track with rounded ends
            self.draw_rounded_rect(
                self.toggle_canvas,
                track_x, track_y,
                track_x + track_width, track_y + track_height,
                track_height // 2,
                track_color
            )

            # Draw thumb shadow
            self.toggle_canvas.create_oval(
                thumb_x + 1, track_y + 3,
                thumb_x + thumb_size + 1, track_y + thumb_size + 1,
                fill=thumb_shadow, outline=''
            )

            # Draw thumb
            self.toggle_canvas.create_oval(
                thumb_x, track_y + 2,
                thumb_x + thumb_size, track_y + thumb_size + 2,
                fill=thumb_color, outline='#e5e7eb', width=1
            )

            # Add theme icon on thumb
            icon = '?' if self.dark_mode.get() else '??'
            self.toggle_canvas.create_text(
                thumb_x + thumb_size//2, track_y + track_height//2 + 1,
                text=icon, font=('Arial', 10)
            )

        except Exception as e:
            logger.error(f"Failed to draw modern toggle: {e}")

    def on_toggle_hover(self, is_hover):
        """Handle toggle hover effects."""
        self.draw_modern_toggle(hover=is_hover)

    def animate_theme_toggle(self):
        """Animate the theme toggle with smooth transition."""
        try:
            # Toggle the mode
            self.dark_mode.set(not self.dark_mode.get())
            
            # Save preference
            self.save_theme_preference()
            
            # Animate toggle switch
            self.draw_modern_toggle()
            
            # Update theme colors smoothly
            self.update_theme_colors()
            
            # Refresh background gradient
            self.create_dynamic_gradient()
            
            # Update stars for new theme
            self.update_stars_for_theme()
            
            # Recreate glassmorphic panel with new theme
            if hasattr(self, 'glass_panel'):
                self.glass_panel.destroy()
            self.create_glassmorphic_panel()
            
        except Exception as e:
            logger.error(f"Failed to animate theme toggle: {e}")

    def update_theme_colors(self):
        """Update UI colors based on current theme."""
        try:
            # Update toggle label color
            theme_color = '#ffffff' if self.dark_mode.get() else '#1f2937'
            self.toggle_label.configure(fg=theme_color)
            
        except Exception as e:
            logger.error(f"Failed to update theme colors: {e}")

    def update_stars_for_theme(self):
        """Update star colors based on current theme."""
        try:
            if self.dark_mode.get():
                star_colors = ['#ffffff', '#e0e7ff', '#c7d2fe', '#a5b4fc']
                target_count = 80
            else:
                star_colors = ['#cbd5e1', '#94a3b8', '#64748b', '#475569']
                target_count = 40

            # Update existing stars
            for particle in self.particles:
                new_color = random.choice(star_colors)
                particle['color'] = new_color
                particle['base_color'] = new_color
                self.bg_canvas.itemconfig(particle['id'], fill=new_color)

            # Adjust star count
            current_count = len(self.particles)
            if current_count < target_count:
                # Add more stars for dark mode
                self.add_stars(target_count - current_count)
            elif current_count > target_count:
                # Remove stars for light mode
                self.remove_stars(current_count - target_count)

        except Exception as e:
            logger.error(f"Failed to update stars for theme: {e}")

    def add_stars(self, count):
        """Add more stars to the background."""
        try:
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()
            
            colors = ['#ffffff', '#e0e7ff'] if self.dark_mode.get() else ['#cbd5e1', '#94a3b8']
            
            for _ in range(count):
                x = random.randint(0, width)
                y = random.randint(0, height)
                size = random.randint(1, 3)
                color = random.choice(colors)
                
                star_id = self.bg_canvas.create_oval(
                    x, y, x + size, y + size,
                    fill=color, outline='', width=0
                )
                
                self.particles.append({
                    'id': star_id,
                    'x': x, 'y': y,
                    'size': size,
                    'speed': random.uniform(0.2, 1.0),
                    'direction': random.uniform(0, 360),
                    'opacity': random.uniform(0.3, 1.0),
                    'twinkle_speed': random.uniform(0.01, 0.05),
                    'twinkle_phase': random.uniform(0, 2 * math.pi),
                    'color': color,
                    'base_color': color
                })
                
        except Exception as e:
            logger.error(f"Failed to add stars: {e}")

    def remove_stars(self, count):
        """Remove stars from the background."""
        try:
            for _ in range(min(count, len(self.particles))):
                particle = self.particles.pop()
                self.bg_canvas.delete(particle['id'])
                
        except Exception as e:
            logger.error(f"Failed to remove stars: {e}")

    def create_glassmorphic_panel(self):
        """Create stunning glassmorphic login panel with blur effects."""
        try:
            # Main glass panel container
            bg_color = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
            self.glass_panel = tk.Frame(self, bg=bg_color)
            self.glass_panel.place(relx=0.5, rely=0.5, anchor='center')

            # Glass effect canvas
            panel_width, panel_height = 420, 580
            self.glass_canvas = tk.Canvas(
                self.glass_panel,
                width=panel_width,
                height=panel_height,
                highlightthickness=0,
                bg=bg_color
            )
            self.glass_canvas.pack()

            # Draw glassmorphic background
            self.draw_glassmorphic_background(panel_width, panel_height)

            # Create content frame
            self.create_panel_content()

        except Exception as e:
            logger.error(f"Failed to create glassmorphic panel: {e}")

    def draw_glassmorphic_background(self, width, height):
        """Draw true glassmorphic background with blur and transparency."""
        try:
            # Clear canvas
            self.glass_canvas.delete('all')
            
            corner_radius = 24
            
            # Draw multiple layers for glassmorphism effect
            if self.dark_mode.get():
                # Dark glassmorphism
                # Layer 1: Deep shadow
                self.draw_rounded_rect(
                    self.glass_canvas, 8, 8, width, height + 8,
                    corner_radius, '#000000'
                )

                # Layer 2: Main glass panel
                self.draw_rounded_rect(
                    self.glass_canvas, 0, 0, width - 8, height,
                    corner_radius, '#ffffff'
                )

                # Layer 3: Inner glow
                self.draw_rounded_rect(
                    self.glass_canvas, 2, 2, width - 10, height - 2,
                    corner_radius - 2, '#ffffff'
                )

                # Layer 4: Top highlight
                self.glass_canvas.create_arc(
                    2, 2, width - 10, 60,
                    start=0, extent=180,
                    fill='#ffffff', outline='', style='chord'
                )

                # Subtle border
                self.draw_rounded_rect_outline(
                    self.glass_canvas, 1, 1, width - 9, height - 1,
                    corner_radius, '#ffffff'
                )
                
            else:
                # Light glassmorphism
                # Layer 1: Soft shadow
                self.draw_rounded_rect(
                    self.glass_canvas, 6, 6, width, height + 6,
                    corner_radius, '#000000'
                )

                # Layer 2: Main glass panel
                self.draw_rounded_rect(
                    self.glass_canvas, 0, 0, width - 6, height,
                    corner_radius, '#ffffff'
                )

                # Layer 3: Inner brightness
                self.draw_rounded_rect(
                    self.glass_canvas, 2, 2, width - 8, height - 2,
                    corner_radius - 2, '#ffffff'
                )

                # Subtle border
                self.draw_rounded_rect_outline(
                    self.glass_canvas, 1, 1, width - 7, height - 1,
                    corner_radius, '#ffffff'
                )

        except Exception as e:
            logger.error(f"Failed to draw glassmorphic background: {e}")

    def draw_rounded_rect(self, canvas, x1, y1, x2, y2, radius, color):
        """Draw rounded rectangle."""
        try:
            # Main rectangles
            canvas.create_rectangle(x1 + radius, y1, x2 - radius, y2, 
                                  fill=color, outline='')
            canvas.create_rectangle(x1, y1 + radius, x2, y2 - radius, 
                                  fill=color, outline='')
            
            # Corner arcs
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, fill=color, outline='')
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, fill=color, outline='')  
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, fill=color, outline='')
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, fill=color, outline='')
            
        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle: {e}")

    def draw_rounded_rect_outline(self, canvas, x1, y1, x2, y2, radius, color):
        """Draw rounded rectangle outline."""
        try:
            # Border lines
            canvas.create_line(x1 + radius, y1, x2 - radius, y1, 
                             fill=color, width=1)
            canvas.create_line(x1 + radius, y2, x2 - radius, y2, 
                             fill=color, width=1)
            canvas.create_line(x1, y1 + radius, x1, y2 - radius, 
                             fill=color, width=1)
            canvas.create_line(x2, y1 + radius, x2, y2 - radius, 
                             fill=color, width=1)
            
            # Corner arcs
            canvas.create_arc(x1, y1, x1 + 2*radius, y1 + 2*radius,
                            start=90, extent=90, outline=color, width=1, style='arc')
            canvas.create_arc(x2 - 2*radius, y1, x2, y1 + 2*radius,
                            start=0, extent=90, outline=color, width=1, style='arc')
            canvas.create_arc(x2 - 2*radius, y2 - 2*radius, x2, y2,
                            start=270, extent=90, outline=color, width=1, style='arc')
            canvas.create_arc(x1, y2 - 2*radius, x1 + 2*radius, y2,
                            start=180, extent=90, outline=color, width=1, style='arc')
            
        except Exception as e:
            logger.error(f"Failed to draw rounded rectangle outline: {e}")

    def create_panel_content(self):
        """Create the content inside the glassmorphic panel."""
        try:
            # Content container with transparent background
            bg_color = '#1a1a2e' if self.dark_mode.get() else '#f8fafc'
            self.content_frame = tk.Frame(self.glass_panel, bg=bg_color)
            self.content_frame.place(
                relx=0.5, rely=0.5, anchor='center',
                width=380, height=540
            )

            # Add all content elements
            self.create_premium_header()
            self.create_modern_input_fields()
            self.create_premium_actions()
            self.create_elegant_footer()

        except Exception as e:
            logger.error(f"Failed to create panel content: {e}")

    def create_premium_header(self):
        """Create premium header with logo and title."""
        try:
            # Header container
            bg_color = self.get_bg_color()
            header_frame = tk.Frame(self.content_frame, bg=bg_color)
            header_frame.pack(pady=(40, 30))

            # Modern logo
            logo_canvas = tk.Canvas(
                header_frame, width=80, height=80,
                highlightthickness=0, bg=bg_color
            )
            logo_canvas.pack()

            # Draw premium logo
            self.draw_premium_logo(logo_canvas)

            # App title
            title_color = '#ffffff' if self.dark_mode.get() else '#1f2937'
            title_label = tk.Label(
                header_frame,
                text="PlexiChat",
                font=('Inter', 32, 'bold'),
                fg=title_color,
                bg=bg_color
            )
            title_label.pack(pady=(15, 8))

            # Subtitle
            subtitle_color = '#d1d5db' if self.dark_mode.get() else '#6b7280'
            subtitle_label = tk.Label(
                header_frame,
                text="Management Interface",
                font=('Inter', 14),
                fg=subtitle_color,
                bg=bg_color
            )
            subtitle_label.pack()

        except Exception as e:
            logger.error(f"Failed to create premium header: {e}")

    def draw_premium_logo(self, canvas):
        """Draw premium logo with modern styling."""
        try:
            if self.dark_mode.get():
                # Dark mode logo
                # Outer glow
                canvas.create_oval(5, 5, 75, 75, fill='#3b82f6', outline='')
                # Main circle
                canvas.create_oval(10, 10, 70, 70, fill='#3b82f6', outline='#60a5fa', width=2)
                # Inner highlight
                canvas.create_oval(20, 20, 40, 40, fill='#60a5fa', outline='')
                # Letter
                canvas.create_text(40, 40, text="P", fill='white', font=('Inter', 24, 'bold'))
            else:
                # Light mode logo
                # Shadow
                canvas.create_oval(12, 12, 72, 72, fill='#e5e7eb', outline='')
                # Main circle  
                canvas.create_oval(10, 10, 70, 70, fill='#3b82f6', outline='#2563eb', width=2)
                # Inner highlight
                canvas.create_oval(20, 20, 40, 40, fill='#60a5fa', outline='')
                # Letter
                canvas.create_text(40, 40, text="P", fill='white', font=('Inter', 24, 'bold'))

        except Exception as e:
            logger.error(f"Failed to draw premium logo: {e}")

    def create_modern_input_fields(self):
        """Create beautiful modern input fields with animations."""
        try:
            # Input container
            bg_color = self.get_bg_color()
            input_frame = tk.Frame(self.content_frame, bg=bg_color)
            input_frame.pack(pady=(0, 25), fill='x', padx=40)

            # Username field
            self.create_animated_input(
                input_frame, "Username", self.username_var,
                "?", "Enter your username", row=0
            )

            # Password field  
            self.create_animated_password_input(
                input_frame, "Password", self.password_var,
                "?", "Enter your password", row=1
            )

        except Exception as e:
            logger.error(f"Failed to create modern input fields: {e}")

    def create_animated_input(self, parent, label, var, icon, placeholder, row):
        """Create animated input field with focus effects."""
        try:
            # Field container
            bg_color = self.get_bg_color()
            field_frame = tk.Frame(parent, bg=bg_color)
            field_frame.grid(row=row, column=0, sticky='ew', pady=(0, 20))
            parent.grid_columnconfigure(0, weight=1)

            # Label with icon
            label_color = '#ffffff' if self.dark_mode.get() else '#374151'
            label_widget = tk.Label(
                field_frame,
                text=f"{icon} {label}",
                font=('Inter', 13, 'bold'),
                fg=label_color,
                bg=bg_color,
                anchor='w'
            )
            label_widget.pack(fill='x', pady=(0, 8))

            # Input container canvas for rounded corners
            input_canvas = tk.Canvas(
                field_frame, height=52,
                highlightthickness=0, bg=bg_color
            )
            input_canvas.pack(fill='x')

            # Store canvas reference for focus animations
            setattr(self, f'{label.lower()}_canvas', input_canvas)

            # Draw input background
            self.draw_input_background(input_canvas, focused=False)

            # Create entry widget
            entry_bg = '#374151' if self.dark_mode.get() else '#f9fafb'
            entry_fg = '#ffffff' if self.dark_mode.get() else '#111827'
            
            entry = tk.Entry(
                input_canvas,
                textvariable=var,
                font=('Inter', 14),
                bg=entry_bg,
                fg=entry_fg,
                bd=0,
                highlightthickness=0,
                insertbackground=entry_fg
            )

            # Place entry in canvas
            input_canvas.create_window(
                20, 26, window=entry, anchor='w', width=280
            )

            # Focus animations
            entry.bind('<FocusIn>', lambda e: self.on_input_focus(input_canvas, True))
            entry.bind('<FocusOut>', lambda e: self.on_input_focus(input_canvas, False))
            entry.bind('<Return>', lambda e: self.perform_login())

            # Set placeholder if needed
            if label == "Username" and not var.get():
                var.set("admin")

            return entry

        except Exception as e:
            logger.error(f"Failed to create animated input: {e}")
            return None

    def create_animated_password_input(self, parent, label, var, icon, placeholder, row):
        """Create animated password input with visibility toggle."""
        try:
            # Field container
            bg_color = self.get_bg_color()
            field_frame = tk.Frame(parent, bg=bg_color)
            field_frame.grid(row=row, column=0, sticky='ew', pady=(0, 20))

            # Label with icon
            label_color = '#ffffff' if self.dark_mode.get() else '#374151'
            label_widget = tk.Label(
                field_frame,
                text=f"{icon} {label}",
                font=('Inter', 13, 'bold'),
                fg=label_color,
                bg=bg_color,
                anchor='w'
            )
            label_widget.pack(fill='x', pady=(0, 8))

            # Input container canvas
            input_canvas = tk.Canvas(
                field_frame, height=52,
                highlightthickness=0, bg=bg_color
            )
            input_canvas.pack(fill='x')

            # Store reference
            self.password_canvas = input_canvas

            # Draw input background
            self.draw_input_background(input_canvas, focused=False)

            # Create password entry
            entry_bg = '#374151' if self.dark_mode.get() else '#f9fafb'
            entry_fg = '#ffffff' if self.dark_mode.get() else '#111827'
            
            self.password_entry = tk.Entry(
                input_canvas,
                textvariable=var,
                font=('Inter', 14),
                bg=entry_bg,
                fg=entry_fg,
                bd=0,
                highlightthickness=0,
                show='*',
                insertbackground=entry_fg
            )

            # Place password entry
            input_canvas.create_window(
                20, 26, window=self.password_entry, anchor='w', width=240
            )

            # Eye toggle button
            eye_btn = tk.Button(
                input_canvas,
                text="?",
                font=('Inter', 14),
                bg=entry_bg,
                fg=entry_fg,
                bd=0,
                highlightthickness=0,
                command=self.toggle_password_visibility,
                cursor='hand2'
            )
            input_canvas.create_window(320, 26, window=eye_btn, anchor='center')

            # Focus animations
            self.password_entry.bind('<FocusIn>', lambda e: self.on_input_focus(input_canvas, True))
            self.password_entry.bind('<FocusOut>', lambda e: self.on_input_focus(input_canvas, False))
            self.password_entry.bind('<Return>', lambda e: self.perform_login())

        except Exception as e:
            logger.error(f"Failed to create animated password input: {e}")

    def draw_input_background(self, canvas, focused=False):
        """Draw modern input field background with focus states."""
        try:
            canvas.delete('input_bg')
            
            # Wait for canvas to be properly sized
            canvas.update_idletasks()
            width = canvas.winfo_width()
            if width <= 1:
                canvas.after(10, lambda: self.draw_input_background(canvas, focused))
                return

            if self.dark_mode.get():
                if focused:
                    bg_color = '#4338ca'
                    border_color = '#6366f1'
                    glow_color = '#6366f1'
                else:
                    bg_color = '#374151'
                    border_color = '#4b5563'
                    glow_color = None
            else:
                if focused:
                    bg_color = '#dbeafe'
                    border_color = '#3b82f6'
                    glow_color = '#3b82f6'
                else:
                    bg_color = '#f9fafb'
                    border_color = '#e5e7eb'
                    glow_color = None

            # Draw glow effect for focused state
            if glow_color:
                self.draw_rounded_rect(
                    canvas, 0, 0, width, 52, 16, glow_color
                )

            # Draw input background
            self.draw_rounded_rect(
                canvas, 2, 2, width-2, 50, 14, bg_color
            )

            # Draw border
            self.draw_rounded_rect_outline(
                canvas, 2, 2, width-2, 50, 14, border_color
            )

        except Exception as e:
            logger.error(f"Failed to draw input background: {e}")

    def on_input_focus(self, canvas, focused):
        """Handle input field focus animations."""
        try:
            self.draw_input_background(canvas, focused)
        except Exception as e:
            logger.error(f"Failed to handle input focus: {e}")

    def toggle_password_visibility(self):
        """Toggle password field visibility."""
        try:
            if self.show_password_var.get():
                self.password_entry.configure(show='*')
                self.show_password_var.set(False)
            else:
                self.password_entry.configure(show='')
                self.show_password_var.set(True)
        except Exception as e:
            logger.error(f"Failed to toggle password visibility: {e}")

    def create_premium_actions(self):
        """Create premium action buttons and options."""
        try:
            # Actions container
            bg_color = self.get_bg_color()
            actions_frame = tk.Frame(self.content_frame, bg=bg_color)
            actions_frame.pack(pady=(0, 20), fill='x', padx=40)

            # Remember me and forgot password row
            options_frame = tk.Frame(actions_frame, bg=bg_color)
            options_frame.pack(fill='x', pady=(0, 25))

            # Remember me checkbox
            remember_frame = tk.Frame(options_frame, bg=bg_color)
            remember_frame.pack(side='left')

            text_color = '#ffffff' if self.dark_mode.get() else '#374151'
            remember_check = tk.Checkbutton(
                remember_frame,
                text="Remember me",
                variable=self.remember_var,
                font=('Inter', 11),
                fg=text_color,
                bg=bg_color,
                selectcolor='#3b82f6',
                activebackground=bg_color,
                activeforeground=text_color,
                bd=0,
                highlightthickness=0
            )
            remember_check.pack()

            # Forgot password link
            forgot_frame = tk.Frame(options_frame, bg=bg_color)
            forgot_frame.pack(side='right')

            link_color = '#3b82f6' if self.dark_mode.get() else '#2563eb'
            forgot_link = tk.Label(
                forgot_frame,
                text="Forgot password?",
                font=('Inter', 11, 'underline'),
                fg=link_color,
                bg=bg_color,
                cursor='hand2'
            )
            forgot_link.pack()
            forgot_link.bind('<Button-1>', self.show_password_reset_info)

            # Premium login button
            self.create_premium_button(actions_frame)

        except Exception as e:
            logger.error(f"Failed to create premium actions: {e}")

    def create_premium_button(self, parent):
        """Create premium animated login button."""
        try:
            # Button container
            bg_color = self.get_bg_color()
            button_frame = tk.Frame(parent, bg=bg_color)
            button_frame.pack()

            # Button canvas for custom styling
            self.login_canvas = tk.Canvas(
                button_frame,
                width=300, height=56,
                highlightthickness=0,
                bg=bg_color,
                cursor='hand2'
            )
            self.login_canvas.pack()

            # Draw initial button state
            self.draw_premium_button(hover=False)

            # Button events
            self.login_canvas.bind('<Button-1>', lambda e: self.animate_button_click())
            self.login_canvas.bind('<Enter>', lambda e: self.draw_premium_button(hover=True))
            self.login_canvas.bind('<Leave>', lambda e: self.draw_premium_button(hover=False))

        except Exception as e:
            logger.error(f"Failed to create premium button: {e}")

    def draw_premium_button(self, hover=False, pressed=False):
        """Draw premium button with gradients and animations."""
        try:
            self.login_canvas.delete('all')
            
            width, height = 300, 56
            radius = 16

            if pressed:
                # Pressed state
                bg_color = '#1d4ed8'
                shadow_color = '#1e40af'
                text_color = '#ffffff'
                shadow_offset = 1
            elif hover:
                # Hover state
                bg_color = '#2563eb'
                shadow_color = '#3b82f6'
                text_color = '#ffffff'
                shadow_offset = 6
            else:
                # Normal state
                bg_color = '#3b82f6'
                shadow_color = '#3b82f6'
                text_color = '#ffffff'
                shadow_offset = 4

            # Draw shadow
            self.draw_rounded_rect(
                self.login_canvas,
                shadow_offset, shadow_offset,
                width, height + shadow_offset,
                radius, shadow_color
            )

            # Draw button background
            self.draw_rounded_rect(
                self.login_canvas,
                0, 0, width - shadow_offset, height,
                radius, bg_color
            )

            # Add gradient effect (simulated with overlay)
            if not pressed:
                self.draw_rounded_rect(
                    self.login_canvas,
                    0, 0, width - shadow_offset, height // 2,
                    radius, '#ffffff'
                )

            # Button text
            text = "Signing in..." if self.is_authenticating else "Sign In"
            self.login_canvas.create_text(
                (width - shadow_offset) // 2, height // 2,
                text=text,
                fill=text_color,
                font=('Inter', 16, 'bold')
            )

            # Add login icon
            if not self.is_authenticating:
                self.login_canvas.create_text(
                    (width - shadow_offset) // 2 + 50, height // 2,
                    text=">",
                    fill=text_color,
                    font=('Inter', 18, 'bold')
                )

        except Exception as e:
            logger.error(f"Failed to draw premium button: {e}")

    def animate_button_click(self):
        """Animate button click and perform login."""
        try:
            # Pressed animation
            self.draw_premium_button(pressed=True)
            
            # Return to normal after short delay
            self.after(150, lambda: self.draw_premium_button(hover=False))
            
            # Perform login
            self.after(50, self.perform_login)
            
        except Exception as e:
            logger.error(f"Failed to animate button click: {e}")

    def create_elegant_footer(self):
        """Create elegant footer with system status."""
        try:
            # Footer container
            bg_color = self.get_bg_color()
            footer_frame = tk.Frame(self.content_frame, bg=bg_color)
            footer_frame.pack(side='bottom', fill='x', pady=(20, 40))

            # System status
            status_color = '#9ca3af' if self.dark_mode.get() else '#6b7280'
            self.status_label = tk.Label(
                footer_frame,
                textvariable=self.system_status_text,
                font=('Inter', 9),
                fg=status_color,
                bg=bg_color,
                justify='center'
            )
            self.status_label.pack()

            # Start status updates
            self.update_system_status()

        except Exception as e:
            logger.error(f"Failed to create elegant footer: {e}")

    def start_animations(self):
        """Start all background animations."""
        try:
            self.animation_running = True
            self.animate_stars()
            
        except Exception as e:
            logger.error(f"Failed to start animations: {e}")

    def animate_stars(self):
        """Animate floating stars with twinkling effects."""
        if not self.animation_running:
            return
            
        try:
            width = self.winfo_screenwidth()
            height = self.winfo_screenheight()
            
            for particle in self.particles:
                # Update position
                particle['x'] += math.cos(math.radians(particle['direction'])) * particle['speed']
                particle['y'] += math.sin(math.radians(particle['direction'])) * particle['speed']
                
                # Wrap around screen
                if particle['x'] < -10:
                    particle['x'] = width + 10
                elif particle['x'] > width + 10:
                    particle['x'] = -10
                    
                if particle['y'] < -10:
                    particle['y'] = height + 10
                elif particle['y'] > height + 10:
                    particle['y'] = -10
                
                # Twinkling effect
                particle['twinkle_phase'] += particle['twinkle_speed']
                opacity_factor = (math.sin(particle['twinkle_phase']) + 1) / 2
                current_opacity = particle['opacity'] * opacity_factor
                
                # Update canvas position
                if particle['size'] <= 2:
                    self.bg_canvas.coords(
                        particle['id'],
                        particle['x'], particle['y'],
                        particle['x'] + particle['size'], particle['y'] + particle['size']
                    )
                else:
                    # Update polygon coordinates for larger stars
                    x, y, size = particle['x'], particle['y'], particle['size']
                    coords = [
                        x, y-size, x+size//2, y-size//2, x+size, y,
                        x+size//2, y+size//2, x, y+size, x-size//2, y+size//2,
                        x-size, y, x-size//2, y-size//2
                    ]
                    self.bg_canvas.coords(particle['id'], *coords)
            
            # Schedule next animation frame
            self.after(50, self.animate_stars)
            
        except Exception as e:
            logger.error(f"Star animation error: {e}")

    def update_system_status(self):
        """Update system status information."""
        try:
            # Calculate uptime
            uptime = datetime.now() - self.start_time
            uptime_str = f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m"

            # Get system metrics if available
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                metrics = f"CPU: {cpu_percent:.0f}% | RAM: {memory.percent:.0f}%"
            except:
                metrics = "System metrics unavailable"

            # Network status
            network_icon = "?" if self.check_network_status() else "?"

            # Format status
            status_text = f"{network_icon} Online | {metrics} | Uptime: {uptime_str}"
            self.system_status_text.set(status_text)

            # Schedule next update
            self.after(30000, self.update_system_status)

        except Exception as e:
            logger.error(f"Failed to update system status: {e}")
            self.system_status_text.set("? Status unavailable")

    def check_network_status(self):
        """Check network connectivity."""
        try:
            import socket
            socket.gethostbyname('google.com')
            return True
        except:
            return False

    def load_theme_preference(self):
        """Load saved theme preference."""
        try:
            config_file = Path.home() / '.plexichat' / 'ui_config.json'
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.dark_mode.set(config.get('dark_mode', True))
        except Exception as e:
            logger.error(f"Failed to load theme preference: {e}")

    def save_theme_preference(self):
        """Save theme preference."""
        try:
            config_dir = Path.home() / '.plexichat'
            config_dir.mkdir(exist_ok=True)
            
            config_file = config_dir / 'ui_config.json'
            config = {'dark_mode': self.dark_mode.get()}
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save theme preference: {e}")

    def show_password_reset_info(self, event=None):
        """Show password reset information."""
        try:
            reset_info = """Password Reset Instructions:

To reset your GUI password, use the CLI command:

    python run.py cli gui-password --reset

This will generate a new secure password that will be displayed in the terminal.

For more help with CLI commands:
    python run.py cli --help

Note: You must have access to the command line to reset your password."""

            messagebox.showinfo("Password Reset", reset_info)
            
        except Exception as e:
            logger.error(f"Failed to show password reset info: {e}")

    def perform_login(self):
        """Perform login authentication with modern UX."""
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
            self.draw_premium_button()  # Update button to show "Signing in..."
            
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
            
            # Call authentication API
            auth_result = self.call_auth_api(username, password_hash)
            
            # Schedule UI update on main thread
            self.after(0, self.handle_auth_result, auth_result)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            self.after(0, self.handle_auth_error, str(e))

    def call_auth_api(self, username: str, password_hash: str) -> Dict[str, Any]:
        """Call authentication API with secure credentials."""
        try:
            # Try new credentials system first
            try:
                from plexichat.core.auth.default_credentials import get_default_credentials_manager
                manager = get_default_credentials_manager()
                gui_creds = manager.get_interface_credentials("gui")
                
                if gui_creds and username == gui_creds.get("username", "admin"):
                    stored_hash = hashlib.sha256(gui_creds["password"].encode()).hexdigest()
                    if password_hash == stored_hash:
                        return self.create_success_response(username)
                        
            except ImportError:
                # Fallback to default credentials
                default_creds = self.load_default_credentials()
                if username == default_creds.get("username", "admin"):
                    stored_hash = hashlib.sha256(default_creds["password"].encode()).hexdigest()
                    if password_hash == stored_hash:
                        return self.create_success_response(username)

            return {"success": False, "error": "Invalid username or password"}

        except Exception as e:
            logger.error(f"Auth API call failed: {e}")
            return {"success": False, "error": str(e)}

    def create_success_response(self, username: str) -> Dict[str, Any]:
        """Create successful authentication response."""
        return {
            "success": True,
            "user": {
                "id": "admin",
                "username": username,
                "email": "admin@plexichat.local",
                "permissions": ["admin", "server_manager", "all_access"],
                "role": "server_administrator",
                "profile": {
                    "display_name": "Server Administrator",
                    "theme": "dark_modern" if self.dark_mode.get() else "light_modern"
                }
            },
            "token": self.generate_secure_token(username),
            "expires": (datetime.now() + timedelta(hours=8)).isoformat()
        }

    def load_default_credentials(self) -> Dict[str, str]:
        """Load default credentials from file."""
        try:
            # Try multiple credential file locations
            possible_files = [
                Path(__file__).parent.parent.parent.parent.parent / "src" / "default_creds.txt",
                Path.home() / ".plexichat" / "default-creds.json",
                Path.home() / ".plexichat" / "admin-credentials.txt"
            ]

            for creds_file in possible_files:
                if creds_file.exists():
                    if creds_file.suffix == '.json':
                        with open(creds_file, 'r') as f:
                            data = json.load(f)
                            admin_creds = data.get('admin', {})
                            return {
                                "username": admin_creds.get("username", "admin"),
                                "password": admin_creds.get("password", "admin123")
                            }
                    else:
                        with open(creds_file, 'r') as f:
                            content = f.read()
                            username = "admin"
                            password = "admin123"
                            
                            for line in content.split('\n'):
                                if 'username:' in line.lower():
                                    username = line.split(':')[1].strip()
                                elif 'password:' in line.lower():
                                    password = line.split(':')[1].strip()
                            
                            return {"username": username, "password": password}

            # Return default if no file found
            return {"username": "admin", "password": "admin123"}

        except Exception as e:
            logger.error(f"Failed to load default credentials: {e}")
            return {"username": "admin", "password": "admin123"}

    def generate_secure_token(self, username: str) -> str:
        """Generate secure authentication token."""
        try:
            import secrets
            token_data = f"{username}:{int(time.time())}:{secrets.token_urlsafe(32)}"
            return base64.b64encode(token_data.encode()).decode()
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            return "fallback_token"

    def handle_auth_result(self, result: Dict[str, Any]):
        """Handle authentication result with smooth UX."""
        try:
            self.is_authenticating = False
            self.draw_premium_button()
            
            if result.get("success"):
                # Success - save remember me if checked
                if self.remember_var.get():
                    self.save_remember_me_data(result.get("user", {}))
                
                # Notify parent application
                self.app.on_login_success(result.get("user", {}))
                
            else:
                # Failed login
                self.login_attempts += 1
                error_msg = result.get("error", "Authentication failed")
                messagebox.showerror("Login Failed", error_msg)
                self.password_var.set("")
                
        except Exception as e:
            logger.error(f"Failed to handle auth result: {e}")
            messagebox.showerror("Error", f"Authentication error: {e}")

    def handle_auth_error(self, error: str):
        """Handle authentication error."""
        try:
            self.is_authenticating = False
            self.draw_premium_button()
            self.login_attempts += 1
            
            messagebox.showerror("Authentication Error", f"Login failed: {error}")
            self.password_var.set("")
            
        except Exception as e:
            logger.error(f"Failed to handle auth error: {e}")

    def reset_login_form(self):
        """Reset login form to initial state."""
        try:
            self.is_authenticating = False
            self.draw_premium_button()
            self.password_var.set("")
        except Exception as e:
            logger.error(f"Failed to reset login form: {e}")

    def save_remember_me_data(self, user_data: Dict[str, Any]):
        """Save remember me data securely."""
        try:
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

    def cleanup(self):
        """Cleanup resources and stop animations."""
        try:
            self.animation_running = False
        except Exception as e:
            logger.error(f"Failed to cleanup: {e}")


# Usage example:
if __name__ == "__main__":
    class MockApp:
        def on_login_success(self, user_data):
            print(f"Login successful for user: {user_data.get('username')}")
    
    root = tk.Tk()
    root.title("PlexiChat - Modern Login")
    root.geometry("1200x800")
    root.configure(bg='#1a1a2e')
    
    app = MockApp()
    login_screen = LoginScreen(root, app)
    
    root.mainloop()