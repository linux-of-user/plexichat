import asyncio
import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from pathlib import Path

    import customtkinter as ctk
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import numpy as np


"""
Enhanced Base Widget for PlexiChat GUI
Modern, responsive base widget with advanced styling and features
"""

# GUI imports with proper fallbacks
GUI_AVAILABLE = False
try:
    GUI_AVAILABLE = True
except ImportError:
    pass

# Chart imports
CHART_AVAILABLE = False
try:
    CHART_AVAILABLE = True
except ImportError:
    pass

logger = logging.getLogger(__name__)


@dataclass
class WidgetTheme:
    """Widget theme configuration."""
    primary_color: str = "#1e40af"
    secondary_color: str = "#0891b2"
    accent_color: str = "#dc2626"
    success_color: str = "#059669"
    warning_color: str = "#d97706"
    danger_color: str = "#dc2626"
    background_color: str = "#ffffff"
    surface_color: str = "#f8fafc"
    text_color: str = "#111827"
    text_secondary: str = "#6b7280"
    border_color: str = "#e5e7eb"
    border_radius: int = 8
    shadow_color: str = "rgba(0, 0, 0, 0.1)"


@dataclass
class WidgetConfig:
    """Widget configuration."""
    title: str = "Enhanced Widget"
    width: int = 800
    height: int = 600
    resizable: bool = True
    auto_refresh: bool = True
    refresh_interval: int = 5000  # milliseconds
    theme: WidgetTheme = field(default_factory=WidgetTheme)
    animations_enabled: bool = True
    tooltips_enabled: bool = True
    keyboard_shortcuts: Dict[str, str] = field(default_factory=dict)


class EnhancedBaseWidget(ABC):
    """Enhanced base widget with modern styling and advanced features."""

    def __init__(self, parent=None, config: Optional[WidgetConfig] = None):
        if not GUI_AVAILABLE:
            raise ImportError("GUI libraries not available")

        self.parent = parent
        self.config = config or WidgetConfig()

        # Widget state
        self.is_initialized = False
        self.is_visible = False
        self.is_loading = False
        self.last_update = None

        # Threading
        self.refresh_thread = None
        self.refresh_active = False

        # Event callbacks
        self.callbacks: Dict[str, List[Callable]] = {}

        # Performance tracking
        self.performance_metrics = {
            "render_time": 0,
            "update_time": 0,
            "refresh_count": 0
        }

        # Initialize widget
        self.setup_widget()
        self.setup_theme()
        self.setup_events()
        self.setup_keyboard_shortcuts()

        if self.config.auto_refresh:
            self.start_auto_refresh()

        self.is_initialized = True
        logger.info(f"Enhanced widget initialized: {self.config.title}")

    def setup_widget(self):
        """Setup the main widget container."""
        if self.parent:
            self.main_frame = ctk.CTkFrame(self.parent)
        else:
            self.main_frame = ctk.CTkToplevel()
            self.main_frame.title(self.config.title)
            self.main_frame.geometry(f"{self.config.width}x{self.config.height}")

            if not self.config.resizable:
                self.main_frame.resizable(False, False)

        # Create header
        self.header_frame = ctk.CTkFrame(self.main_frame)
        self.header_frame.pack(fill="x", padx=10, pady=(10, 5))

        # Title and controls
        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text=self.config.title,
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.title_label.pack(side="left", padx=10, pady=10)

        # Header controls
        self.controls_frame = ctk.CTkFrame(self.header_frame)
        self.controls_frame.pack(side="right", padx=10, pady=5)

        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            self.controls_frame,
            text="",
            width=30,
            height=30,
            command=self.manual_refresh
        )
        self.refresh_btn.pack(side="right", padx=2)

        # Settings button
        self.settings_btn = ctk.CTkButton(
            self.controls_frame,
            text="",
            width=30,
            height=30,
            command=self.show_settings
        )
        self.settings_btn.pack(side="right", padx=2)

        # Status indicator
        self.status_frame = ctk.CTkFrame(self.header_frame)
        self.status_frame.pack(side="right", padx=(0, 10))

        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="",
            text_color="green",
            font=ctk.CTkFont(size=16)
        )
        self.status_indicator.pack(padx=5, pady=5)

        # Content area
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Loading overlay
        self.loading_frame = ctk.CTkFrame(self.content_frame)
        self.loading_label = ctk.CTkLabel(
            self.loading_frame,
            text="Loading...",
            font=ctk.CTkFont(size=14)
        )
        self.loading_label.pack(pady=20)

        # Setup content
        self.setup_content()

    def setup_theme(self):
        """Apply theme to widget components."""
        theme = self.config.theme

        # Configure colors
        ctk.set_appearance_mode("light" if theme.background_color == "#ffffff" else "dark")

        # Apply custom styling if needed
        self.apply_custom_styling()

    def apply_custom_styling(self):
        """Apply custom styling to components."""
        # Override in subclasses for custom styling
        pass

    def setup_events(self):
        """Setup event handlers."""
        if hasattr(self.main_frame, 'protocol'):
            self.main_frame.protocol("WM_DELETE_WINDOW", self.on_close)

        # Bind resize events
        if hasattr(self.main_frame, 'bind'):
            self.main_frame.bind('<Configure>', self.on_resize)

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts."""
        shortcuts = {
            '<F5>': self.manual_refresh,
            '<Control-r>': self.manual_refresh,
            '<Control-s>': self.show_settings,
            **self.config.keyboard_shortcuts
        }

        for key, command in shortcuts.items():
            if hasattr(self.main_frame, 'bind'):
                self.main_frame.bind(key, lambda e, cmd=command: cmd())

    @abstractmethod
    def setup_content(self):
        """Setup widget content. Must be implemented by subclasses."""
        pass

    @abstractmethod
    async def refresh_data(self):
        """Refresh widget data. Must be implemented by subclasses."""
        pass

    def show_loading(self, message: str = "Loading..."):
        """Show loading indicator."""
        self.is_loading = True
        self.loading_label.configure(text=message)
        self.loading_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.status_indicator.configure(text_color="orange")

        if hasattr(self.main_frame, 'update'):
            self.main_frame.update()

    def hide_loading(self):
        """Hide loading indicator."""
        self.is_loading = False
        self.loading_frame.place_forget()
        self.status_indicator.configure(text_color="green")

        if hasattr(self.main_frame, 'update'):
            self.main_frame.update()

    def show_error(self, message: str):
        """Show error message."""
        self.status_indicator.configure(text_color="red")

        if GUI_AVAILABLE:
            messagebox.showerror("Error", message)

        logger.error(f"Widget error: {message}")

    def show_success(self, message: str):
        """Show success message."""
        self.status_indicator.configure(text_color="green")

        if GUI_AVAILABLE:
            messagebox.showinfo("Success", message)

        logger.info(f"Widget success: {message}")

    def manual_refresh(self):
        """Manually trigger refresh."""
        if self.is_loading:
            return

        def refresh_task():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.refresh_data())
                loop.close()

                self.last_update = datetime.now(timezone.utc)
                self.performance_metrics["refresh_count"] += 1

            except Exception as e:
                logger.error(f"Manual refresh failed: {e}")
                self.show_error(f"Refresh failed: {e}")

        thread = threading.Thread(target=refresh_task, daemon=True)
        thread.start()

    def start_auto_refresh(self):
        """Start automatic refresh."""
        if self.refresh_active:
            return

        self.refresh_active = True

        def auto_refresh_loop():
            while self.refresh_active:
                try:
                    if not self.is_loading:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(self.refresh_data())
                        loop.close()

                        self.last_update = datetime.now(timezone.utc)
                        self.performance_metrics["refresh_count"] += 1

                    time.sleep(self.config.refresh_interval / 1000)

                except Exception as e:
                    logger.error(f"Auto refresh failed: {e}")
                    time.sleep(5)  # Wait before retrying

        self.refresh_thread = threading.Thread(target=auto_refresh_loop, daemon=True)
        self.refresh_thread.start()

    def stop_auto_refresh(self):
        """Stop automatic refresh."""
        self.refresh_active = False
        if self.refresh_thread:
            self.refresh_thread.join(timeout=1)

    def show_settings(self):
        """Show widget settings dialog."""
        settings_window = ctk.CTkToplevel(self.main_frame)
        settings_window.title(f"{self.config.title} - Settings")
        settings_window.geometry("400x300")
        settings_window.transient(self.main_frame)
        settings_window.grab_set()

        # Auto refresh setting
        auto_refresh_var = ctk.BooleanVar(value=self.config.auto_refresh)
        auto_refresh_check = ctk.CTkCheckBox(
            settings_window,
            text="Auto Refresh",
            variable=auto_refresh_var
        )
        auto_refresh_check.pack(pady=10)

        # Refresh interval
        interval_label = ctk.CTkLabel(settings_window, text="Refresh Interval (seconds):")
        interval_label.pack(pady=(10, 0))

        interval_var = ctk.StringVar(value=str(self.config.refresh_interval // 1000))
        interval_entry = ctk.CTkEntry(settings_window, textvariable=interval_var)
        interval_entry.pack(pady=5)

        # Apply button
        def apply_settings():
            self.config.auto_refresh = auto_refresh_var.get()
            try:
                self.config.refresh_interval = int(interval_var.get()) * 1000
            except ValueError:
                pass

            if self.config.auto_refresh and not self.refresh_active:
                self.start_auto_refresh()
            elif not self.config.auto_refresh and self.refresh_active:
                self.stop_auto_refresh()

            settings_window.destroy()

        apply_btn = ctk.CTkButton(settings_window, text="Apply", command=apply_settings)
        apply_btn.pack(pady=20)

    def on_resize(self, event):
        """Handle resize events."""
        # Override in subclasses if needed
        pass

    def on_close(self):
        """Handle close events."""
        self.stop_auto_refresh()
        if hasattr(self.main_frame, 'destroy'):
            self.main_frame.destroy()

    def pack(self, **kwargs):
        """Pack the widget."""
        self.main_frame.pack(**kwargs)
        self.is_visible = True

    def grid(self, **kwargs):
        """Grid the widget."""
        self.main_frame.grid(**kwargs)
        self.is_visible = True

    def place(self, **kwargs):
        """Place the widget."""
        self.main_frame.place(**kwargs)
        self.is_visible = True
