"""
Advanced Theme Manager for PlexiChat GUI
Provides sophisticated theming system with multiple themes and customization.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, Optional, List
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ThemeManager:
    """
    Advanced theme management system for PlexiChat GUI.
    
    Features:
    - Multiple built-in themes (dark, light, high contrast, etc.)
    - Custom theme creation and editing
    - Dynamic theme switching
    - Component-specific styling
    - Animation support
    - Theme persistence
    - Accessibility features
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.style = ttk.Style()
        self.current_theme = "dark_modern"
        self.custom_themes = {}
        self.theme_callbacks = []
        
        # Built-in themes
        self.builtin_themes = {
            "dark_modern": self.create_dark_modern_theme(),
            "light_modern": self.create_light_modern_theme(),
            "high_contrast": self.create_high_contrast_theme(),
            "cyberpunk": self.create_cyberpunk_theme(),
            "minimal": self.create_minimal_theme(),
            "corporate": self.create_corporate_theme()
        }
        
        self.load_custom_themes()
        self.configure_base_styles()

    def create_dark_modern_theme(self) -> Dict[str, Any]:
        """Create dark modern glassmorphic theme."""
        return {
            "name": "Dark Modern",
            "description": "Modern dark theme with glassmorphic effects",
            "colors": {
                "primary": "#1a1a2e",
                "secondary": "#4A90E2",
                "accent": "#6C7CE7",
                "success": "#00D4AA",
                "warning": "#FFB800",
                "danger": "#FF6B6B",
                "dark": "#0f0f23",
                "light": "#ffffff",
                "background": "#1a1a2e",
                "surface": "rgba(42, 52, 94, 0.8)",
                "text": "#ffffff",
                "text_secondary": "#B8C5D6",
                "border": "rgba(74, 144, 226, 0.3)",
                "hover": "rgba(74, 144, 226, 0.2)",
                "active": "#4A90E2",
                "disabled": "#6B7280"
            },
            "fonts": {
                "default": ("Inter", 10),
                "heading": ("Inter", 14, "bold"),
                "title": ("Inter", 18, "bold"),
                "mono": ("JetBrains Mono", 10)
            },
            "effects": {
                "shadows": True,
                "animations": True,
                "transparency": True,
                "blur": True
            }
        }

    def create_light_modern_theme(self) -> Dict[str, Any]:
        """Create light modern theme."""
        return {
            "name": "Light Modern",
            "description": "Clean light theme with subtle shadows",
            "colors": {
                "primary": "#ffffff",
                "secondary": "#3498db",
                "accent": "#e74c3c",
                "success": "#27ae60",
                "warning": "#f39c12",
                "danger": "#e74c3c",
                "dark": "#2c3e50",
                "light": "#ffffff",
                "background": "#f8f9fa",
                "surface": "#ffffff",
                "text": "#2c3e50",
                "text_secondary": "#6c757d",
                "border": "#dee2e6",
                "hover": "#e9ecef",
                "active": "#3498db",
                "disabled": "#adb5bd"
            },
            "fonts": {
                "default": ("Segoe UI", 10),
                "heading": ("Segoe UI", 14, "bold"),
                "title": ("Segoe UI", 18, "bold"),
                "mono": ("Consolas", 10)
            },
            "effects": {
                "shadows": True,
                "animations": True,
                "transparency": False,
                "blur": False
            }
        }

    def create_high_contrast_theme(self) -> Dict[str, Any]:
        """Create high contrast theme for accessibility."""
        return {
            "name": "High Contrast",
            "description": "High contrast theme for accessibility",
            "colors": {
                "primary": "#000000",
                "secondary": "#ffffff",
                "accent": "#ffff00",
                "success": "#00ff00",
                "warning": "#ffff00",
                "danger": "#ff0000",
                "dark": "#000000",
                "light": "#ffffff",
                "background": "#000000",
                "surface": "#000000",
                "text": "#ffffff",
                "text_secondary": "#ffffff",
                "border": "#ffffff",
                "hover": "#333333",
                "active": "#666666",
                "disabled": "#808080"
            },
            "fonts": {
                "default": ("Segoe UI", 12, "bold"),
                "heading": ("Segoe UI", 16, "bold"),
                "title": ("Segoe UI", 20, "bold"),
                "mono": ("Consolas", 12, "bold")
            },
            "effects": {
                "shadows": False,
                "animations": False,
                "transparency": False,
                "blur": False
            }
        }

    def create_cyberpunk_theme(self) -> Dict[str, Any]:
        """Create cyberpunk theme."""
        return {
            "name": "Cyberpunk",
            "description": "Futuristic cyberpunk theme with neon accents",
            "colors": {
                "primary": "#0a0a0a",
                "secondary": "#00ff41",
                "accent": "#ff0080",
                "success": "#00ff41",
                "warning": "#ffff00",
                "danger": "#ff0080",
                "dark": "#000000",
                "light": "#00ff41",
                "background": "#0a0a0a",
                "surface": "#1a1a1a",
                "text": "#00ff41",
                "text_secondary": "#80ff80",
                "border": "#00ff41",
                "hover": "#003311",
                "active": "#00ff41",
                "disabled": "#404040"
            },
            "fonts": {
                "default": ("Courier New", 10),
                "heading": ("Courier New", 14, "bold"),
                "title": ("Courier New", 18, "bold"),
                "mono": ("Courier New", 10)
            },
            "effects": {
                "shadows": True,
                "animations": True,
                "transparency": True,
                "blur": True
            }
        }

    def create_minimal_theme(self) -> Dict[str, Any]:
        """Create minimal theme."""
        return {
            "name": "Minimal",
            "description": "Clean minimal theme with subtle colors",
            "colors": {
                "primary": "#ffffff",
                "secondary": "#6c757d",
                "accent": "#007bff",
                "success": "#28a745",
                "warning": "#ffc107",
                "danger": "#dc3545",
                "dark": "#343a40",
                "light": "#f8f9fa",
                "background": "#ffffff",
                "surface": "#ffffff",
                "text": "#212529",
                "text_secondary": "#6c757d",
                "border": "#e9ecef",
                "hover": "#f8f9fa",
                "active": "#007bff",
                "disabled": "#adb5bd"
            },
            "fonts": {
                "default": ("Segoe UI", 10),
                "heading": ("Segoe UI", 14),
                "title": ("Segoe UI", 18),
                "mono": ("Consolas", 10)
            },
            "effects": {
                "shadows": False,
                "animations": False,
                "transparency": False,
                "blur": False
            }
        }

    def create_corporate_theme(self) -> Dict[str, Any]:
        """Create corporate theme."""
        return {
            "name": "Corporate",
            "description": "Professional corporate theme",
            "colors": {
                "primary": "#003366",
                "secondary": "#0066cc",
                "accent": "#ff6600",
                "success": "#009900",
                "warning": "#ff9900",
                "danger": "#cc0000",
                "dark": "#001122",
                "light": "#f0f4f8",
                "background": "#f0f4f8",
                "surface": "#ffffff",
                "text": "#003366",
                "text_secondary": "#666666",
                "border": "#ccddee",
                "hover": "#e6f2ff",
                "active": "#0066cc",
                "disabled": "#999999"
            },
            "fonts": {
                "default": ("Calibri", 10),
                "heading": ("Calibri", 14, "bold"),
                "title": ("Calibri", 18, "bold"),
                "mono": ("Courier New", 10)
            },
            "effects": {
                "shadows": True,
                "animations": False,
                "transparency": False,
                "blur": False
            }
        }

    def configure_base_styles(self):
        """Configure base ttk styles."""
        try:
            # Configure base styles that will be themed
            self.style.theme_use('clam')  # Use clam as base theme
            
            # Define style mappings
            self.style_mappings = {
                "TFrame": ["background"],
                "TLabel": ["background", "foreground"],
                "TButton": ["background", "foreground", "focuscolor"],
                "TEntry": ["fieldbackground", "foreground", "bordercolor"],
                "TCheckbutton": ["background", "foreground", "focuscolor"],
                "TRadiobutton": ["background", "foreground", "focuscolor"],
                "TCombobox": ["fieldbackground", "foreground", "bordercolor"],
                "TProgressbar": ["background", "troughcolor"],
                "TScrollbar": ["background", "troughcolor"],
                "TNotebook": ["background"],
                "TNotebook.Tab": ["background", "foreground"],
                "TText": ["background", "foreground"],
                "TListbox": ["background", "foreground"],
                "TTreeview": ["background", "foreground"],
                "TMenubutton": ["background", "foreground"],
                "TScale": ["background", "troughcolor"],
                "TSeparator": ["background"],
                "TSpinbox": ["fieldbackground", "foreground", "bordercolor"]
            }
            
        except Exception as e:
            logger.error(f"Failed to configure base styles: {e}")

    def apply_theme(self, theme_name: str):
        """Apply a theme to the application."""
        try:
            # Get theme data
            theme_data = self.get_theme(theme_name)
            if not theme_data:
                logger.error(f"Theme '{theme_name}' not found")
                return False
            
            self.current_theme = theme_name
            colors = theme_data["colors"]
            fonts = theme_data["fonts"]
            
            # Apply colors to root window
            self.root.configure(bg=colors["background"])
            
            # Apply styles to ttk widgets
            self.apply_ttk_styles(colors, fonts)
            
            # Apply custom component styles
            self.apply_custom_styles(theme_data)
            
            # Notify theme change callbacks
            self.notify_theme_change(theme_name, theme_data)
            
            logger.info(f"Applied theme: {theme_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply theme '{theme_name}': {e}")
            return False

    def apply_ttk_styles(self, colors: Dict[str, str], fonts: Dict[str, tuple]):
        """Apply theme colors and fonts to ttk styles."""
        try:
            # Apply to each widget type
            for widget_type, properties in self.style_mappings.items():
                style_config = {}
                
                # Map colors to properties
                for prop in properties:
                    if prop == "background":
                        style_config[prop] = colors["surface"]
                    elif prop == "foreground":
                        style_config[prop] = colors["text"]
                    elif prop == "fieldbackground":
                        style_config[prop] = colors["background"]
                    elif prop == "bordercolor":
                        style_config[prop] = colors["border"]
                    elif prop == "focuscolor":
                        style_config[prop] = colors["accent"]
                    elif prop == "troughcolor":
                        style_config[prop] = colors["background"]
                
                # Apply font
                if "font" not in style_config:
                    style_config["font"] = fonts["default"]
                
                # Configure the style
                self.style.configure(widget_type, **style_config)
                
                # Configure state-specific styles
                self.style.map(widget_type,
                    background=[('active', colors["hover"]), ('pressed', colors["active"])],
                    foreground=[('disabled', colors["disabled"])]
                )
            
        except Exception as e:
            logger.error(f"Failed to apply ttk styles: {e}")

    def apply_custom_styles(self, theme_data: Dict[str, Any]):
        """Apply custom styles for specific components."""
        try:
            colors = theme_data["colors"]
            fonts = theme_data["fonts"]
            
            # Login screen styles
            self.style.configure("Login.TFrame", background=colors["background"])
            self.style.configure("LoginMain.TFrame", background=colors["surface"], relief="raised", borderwidth=2)
            self.style.configure("LoginCard.TFrame", background=colors["surface"], relief="solid", borderwidth=1)
            
            self.style.configure("LoginTitle.TLabel", 
                background=colors["surface"], 
                foreground=colors["text"], 
                font=fonts["title"]
            )
            
            self.style.configure("LoginSubtitle.TLabel", 
                background=colors["surface"], 
                foreground=colors["text_secondary"], 
                font=fonts["default"]
            )
            
            self.style.configure("LoginLabel.TLabel", 
                background=colors["surface"], 
                foreground=colors["text"], 
                font=fonts["default"]
            )
            
            self.style.configure("LoginEntry.TEntry", 
                fieldbackground=colors["background"], 
                foreground=colors["text"], 
                bordercolor=colors["border"],
                font=fonts["default"]
            )
            
            self.style.configure("LoginButton.TButton", 
                background=colors["secondary"], 
                foreground=colors["light"], 
                font=(fonts["default"][0], fonts["default"][1], "bold"),
                padding=(20, 10)
            )
            
            self.style.configure("AltLogin.TButton", 
                background=colors["surface"], 
                foreground=colors["text"], 
                font=fonts["default"],
                padding=(10, 5)
            )
            
            self.style.configure("ShowPassword.TButton", 
                background=colors["surface"], 
                foreground=colors["text"], 
                font=fonts["default"],
                padding=(5, 5)
            )
            
            self.style.configure("LoginCheck.TCheckbutton", 
                background=colors["surface"], 
                foreground=colors["text"], 
                font=fonts["default"]
            )
            
            self.style.configure("LoginLink.TLabel", 
                background=colors["surface"], 
                foreground=colors["secondary"], 
                font=fonts["default"]
            )
            
            self.style.configure("LoginFooter.TLabel", 
                background=colors["surface"], 
                foreground=colors["text_secondary"], 
                font=fonts["default"]
            )
            
            # Password strength styles
            self.style.configure("WeakPassword.Horizontal.TProgressbar", 
                background=colors["danger"], 
                troughcolor=colors["background"]
            )
            
            self.style.configure("MediumPassword.Horizontal.TProgressbar", 
                background=colors["warning"], 
                troughcolor=colors["background"]
            )
            
            self.style.configure("StrongPassword.Horizontal.TProgressbar", 
                background=colors["success"], 
                troughcolor=colors["background"]
            )
            
        except Exception as e:
            logger.error(f"Failed to apply custom styles: {e}")

    def get_theme(self, theme_name: str) -> Optional[Dict[str, Any]]:
        """Get theme data by name."""
        if theme_name in self.builtin_themes:
            return self.builtin_themes[theme_name]
        elif theme_name in self.custom_themes:
            return self.custom_themes[theme_name]
        else:
            return None

    def get_available_themes(self) -> List[str]:
        """Get list of available theme names."""
        return list(self.builtin_themes.keys()) + list(self.custom_themes.keys())

    def get_current_theme(self) -> str:
        """Get current theme name."""
        return self.current_theme

    def get_theme_colors(self, theme_name: Optional[str] = None) -> Dict[str, str]:
        """Get colors for a theme (current theme if not specified)."""
        theme_name = theme_name or self.current_theme
        theme_data = self.get_theme(theme_name)
        return theme_data["colors"] if theme_data else {}

    def register_theme_callback(self, callback: callable):
        """Register a callback for theme changes."""
        self.theme_callbacks.append(callback)

    def notify_theme_change(self, theme_name: str, theme_data: Dict[str, Any]):
        """Notify all registered callbacks of theme change."""
        for callback in self.theme_callbacks:
            try:
                callback(theme_name, theme_data)
            except Exception as e:
                logger.error(f"Theme callback error: {e}")

    def create_custom_theme(self, name: str, theme_data: Dict[str, Any]):
        """Create a custom theme."""
        try:
            self.custom_themes[name] = theme_data
            self.save_custom_themes()
            logger.info(f"Created custom theme: {name}")
        except Exception as e:
            logger.error(f"Failed to create custom theme: {e}")

    def load_custom_themes(self):
        """Load custom themes from file."""
        try:
            themes_file = Path.home() / ".plexichat" / "custom_themes.json"
            if themes_file.exists():
                with open(themes_file, 'r') as f:
                    self.custom_themes = json.load(f)
                logger.info(f"Loaded {len(self.custom_themes)} custom themes")
        except Exception as e:
            logger.error(f"Failed to load custom themes: {e}")

    def save_custom_themes(self):
        """Save custom themes to file."""
        try:
            themes_file = Path.home() / ".plexichat" / "custom_themes.json"
            themes_file.parent.mkdir(exist_ok=True)
            
            with open(themes_file, 'w') as f:
                json.dump(self.custom_themes, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save custom themes: {e}")

    def export_theme(self, theme_name: str, file_path: str):
        """Export a theme to file."""
        try:
            theme_data = self.get_theme(theme_name)
            if theme_data:
                with open(file_path, 'w') as f:
                    json.dump(theme_data, f, indent=2)
                logger.info(f"Exported theme '{theme_name}' to {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to export theme: {e}")
            return False

    def import_theme(self, file_path: str) -> Optional[str]:
        """Import a theme from file."""
        try:
            with open(file_path, 'r') as f:
                theme_data = json.load(f)
            
            theme_name = theme_data.get("name", "Imported Theme")
            self.create_custom_theme(theme_name, theme_data)
            
            logger.info(f"Imported theme: {theme_name}")
            return theme_name
            
        except Exception as e:
            logger.error(f"Failed to import theme: {e}")
            return None
