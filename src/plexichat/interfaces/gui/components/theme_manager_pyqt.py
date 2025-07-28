"""
PlexiChat PyQt6 Theme Manager
Advanced theme management system with modern styling.
"""

import logging
from typing import Dict, Any, Optional
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QPalette, QColor

logger = logging.getLogger(__name__)


class ThemeManagerPyQt(QObject):
    """
    Advanced theme management system for PyQt6.
    Supports multiple themes with smooth transitions.
    """
    
    theme_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_widget = parent
        self.current_theme = "dark_modern"
        self.themes = self.load_themes()
        
    def load_themes(self) -> Dict[str, Dict[str, Any]]:
        """Load all available themes."""
        return {
            "dark_modern": {
                "name": "Dark Modern",
                "description": "Modern dark theme with blue accents",
                "colors": {
                    "primary": "#4A90E2",
                    "secondary": "#357ABD", 
                    "background": "#1a1a2e",
                    "surface": "#16213e",
                    "accent": "#0f3460",
                    "text": "#ffffff",
                    "text_secondary": "#b0b0b0",
                    "border": "#333333",
                    "success": "#4CAF50",
                    "warning": "#FF9800",
                    "error": "#F44336"
                },
                "stylesheet": self.get_dark_modern_stylesheet()
            },
            "light_modern": {
                "name": "Light Modern", 
                "description": "Clean light theme with blue accents",
                "colors": {
                    "primary": "#4A90E2",
                    "secondary": "#357ABD",
                    "background": "#f8fafc",
                    "surface": "#ffffff",
                    "accent": "#e3f2fd",
                    "text": "#333333",
                    "text_secondary": "#666666",
                    "border": "#e0e0e0",
                    "success": "#4CAF50",
                    "warning": "#FF9800", 
                    "error": "#F44336"
                },
                "stylesheet": self.get_light_modern_stylesheet()
            },
            "cyberpunk": {
                "name": "Cyberpunk",
                "description": "Futuristic neon theme",
                "colors": {
                    "primary": "#00ff9f",
                    "secondary": "#ff0080",
                    "background": "#0a0a0a",
                    "surface": "#1a1a1a",
                    "accent": "#2a2a2a",
                    "text": "#00ff9f",
                    "text_secondary": "#ff0080",
                    "border": "#333333",
                    "success": "#00ff9f",
                    "warning": "#ffff00",
                    "error": "#ff0080"
                },
                "stylesheet": self.get_cyberpunk_stylesheet()
            },
            "neon_blue": {
                "name": "Neon Blue",
                "description": "Electric blue neon theme",
                "colors": {
                    "primary": "#00d4ff",
                    "secondary": "#0099cc",
                    "background": "#0a0f1a",
                    "surface": "#1a2332",
                    "accent": "#2a3441",
                    "text": "#ffffff",
                    "text_secondary": "#00d4ff",
                    "border": "#00d4ff",
                    "success": "#00ff88",
                    "warning": "#ffaa00",
                    "error": "#ff4444"
                },
                "stylesheet": self.get_neon_blue_stylesheet()
            },
            "forest_green": {
                "name": "Forest Green",
                "description": "Natural forest theme",
                "colors": {
                    "primary": "#4CAF50",
                    "secondary": "#388E3C",
                    "background": "#0d1b0f",
                    "surface": "#1a2e1d",
                    "accent": "#2e5233",
                    "text": "#ffffff",
                    "text_secondary": "#81C784",
                    "border": "#4CAF50",
                    "success": "#66BB6A",
                    "warning": "#FFA726",
                    "error": "#EF5350"
                },
                "stylesheet": self.get_forest_green_stylesheet()
            },
            "sunset_orange": {
                "name": "Sunset Orange",
                "description": "Warm sunset theme",
                "colors": {
                    "primary": "#FF6B35",
                    "secondary": "#E55100",
                    "background": "#1a0f0a",
                    "surface": "#2e1a12",
                    "accent": "#3d2318",
                    "text": "#ffffff",
                    "text_secondary": "#FFB74D",
                    "border": "#FF6B35",
                    "success": "#66BB6A",
                    "warning": "#FFCA28",
                    "error": "#EF5350"
                },
                "stylesheet": self.get_sunset_orange_stylesheet()
            },
            "royal_purple": {
                "name": "Royal Purple",
                "description": "Elegant purple theme",
                "colors": {
                    "primary": "#9C27B0",
                    "secondary": "#7B1FA2",
                    "background": "#1a0f1a",
                    "surface": "#2e1a2e",
                    "accent": "#3d233d",
                    "text": "#ffffff",
                    "text_secondary": "#CE93D8",
                    "border": "#9C27B0",
                    "success": "#66BB6A",
                    "warning": "#FFCA28",
                    "error": "#EF5350"
                },
                "stylesheet": self.get_royal_purple_stylesheet()
            }
        }
    
    def get_dark_modern_stylesheet(self) -> str:
        """Get dark modern theme stylesheet with glass effects."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:1 #16213e);
                color: #ffffff;
            }

            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }

            QFrame {
                background: rgba(22, 33, 62, 0.8);
                border: 2px solid #4A90E2;
                border-radius: 12px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4A90E2, stop:1 #357ABD);
                color: white;
                border: 2px solid #4A90E2;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 36px;
            }

            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #5BA0F2, stop:1 #4A90E2);
            }

            QPushButton:pressed {
                background: #357ABD;
            }

            QLineEdit {
                background: rgba(22, 33, 62, 0.6);
                border: 2px solid #4A90E2;
                border-radius: 8px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 14px;
            }

            QLineEdit:focus {
                border-color: #5BA0F2;
            }

            QTabWidget::pane {
                background: rgba(22, 33, 62, 0.8);
                border: 2px solid #4A90E2;
                border-radius: 8px;
            }

            QTabBar::tab {
                background: rgba(22, 33, 62, 0.6);
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 2px solid #4A90E2;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #4A90E2;
                color: #ffffff;
            }

            QTabBar::tab:hover {
                background: rgba(74, 144, 226, 0.3);
            }

            QComboBox {
                background: rgba(22, 33, 62, 0.6);
                border: 2px solid #4A90E2;
                border-radius: 8px;
                padding: 5px;
                color: #ffffff;
            }

            QComboBox:hover {
                border-color: #5BA0F2;
            }

            QComboBox::drop-down {
                border: none;
            }

            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #4A90E2;
            }
            
            QPushButton:pressed {
                background-color: #357ABD;
            }
            
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
            
            QLineEdit {
                background-color: #16213e;
                border: 2px solid #333333;
                border-radius: 6px;
                padding: 8px 12px;
                color: white;
                min-height: 20px;
            }
            
            QLineEdit:focus {
                border-color: #4A90E2;
            }
            
            QTextEdit {
                background-color: #16213e;
                border: 2px solid #333333;
                border-radius: 6px;
                color: white;
                padding: 8px;
            }
            
            QTextEdit:focus {
                border-color: #4A90E2;
            }
            
            QLabel {
                color: #ffffff;
                background: transparent;
            }
            
            QMenuBar {
                background-color: #16213e;
                color: white;
                border-bottom: 1px solid #333333;
            }
            
            QMenuBar::item {
                background: transparent;
                padding: 8px 12px;
            }
            
            QMenuBar::item:selected {
                background-color: #4A90E2;
            }
            
            QMenu {
                background-color: #16213e;
                color: white;
                border: 1px solid #333333;
            }
            
            QMenu::item {
                padding: 8px 20px;
            }
            
            QMenu::item:selected {
                background-color: #4A90E2;
            }
            
            QStatusBar {
                background-color: #16213e;
                color: white;
                border-top: 1px solid #333333;
            }
            
            QToolBar {
                background-color: #16213e;
                border: none;
                spacing: 4px;
            }
            
            QTabWidget::pane {
                border: 1px solid #333333;
                background-color: #16213e;
            }
            
            QTabBar::tab {
                background-color: #1a1a2e;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: #4A90E2;
            }
            
            QScrollBar:vertical {
                background-color: #16213e;
                width: 12px;
                border-radius: 6px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #4A90E2;
                border-radius: 6px;
                min-height: 20px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #5BA0F2;
            }
            
            QCheckBox {
                color: white;
                spacing: 8px;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #333333;
                border-radius: 3px;
                background-color: #16213e;
            }
            
            QCheckBox::indicator:checked {
                background-color: #4A90E2;
                border-color: #4A90E2;
            }
            
            QComboBox {
                background-color: #16213e;
                border: 2px solid #333333;
                border-radius: 6px;
                padding: 8px 12px;
                color: white;
                min-height: 20px;
            }
            
            QComboBox:focus {
                border-color: #4A90E2;
            }
            
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid white;
            }
            
            QProgressBar {
                background-color: #16213e;
                border: 1px solid #333333;
                border-radius: 6px;
                text-align: center;
                color: white;
            }
            
            QProgressBar::chunk {
                background-color: #4A90E2;
                border-radius: 6px;
            }
        """
    
    def get_light_modern_stylesheet(self) -> str:
        """Get light modern theme stylesheet."""
        return """
            QMainWindow {
                background-color: #f8fafc;
                color: #333333;
            }
            
            QWidget {
                background-color: #f8fafc;
                color: #333333;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }
            
            QFrame {
                background-color: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
            }
            
            QPushButton {
                background-color: #4A90E2;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                min-height: 32px;
            }
            
            QPushButton:hover {
                background-color: #5BA0F2;
            }
            
            QPushButton:pressed {
                background-color: #357ABD;
            }
            
            QLineEdit {
                background-color: white;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                padding: 8px 12px;
                color: #333333;
                min-height: 20px;
            }
            
            QLineEdit:focus {
                border-color: #4A90E2;
            }
            
            QLabel {
                color: #333333;
                background: transparent;
            }
            
            QMenuBar {
                background-color: white;
                color: #333333;
                border-bottom: 1px solid #e0e0e0;
            }
            
            QMenuBar::item:selected {
                background-color: #4A90E2;
                color: white;
            }
            
            QStatusBar {
                background-color: white;
                color: #333333;
                border-top: 1px solid #e0e0e0;
            }
        """
    
    def get_cyberpunk_stylesheet(self) -> str:
        """Get cyberpunk theme stylesheet with enhanced neon effects."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.5 #1a0a1a, stop:1 #0a1a0a);
                color: #00ff9f;
            }

            QWidget {
                background-color: transparent;
                color: #00ff9f;
                font-family: 'Courier New', 'Consolas', monospace;
            }

            QFrame {
                background: rgba(26, 26, 26, 0.9);
                border: 2px solid #00ff9f;
                border-radius: 0px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ff9f, stop:1 #ff0080);
                color: #0a0a0a;
                border: 2px solid #00ff9f;
                border-radius: 0px;
                padding: 10px 20px;
                font-weight: bold;
                text-transform: uppercase;
                min-height: 36px;
            }

            QPushButton:hover {
                background: transparent;
                color: #00ff9f;
                border: 2px solid #ff0080;
            }

            QPushButton:pressed {
                background: #ff0080;
                color: #0a0a0a;
            }

            QLineEdit {
                background: rgba(26, 26, 26, 0.8);
                border: 2px solid #00ff9f;
                border-radius: 0px;
                padding: 8px 12px;
                color: #00ff9f;
                font-size: 14px;
            }

            QLineEdit:focus {
                border-color: #ff0080;
            }

            QTabWidget::pane {
                background: rgba(26, 26, 26, 0.9);
                border: 2px solid #00ff9f;
                border-radius: 0px;
            }

            QTabBar::tab {
                background: rgba(26, 26, 26, 0.8);
                color: #00ff9f;
                padding: 8px 16px;
                margin-right: 2px;
                border: 2px solid #00ff9f;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #00ff9f;
                color: #0a0a0a;
            }

            QTabBar::tab:hover {
                background: rgba(255, 0, 128, 0.3);
                border-color: #ff0080;
            }

            QComboBox {
                background: rgba(26, 26, 26, 0.8);
                border: 2px solid #00ff9f;
                border-radius: 0px;
                padding: 5px;
                color: #00ff9f;
            }

            QComboBox:hover {
                border-color: #ff0080;
            }

            QComboBox::drop-down {
                border: none;
            }

            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #00ff9f;
            }
        """
    
    def apply_theme(self, theme_name: str):
        """Apply a theme to the application."""
        try:
            if theme_name not in self.themes:
                logger.warning(f"Theme '{theme_name}' not found, using default")
                theme_name = "dark_modern"
            
            theme = self.themes[theme_name]
            self.current_theme = theme_name
            
            # Apply stylesheet to application
            app = QApplication.instance()
            if app:
                app.setStyleSheet(theme["stylesheet"])
            
            # Apply to parent widget if available
            if self.parent_widget:
                self.parent_widget.setStyleSheet(theme["stylesheet"])
            
            # Emit theme changed signal
            self.theme_changed.emit(theme_name)
            
            logger.info(f"Applied theme: {theme['name']}")
            
        except Exception as e:
            logger.error(f"Failed to apply theme '{theme_name}': {e}")
    
    def get_current_theme(self) -> str:
        """Get the current theme name."""
        return self.current_theme
    
    def get_theme_info(self, theme_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific theme."""
        return self.themes.get(theme_name)
    
    def get_available_themes(self) -> Dict[str, str]:
        """Get list of available themes."""
        return {name: theme["name"] for name, theme in self.themes.items()}
    
    def get_theme_color(self, color_name: str, theme_name: Optional[str] = None) -> str:
        """Get a specific color from the current or specified theme."""
        if theme_name is None:
            theme_name = self.current_theme
        
        theme = self.themes.get(theme_name)
        if theme and "colors" in theme:
            return theme["colors"].get(color_name, "#000000")
        
        return "#000000"
    
    def toggle_theme(self):
        """Toggle between dark and light themes."""
        if self.current_theme == "dark_modern":
            self.apply_theme("light_modern")
        else:
            self.apply_theme("dark_modern")

    def get_neon_blue_stylesheet(self) -> str:
        """Get neon blue theme stylesheet with glass effects."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0f1a, stop:1 #1a2332);
                color: #ffffff;
            }

            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }

            QFrame {
                background: rgba(26, 35, 50, 0.8);
                border: 2px solid #00d4ff;
                border-radius: 12px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00d4ff, stop:1 #0099cc);
                color: white;
                border: 2px solid #00d4ff;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 36px;
            }

            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00e6ff, stop:1 #00b3e6);
            }

            QLineEdit {
                background: rgba(26, 35, 50, 0.6);
                border: 2px solid #00d4ff;
                border-radius: 8px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 14px;
            }

            QTabWidget::pane {
                background: rgba(26, 35, 50, 0.8);
                border: 2px solid #00d4ff;
                border-radius: 8px;
            }

            QTabBar::tab {
                background: rgba(26, 35, 50, 0.6);
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 2px solid #00d4ff;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #00d4ff;
                color: #000000;
            }
        """

    def get_forest_green_stylesheet(self) -> str:
        """Get forest green theme stylesheet with glass effects."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0d1b0f, stop:1 #1a2e1d);
                color: #ffffff;
            }

            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }

            QFrame {
                background: rgba(26, 46, 29, 0.8);
                border: 2px solid #4CAF50;
                border-radius: 12px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #388E3C);
                color: white;
                border: 2px solid #4CAF50;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 36px;
            }

            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #66BB6A, stop:1 #4CAF50);
            }

            QLineEdit {
                background: rgba(26, 46, 29, 0.6);
                border: 2px solid #4CAF50;
                border-radius: 8px;
                padding: 8px 12px;
                color: #ffffff;
                font-size: 14px;
            }

            QTabWidget::pane {
                background: rgba(26, 46, 29, 0.8);
                border: 2px solid #4CAF50;
                border-radius: 8px;
            }

            QTabBar::tab {
                background: rgba(26, 46, 29, 0.6);
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 2px solid #4CAF50;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #4CAF50;
                color: #ffffff;
            }
        """

    def get_sunset_orange_stylesheet(self) -> str:
        """Get sunset orange theme stylesheet."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0f0a, stop:1 #2e1a12);
                color: #ffffff;
            }

            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }

            QFrame {
                background: rgba(46, 26, 18, 0.8);
                border: 2px solid #FF6B35;
                border-radius: 12px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #FF6B35, stop:1 #E55100);
                color: white;
                border: 2px solid #FF6B35;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 36px;
            }

            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #FF8A65, stop:1 #FF6B35);
            }

            QTabWidget::pane {
                background: rgba(46, 26, 18, 0.8);
                border: 2px solid #FF6B35;
                border-radius: 8px;
            }

            QTabBar::tab {
                background: rgba(46, 26, 18, 0.6);
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 2px solid #FF6B35;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #FF6B35;
                color: #ffffff;
            }
        """

    def get_royal_purple_stylesheet(self) -> str:
        """Get royal purple theme stylesheet."""
        return """
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a0f1a, stop:1 #2e1a2e);
                color: #ffffff;
            }

            QWidget {
                background-color: transparent;
                color: #ffffff;
                font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            }

            QFrame {
                background: rgba(46, 26, 46, 0.8);
                border: 2px solid #9C27B0;
                border-radius: 12px;
            }

            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #9C27B0, stop:1 #7B1FA2);
                color: white;
                border: 2px solid #9C27B0;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                min-height: 36px;
            }

            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #BA68C8, stop:1 #9C27B0);
            }

            QTabWidget::pane {
                background: rgba(46, 26, 46, 0.8);
                border: 2px solid #9C27B0;
                border-radius: 8px;
            }

            QTabBar::tab {
                background: rgba(46, 26, 46, 0.6);
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: 2px solid #9C27B0;
                border-bottom: none;
            }

            QTabBar::tab:selected {
                background: #9C27B0;
                color: #ffffff;
            }
        """
