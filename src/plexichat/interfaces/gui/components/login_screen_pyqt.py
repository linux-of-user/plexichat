"""
PlexiChat Modern PyQt6 Login Screen
Beautiful, modern login interface with glassmorphic design and animations.
"""

import sys
import logging
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QFrame, QGraphicsDropShadowEffect,
    QApplication, QMessageBox, QProgressBar, QSpacerItem,
    QSizePolicy, QGridLayout, QFormLayout
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect,
    pyqtSignal, QThread, QSize, QPoint
)
from PyQt6.QtGui import (
    QFont, QPixmap, QPainter, QBrush, QLinearGradient,
    QColor, QPen, QPalette, QIcon, QMovie, QFontMetrics
)

logger = logging.getLogger(__name__)


class AnimatedBackground(QWidget):
    """Animated starry background widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.stars = []
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_animation)
        self.timer.start(50)  # 20 FPS
        self.init_stars()
    
    def init_stars(self):
        """Initialize star positions."""
        import random
        for _ in range(100):
            self.stars.append({
                'x': random.randint(0, 1400),
                'y': random.randint(0, 900),
                'size': random.randint(1, 3),
                'speed': random.uniform(0.1, 0.5),
                'opacity': random.uniform(0.3, 1.0)
            })
    
    def update_animation(self):
        """Update star animation."""
        for star in self.stars:
            star['y'] += star['speed']
            if star['y'] > self.height():
                star['y'] = -10
                import random
                star['x'] = random.randint(0, self.width())
        self.update()
    
    def paintEvent(self, event):
        """Paint the animated background."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Dark gradient background
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor("#1a1a2e"))
        gradient.setColorAt(0.5, QColor("#16213e"))
        gradient.setColorAt(1, QColor("#0f3460"))
        painter.fillRect(self.rect(), QBrush(gradient))
        
        # Draw stars
        painter.setPen(Qt.PenStyle.NoPen)
        for star in self.stars:
            color = QColor(255, 255, 255, int(star['opacity'] * 255))
            painter.setBrush(QBrush(color))
            painter.drawEllipse(int(star['x']), int(star['y']), 
                              star['size'], star['size'])


class ModernButton(QPushButton):
    """Modern styled button with hover effects."""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(50)
        self.setFont(QFont("Inter", 14, QFont.Weight.Bold))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setup_style()
        
        # Animation
        self.animation = QPropertyAnimation(self, b"geometry")
        self.animation.setDuration(200)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    
    def setup_style(self):
        """Setup button styling."""
        self.setStyleSheet("""
            ModernButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4A90E2, stop:1 #357ABD);
                border: none;
                border-radius: 25px;
                color: white;
                font-weight: bold;
                padding: 15px 30px;
            }
            ModernButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5BA0F2, stop:1 #4A90E2);
                transform: translateY(-2px);
            }
            ModernButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #357ABD, stop:1 #2E6BA8);
            }
        """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 5)
        self.setGraphicsEffect(shadow)


class ModernLineEdit(QLineEdit):
    """Modern styled line edit with floating labels."""
    
    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setMinimumHeight(50)
        self.setFont(QFont("Inter", 12))
        self.setup_style()
    
    def setup_style(self):
        """Setup line edit styling."""
        self.setStyleSheet("""
            ModernLineEdit {
                background: rgba(255, 255, 255, 0.1);
                border: 2px solid rgba(255, 255, 255, 0.2);
                border-radius: 25px;
                padding: 15px 20px;
                color: white;
                font-size: 14px;
            }
            ModernLineEdit:focus {
                border: 2px solid #4A90E2;
                background: rgba(255, 255, 255, 0.15);
            }
            ModernLineEdit::placeholder {
                color: rgba(255, 255, 255, 0.6);
            }
        """)


class LoginScreenPyQt(QWidget):
    """
    Modern PyQt6 login screen with glassmorphic design.
    Features:
    - Animated starry background
    - Glassmorphic login panel
    - Modern input fields with floating labels
    - Beautiful login button with hover effects
    - Dark/light theme toggle
    - Remember me functionality
    - Password visibility toggle
    - Smooth animations and transitions
    """
    
    # Signals
    login_requested = pyqtSignal(str, str, bool)  # username, password, remember_me
    login_success = pyqtSignal(dict)  # user_data
    theme_toggle_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.is_authenticating = False
        self.dark_mode = True
        
        # UI components
        self.background: Optional[AnimatedBackground] = None
        self.login_panel: Optional[QFrame] = None
        self.username_input: Optional[ModernLineEdit] = None
        self.password_input: Optional[ModernLineEdit] = None
        self.login_button: Optional[ModernButton] = None
        self.remember_checkbox: Optional[QCheckBox] = None
        self.theme_toggle: Optional[QPushButton] = None
        self.progress_bar: Optional[QProgressBar] = None
        
        self.setup_ui()
        self.setup_animations()
        self.load_saved_credentials()
        
        logger.info("Modern PyQt6 login interface initialized successfully")
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Animated background
        self.background = AnimatedBackground(self)
        main_layout.addWidget(self.background)
        
        # Overlay layout for login panel
        overlay_layout = QVBoxLayout(self.background)
        overlay_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Theme toggle button (top right)
        self.create_theme_toggle()
        
        # Login panel
        self.create_login_panel()
        overlay_layout.addWidget(self.login_panel)
        
        # Footer
        self.create_footer()
    
    def create_theme_toggle(self):
        """Create theme toggle button."""
        self.theme_toggle = QPushButton("🌙 Dark Mode")
        self.theme_toggle.setFixedSize(120, 40)
        self.theme_toggle.clicked.connect(self.toggle_theme)
        self.theme_toggle.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 20px;
                color: white;
                font-weight: bold;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.2);
            }
        """)
        
        # Position in top right
        self.theme_toggle.setParent(self.background)
        self.theme_toggle.move(self.width() - 140, 20)
    
    def create_login_panel(self):
        """Create the main login panel."""
        self.login_panel = QFrame()
        self.login_panel.setFixedSize(400, 500)
        self.login_panel.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 20px;
                backdrop-filter: blur(10px);
            }
        """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 10)
        self.login_panel.setGraphicsEffect(shadow)
        
        # Panel layout
        panel_layout = QVBoxLayout(self.login_panel)
        panel_layout.setContentsMargins(40, 40, 40, 40)
        panel_layout.setSpacing(20)
        
        # Logo and title
        self.create_header(panel_layout)
        
        # Input fields
        self.create_input_fields(panel_layout)
        
        # Actions (remember me, forgot password)
        self.create_actions(panel_layout)
        
        # Login button
        self.create_login_button(panel_layout)
        
        # Progress bar
        self.create_progress_bar(panel_layout)
    
    def create_header(self, layout):
        """Create header with logo and title."""
        # Logo
        logo_label = QLabel("🔷")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setFont(QFont("Arial", 48))
        logo_label.setStyleSheet("color: #4A90E2; margin-bottom: 10px;")
        layout.addWidget(logo_label)
        
        # Title
        title_label = QLabel("PlexiChat")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Inter", 24, QFont.Weight.Bold))
        title_label.setStyleSheet("color: white; margin-bottom: 5px;")
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Management Interface")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setFont(QFont("Inter", 12))
        subtitle_label.setStyleSheet("color: rgba(255, 255, 255, 0.7); margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
    
    def create_input_fields(self, layout):
        """Create input fields."""
        # Username field
        username_label = QLabel("🔒 Username")
        username_label.setFont(QFont("Inter", 12, QFont.Weight.Bold))
        username_label.setStyleSheet("color: white; margin-bottom: 5px;")
        layout.addWidget(username_label)
        
        self.username_input = ModernLineEdit("Enter your username")
        layout.addWidget(self.username_input)
        
        # Password field
        password_label = QLabel("🔑 Password")
        password_label.setFont(QFont("Inter", 12, QFont.Weight.Bold))
        password_label.setStyleSheet("color: white; margin-bottom: 5px; margin-top: 10px;")
        layout.addWidget(password_label)
        
        self.password_input = ModernLineEdit("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)
        
        # Password visibility toggle
        self.create_password_toggle()
    
    def create_password_toggle(self):
        """Create password visibility toggle."""
        toggle_btn = QPushButton("👁")
        toggle_btn.setFixedSize(30, 30)
        toggle_btn.clicked.connect(self.toggle_password_visibility)
        toggle_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: rgba(255, 255, 255, 0.7);
                font-size: 16px;
            }
            QPushButton:hover {
                color: white;
            }
        """)
        
        # Position toggle button
        toggle_btn.setParent(self.password_input)
        toggle_btn.move(self.password_input.width() - 40, 10)
    
    def create_actions(self, layout):
        """Create action buttons and checkboxes."""
        actions_layout = QHBoxLayout()
        
        # Remember me checkbox
        self.remember_checkbox = QCheckBox("Remember me")
        self.remember_checkbox.setFont(QFont("Inter", 10))
        self.remember_checkbox.setStyleSheet("""
            QCheckBox {
                color: rgba(255, 255, 255, 0.8);
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid rgba(255, 255, 255, 0.3);
                background: transparent;
            }
            QCheckBox::indicator:checked {
                background: #4A90E2;
                border: 2px solid #4A90E2;
            }
        """)
        actions_layout.addWidget(self.remember_checkbox)
        
        actions_layout.addStretch()
        
        # Forgot password link
        forgot_link = QPushButton("Forgot password?")
        forgot_link.setFlat(True)
        forgot_link.setFont(QFont("Inter", 10))
        forgot_link.setStyleSheet("""
            QPushButton {
                color: #4A90E2;
                border: none;
                text-decoration: underline;
            }
            QPushButton:hover {
                color: #5BA0F2;
            }
        """)
        forgot_link.clicked.connect(self.show_password_reset_info)
        actions_layout.addWidget(forgot_link)
        
        layout.addLayout(actions_layout)
    
    def create_login_button(self, layout):
        """Create the main login button."""
        self.login_button = ModernButton("Sign In →")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        # Connect Enter key to login
        self.username_input.returnPressed.connect(self.handle_login)
        self.password_input.returnPressed.connect(self.handle_login)
    
    def create_progress_bar(self, layout):
        """Create progress bar for login process."""
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 10px;
                background: rgba(255, 255, 255, 0.1);
                height: 20px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4A90E2, stop:1 #5BA0F2);
                border-radius: 10px;
            }
        """)
        layout.addWidget(self.progress_bar)
    
    def create_footer(self):
        """Create footer with system status."""
        footer = QLabel("System Status: Online | Version: a.1.1-144")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setFont(QFont("Inter", 10))
        footer.setStyleSheet("""
            color: rgba(255, 255, 255, 0.5);
            padding: 20px;
        """)
        footer.setParent(self.background)
        footer.move(0, self.height() - 60)
    
    def setup_animations(self):
        """Setup UI animations."""
        # Panel entrance animation
        self.panel_animation = QPropertyAnimation(self.login_panel, b"geometry")
        self.panel_animation.setDuration(800)
        self.panel_animation.setEasingCurve(QEasingCurve.Type.OutBack)
        
        # Start animation
        QTimer.singleShot(100, self.animate_panel_entrance)
    
    def animate_panel_entrance(self):
        """Animate panel entrance."""
        if self.login_panel:
            start_rect = QRect(200, -500, 400, 500)
            end_rect = QRect(200, 200, 400, 500)
            
            self.panel_animation.setStartValue(start_rect)
            self.panel_animation.setEndValue(end_rect)
            self.panel_animation.start()
    
    def toggle_theme(self):
        """Toggle between dark and light themes."""
        self.dark_mode = not self.dark_mode
        self.theme_toggle.setText("☀️ Light Mode" if self.dark_mode else "🌙 Dark Mode")
        self.theme_toggle_requested.emit()
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def handle_login(self):
        """Handle login button click."""
        if self.is_authenticating:
            return

        username = self.username_input.text().strip()
        password = self.password_input.text()
        remember_me = self.remember_checkbox.isChecked()

        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Please enter both username and password.")
            return

        self.start_login_process()

        # Simulate authentication (replace with real auth)
        QTimer.singleShot(1000, lambda: self.simulate_login_success(username))

    def simulate_login_success(self, username):
        """Simulate successful login."""
        user_data = {
            'username': username,
            'role': 'admin',
            'authenticated': True
        }
        self.login_success(user_data)
    
    def start_login_process(self):
        """Start the login process with visual feedback."""
        self.is_authenticating = True
        self.login_button.setText("Signing in...")
        self.login_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
    
    def handle_login_success(self, user_data: dict):
        """Handle successful login."""
        self.is_authenticating = False
        self.login_button.setText("Success! ✓")
        self.progress_bar.setVisible(False)

        # Save credentials if remember me is checked
        if self.remember_checkbox.isChecked():
            self.save_credentials()

        # Emit success signal
        self.login_success.emit(user_data)

        # Also emit to parent if available (backward compatibility)
        if self.parent_app and hasattr(self.parent_app, 'user_authenticated'):
            self.parent_app.user_authenticated.emit(user_data)
    
    def login_failed(self, error_message: str):
        """Handle failed login."""
        self.is_authenticating = False
        self.login_button.setText("Sign In →")
        self.login_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        QMessageBox.critical(self, "Login Failed", error_message)
    
    def save_credentials(self):
        """Save login credentials."""
        # In a real app, you'd want to encrypt these
        settings = QApplication.instance().property("settings")
        if settings:
            settings.setValue("username", self.username_input.text())
            settings.setValue("remember_me", self.remember_checkbox.isChecked())
    
    def load_saved_credentials(self):
        """Load saved login credentials."""
        settings = QApplication.instance().property("settings")
        if settings:
            username = settings.value("username", "")
            remember_me = settings.value("remember_me", False, type=bool)
            
            if username:
                self.username_input.setText(username)
            self.remember_checkbox.setChecked(remember_me)
    
    def show_password_reset_info(self):
        """Show password reset information."""
        QMessageBox.information(self, "Password Reset",
                              "To reset your password, please contact your system administrator "
                              "or check the PlexiChat documentation for password recovery options.")
    
    def resizeEvent(self, event):
        """Handle resize events."""
        super().resizeEvent(event)
        
        # Reposition theme toggle
        if self.theme_toggle:
            self.theme_toggle.move(self.width() - 140, 20)
        
        # Center login panel
        if self.login_panel:
            x = (self.width() - self.login_panel.width()) // 2
            y = (self.height() - self.login_panel.height()) // 2
            self.login_panel.move(x, y)
