"""
PlexiChat PyQt6 Notification System
Advanced notification management with multiple notification types.
"""

import logging
from typing import Dict, Any, Optional, List
from enum import Enum
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGraphicsDropShadowEffect, QApplication, QSystemTrayIcon,
    QMenu, QMessageBox
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect,
    pyqtSignal, QPoint, QSize
)
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    """Notification types."""
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class NotificationWidget(QFrame):
    """Individual notification widget."""
    
    closed = pyqtSignal()
    
    def __init__(self, title: str, message: str, notification_type: NotificationType, parent=None):
        super().__init__(parent)
        self.title = title
        self.message = message
        self.notification_type = notification_type
        self.setup_ui()
        self.setup_animations()
        
        # Auto-close timer
        self.close_timer = QTimer()
        self.close_timer.timeout.connect(self.close_notification)
        self.close_timer.start(5000)  # 5 seconds
    
    def setup_ui(self):
        """Setup the notification UI."""
        self.setFixedSize(350, 80)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        
        # Set style based on notification type
        self.apply_style()
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 5)
        self.setGraphicsEffect(shadow)
        
        # Layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        
        # Icon
        icon_label = QLabel(self.get_icon())
        icon_label.setFont(QFont("Arial", 20))
        icon_label.setFixedSize(30, 30)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        # Content
        content_layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(self.title)
        title_label.setFont(QFont("Inter", 12, QFont.Weight.Bold))
        title_label.setStyleSheet("color: white;")
        content_layout.addWidget(title_label)
        
        # Message
        message_label = QLabel(self.message)
        message_label.setFont(QFont("Inter", 10))
        message_label.setStyleSheet("color: rgba(255, 255, 255, 0.9);")
        message_label.setWordWrap(True)
        content_layout.addWidget(message_label)
        
        layout.addLayout(content_layout)
        
        # Close button
        close_btn = QPushButton("×")
        close_btn.setFixedSize(20, 20)
        close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: white;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 10px;
            }
        """)
        close_btn.clicked.connect(self.close_notification)
        layout.addWidget(close_btn)
    
    def apply_style(self):
        """Apply style based on notification type."""
        styles = {
            NotificationType.INFO: """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #2196F3, stop:1 #1976D2);
                    border-radius: 8px;
                    border: 1px solid #1565C0;
                }
            """,
            NotificationType.SUCCESS: """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #4CAF50, stop:1 #388E3C);
                    border-radius: 8px;
                    border: 1px solid #2E7D32;
                }
            """,
            NotificationType.WARNING: """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #FF9800, stop:1 #F57C00);
                    border-radius: 8px;
                    border: 1px solid #E65100;
                }
            """,
            NotificationType.ERROR: """
                QFrame {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #F44336, stop:1 #D32F2F);
                    border-radius: 8px;
                    border: 1px solid #C62828;
                }
            """
        }
        
        self.setStyleSheet(styles.get(self.notification_type, styles[NotificationType.INFO]))
    
    def get_icon(self) -> str:
        """Get icon for notification type."""
        icons = {
            NotificationType.INFO: "ℹ️",
            NotificationType.SUCCESS: "✅",
            NotificationType.WARNING: "⚠️",
            NotificationType.ERROR: "❌"
        }
        return icons.get(self.notification_type, "ℹ️")
    
    def setup_animations(self):
        """Setup entrance and exit animations."""
        # Entrance animation
        self.entrance_animation = QPropertyAnimation(self, b"geometry")
        self.entrance_animation.setDuration(300)
        self.entrance_animation.setEasingCurve(QEasingCurve.Type.OutBack)
        
        # Exit animation
        self.exit_animation = QPropertyAnimation(self, b"geometry")
        self.exit_animation.setDuration(200)
        self.exit_animation.setEasingCurve(QEasingCurve.Type.InCubic)
        self.exit_animation.finished.connect(self.closed.emit)
    
    def show_notification(self, position: QPoint):
        """Show notification with animation."""
        # Set initial position (off-screen)
        start_rect = QRect(position.x() + 400, position.y(), 350, 80)
        end_rect = QRect(position.x(), position.y(), 350, 80)
        
        self.setGeometry(start_rect)
        self.show()
        
        # Animate entrance
        self.entrance_animation.setStartValue(start_rect)
        self.entrance_animation.setEndValue(end_rect)
        self.entrance_animation.start()
    
    def close_notification(self):
        """Close notification with animation."""
        self.close_timer.stop()
        
        # Animate exit
        current_rect = self.geometry()
        end_rect = QRect(current_rect.x() + 400, current_rect.y(), 350, 80)
        
        self.exit_animation.setStartValue(current_rect)
        self.exit_animation.setEndValue(end_rect)
        self.exit_animation.start()
    
    def mousePressEvent(self, event):
        """Handle mouse press to close notification."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.close_notification()


class NotificationSystemPyQt(QWidget):
    """
    Advanced notification system for PyQt6.
    Features:
    - Multiple notification types (info, success, warning, error)
    - Animated notifications with smooth entrance/exit
    - System tray integration
    - Desktop notifications
    - Notification history
    - Sound notifications
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.active_notifications: List[NotificationWidget] = []
        self.notification_history: List[Dict[str, Any]] = []
        self.max_notifications = 5
        
        # System tray
        self.system_tray = None
        self.setup_system_tray()
        
        logger.info("Notification system initialized")
    
    def setup_system_tray(self):
        """Setup system tray icon and menu."""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.system_tray = QSystemTrayIcon(self)
            
            # Set icon
            self.set_tray_icon()
            
            # Create context menu
            tray_menu = QMenu()
            
            # Show action
            show_action = tray_menu.addAction("Show PlexiChat")
            show_action.triggered.connect(self.show_main_window)
            
            # Separator
            tray_menu.addSeparator()
            
            # Notifications toggle
            self.notifications_action = tray_menu.addAction("Disable Notifications")
            self.notifications_action.setCheckable(True)
            self.notifications_action.triggered.connect(self.toggle_notifications)
            
            # Separator
            tray_menu.addSeparator()
            
            # Quit action
            quit_action = tray_menu.addAction("Quit")
            quit_action.triggered.connect(self.quit_application)
            
            self.system_tray.setContextMenu(tray_menu)
            self.system_tray.show()
            
            # Connect signals
            self.system_tray.activated.connect(self.on_tray_activated)
        else:
            logger.warning("System tray not available")
    
    def set_tray_icon(self):
        """Set system tray icon."""
        try:
            # Create a simple icon
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.GlobalColor.transparent)
            
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Draw a simple "P" for PlexiChat
            painter.setPen(Qt.GlobalColor.white)
            painter.setFont(QFont("Arial", 20, QFont.Weight.Bold))
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "P")
            
            painter.end()
            
            self.system_tray.setIcon(QIcon(pixmap))
            self.system_tray.setToolTip("PlexiChat")
            
        except Exception as e:
            logger.warning(f"Could not set tray icon: {e}")
    
    def show_notification(self, title: str, message: str, 
                         notification_type: NotificationType = NotificationType.INFO,
                         duration: int = 5000):
        """Show a notification."""
        try:
            # Add to history
            self.notification_history.append({
                "title": title,
                "message": message,
                "type": notification_type,
                "timestamp": QTimer().remainingTime()
            })
            
            # Limit history size
            if len(self.notification_history) > 100:
                self.notification_history = self.notification_history[-100:]
            
            # Remove oldest notification if at max
            if len(self.active_notifications) >= self.max_notifications:
                oldest = self.active_notifications[0]
                oldest.close_notification()
            
            # Create notification widget
            notification = NotificationWidget(title, message, notification_type)
            notification.closed.connect(lambda: self.remove_notification(notification))
            
            # Calculate position
            position = self.calculate_notification_position(len(self.active_notifications))
            
            # Show notification
            notification.show_notification(position)
            self.active_notifications.append(notification)
            
            # System tray notification
            if self.system_tray and self.system_tray.isVisible():
                self.system_tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, duration)
            
            logger.info(f"Notification shown: {title}")
            
        except Exception as e:
            logger.error(f"Failed to show notification: {e}")
    
    def calculate_notification_position(self, index: int) -> QPoint:
        """Calculate position for notification."""
        if self.parent_app:
            parent_rect = self.parent_app.geometry()
            x = parent_rect.right() - 370  # 350 width + 20 margin
            y = parent_rect.top() + 50 + (index * 90)  # 80 height + 10 spacing
        else:
            # Fallback to screen position
            screen = QApplication.primaryScreen().geometry()
            x = screen.right() - 370
            y = screen.top() + 50 + (index * 90)
        
        return QPoint(x, y)
    
    def remove_notification(self, notification: NotificationWidget):
        """Remove notification from active list."""
        if notification in self.active_notifications:
            self.active_notifications.remove(notification)
            notification.deleteLater()
            
            # Reposition remaining notifications
            self.reposition_notifications()
    
    def reposition_notifications(self):
        """Reposition all active notifications."""
        for i, notification in enumerate(self.active_notifications):
            new_position = self.calculate_notification_position(i)
            
            # Animate to new position
            animation = QPropertyAnimation(notification, b"geometry")
            animation.setDuration(200)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.setStartValue(notification.geometry())
            animation.setEndValue(QRect(new_position.x(), new_position.y(), 350, 80))
            animation.start()
    
    def show_info(self, title: str, message: str):
        """Show info notification."""
        self.show_notification(title, message, NotificationType.INFO)
    
    def show_success(self, title: str, message: str):
        """Show success notification."""
        self.show_notification(title, message, NotificationType.SUCCESS)
    
    def show_warning(self, title: str, message: str):
        """Show warning notification."""
        self.show_notification(title, message, NotificationType.WARNING)
    
    def show_error(self, title: str, message: str):
        """Show error notification."""
        self.show_notification(title, message, NotificationType.ERROR)
    
    def clear_all_notifications(self):
        """Clear all active notifications."""
        for notification in self.active_notifications[:]:
            notification.close_notification()
    
    def on_tray_activated(self, reason):
        """Handle system tray activation."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_main_window()
    
    def show_main_window(self):
        """Show main application window."""
        if self.parent_app:
            self.parent_app.show()
            self.parent_app.raise_()
            self.parent_app.activateWindow()
    
    def toggle_notifications(self):
        """Toggle notifications on/off."""
        # Implementation would depend on settings system
        pass
    
    def quit_application(self):
        """Quit the application."""
        if self.parent_app:
            self.parent_app.close()
        else:
            QApplication.quit()
    
    def get_notification_history(self) -> List[Dict[str, Any]]:
        """Get notification history."""
        return self.notification_history.copy()
    
    def cleanup(self):
        """Cleanup notification system."""
        self.clear_all_notifications()
        if self.system_tray:
            self.system_tray.hide()
