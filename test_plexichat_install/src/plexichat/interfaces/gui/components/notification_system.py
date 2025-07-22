"""
Advanced Notification System for PlexiChat GUI
Provides sophisticated notification management with animations and customization.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, Optional, List, Callable
import threading
import time
import logging
from datetime import datetime, timedelta
from enum import Enum
import queue

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    """Notification types."""
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    CHAT = "chat"
    SYSTEM = "system"


class NotificationPriority(Enum):
    """Notification priorities."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


class Notification:
    """Individual notification object."""
    
    def __init__(self, title: str, message: str, notification_type: NotificationType = NotificationType.INFO,
                 priority: NotificationPriority = NotificationPriority.NORMAL, duration: int = 5000,
                 actions: Optional[List[Dict[str, Any]]] = None, data: Optional[Dict[str, Any]] = None):
        self.id = f"notif_{int(time.time() * 1000)}"
        self.title = title
        self.message = message
        self.type = notification_type
        self.priority = priority
        self.duration = duration
        self.actions = actions or []
        self.data = data or {}
        self.created_at = datetime.now()
        self.shown_at = None
        self.dismissed_at = None
        self.is_read = False
        self.is_persistent = duration == 0


class NotificationSystem:
    """
    Advanced notification system for PlexiChat GUI.
    
    Features:
    - Multiple notification types and priorities
    - Animated toast notifications
    - Notification center/history
    - Sound alerts
    - Custom actions
    - Persistent notifications
    - Notification grouping
    - Do not disturb mode
    - Custom positioning
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.enabled = True
        self.do_not_disturb = False
        self.sound_enabled = True
        
        # Notification storage
        self.active_notifications: List[Notification] = []
        self.notification_history: List[Notification] = []
        self.notification_queue = queue.Queue()
        
        # UI components
        self.toast_windows: Dict[str, tk.Toplevel] = {}
        self.notification_center = None
        
        # Settings
        self.max_active_notifications = 5
        self.default_duration = 5000
        self.position = "top_right"  # top_right, top_left, bottom_right, bottom_left
        self.animation_speed = 10
        
        # Callbacks
        self.notification_callbacks: List[Callable] = []
        
        # Start notification processor
        self.start_notification_processor()

    def show_notification(self, title: str, message: str, notification_type: str = "info",
                         priority: str = "normal", duration: int = None, actions: List[Dict[str, Any]] = None,
                         data: Dict[str, Any] = None) -> str:
        """Show a notification."""
        try:
            if not self.enabled:
                return ""
            
            # Convert string types to enums
            notif_type = NotificationType(notification_type.lower())
            notif_priority = NotificationPriority[priority.upper()]
            
            # Use default duration if not specified
            if duration is None:
                duration = self.default_duration
            
            # Create notification
            notification = Notification(
                title=title,
                message=message,
                notification_type=notif_type,
                priority=notif_priority,
                duration=duration,
                actions=actions,
                data=data
            )
            
            # Add to queue
            self.notification_queue.put(notification)
            
            logger.info(f"Notification queued: {title}")
            return notification.id
            
        except Exception as e:
            logger.error(f"Failed to show notification: {e}")
            return ""

    def start_notification_processor(self):
        """Start the notification processing thread."""
        def process_notifications():
            while True:
                try:
                    # Get notification from queue (blocking)
                    notification = self.notification_queue.get(timeout=1)
                    
                    # Process notification on main thread
                    self.root.after(0, self.process_notification, notification)
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Notification processor error: {e}")
        
        processor_thread = threading.Thread(target=process_notifications, daemon=True)
        processor_thread.start()

    def process_notification(self, notification: Notification):
        """Process a notification on the main thread."""
        try:
            # Check if we should show this notification
            if not self.should_show_notification(notification):
                return
            
            # Add to active notifications
            self.active_notifications.append(notification)
            self.notification_history.append(notification)
            
            # Limit active notifications
            while len(self.active_notifications) > self.max_active_notifications:
                oldest = self.active_notifications.pop(0)
                self.dismiss_notification(oldest.id, auto_dismiss=True)
            
            # Show toast notification
            self.show_toast_notification(notification)
            
            # Play sound if enabled
            if self.sound_enabled:
                self.play_notification_sound(notification.type)
            
            # Schedule auto-dismiss if not persistent
            if not notification.is_persistent:
                self.root.after(notification.duration, lambda: self.dismiss_notification(notification.id, auto_dismiss=True))
            
            # Notify callbacks
            self.notify_callbacks(notification)
            
            notification.shown_at = datetime.now()
            
        except Exception as e:
            logger.error(f"Failed to process notification: {e}")

    def should_show_notification(self, notification: Notification) -> bool:
        """Check if notification should be shown."""
        if not self.enabled:
            return False
        
        if self.do_not_disturb and notification.priority != NotificationPriority.URGENT:
            return False
        
        return True

    def show_toast_notification(self, notification: Notification):
        """Show a toast notification window."""
        try:
            # Create toast window
            toast = tk.Toplevel(self.root)
            toast.withdraw()  # Hide initially for positioning
            
            # Configure window
            toast.overrideredirect(True)
            toast.attributes('-topmost', True)
            toast.configure(bg='#2c3e50')
            
            # Store reference
            self.toast_windows[notification.id] = toast
            
            # Create notification content
            self.create_toast_content(toast, notification)
            
            # Position and show toast
            self.position_toast(toast)
            self.animate_toast_in(toast, notification)
            
        except Exception as e:
            logger.error(f"Failed to show toast notification: {e}")

    def create_toast_content(self, toast: tk.Toplevel, notification: Notification):
        """Create the content for a toast notification."""
        try:
            # Main frame
            main_frame = tk.Frame(toast, bg='#34495e', padx=15, pady=10)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Header frame
            header_frame = tk.Frame(main_frame, bg='#34495e')
            header_frame.pack(fill=tk.X, pady=(0, 5))
            
            # Notification icon
            icon_label = tk.Label(
                header_frame,
                text=self.get_notification_icon(notification.type),
                font=("Segoe UI", 16),
                fg=self.get_notification_color(notification.type),
                bg='#34495e'
            )
            icon_label.pack(side=tk.LEFT, padx=(0, 10))
            
            # Title
            title_label = tk.Label(
                header_frame,
                text=notification.title,
                font=("Segoe UI", 12, "bold"),
                fg='#ecf0f1',
                bg='#34495e'
            )
            title_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            # Close button
            close_btn = tk.Label(
                header_frame,
                text="✕",
                font=("Segoe UI", 12),
                fg='#bdc3c7',
                bg='#34495e',
                cursor='hand2'
            )
            close_btn.pack(side=tk.RIGHT)
            close_btn.bind("<Button-1>", lambda e: self.dismiss_notification(notification.id))
            
            # Message
            message_label = tk.Label(
                main_frame,
                text=notification.message,
                font=("Segoe UI", 10),
                fg='#bdc3c7',
                bg='#34495e',
                wraplength=300,
                justify=tk.LEFT
            )
            message_label.pack(fill=tk.X, pady=(0, 10))
            
            # Actions
            if notification.actions:
                self.create_notification_actions(main_frame, notification)
            
            # Timestamp
            timestamp_label = tk.Label(
                main_frame,
                text=notification.created_at.strftime("%H:%M"),
                font=("Segoe UI", 8),
                fg='#7f8c8d',
                bg='#34495e'
            )
            timestamp_label.pack(anchor=tk.E)
            
            # Bind click events
            self.bind_toast_events(toast, notification)
            
        except Exception as e:
            logger.error(f"Failed to create toast content: {e}")

    def create_notification_actions(self, parent: tk.Widget, notification: Notification):
        """Create action buttons for notification."""
        try:
            actions_frame = tk.Frame(parent, bg='#34495e')
            actions_frame.pack(fill=tk.X, pady=(5, 0))
            
            for action in notification.actions:
                btn = tk.Button(
                    actions_frame,
                    text=action.get("text", "Action"),
                    font=("Segoe UI", 9),
                    bg='#3498db',
                    fg='white',
                    relief=tk.FLAT,
                    padx=10,
                    pady=2,
                    cursor='hand2',
                    command=lambda a=action: self.handle_notification_action(notification, a)
                )
                btn.pack(side=tk.LEFT, padx=(0, 5))
                
        except Exception as e:
            logger.error(f"Failed to create notification actions: {e}")

    def handle_notification_action(self, notification: Notification, action: Dict[str, Any]):
        """Handle notification action click."""
        try:
            callback = action.get("callback")
            if callback and callable(callback):
                callback(notification, action)
            
            # Auto-dismiss if specified
            if action.get("dismiss", True):
                self.dismiss_notification(notification.id)
                
        except Exception as e:
            logger.error(f"Failed to handle notification action: {e}")

    def bind_toast_events(self, toast: tk.Toplevel, notification: Notification):
        """Bind events to toast window."""
        try:
            # Click to dismiss
            def on_click(event):
                self.dismiss_notification(notification.id)
            
            # Hover effects
            def on_enter(event):
                toast.configure(bg='#3498db')
            
            def on_leave(event):
                toast.configure(bg='#2c3e50')
            
            # Bind to all widgets
            for widget in self.get_all_children(toast):
                widget.bind("<Button-1>", on_click)
                widget.bind("<Enter>", on_enter)
                widget.bind("<Leave>", on_leave)
                
        except Exception as e:
            logger.error(f"Failed to bind toast events: {e}")

    def get_all_children(self, widget: tk.Widget) -> List[tk.Widget]:
        """Get all child widgets recursively."""
        children = [widget]
        for child in widget.winfo_children():
            children.extend(self.get_all_children(child))
        return children

    def position_toast(self, toast: tk.Toplevel):
        """Position toast notification on screen."""
        try:
            toast.update_idletasks()
            
            # Get dimensions
            toast_width = toast.winfo_reqwidth()
            toast_height = toast.winfo_reqheight()
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            
            # Calculate position based on setting
            margin = 20
            if self.position == "top_right":
                x = screen_width - toast_width - margin
                y = margin
            elif self.position == "top_left":
                x = margin
                y = margin
            elif self.position == "bottom_right":
                x = screen_width - toast_width - margin
                y = screen_height - toast_height - margin
            elif self.position == "bottom_left":
                x = margin
                y = screen_height - toast_height - margin
            else:
                x = screen_width - toast_width - margin
                y = margin
            
            # Adjust for multiple notifications
            active_count = len([t for t in self.toast_windows.values() if t.winfo_exists()])
            if self.position.startswith("top"):
                y += (toast_height + 10) * (active_count - 1)
            else:
                y -= (toast_height + 10) * (active_count - 1)
            
            toast.geometry(f"{toast_width}x{toast_height}+{x}+{y}")
            
        except Exception as e:
            logger.error(f"Failed to position toast: {e}")

    def animate_toast_in(self, toast: tk.Toplevel, notification: Notification):
        """Animate toast notification appearing."""
        try:
            toast.deiconify()
            
            # Simple fade-in effect (simplified for this example)
            toast.attributes('-alpha', 0.0)
            
            def fade_in(alpha=0.0):
                if alpha < 1.0:
                    alpha += 0.1
                    toast.attributes('-alpha', alpha)
                    toast.after(50, lambda: fade_in(alpha))
            
            fade_in()
            
        except Exception as e:
            logger.error(f"Failed to animate toast in: {e}")

    def animate_toast_out(self, toast: tk.Toplevel, callback: Callable = None):
        """Animate toast notification disappearing."""
        try:
            def fade_out(alpha=1.0):
                if alpha > 0.0:
                    alpha -= 0.1
                    toast.attributes('-alpha', alpha)
                    toast.after(50, lambda: fade_out(alpha))
                else:
                    toast.destroy()
                    if callback:
                        callback()
            
            fade_out()
            
        except Exception as e:
            logger.error(f"Failed to animate toast out: {e}")
            if callback:
                callback()

    def dismiss_notification(self, notification_id: str, auto_dismiss: bool = False):
        """Dismiss a notification."""
        try:
            # Find and remove from active notifications
            notification = None
            for i, notif in enumerate(self.active_notifications):
                if notif.id == notification_id:
                    notification = self.active_notifications.pop(i)
                    break
            
            if notification:
                notification.dismissed_at = datetime.now()
                if not auto_dismiss:
                    notification.is_read = True
            
            # Remove toast window
            if notification_id in self.toast_windows:
                toast = self.toast_windows[notification_id]
                if toast.winfo_exists():
                    self.animate_toast_out(toast, lambda: self.toast_windows.pop(notification_id, None))
                else:
                    self.toast_windows.pop(notification_id, None)
            
        except Exception as e:
            logger.error(f"Failed to dismiss notification: {e}")

    def get_notification_icon(self, notification_type: NotificationType) -> str:
        """Get icon for notification type."""
        icons = {
            NotificationType.INFO: "ℹ",
            NotificationType.SUCCESS: "✓",
            NotificationType.WARNING: "⚠",
            NotificationType.ERROR: "✕",
            NotificationType.CHAT: "💬",
            NotificationType.SYSTEM: "⚙"
        }
        return icons.get(notification_type, "ℹ")

    def get_notification_color(self, notification_type: NotificationType) -> str:
        """Get color for notification type."""
        colors = {
            NotificationType.INFO: "#3498db",
            NotificationType.SUCCESS: "#27ae60",
            NotificationType.WARNING: "#f39c12",
            NotificationType.ERROR: "#e74c3c",
            NotificationType.CHAT: "#9b59b6",
            NotificationType.SYSTEM: "#34495e"
        }
        return colors.get(notification_type, "#3498db")

    def play_notification_sound(self, notification_type: NotificationType):
        """Play notification sound."""
        try:
            # Simple beep for now (can be enhanced with actual sound files)
            if notification_type == NotificationType.ERROR:
                self.root.bell()  # System error sound
            else:
                pass  # Could play custom sounds here
                
        except Exception as e:
            logger.error(f"Failed to play notification sound: {e}")

    def clear_all_notifications(self):
        """Clear all active notifications."""
        try:
            for notification in self.active_notifications.copy():
                self.dismiss_notification(notification.id)
            
        except Exception as e:
            logger.error(f"Failed to clear all notifications: {e}")

    def set_enabled(self, enabled: bool):
        """Enable or disable notifications."""
        self.enabled = enabled

    def set_do_not_disturb(self, enabled: bool):
        """Enable or disable do not disturb mode."""
        self.do_not_disturb = enabled

    def set_sound_enabled(self, enabled: bool):
        """Enable or disable notification sounds."""
        self.sound_enabled = enabled

    def register_callback(self, callback: Callable):
        """Register a callback for notification events."""
        self.notification_callbacks.append(callback)

    def notify_callbacks(self, notification: Notification):
        """Notify all registered callbacks."""
        for callback in self.notification_callbacks:
            try:
                callback(notification)
            except Exception as e:
                logger.error(f"Notification callback error: {e}")

    def get_notification_history(self) -> List[Notification]:
        """Get notification history."""
        return self.notification_history.copy()

    def get_active_notifications(self) -> List[Notification]:
        """Get active notifications."""
        return self.active_notifications.copy()

    def cleanup(self):
        """Cleanup notification system."""
        try:
            self.clear_all_notifications()
            
            # Close all toast windows
            for toast in self.toast_windows.values():
                if toast.winfo_exists():
                    toast.destroy()
            
            self.toast_windows.clear()
            
        except Exception as e:
            logger.error(f"Failed to cleanup notification system: {e}")
