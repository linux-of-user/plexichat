# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
WebUI Renderer for GUI

Renders WebUI pages within the desktop GUI application using embedded web browser.
"""

import asyncio
import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urljoin
import webbrowser

try:
    import webview  # type: ignore
    WEBVIEW_AVAILABLE = True
except ImportError:
    WEBVIEW_AVAILABLE = False
    webview = None

try:
    from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTabWidget  # type: ignore
    from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
    from PyQt5.QtCore import QUrl, pyqtSignal, QTimer  # type: ignore
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

logger = logging.getLogger(__name__)


class WebUIRenderer:
    """Renders WebUI pages in the desktop GUI."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.webview_windows: Dict[str, Any] = {}
        self.qt_widgets: Dict[str, Any] = {}
        self.plugin_pages: Dict[str, Dict[str, str]] = {}
        self.callbacks: Dict[str, Callable] = {}
        
        # Check available rendering engines
        self.rendering_engine = self._detect_rendering_engine()
        
        logger.info(f"WebUI Renderer initialized with engine: {self.rendering_engine}")
    
    def _detect_rendering_engine(self) -> str:
        """Detect available rendering engine."""
        if PYQT_AVAILABLE:
            return "pyqt"
        elif WEBVIEW_AVAILABLE:
            return "webview"
        else:
            return "browser"
    
    def register_plugin_pages(self, plugin_name: str, pages: List[Dict[str, str]]):
        """Register WebUI pages for a plugin."""
        try:
            self.plugin_pages[plugin_name] = {}
            
            for page in pages:
                page_id = f"{plugin_name}_{page['path'].replace('/', '_')}"
                self.plugin_pages[plugin_name][page_id] = {
                    "title": page.get("title", page["path"]),
                    "path": page["path"],
                    "icon": page.get("icon", "globe"),
                    "component": page.get("component", ""),
                    "url": urljoin(self.base_url, page["path"])
                }
            
            logger.info(f"Registered {len(pages)} pages for plugin {plugin_name}")
            
        except Exception as e:
            logger.error(f"Error registering plugin pages: {e}")
    
    def create_plugin_tab_widget(self, parent=None) -> Optional[Any]:
        """Create a tab widget with plugin pages (PyQt version)."""
        if not PYQT_AVAILABLE:
            logger.warning("PyQt not available for tab widget creation")
            return None
        
        try:
            from PyQt5.QtWidgets import QTabWidget, QWidget, QVBoxLayout  # type: ignore
            from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
            from PyQt5.QtCore import QUrl  # type: ignore
            
            tab_widget = QTabWidget(parent)
            
            # Add plugin pages as tabs
            for plugin_name, pages in self.plugin_pages.items():
                for page_id, page_info in pages.items():
                    # Create web view for this page
                    web_view = QWebEngineView()
                    web_view.load(QUrl(page_info["url"]))
                    
                    # Add tab
                    tab_widget.addTab(web_view, f"{page_info['title']}")
                    
                    # Store reference
                    self.qt_widgets[page_id] = web_view
            
            return tab_widget
            
        except Exception as e:
            logger.error(f"Error creating plugin tab widget: {e}")
            return None
    
    def create_plugin_window(self, plugin_name: str, page_path: str, 
                           width: int = 1200, height: int = 800) -> bool:
        """Create a standalone window for a plugin page."""
        try:
            page_url = urljoin(self.base_url, page_path)
            window_id = f"{plugin_name}_{page_path.replace('/', '_')}"
            
            if self.rendering_engine == "pyqt":
                return self._create_pyqt_window(window_id, page_url, width, height)
            elif self.rendering_engine == "webview":
                return self._create_webview_window(window_id, page_url, width, height)
            else:
                return self._open_in_browser(page_url)
                
        except Exception as e:
            logger.error(f"Error creating plugin window: {e}")
            return False
    
    def _create_pyqt_window(self, window_id: str, url: str, width: int, height: int) -> bool:
        """Create PyQt window with embedded web view."""
        try:
            from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QPushButton, QHBoxLayout  # type: ignore
            from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
            from PyQt5.QtCore import QUrl  # type: ignore
            
            class PluginWindow(QMainWindow):
                def __init__(self):
                    super().__init__()
                    self.setWindowTitle(f"PlexiChat - {window_id}")
                    self.setGeometry(100, 100, width, height)
                    
                    # Central widget
                    central_widget = QWidget()
                    self.setCentralWidget(central_widget)
                    
                    # Layout
                    layout = QVBoxLayout(central_widget)
                    
                    # Toolbar
                    toolbar_layout = QHBoxLayout()
                    
                    refresh_btn = QPushButton("🔄 Refresh")
                    refresh_btn.clicked.connect(self.refresh_page)
                    toolbar_layout.addWidget(refresh_btn)
                    
                    home_btn = QPushButton("🏠 Home")
                    home_btn.clicked.connect(self.go_home)
                    toolbar_layout.addWidget(home_btn)
                    
                    toolbar_layout.addStretch()
                    
                    layout.addLayout(toolbar_layout)
                    
                    # Web view
                    self.web_view = QWebEngineView()
                    self.web_view.load(QUrl(url))
                    layout.addWidget(self.web_view)
                
                def refresh_page(self):
                    self.web_view.reload()
                
                def go_home(self):
                    self.web_view.load(QUrl(url))
            
            window = PluginWindow()
            window.show()
            
            self.qt_widgets[window_id] = window
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating PyQt window: {e}")
            return False
    
    def _create_webview_window(self, window_id: str, url: str, width: int, height: int) -> bool:
        """Create webview window."""
        try:
            if not WEBVIEW_AVAILABLE or webview is None:
                return False

            def create_window():
                window = webview.create_window(  # type: ignore
                    title=f"PlexiChat - {window_id}",
                    url=url,
                    width=width,
                    height=height
                )
                self.webview_windows[window_id] = window

            # Start webview in a new thread
            threading.Thread(target=lambda: (create_window(), webview.start()), daemon=True).start()  # type: ignore
            return True
        except Exception as e:
            logger.error(f"Error creating webview window: {e}")
            return False
    
    def _open_in_browser(self, url: str) -> bool:
        """Open URL in default browser."""
        try:
            webbrowser.open(url)
            return True
        except Exception as e:
            logger.error(f"Error opening browser: {e}")
            return False
    
    def create_test_dashboard_widget(self, parent=None) -> Optional[Any]:
        """Create a widget specifically for the test dashboard."""
        if not PYQT_AVAILABLE:
            return None
        
        try:
            from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel  # type: ignore
            from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
            from PyQt5.QtCore import QUrl, QTimer  # type: ignore
            
            class TestDashboardWidget(QWidget):
                def __init__(self, parent=None):
                    super().__init__(parent)
                    self.setup_ui()
                    self.setup_auto_refresh()
                
                def setup_ui(self):
                    layout = QVBoxLayout(self)
                    
                    # Header
                    header_layout = QHBoxLayout()
                    
                    title_label = QLabel("Plugin Tests Dashboard")
                    title_label.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
                    header_layout.addWidget(title_label)
                    
                    header_layout.addStretch()
                    
                    # Control buttons
                    self.refresh_btn = QPushButton("🔄 Refresh")
                    self.refresh_btn.clicked.connect(self.refresh_dashboard)
                    header_layout.addWidget(self.refresh_btn)
                    
                    self.discover_btn = QPushButton("🔍 Discover Tests")
                    self.discover_btn.clicked.connect(self.discover_tests)
                    header_layout.addWidget(self.discover_btn)
                    
                    self.run_all_btn = QPushButton("▶️ Run All Tests")
                    self.run_all_btn.clicked.connect(self.run_all_tests)
                    header_layout.addWidget(self.run_all_btn)
                    
                    layout.addLayout(header_layout)
                    
                    # Web view
                    self.web_view = QWebEngineView()
                    test_dashboard_url = urljoin(self.parent().base_url if hasattr(self.parent(), 'base_url') else "http://localhost:8000", "/tests")
                    self.web_view.load(QUrl(test_dashboard_url))
                    layout.addWidget(self.web_view)
                
                def setup_auto_refresh(self):
                    # Auto-refresh every 30 seconds
                    self.refresh_timer = QTimer()
                    self.refresh_timer.timeout.connect(self.refresh_dashboard)
                    self.refresh_timer.start(30000)  # 30 seconds
                
                def refresh_dashboard(self):
                    self.web_view.reload()
                
                def discover_tests(self):
                    # Execute JavaScript to trigger test discovery
                    self.web_view.page().runJavaScript("discoverAllTests();")
                
                def run_all_tests(self):
                    # Execute JavaScript to run all tests
                    self.web_view.page().runJavaScript("runAllTests();")
            
            widget = TestDashboardWidget(parent)
            return widget
            
        except Exception as e:
            logger.error(f"Error creating test dashboard widget: {e}")
            return None
    
    def create_plugin_manager_widget(self, parent=None) -> Optional[Any]:
        """Create a widget for plugin management."""
        if not PYQT_AVAILABLE:
            return None
        
        try:
            from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QListWidget, QSplitter  # type: ignore
            from PyQt5.QtWebEngineWidgets import QWebEngineView  # type: ignore
            from PyQt5.QtCore import QUrl, Qt  # type: ignore
            
            class PluginManagerWidget(QWidget):
                def __init__(self, parent=None):
                    super().__init__(parent)
                    self.setup_ui()
                
                def setup_ui(self):
                    layout = QHBoxLayout(self)
                    
                    # Splitter for plugin list and web view
                    splitter = QSplitter(Qt.Horizontal)
                    
                    # Plugin list
                    list_widget = QWidget()
                    list_layout = QVBoxLayout(list_widget)
                    
                    list_label = QLabel("Plugins")
                    list_label.setStyleSheet("font-weight: bold; margin: 5px;")
                    list_layout.addWidget(list_label)
                    
                    self.plugin_list = QListWidget()
                    self.plugin_list.itemClicked.connect(self.on_plugin_selected)
                    list_layout.addWidget(self.plugin_list)
                    
                    # Populate plugin list (would be dynamic in real implementation)
                    plugins = [
                        "api_integration_layer",
                        "file_manager", 
                        "advanced_client",
                        "messaging_hub",
                        "analytics_dashboard"
                    ]
                    
                    for plugin in plugins:
                        self.plugin_list.addItem(plugin)
                    
                    splitter.addWidget(list_widget)
                    
                    # Web view for plugin details
                    self.web_view = QWebEngineView()
                    plugins_url = urljoin(self.parent().base_url if hasattr(self.parent(), 'base_url') else "http://localhost:8000", "/plugins")
                    self.web_view.load(QUrl(plugins_url))
                    splitter.addWidget(self.web_view)
                    
                    # Set splitter proportions
                    splitter.setSizes([300, 900])
                    
                    layout.addWidget(splitter)
                
                def on_plugin_selected(self, item):
                    plugin_name = item.text()
                    plugin_url = urljoin(
                        self.parent().base_url if hasattr(self.parent(), 'base_url') else "http://localhost:8000", 
                        f"/plugins/{plugin_name}"
                    )
                    self.web_view.load(QUrl(plugin_url))
            
            widget = PluginManagerWidget(parent)
            return widget
            
        except Exception as e:
            logger.error(f"Error creating plugin manager widget: {e}")
            return None
    
    def get_available_pages(self) -> Dict[str, List[Dict[str, str]]]:
        """Get all available plugin pages."""
        return self.plugin_pages
    
    def close_window(self, window_id: str) -> bool:
        """Close a specific window."""
        try:
            if window_id in self.qt_widgets:
                widget = self.qt_widgets[window_id]
                if hasattr(widget, 'close'):
                    widget.close()
                del self.qt_widgets[window_id]
                return True
            
            if window_id in self.webview_windows:
                # Webview windows are harder to close programmatically
                del self.webview_windows[window_id]
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error closing window {window_id}: {e}")
            return False
    
    def close_all_windows(self):
        """Close all plugin windows."""
        try:
            # Close Qt widgets
            for window_id in list(self.qt_widgets.keys()):
                self.close_window(window_id)
            
            # Clear webview windows
            self.webview_windows.clear()
            
            logger.info("All plugin windows closed")
            
        except Exception as e:
            logger.error(f"Error closing all windows: {e}")
    
    def register_callback(self, event_name: str, callback: Callable):
        """Register a callback for GUI events."""
        self.callbacks[event_name] = callback
        logger.info(f"Registered callback for event: {event_name}")
    
    def trigger_callback(self, event_name: str, *args, **kwargs):
        """Trigger a registered callback."""
        try:
            if event_name in self.callbacks:
                self.callbacks[event_name](*args, **kwargs)
        except Exception as e:
            logger.error(f"Error triggering callback {event_name}: {e}")


# Global renderer instance
_webui_renderer = None


def get_webui_renderer(base_url: str = "http://localhost:8000") -> WebUIRenderer:
    """Get the global WebUI renderer instance."""
    global _webui_renderer
    if _webui_renderer is None:
        _webui_renderer = WebUIRenderer(base_url)
    return _webui_renderer
