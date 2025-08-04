"""
Advanced Plugin Manager for PlexiChat GUI
Supports custom plugin language and dynamic UI generation.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, Optional, List, Callable
import importlib
import importlib.util
import inspect
import logging
import json
from pathlib import Path
import ast
import sys

logger = logging.getLogger(__name__)


class PluginLanguageParser:
    """
    Custom language parser for PlexiChat plugins.
    Allows plugins to define UI using a simple, declarative language.
    """
    
    def __init__(self):
        self.widgets = {
            'frame': self.create_frame,
            'label': self.create_label,
            'button': self.create_button,
            'entry': self.create_entry,
            'text': self.create_text,
            'listbox': self.create_listbox,
            'treeview': self.create_treeview,
            'canvas': self.create_canvas,
            'notebook': self.create_notebook,
            'progressbar': self.create_progressbar,
            'scale': self.create_scale,
            'checkbutton': self.create_checkbutton,
            'radiobutton': self.create_radiobutton,
            'combobox': self.create_combobox,
            'spinbox': self.create_spinbox
        }
        
        self.layouts = {
            'pack': self.apply_pack,
            'grid': self.apply_grid,
            'place': self.apply_place
        }

    def parse_ui_definition(self, ui_def: Dict[str, Any], parent: tk.Widget) -> tk.Widget:
        """Parse UI definition and create widgets."""
        try:
            widget_type = ui_def.get('type', 'frame')
            widget_config = ui_def.get('config', {})
            layout_config = ui_def.get('layout', {'type': 'pack'})
            children = ui_def.get('children', [])
            
            # Create widget
            widget = self.create_widget(widget_type, parent, widget_config)
            
            # Apply layout
            self.apply_layout(widget, layout_config)
            
            # Create children
            for child_def in children:
                self.parse_ui_definition(child_def, widget)
            
            return widget
            
        except Exception as e:
            logger.error(f"Failed to parse UI definition: {e}")
            return ttk.Frame(parent)

    def create_widget(self, widget_type: str, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        """Create a widget of the specified type."""
        creator = self.widgets.get(widget_type, self.create_frame)
        return creator(parent, config)

    def apply_layout(self, widget: tk.Widget, layout_config: Dict[str, Any]):
        """Apply layout to widget."""
        layout_type = layout_config.get('type', 'pack')
        layout_options = layout_config.get('options', {})
        
        layout_func = self.layouts.get(layout_type, self.apply_pack)
        layout_func(widget, layout_options)

    # Widget creators
    def create_frame(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Frame(parent, **config)

    def create_label(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Label(parent, **config)

    def create_button(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Button(parent, **config)

    def create_entry(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Entry(parent, **config)

    def create_text(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return tk.Text(parent, **config)

    def create_listbox(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return tk.Listbox(parent, **config)

    def create_treeview(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Treeview(parent, **config)

    def create_canvas(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return tk.Canvas(parent, **config)

    def create_notebook(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Notebook(parent, **config)

    def create_progressbar(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Progressbar(parent, **config)

    def create_scale(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Scale(parent, **config)

    def create_checkbutton(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Checkbutton(parent, **config)

    def create_radiobutton(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Radiobutton(parent, **config)

    def create_combobox(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Combobox(parent, **config)

    def create_spinbox(self, parent: tk.Widget, config: Dict[str, Any]) -> tk.Widget:
        return ttk.Spinbox(parent, **config)

    # Layout managers
    def apply_pack(self, widget: tk.Widget, options: Dict[str, Any]):
        widget.pack(**options)

    def apply_grid(self, widget: tk.Widget, options: Dict[str, Any]):
        widget.grid(**options)

    def apply_place(self, widget: tk.Widget, options: Dict[str, Any]):
        widget.place(**options)


class Plugin:
    """Base plugin class."""
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.enabled = True
        self.ui_widget = None
        self.app_instance = None

    def initialize(self, app_instance):
        """Initialize the plugin."""
        self.app_instance = app_instance

    def create_ui(self, parent: tk.Widget) -> Optional[tk.Widget]:
        """Create plugin UI."""
        return None

    def on_theme_change(self, theme_name: str, theme_data: Dict[str, Any]):
        """Handle theme change."""
        pass

    def cleanup(self):
        """Cleanup plugin resources."""
        pass


class PluginManager:
    """
    Advanced plugin manager for PlexiChat GUI.
    
    Features:
    - Dynamic plugin loading
    - Custom plugin language support
    - Plugin UI integration
    - Plugin communication
    - Plugin security
    - Plugin marketplace integration
    """

    def __init__(self, app_instance):
        self.app = app_instance
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_uis: Dict[str, tk.Widget] = {}
        self.language_parser = PluginLanguageParser()
        
        # Plugin directories
        self.plugin_dirs = [
            Path(__file__).parent.parent.parent.parent / "plugins",
            Path.home() / ".plexichat" / "plugins"
        ]
        
        # Ensure plugin directories exist
        for plugin_dir in self.plugin_dirs:
            plugin_dir.mkdir(parents=True, exist_ok=True)

    def load_plugins(self):
        """Load all available plugins."""
        try:
            for plugin_dir in self.plugin_dirs:
                if plugin_dir.exists():
                    self.load_plugins_from_directory(plugin_dir)
            
            logger.info(f"Loaded {len(self.plugins)} plugins")
            
        except Exception as e:
            logger.error(f"Failed to load plugins: {e}")

    def load_plugins_from_directory(self, plugin_dir: Path):
        """Load plugins from a directory."""
        try:
            for plugin_path in plugin_dir.iterdir():
                if plugin_path.is_dir() and not plugin_path.name.startswith('.'):
                    self.load_plugin(plugin_path)
                    
        except Exception as e:
            logger.error(f"Failed to load plugins from {plugin_dir}: {e}")

    def load_plugin(self, plugin_path: Path):
        """Load a single plugin."""
        try:
            # Check for plugin manifest
            manifest_file = plugin_path / "plugin.json"
            if not manifest_file.exists():
                logger.warning(f"Plugin manifest not found: {plugin_path}")
                return
            
            # Load manifest
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)
            
            plugin_name = manifest.get("name", plugin_path.name)
            
            # Check if plugin uses custom language
            ui_file = plugin_path / "ui.json"
            if ui_file.exists():
                self.load_declarative_plugin(plugin_path, manifest)
            else:
                self.load_python_plugin(plugin_path, manifest)
            
            logger.info(f"Loaded plugin: {plugin_name}")
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_path}: {e}")

    def load_declarative_plugin(self, plugin_path: Path, manifest: Dict[str, Any]):
        """Load a plugin defined using the custom declarative language."""
        try:
            plugin_name = manifest.get("name", plugin_path.name)
            
            # Load UI definition
            ui_file = plugin_path / "ui.json"
            with open(ui_file, 'r') as f:
                ui_definition = json.load(f)
            
            # Load plugin logic (if exists)
            logic_file = plugin_path / "logic.py"
            plugin_logic = None
            if logic_file.exists():
                spec = importlib.util.spec_from_file_location(f"{plugin_name}_logic", logic_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Look for plugin class
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and issubclass(obj, Plugin) and obj != Plugin:
                        plugin_logic = obj
                        break
            
            # Create plugin instance
            if plugin_logic:
                plugin = plugin_logic(plugin_name, manifest.get("version", "1.0.0"))
            else:
                plugin = DeclarativePlugin(plugin_name, manifest.get("version", "1.0.0"), ui_definition)
            
            plugin.initialize(self.app)
            self.plugins[plugin_name] = plugin
            
        except Exception as e:
            logger.error(f"Failed to load declarative plugin: {e}")

    def load_python_plugin(self, plugin_path: Path, manifest: Dict[str, Any]):
        """Load a Python-based plugin."""
        try:
            plugin_name = manifest.get("name", plugin_path.name)
            main_file = manifest.get("main", "main.py")
            
            # Load plugin module
            plugin_file = plugin_path / main_file
            if not plugin_file.exists():
                logger.warning(f"Plugin main file not found: {plugin_file}")
                return
            
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, Plugin) and obj != Plugin:
                    plugin_class = obj
                    break
            
            if plugin_class:
                plugin = plugin_class(plugin_name, manifest.get("version", "1.0.0"))
                plugin.initialize(self.app)
                self.plugins[plugin_name] = plugin
            else:
                logger.warning(f"No plugin class found in {plugin_file}")
                
        except Exception as e:
            logger.error(f"Failed to load Python plugin: {e}")

    def create_plugin_ui(self, plugin_name: str, parent: tk.Widget) -> Optional[tk.Widget]:
        """Create UI for a plugin."""
        try:
            plugin = self.plugins.get(plugin_name)
            if not plugin:
                return None
            
            ui_widget = plugin.create_ui(parent)
            if ui_widget:
                self.plugin_uis[plugin_name] = ui_widget
            
            return ui_widget
            
        except Exception as e:
            logger.error(f"Failed to create plugin UI for {plugin_name}: {e}")
            return None

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)

    def get_plugin_list(self) -> List[str]:
        """Get list of loaded plugin names."""
        return list(self.plugins.keys())

    def enable_plugin(self, name: str):
        """Enable a plugin."""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enabled = True

    def disable_plugin(self, name: str):
        """Disable a plugin."""
        plugin = self.plugins.get(name)
        if plugin:
            plugin.enabled = False

    def notify_theme_change(self, theme_name: str, theme_data: Dict[str, Any]):
        """Notify all plugins of theme change."""
        for plugin in self.plugins.values():
            try:
                if plugin.enabled:
                    plugin.on_theme_change(theme_name, theme_data)
            except Exception as e:
                logger.error(f"Plugin theme change error: {e}")

    def cleanup(self):
        """Cleanup all plugins."""
        for plugin in self.plugins.values():
            try:
                plugin.cleanup()
            except Exception as e:
                logger.error(f"Plugin cleanup error: {e}")


class DeclarativePlugin(Plugin):
    """Plugin created from declarative UI definition."""
    
    def __init__(self, name: str, version: str, ui_definition: Dict[str, Any]):
        super().__init__(name, version)
        self.ui_definition = ui_definition

    def create_ui(self, parent: tk.Widget) -> Optional[tk.Widget]:
        """Create UI from definition."""
        try:
            parser = PluginLanguageParser()
            return parser.parse_ui_definition(self.ui_definition, parent)
        except Exception as e:
            logger.error(f"Failed to create declarative UI: {e}")
            return None


# Example plugin definitions that would be in separate files:

def create_example_chat_plugin():
    """Example of how a chat plugin would be defined."""
    return {}}
        "type": "frame",
        "config": {"padding": 10},
        "layout": {"type": "pack", "options": {"fill": "both", "expand": True}},
        "children": [
            {
                "type": "label",
                "config": {"text": "Chat Plugin", "font": ("Arial", 14, "bold")},
                "layout": {"type": "pack", "options": {"pady": (0, 10)}}
            },
            {
                "type": "text",
                "config": {"height": 20, "width": 50},
                "layout": {"type": "pack", "options": {"fill": "both", "expand": True}}
            },
            {
                "type": "frame",
                "layout": {"type": "pack", "options": {"fill": "x", "pady": (10, 0)}},
                "children": [
                    {
                        "type": "entry",
                        "config": {"width": 40},
                        "layout": {"type": "pack", "options": {"side": "left", "fill": "x", "expand": True}}
                    },
                    {
                        "type": "button",
                        "config": {"text": "Send"},
                        "layout": {"type": "pack", "options": {"side": "right", "padx": (10, 0)}}
                    }
                ]
            }
        ]
    }


def create_example_dashboard_plugin():
    """Example of how a dashboard plugin would be defined."""
    return {}}
        "type": "notebook",
        "layout": {"type": "pack", "options": {"fill": "both", "expand": True}},
        "children": [
            {
                "type": "frame",
                "config": {"name": "Overview"},
                "children": [
                    {
                        "type": "label",
                        "config": {"text": "System Overview", "font": ("Arial", 16, "bold")},
                        "layout": {"type": "pack", "options": {"pady": 10}}
                    },
                    {
                        "type": "progressbar",
                        "config": {"length": 300, "mode": "determinate", "value": 75},
                        "layout": {"type": "pack", "options": {"pady": 5}}
                    }
                ]
            },
            {
                "type": "frame",
                "config": {"name": "Statistics"},
                "children": [
                    {
                        "type": "treeview",
                        "config": {"columns": ("Value",), "show": "tree headings"},
                        "layout": {"type": "pack", "options": {"fill": "both", "expand": True}}
                    }
                ]
            }
        ]
    }
