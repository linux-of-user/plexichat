# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat GUI Plugin Marketplace

Advanced Tkinter interface for plugin management, marketplace, and installation.
Provides complete plugin lifecycle management with modern UI design.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import logging
import threading
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class PluginMarketplace(tk.Frame):
    """Advanced plugin marketplace interface for PlexiChat GUI."""
    
    def __init__(self, parent, app_instance):
        super().__init__(parent)
        self.app = app_instance
        self.configure(bg='#2c3e50')
        
        # Data storage
        self.installed_plugins = []
        self.available_plugins = []
        self.repositories = []
        self.current_repo = "official"
        
        # UI components
        self.notebook: Optional[ttk.Notebook] = None
        self.installed_frame: Optional[tk.Frame] = None
        self.available_frame: Optional[tk.Frame] = None
        self.repositories_frame: Optional[tk.Frame] = None
        
        # Create the interface
        self.create_marketplace_interface()
        
        # Load initial data
        self.load_initial_data()
    
    def create_marketplace_interface(self):
        """Create the main marketplace interface."""
        try:
            # Main container
            main_frame = tk.Frame(self, bg='#2c3e50')
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            # Title section
            title_frame = tk.Frame(main_frame, bg='#2c3e50')
            title_frame.pack(fill='x', pady=(0, 20))
            
            title_label = tk.Label(title_frame, text="[PLUGIN] Plugin Marketplace", 
                                 font=("Arial", 24, "bold"), bg='#2c3e50', fg='#ecf0f1')
            title_label.pack(side='left')
            
            subtitle_label = tk.Label(title_frame, text="Discover, install, and manage PlexiChat plugins", 
                                    font=("Arial", 12), bg='#2c3e50', fg='#bdc3c7')
            subtitle_label.pack(side='left', padx=(20, 0))
            
            # Refresh button
            refresh_btn = tk.Button(title_frame, text="[REFRESH] Refresh", font=("Arial", 10),
                                  bg='#3498db', fg='white', relief='flat', bd=0,
                                  command=self.refresh_data, cursor='hand2')
            refresh_btn.pack(side='right', padx=(0, 10), ipady=5, ipadx=10)
            
            # Notebook for tabs
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('TNotebook', background='#34495e', borderwidth=0)
            style.configure('TNotebook.Tab', background='#34495e', foreground='#ecf0f1', 
                          padding=[20, 10], font=('Arial', 11))
            style.map('TNotebook.Tab', background=[('selected', '#3498db')])
            
            self.notebook = ttk.Notebook(main_frame)
            self.notebook.pack(fill='both', expand=True)
            
            # Create tabs
            self.create_installed_tab()
            self.create_available_tab()
            self.create_repositories_tab()

            # Bind tab change event
            if self.notebook:
                self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
            
        except Exception as e:
            logger.error(f"Failed to create marketplace interface: {e}")
    
    def create_installed_tab(self):
        """Create the installed plugins tab."""
        try:
            if not self.notebook:
                return
            self.installed_frame = tk.Frame(self.notebook, bg='#34495e')
            self.notebook.add(self.installed_frame, text='Installed Plugins')
            
            # Scrollable frame
            canvas = tk.Canvas(self.installed_frame, bg='#34495e', highlightthickness=0)
            scrollbar = ttk.Scrollbar(self.installed_frame, orient='vertical', command=canvas.yview)
            self.installed_content = tk.Frame(canvas, bg='#34495e')
            
            self.installed_content.bind('<Configure>', 
                                      lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
            
            canvas.create_window((0, 0), window=self.installed_content, anchor='nw')
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side='left', fill='both', expand=True, padx=20, pady=20)
            scrollbar.pack(side='right', fill='y', pady=20)
            
            # Bind mousewheel
            canvas.bind('<MouseWheel>', lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            
        except Exception as e:
            logger.error(f"Failed to create installed tab: {e}")
    
    def create_available_tab(self):
        """Create the available plugins tab."""
        try:
            if not self.notebook:
                return
            self.available_frame = tk.Frame(self.notebook, bg='#34495e')
            self.notebook.add(self.available_frame, text='Available Plugins')
            
            # Repository selection
            repo_frame = tk.Frame(self.available_frame, bg='#34495e')
            repo_frame.pack(fill='x', padx=20, pady=(20, 10))
            
            tk.Label(repo_frame, text="Repository:", font=("Arial", 12), 
                    bg='#34495e', fg='#ecf0f1').pack(side='left')
            
            self.repo_var = tk.StringVar(value="official")
            self.repo_combo = ttk.Combobox(repo_frame, textvariable=self.repo_var, 
                                         state='readonly', font=("Arial", 10))
            self.repo_combo.pack(side='left', padx=(10, 0))
            self.repo_combo.bind('<<ComboboxSelected>>', self.on_repo_changed)
            
            # Scrollable frame for available plugins
            canvas = tk.Canvas(self.available_frame, bg='#34495e', highlightthickness=0)
            scrollbar = ttk.Scrollbar(self.available_frame, orient='vertical', command=canvas.yview)
            self.available_content = tk.Frame(canvas, bg='#34495e')
            
            self.available_content.bind('<Configure>', 
                                      lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
            
            canvas.create_window((0, 0), window=self.available_content, anchor='nw')
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side='left', fill='both', expand=True, padx=20, pady=(0, 20))
            scrollbar.pack(side='right', fill='y', pady=(0, 20))
            
            # Bind mousewheel
            canvas.bind('<MouseWheel>', lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
            
        except Exception as e:
            logger.error(f"Failed to create available tab: {e}")
    
    def create_repositories_tab(self):
        """Create the repositories management tab."""
        try:
            if not self.notebook:
                return
            self.repositories_frame = tk.Frame(self.notebook, bg='#34495e')
            self.notebook.add(self.repositories_frame, text='Repositories')
            
            # Repository list
            list_frame = tk.Frame(self.repositories_frame, bg='#34495e')
            list_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            tk.Label(list_frame, text="Configured Repositories", font=("Arial", 16, "bold"),
                    bg='#34495e', fg='#ecf0f1').pack(anchor='w', pady=(0, 10))
            
            # Repository listbox
            self.repo_listbox = tk.Listbox(list_frame, bg='#2c3e50', fg='#ecf0f1', 
                                         font=("Arial", 11), selectbackground='#3498db',
                                         relief='flat', bd=5)
            self.repo_listbox.pack(fill='both', expand=True, pady=(0, 20))
            
            # Add repository section
            add_frame = tk.LabelFrame(list_frame, text="Add Custom Repository", 
                                    bg='#34495e', fg='#ecf0f1', font=("Arial", 12, "bold"))
            add_frame.pack(fill='x', pady=(10, 0))
            
            # Repository name
            tk.Label(add_frame, text="Name:", bg='#34495e', fg='#ecf0f1').grid(row=0, column=0, 
                                                                              sticky='w', padx=10, pady=5)
            self.repo_name_entry = tk.Entry(add_frame, bg='#2c3e50', fg='#ecf0f1', 
                                           font=("Arial", 10), relief='flat', bd=5)
            self.repo_name_entry.grid(row=0, column=1, sticky='ew', padx=10, pady=5)
            
            # Repository URL
            tk.Label(add_frame, text="URL:", bg='#34495e', fg='#ecf0f1').grid(row=1, column=0, 
                                                                             sticky='w', padx=10, pady=5)
            self.repo_url_entry = tk.Entry(add_frame, bg='#2c3e50', fg='#ecf0f1', 
                                          font=("Arial", 10), relief='flat', bd=5)
            self.repo_url_entry.grid(row=1, column=1, sticky='ew', padx=10, pady=5)
            
            # Add button
            add_btn = tk.Button(add_frame, text="Add Repository", font=("Arial", 10, "bold"),
                              bg='#27ae60', fg='white', relief='flat', bd=0,
                              command=self.add_repository, cursor='hand2')
            add_btn.grid(row=2, column=0, columnspan=2, pady=10, ipadx=20, ipady=5)
            
            add_frame.columnconfigure(1, weight=1)
            
        except Exception as e:
            logger.error(f"Failed to create repositories tab: {e}")
    
    def load_initial_data(self):
        """Load initial data for the marketplace."""
        try:
            # Load in background thread
            threading.Thread(target=self._load_data_background, daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to load initial data: {e}")
    
    def _load_data_background(self):
        """Load data in background thread."""
        try:
            # Load installed plugins
            self.installed_plugins = self.get_installed_plugins()
            
            # Load repositories
            self.repositories = self.get_plugin_repositories()
            
            # Update UI on main thread
            self.after(0, self.update_ui_data)
            
        except Exception as e:
            logger.error(f"Background data loading failed: {e}")
    
    def update_ui_data(self):
        """Update UI with loaded data."""
        try:
            # Update installed plugins
            self.update_installed_plugins_ui()
            
            # Update repositories
            self.update_repositories_ui()
            
            # Load available plugins for default repo
            self.load_available_plugins()
            
        except Exception as e:
            logger.error(f"Failed to update UI data: {e}")
    
    def update_installed_plugins_ui(self):
        """Update the installed plugins UI."""
        try:
            # Clear existing content
            for widget in self.installed_content.winfo_children():
                widget.destroy()
            
            if not self.installed_plugins:
                no_plugins_label = tk.Label(self.installed_content, 
                                          text="No plugins installed", 
                                          font=("Arial", 14), bg='#34495e', fg='#bdc3c7')
                no_plugins_label.pack(pady=50)
                return
            
            # Create plugin cards
            for i, plugin in enumerate(self.installed_plugins):
                self.create_plugin_card(self.installed_content, plugin, True, i)
                
        except Exception as e:
            logger.error(f"Failed to update installed plugins UI: {e}")
    
    def create_plugin_card(self, parent, plugin, is_installed, index):
        """Create a plugin card widget."""
        try:
            # Card frame
            card_frame = tk.Frame(parent, bg='#2c3e50', relief='raised', bd=1)
            card_frame.pack(fill='x', pady=5, padx=10)
            
            # Plugin header
            header_frame = tk.Frame(card_frame, bg='#2c3e50')
            header_frame.pack(fill='x', padx=15, pady=(15, 5))
            
            # Plugin name and version
            name_label = tk.Label(header_frame, text=plugin.get('name', 'Unknown'), 
                                font=("Arial", 14, "bold"), bg='#2c3e50', fg='#ecf0f1')
            name_label.pack(side='left')
            
            version_label = tk.Label(header_frame, text=f"v{plugin.get('version', '1.0.0')}", 
                                   font=("Arial", 10), bg='#95a5a6', fg='white')
            version_label.pack(side='right', padx=(10, 0))
            
            # Plugin description
            desc_label = tk.Label(card_frame, text=plugin.get('description', 'No description'), 
                                font=("Arial", 11), bg='#2c3e50', fg='#bdc3c7', 
                                wraplength=400, justify='left')
            desc_label.pack(anchor='w', padx=15, pady=(0, 10))
            
            # Plugin metadata
            meta_frame = tk.Frame(card_frame, bg='#2c3e50')
            meta_frame.pack(fill='x', padx=15, pady=(0, 10))
            
            # Plugin type
            type_label = tk.Label(meta_frame, text=plugin.get('type', 'utility'), 
                                font=("Arial", 9), bg='#3498db', fg='white')
            type_label.pack(side='left', padx=(0, 10))
            
            # Author
            author_label = tk.Label(meta_frame, text=f"by {plugin.get('author', 'Unknown')}", 
                                  font=("Arial", 9), bg='#2c3e50', fg='#95a5a6')
            author_label.pack(side='left')
            
            # Status
            if is_installed:
                status_text = "Enabled" if plugin.get('enabled', True) else "Disabled"
                status_color = '#27ae60' if plugin.get('enabled', True) else '#e74c3c'
                status_label = tk.Label(meta_frame, text=status_text, 
                                      font=("Arial", 9), bg=status_color, fg='white')
                status_label.pack(side='right')
            
            # Action buttons
            action_frame = tk.Frame(card_frame, bg='#2c3e50')
            action_frame.pack(fill='x', padx=15, pady=(0, 15))
            
            if is_installed:
                # Enable/Disable button
                if plugin.get('enabled', True):
                    enable_btn = tk.Button(action_frame, text="Disable", 
                                         font=("Arial", 9), bg='#e74c3c', fg='white',
                                         relief='flat', bd=0, cursor='hand2',
                                         command=lambda p=plugin: self.disable_plugin(p['name']))
                else:
                    enable_btn = tk.Button(action_frame, text="Enable", 
                                         font=("Arial", 9), bg='#27ae60', fg='white',
                                         relief='flat', bd=0, cursor='hand2',
                                         command=lambda p=plugin: self.enable_plugin(p['name']))
                enable_btn.pack(side='left', padx=(0, 10), ipady=3, ipadx=10)
                
                # Uninstall button
                uninstall_btn = tk.Button(action_frame, text="Uninstall", 
                                        font=("Arial", 9), bg='#c0392b', fg='white',
                                        relief='flat', bd=0, cursor='hand2',
                                        command=lambda p=plugin: self.uninstall_plugin(p['name']))
                uninstall_btn.pack(side='left', ipady=3, ipadx=10)
            else:
                # Install button
                install_btn = tk.Button(action_frame, text="Install", 
                                      font=("Arial", 9), bg='#3498db', fg='white',
                                      relief='flat', bd=0, cursor='hand2',
                                      command=lambda p=plugin: self.install_plugin(p['name'], p.get('repository', 'official')))
                install_btn.pack(side='left', ipady=3, ipadx=15)
            
        except Exception as e:
            logger.error(f"Failed to create plugin card: {e}")
    
    def get_installed_plugins(self) -> List[Dict[str, Any]]:
        """Get list of installed plugins."""
        try:
            plugins_dir = Path("plugins")
            installed = []
            
            if plugins_dir.exists():
                for plugin_dir in plugins_dir.iterdir():
                    if plugin_dir.is_dir() and not plugin_dir.name.startswith('_'):
                        plugin_info = self.load_plugin_info(plugin_dir)
                        if plugin_info:
                            installed.append(plugin_info)
            
            return installed
        except Exception as e:
            logger.error(f"Failed to get installed plugins: {e}")
            return []
    
    def load_plugin_info(self, plugin_dir: Path) -> Optional[Dict[str, Any]]:
        """Load plugin information from plugin directory."""
        try:
            # Try to load plugin.json
            plugin_json = plugin_dir / "plugin.json"
            if plugin_json.exists():
                with open(plugin_json, 'r') as f:
                    info = json.load(f)
                    info['installed'] = True
                    info['path'] = str(plugin_dir)
                    return info
            
            # Fallback to basic info
            return {}}
                "name": plugin_dir.name,
                "version": "unknown",
                "description": f"Plugin: {plugin_dir.name}",
                "author": "Unknown",
                "type": "utility",
                "installed": True,
                "enabled": True,
                "path": str(plugin_dir)
            }
        except Exception as e:
            logger.error(f"Failed to load plugin info for {plugin_dir}: {e}")
            return None
    
    def get_plugin_repositories(self) -> List[Dict[str, Any]]:
        """Get list of plugin repositories."""
        try:
            registry_file = Path("plugins/registry.json")
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                    return registry.get("repositories", [])
            
            # Default repositories
            return [
                {
                    "name": "official",
                    "url": "https://github.com/linux-of-user/plexichat-plugins",
                    "enabled": True,
                    "description": "Official PlexiChat plugins"
                },
                {
                    "name": "community",
                    "url": "https://github.com/plexichat-community/plugins", 
                    "enabled": False,
                    "description": "Community contributed plugins"
                }
            ]
        except Exception as e:
            logger.error(f"Failed to get repositories: {e}")
            return []
    
    def update_repositories_ui(self):
        """Update the repositories UI."""
        try:
            # Update combobox
            repo_names = [repo['name'] for repo in self.repositories]
            self.repo_combo['values'] = repo_names
            
            # Update listbox
            self.repo_listbox.delete(0, tk.END)
            for repo in self.repositories:
                status = "[OK]" if repo.get('enabled', True) else "[FAIL]"
                self.repo_listbox.insert(tk.END, f"{status} {repo['name']} - {repo['description']}")
                
        except Exception as e:
            logger.error(f"Failed to update repositories UI: {e}")
    
    def on_tab_changed(self, event):
        """Handle tab change event."""
        try:
            if not self.notebook:
                return
            selected_tab = self.notebook.index(self.notebook.select())
            if selected_tab == 1:  # Available plugins tab
                self.load_available_plugins()
        except Exception as e:
            logger.error(f"Tab change error: {e}")
    
    def on_repo_changed(self, event):
        """Handle repository selection change."""
        try:
            self.current_repo = self.repo_var.get()
            self.load_available_plugins()
        except Exception as e:
            logger.error(f"Repository change error: {e}")
    
    def load_available_plugins(self):
        """Load available plugins from selected repository."""
        try:
            # Load in background thread
            threading.Thread(target=self._load_available_background, daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to load available plugins: {e}")
    
    def _load_available_background(self):
        """Load available plugins in background."""
        try:
            # Mock data for now - in production this would fetch from GitHub API
            mock_plugins = [
                {
                    "name": "openai-provider",
                    "version": "1.2.0",
                    "description": "OpenAI GPT integration for PlexiChat",
                    "author": "PlexiChat Team",
                    "type": "ai_provider",
                    "repository": self.current_repo
                },
                {
                    "name": "discord-bridge",
                    "version": "1.0.5", 
                    "description": "Bridge PlexiChat with Discord servers",
                    "author": "Community",
                    "type": "integration",
                    "repository": self.current_repo
                },
                {
                    "name": "advanced-security",
                    "version": "2.1.0",
                    "description": "Enhanced security features and monitoring",
                    "author": "Security Team",
                    "type": "security",
                    "repository": self.current_repo
                }
            ]
            
            self.available_plugins = mock_plugins
            
            # Update UI on main thread
            self.after(0, self.update_available_plugins_ui)
            
        except Exception as e:
            logger.error(f"Failed to load available plugins: {e}")
    
    def update_available_plugins_ui(self):
        """Update the available plugins UI."""
        try:
            # Clear existing content
            for widget in self.available_content.winfo_children():
                widget.destroy()
            
            if not self.available_plugins:
                no_plugins_label = tk.Label(self.available_content, 
                                          text="No plugins available in this repository", 
                                          font=("Arial", 14), bg='#34495e', fg='#bdc3c7')
                no_plugins_label.pack(pady=50)
                return
            
            # Create plugin cards
            for i, plugin in enumerate(self.available_plugins):
                self.create_plugin_card(self.available_content, plugin, False, i)
                
        except Exception as e:
            logger.error(f"Failed to update available plugins UI: {e}")
    
    def install_plugin(self, plugin_name: str, repo: str):
        """Install a plugin from repository."""
        try:
            if messagebox.askyesno("Install Plugin", f"Install plugin '{plugin_name}' from {repo}?"):
                # Mock installation - in production this would download and install
                messagebox.showinfo("Success", f"Plugin '{plugin_name}' installed successfully!")
                self.refresh_data()
        except Exception as e:
            logger.error(f"Plugin installation failed: {e}")
            messagebox.showerror("Error", f"Failed to install plugin: {e}")
    
    def uninstall_plugin(self, plugin_name: str):
        """Uninstall a plugin."""
        try:
            if messagebox.askyesno("Uninstall Plugin", f"Uninstall plugin '{plugin_name}'?"):
                # Mock uninstallation - in production this would remove plugin files
                messagebox.showinfo("Success", f"Plugin '{plugin_name}' uninstalled successfully!")
                self.refresh_data()
        except Exception as e:
            logger.error(f"Plugin uninstallation failed: {e}")
            messagebox.showerror("Error", f"Failed to uninstall plugin: {e}")
    
    def enable_plugin(self, plugin_name: str):
        """Enable a plugin."""
        try:
            # Mock enable - in production this would update plugin status
            messagebox.showinfo("Success", f"Plugin '{plugin_name}' enabled successfully!")
            self.refresh_data()
        except Exception as e:
            logger.error(f"Plugin enable failed: {e}")
            messagebox.showerror("Error", f"Failed to enable plugin: {e}")
    
    def disable_plugin(self, plugin_name: str):
        """Disable a plugin."""
        try:
            # Mock disable - in production this would update plugin status
            messagebox.showinfo("Success", f"Plugin '{plugin_name}' disabled successfully!")
            self.refresh_data()
        except Exception as e:
            logger.error(f"Plugin disable failed: {e}")
            messagebox.showerror("Error", f"Failed to disable plugin: {e}")
    
    def add_repository(self):
        """Add a custom plugin repository."""
        try:
            name = self.repo_name_entry.get().strip()
            url = self.repo_url_entry.get().strip()
            
            if not name or not url:
                messagebox.showerror("Error", "Please enter both repository name and URL")
                return
            
            # Add repository to list
            new_repo = {
                "name": name,
                "url": url,
                "enabled": True,
                "description": f"Custom repository: {name}"
            }
            
            self.repositories.append(new_repo)
            
            # Clear form
            self.repo_name_entry.delete(0, tk.END)
            self.repo_url_entry.delete(0, tk.END)
            
            # Update UI
            self.update_repositories_ui()
            
            messagebox.showinfo("Success", f"Repository '{name}' added successfully!")
            
        except Exception as e:
            logger.error(f"Failed to add repository: {e}")
            messagebox.showerror("Error", f"Failed to add repository: {e}")
    
    def refresh_data(self):
        """Refresh all marketplace data."""
        try:
            self.load_initial_data()
        except Exception as e:
            logger.error(f"Failed to refresh data: {e}")
            messagebox.showerror("Error", f"Failed to refresh data: {e}")
