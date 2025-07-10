"""
Backup Management GUI Widget
Comprehensive GUI component for backup system management and monitoring.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    # Create dummy classes for when GUI is not available
    class tk:
        class Tk: pass
        class Frame: pass
        class Label: pass
        class Button: pass
        class Entry: pass
        class Text: pass
        class Scrollbar: pass
        class Listbox: pass
        class Checkbutton: pass
        class Combobox: pass
        BOTH = HORIZONTAL = VERTICAL = LEFT = RIGHT = TOP = BOTTOM = None
        END = None
    
    class ttk:
        class Frame: pass
        class Label: pass
        class Button: pass
        class Entry: pass
        class Combobox: pass
        class Progressbar: pass
        class Treeview: pass
        class Notebook: pass
    
    class messagebox:
        @staticmethod
        def showinfo(*args, **kwargs): pass
        @staticmethod
        def showerror(*args, **kwargs): pass
        @staticmethod
        def askyesno(*args, **kwargs): return False
    
    class filedialog:
        @staticmethod
        def askopenfilename(*args, **kwargs): return ""
        @staticmethod
        def asksaveasfilename(*args, **kwargs): return ""

from ...backup import government_backup_manager
from ...core.exceptions import PlexiChatException

logger = logging.getLogger(__name__)


@dataclass
class BackupSystemStatus:
    """Backup system status information."""
    overall_health: str
    total_shards: int
    active_nodes: int
    coverage_percentage: float
    last_backup: Optional[datetime]
    proxy_mode_active: bool
    recent_operations: List[Dict[str, Any]]


class BackupManagementWidget:
    """GUI widget for backup management."""
    
    def __init__(self, parent_frame: tk.Frame):
        """Initialize backup management widget."""
        self.parent_frame = parent_frame
        self.status_data: Optional[BackupSystemStatus] = None
        self.refresh_interval = 30000  # 30 seconds
        self.auto_refresh_enabled = True
        
        # GUI components
        self.main_frame = None
        self.notebook = None
        self.status_frame = None
        self.operations_frame = None
        self.shards_frame = None
        self.nodes_frame = None
        self.archives_frame = None
        
        # Status widgets
        self.health_label = None
        self.shards_label = None
        self.coverage_label = None
        self.last_backup_label = None
        self.proxy_status_label = None
        
        # Operations widgets
        self.operations_tree = None
        self.create_backup_button = None
        
        # Charts
        self.status_chart = None
        self.chart_canvas = None
        
        if GUI_AVAILABLE:
            self.setup_gui()
            self.start_auto_refresh()
    
    def setup_gui(self):
        """Set up the GUI components."""
        try:
            # Main frame
            self.main_frame = ttk.Frame(self.parent_frame)
            self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Title
            title_label = ttk.Label(
                self.main_frame,
                text="Backup Management",
                font=("Arial", 16, "bold")
            )
            title_label.pack(pady=(0, 10))
            
            # Create notebook for tabs
            self.notebook = ttk.Notebook(self.main_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True)
            
            # Setup tabs
            self.setup_status_tab()
            self.setup_operations_tab()
            self.setup_shards_tab()
            self.setup_nodes_tab()
            self.setup_archives_tab()
            
            # Control buttons
            self.setup_control_buttons()
            
        except Exception as e:
            logger.error(f"Error setting up backup management GUI: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("GUI Error", f"Failed to setup backup management interface: {str(e)}")
    
    def setup_status_tab(self):
        """Set up the status overview tab."""
        self.status_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.status_frame, text="System Status")
        
        # Status metrics frame
        metrics_frame = ttk.LabelFrame(self.status_frame, text="System Health", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Health status
        health_frame = ttk.Frame(metrics_frame)
        health_frame.pack(fill=tk.X, pady=2)
        ttk.Label(health_frame, text="Overall Health:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.health_label = ttk.Label(health_frame, text="Loading...", foreground="blue")
        self.health_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Total shards
        shards_frame = ttk.Frame(metrics_frame)
        shards_frame.pack(fill=tk.X, pady=2)
        ttk.Label(shards_frame, text="Total Shards:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.shards_label = ttk.Label(shards_frame, text="0")
        self.shards_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Coverage percentage
        coverage_frame = ttk.Frame(metrics_frame)
        coverage_frame.pack(fill=tk.X, pady=2)
        ttk.Label(coverage_frame, text="Backup Coverage:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.coverage_label = ttk.Label(coverage_frame, text="0%")
        self.coverage_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Last backup
        backup_frame = ttk.Frame(metrics_frame)
        backup_frame.pack(fill=tk.X, pady=2)
        ttk.Label(backup_frame, text="Last Backup:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.last_backup_label = ttk.Label(backup_frame, text="Never")
        self.last_backup_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Proxy mode status
        proxy_frame = ttk.Frame(metrics_frame)
        proxy_frame.pack(fill=tk.X, pady=2)
        ttk.Label(proxy_frame, text="Proxy Mode:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.proxy_status_label = ttk.Label(proxy_frame, text="Inactive", foreground="green")
        self.proxy_status_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Chart frame
        chart_frame = ttk.LabelFrame(self.status_frame, text="System Activity", padding=10)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create matplotlib chart
        if GUI_AVAILABLE:
            try:
                self.status_chart = Figure(figsize=(8, 4), dpi=100)
                self.chart_canvas = FigureCanvasTkAgg(self.status_chart, chart_frame)
                self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            except Exception as e:
                logger.warning(f"Could not create status chart: {e}")
                ttk.Label(chart_frame, text="Chart not available").pack()
    
    def setup_operations_tab(self):
        """Set up the backup operations tab."""
        self.operations_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.operations_frame, text="Operations")
        
        # Operations control frame
        control_frame = ttk.Frame(self.operations_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.create_backup_button = ttk.Button(
            control_frame,
            text="Create Backup",
            command=self.create_backup_dialog
        )
        self.create_backup_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Refresh Operations",
            command=self.refresh_operations
        ).pack(side=tk.LEFT)
        
        # Operations list
        list_frame = ttk.LabelFrame(self.operations_frame, text="Active Operations", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for operations
        columns = ("ID", "Type", "Status", "Progress", "Created")
        self.operations_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        # Configure columns
        for col in columns:
            self.operations_tree.heading(col, text=col)
            self.operations_tree.column(col, width=120)
        
        # Scrollbar for operations tree
        operations_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.operations_tree.yview)
        self.operations_tree.configure(yscrollcommand=operations_scrollbar.set)
        
        self.operations_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        operations_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_shards_tab(self):
        """Set up the shard management tab."""
        self.shards_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.shards_frame, text="Shard Management")
        
        # Shard controls
        control_frame = ttk.Frame(self.shards_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            control_frame,
            text="Redistribute Shards",
            command=self.redistribute_shards
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Verify Shards",
            command=self.verify_shards
        ).pack(side=tk.LEFT)
        
        # Shard information display
        info_frame = ttk.LabelFrame(self.shards_frame, text="Shard Information", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.shard_info_text = tk.Text(info_frame, height=15, wrap=tk.WORD)
        shard_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.shard_info_text.yview)
        self.shard_info_text.configure(yscrollcommand=shard_scrollbar.set)

        self.shard_info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        shard_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_nodes_tab(self):
        """Set up the backup nodes tab."""
        self.nodes_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.nodes_frame, text="Backup Nodes")
        
        # Node controls
        control_frame = ttk.Frame(self.nodes_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            control_frame,
            text="Add Node",
            command=self.add_backup_node_dialog
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Generate API Key",
            command=self.generate_api_key_dialog
        ).pack(side=tk.LEFT)
        
        # Nodes list
        nodes_frame = ttk.LabelFrame(self.nodes_frame, text="Backup Nodes", padding=10)
        nodes_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for nodes
        node_columns = ("ID", "Name", "Address", "Status", "Shards", "Last Seen")
        self.nodes_tree = ttk.Treeview(nodes_frame, columns=node_columns, show="headings", height=10)
        
        # Configure columns
        for col in node_columns:
            self.nodes_tree.heading(col, text=col)
            self.nodes_tree.column(col, width=120)
        
        # Scrollbar for nodes tree
        nodes_scrollbar = ttk.Scrollbar(nodes_frame, orient=tk.VERTICAL, command=self.nodes_tree.yview)
        self.nodes_tree.configure(yscrollcommand=nodes_scrollbar.set)
        
        self.nodes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        nodes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_archives_tab(self):
        """Set up the archives management tab."""
        self.archives_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.archives_frame, text="Archives")
        
        # Archive controls
        control_frame = ttk.Frame(self.archives_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            control_frame,
            text="Create Archive",
            command=self.create_archive_dialog
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Import Archive",
            command=self.import_archive_dialog
        ).pack(side=tk.LEFT)
        
        # Archives list
        archives_frame = ttk.LabelFrame(self.archives_frame, text="Archives", padding=10)
        archives_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for archives
        archive_columns = ("Name", "Versions", "Size", "Created", "Last Modified")
        self.archives_tree = ttk.Treeview(archives_frame, columns=archive_columns, show="headings", height=10)
        
        # Configure columns
        for col in archive_columns:
            self.archives_tree.heading(col, text=col)
            self.archives_tree.column(col, width=120)
        
        # Scrollbar for archives tree
        archives_scrollbar = ttk.Scrollbar(archives_frame, orient=tk.VERTICAL, command=self.archives_tree.yview)
        self.archives_tree.configure(yscrollcommand=archives_scrollbar.set)
        
        self.archives_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        archives_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_control_buttons(self):
        """Set up control buttons."""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            button_frame,
            text="Refresh All",
            command=self.refresh_all_data
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Enable Proxy Mode",
            command=self.toggle_proxy_mode
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            button_frame,
            text="Auto Refresh",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        ).pack(side=tk.RIGHT)
    
    async def load_backup_status(self) -> Optional[BackupSystemStatus]:
        """Load backup system status."""
        try:
            if not government_backup_manager.initialized:
                await government_backup_manager.initialize()
            
            health = await government_backup_manager.get_system_health()
            recent_ops = await government_backup_manager.list_backups(limit=5)
            
            return BackupSystemStatus(
                overall_health=health.overall_status.value,
                total_shards=health.total_shards,
                active_nodes=health.active_backup_nodes,
                coverage_percentage=health.backup_coverage_percentage,
                last_backup=health.last_successful_backup,
                proxy_mode_active=government_backup_manager.proxy_mode_active,
                recent_operations=[
                    {
                        "id": op.backup_id,
                        "type": op.operation_type.value,
                        "status": op.status.value,
                        "progress": op.progress_percentage,
                        "created": op.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    for op in recent_ops
                ]
            )
        except Exception as e:
            logger.error(f"Error loading backup status: {e}")
            return None
    
    def update_status_display(self):
        """Update the status display with current data."""
        if not self.status_data or not GUI_AVAILABLE:
            return
        
        try:
            # Update status labels
            if self.health_label:
                self.health_label.config(text=self.status_data.overall_health)
                color = "green" if self.status_data.overall_health == "HEALTHY" else "red"
                self.health_label.config(foreground=color)
            
            if self.shards_label:
                self.shards_label.config(text=str(self.status_data.total_shards))
            
            if self.coverage_label:
                self.coverage_label.config(text=f"{self.status_data.coverage_percentage:.1f}%")
            
            if self.last_backup_label:
                if self.status_data.last_backup:
                    backup_text = self.status_data.last_backup.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    backup_text = "Never"
                self.last_backup_label.config(text=backup_text)
            
            if self.proxy_status_label:
                proxy_text = "Active" if self.status_data.proxy_mode_active else "Inactive"
                proxy_color = "red" if self.status_data.proxy_mode_active else "green"
                self.proxy_status_label.config(text=proxy_text, foreground=proxy_color)
            
            # Update operations tree
            if self.operations_tree:
                # Clear existing items
                for item in self.operations_tree.get_children():
                    self.operations_tree.delete(item)
                
                # Add recent operations
                for op in self.status_data.recent_operations:
                    self.operations_tree.insert("", tk.END, values=(
                        op["id"][:8] + "...",
                        op["type"],
                        op["status"],
                        f"{op['progress']:.1f}%",
                        op["created"]
                    ))
            
            # Update chart if available
            self.update_status_chart()
            
        except Exception as e:
            logger.error(f"Error updating status display: {e}")
    
    def update_status_chart(self):
        """Update the status chart."""
        if not self.status_chart or not self.chart_canvas:
            return
        
        try:
            self.status_chart.clear()
            ax = self.status_chart.add_subplot(111)
            
            # Create a simple pie chart of backup coverage
            if self.status_data:
                coverage = self.status_data.coverage_percentage
                remaining = 100 - coverage
                
                ax.pie([coverage, remaining], 
                      labels=['Backed Up', 'Not Backed Up'],
                      colors=['#4CAF50', '#FFC107'],
                      autopct='%1.1f%%',
                      startangle=90)
                ax.set_title('Backup Coverage')
            
            self.chart_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating status chart: {e}")
    
    def refresh_all_data(self):
        """Refresh all backup data."""
        asyncio.create_task(self._refresh_all_data())
    
    async def _refresh_all_data(self):
        """Async method to refresh all data."""
        try:
            self.status_data = await self.load_backup_status()
            if GUI_AVAILABLE:
                self.parent_frame.after(0, self.update_status_display)
        except Exception as e:
            logger.error(f"Error refreshing backup data: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Refresh Error", f"Failed to refresh backup data: {str(e)}")
    
    def start_auto_refresh(self):
        """Start automatic data refresh."""
        if self.auto_refresh_enabled and GUI_AVAILABLE:
            self.refresh_all_data()
            self.parent_frame.after(self.refresh_interval, self.start_auto_refresh)
    
    def toggle_auto_refresh(self):
        """Toggle automatic refresh."""
        self.auto_refresh_enabled = self.auto_refresh_var.get()
        if self.auto_refresh_enabled:
            self.start_auto_refresh()
    
    # Dialog methods
    def create_backup_dialog(self):
        """Show create backup dialog."""
        if not GUI_AVAILABLE:
            return
        
        dialog = tk.Toplevel(self.parent_frame)
        dialog.title("Create Backup")
        dialog.geometry("400x300")
        dialog.transient(self.parent_frame)
        dialog.grab_set()
        
        # Backup name
        ttk.Label(dialog, text="Backup Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=40)
        name_entry.pack(pady=5)
        
        # Backup type
        ttk.Label(dialog, text="Backup Type:").pack(pady=5)
        type_combo = ttk.Combobox(dialog, values=["full", "incremental", "differential"])
        type_combo.set("full")
        type_combo.pack(pady=5)
        
        # Description
        ttk.Label(dialog, text="Description:").pack(pady=5)
        desc_text = tk.Text(dialog, height=4, width=40)
        desc_text.pack(pady=5)
        
        # Options
        encrypt_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Enable Encryption", variable=encrypt_var).pack(pady=2)
        
        compress_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Enable Compression", variable=compress_var).pack(pady=2)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def create_backup():
            asyncio.create_task(self._create_backup(
                name_entry.get(),
                type_combo.get(),
                desc_text.get("1.0", tk.END).strip(),
                encrypt_var.get(),
                compress_var.get()
            ))
            dialog.destroy()
        
        ttk.Button(button_frame, text="Create", command=create_backup).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    async def _create_backup(self, name: str, backup_type: str, description: str, encrypt: bool, compress: bool):
        """Create a backup operation."""
        try:
            if not government_backup_manager.initialized:
                await government_backup_manager.initialize()
            
            operation = await government_backup_manager.create_backup(
                name=name,
                description=description,
                backup_type=backup_type,
                encryption_enabled=encrypt,
                compression_enabled=compress,
                created_by="gui_user"
            )
            
            if GUI_AVAILABLE:
                messagebox.showinfo("Success", f"Backup operation created: {operation.backup_id}")
            
            # Refresh data
            await self._refresh_all_data()
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to create backup: {str(e)}")
    
    def add_backup_node_dialog(self):
        """Show add backup node dialog."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Add backup node functionality would be implemented here")
    
    def generate_api_key_dialog(self):
        """Show generate API key dialog."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Generate API key functionality would be implemented here")
    
    def create_archive_dialog(self):
        """Show create archive dialog."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Create archive functionality would be implemented here")
    
    def import_archive_dialog(self):
        """Show import archive dialog."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Import archive functionality would be implemented here")
    
    def redistribute_shards(self):
        """Redistribute shards across nodes."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Shard redistribution would be implemented here")
    
    def verify_shards(self):
        """Verify shard integrity."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Shard verification would be implemented here")
    
    def refresh_operations(self):
        """Refresh operations list."""
        self.refresh_all_data()
    
    def toggle_proxy_mode(self):
        """Toggle proxy mode."""
        asyncio.create_task(self._toggle_proxy_mode())
    
    async def _toggle_proxy_mode(self):
        """Async method to toggle proxy mode."""
        try:
            if not government_backup_manager.initialized:
                await government_backup_manager.initialize()
            
            if government_backup_manager.proxy_mode_active:
                await government_backup_manager.disable_proxy_mode()
                message = "Proxy mode disabled"
            else:
                await government_backup_manager.enable_proxy_mode("Manual activation from GUI")
                message = "Proxy mode enabled"
            
            if GUI_AVAILABLE:
                messagebox.showinfo("Success", message)
            
            # Refresh data
            await self._refresh_all_data()
            
        except Exception as e:
            logger.error(f"Error toggling proxy mode: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to toggle proxy mode: {str(e)}")


def create_backup_management_widget(parent_frame: tk.Frame) -> BackupManagementWidget:
    """Create and return a backup management widget."""
    return BackupManagementWidget(parent_frame)
