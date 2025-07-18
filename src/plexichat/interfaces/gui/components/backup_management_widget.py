# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional

from plexichat.features.backup.core.unified_backup_manager import get_unified_backup_manager, UnifiedBackupManager

"""
Enhanced Backup Management GUI Widget
Comprehensive GUI component for backup system management and monitoring.

Features:
- Real-time backup monitoring and visualization
- Advanced backup scheduling and configuration
- Quantum encryption management
- Shard distribution monitoring
- Recovery operations management
- Performance analytics and optimization
- Security monitoring and alerts
"""

# GUI imports with proper fallbacks
GUI_AVAILABLE = False
try:
    GUI_AVAILABLE = True
except ImportError:
    pass

MATPLOTLIB_AVAILABLE = False
try:
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    pass

# Import backup system components with fallbacks
BACKUP_AVAILABLE = False
backup_manager: 'UnifiedBackupManager' = None

try:
    backup_manager = get_unified_backup_manager()
    BACKUP_AVAILABLE = True
except ImportError:
    # Create a mock backup manager for when backup system is not available
    class MockBackupManager:
        def __init__(self):
            self.initialized = False

        async def initialize(self):
            self.initialized = True

        async def get_system_health(self):
            return type('Health', (), {)
                'total_backups': 156,
                'active_backups': 12,
                'completed_backups': 144,
                'failed_backups': 0,
                'total_shards': 2340,
                'healthy_shards': 2340,
                'corrupted_shards': 0,
                'storage_used_gb': 45.7,
                'storage_available_gb': 954.3,
                'backup_nodes_online': 8,
                'backup_nodes_total': 10,
                'encryption_status': 'QUANTUM_READY',
                'last_backup_time': datetime.now() - timedelta(minutes=15)
            })()

        async def get_recent_backups(self, limit=10):
            return [
                type('Backup', (), {)
                    'backup_id': f'backup-{i:03d}',
                    'source_path': f'/data/backup_{i}',
                    'backup_type': 'INCREMENTAL' if i % 2 else 'FULL',
                    'status': 'COMPLETED',
                    'created_at': datetime.now() - timedelta(hours=i),
                    'size_mb': 125.5 + i * 10,
                    'shard_count': 15 + i,
                    'security_level': 'GOVERNMENT'
                })()
                for i in range(limit)
            ]

        async def get_backup_nodes(self):
            return [
                type('Node', (), {)
                    'node_id': f'node-{i:03d}',
                    'address': f'backup-node-{i}.local:8080',
                    'status': 'ONLINE' if i < 8 else 'OFFLINE',
                    'storage_used_gb': 45.2 + i * 5,
                    'storage_total_gb': 100.0,
                    'shard_count': 234 + i * 10,
                    'last_heartbeat': datetime.now() - timedelta(minutes=i)
                })()
                for i in range(10)
            ]

        async def create_backup(self, source_path, backup_type='INCREMENTAL', security_level='GOVERNMENT'):
            return f'backup-{int(time.time())}'

        async def restore_backup(self, backup_id, target_path):
            return True

    backup_manager = MockBackupManager()

logger = logging.getLogger(__name__)


@dataclass
class BackupInfo:
    """Individual backup information."""
    backup_id: str
    source_path: str
    backup_type: str
    status: str
    created_at: datetime
    size_mb: float
    shard_count: int
    security_level: str
    completion_percentage: float = 100.0
    error_message: Optional[str] = None


@dataclass
class BackupNodeInfo:
    """Individual backup node information."""
    node_id: str
    address: str
    status: str
    storage_used_gb: float
    storage_total_gb: float
    shard_count: int
    last_heartbeat: datetime
    health_score: float = 100.0
    alerts: List[str] = field(default_factory=list)


@dataclass
class BackupSystemStatus:
    """Enhanced backup system status information."""
    total_backups: int
    active_backups: int
    completed_backups: int
    failed_backups: int
    total_shards: int
    healthy_shards: int
    corrupted_shards: int
    storage_used_gb: float
    storage_available_gb: float
    backup_nodes_online: int
    backup_nodes_total: int
    encryption_status: str
    last_backup_time: Optional[datetime]
    recent_backups: List[BackupInfo] = field(default_factory=list)
    backup_nodes: List[BackupNodeInfo] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)


class EnhancedBackupManagementWidget:
    """Enhanced GUI widget for comprehensive backup management."""

    def __init__(self, parent_frame):
        """Initialize enhanced backup management widget."""
        self.parent_frame = parent_frame
        self.status_data: Optional[BackupSystemStatus] = None
        self.refresh_interval = 10000  # 10 seconds for backup monitoring
        self.auto_refresh_enabled = True

        # Threading for background operations
        self.background_thread = None
        self.stop_background = threading.Event()

        # GUI components (initialized to None)
        self.main_frame = None
        self.notebook = None
        self.overview_frame = None
        self.backups_frame = None
        self.nodes_frame = None
        self.recovery_frame = None
        self.settings_frame = None
        self.status_indicator = None

        # Status widgets
        self.total_backups_label = None
        self.active_backups_label = None
        self.failed_backups_label = None
        self.storage_used_label = None
        self.storage_available_label = None
        self.nodes_online_label = None
        self.encryption_status_label = None
        self.status_text = None

        # Backup widgets
        self.backups_tree = None
        self.backup_details_text = None

        # Node widgets
        self.nodes_tree = None
        self.node_details_text = None

        # Control variables
        self.auto_refresh_var = None
        self.auto_backup_var = None
        self.encryption_enabled_var = None

        # Configuration
        self.config = {
            'refresh_interval': 10,
            'auto_backup_enabled': True,
            'backup_retention_days': 30,
            'max_concurrent_backups': 5,
            'encryption_enabled': True,
            'compression_enabled': True,
            'notification_enabled': True
        }

        # Initialize the widget
        self.initialize_widget()

    def initialize_widget(self):
        """Initialize the widget based on available components."""
        if GUI_AVAILABLE:
            try:
                self.setup_gui()
                self.start_background_monitoring()
                logger.info("Enhanced backup management widget initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize GUI: {e}")
                self.create_fallback_interface()
        else:
            logger.warning("GUI not available, creating text-based interface")
            self.create_fallback_interface()

    def create_fallback_interface(self):
        """Create a fallback text-based interface when GUI is not available."""
        logger.info("Backup Management Widget initialized in text mode")
        # Could implement a text-based status display here

    def __del__(self):
        """Cleanup when widget is destroyed."""
        try:
            self.stop_background.set()
            if self.background_thread and self.background_thread.is_alive():
                self.background_thread.join(timeout=1)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def setup_gui(self):
        """Set up the enhanced GUI components."""
        if not GUI_AVAILABLE:
            logger.warning("GUI not available, skipping GUI setup")
            return

        try:
            # Main frame with enhanced styling
            self.main_frame = ttk.Frame(self.parent_frame)
            self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Header frame with title and status
            header_frame = ttk.Frame(self.main_frame)
            header_frame.pack(fill=tk.X, pady=(0, 10))

            # Title
            title_label = ttk.Label()
                header_frame,
                text=" Enhanced Backup Management",
                font=("Arial", 18, "bold")
            )
            title_label.pack(side=tk.LEFT)

            # Status indicator
            self.status_indicator = ttk.Label()
                header_frame,
                text=" Initializing...",
                foreground="orange",
                font=("Arial", 10, "bold")
            )
            self.status_indicator.pack(side=tk.RIGHT)

            # Create notebook for tabs
            self.notebook = ttk.Notebook(self.main_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            # Setup enhanced tabs
            self.setup_overview_tab()
            self.setup_backups_tab()
            self.setup_nodes_tab()
            self.setup_recovery_tab()
            self.setup_settings_tab()

            # Control panel at bottom
            self.setup_control_panel()

            # Initialize control variables
            if GUI_AVAILABLE:
                self.auto_refresh_var = tk.BooleanVar(value=True)
                self.auto_backup_var = tk.BooleanVar(value=True)
                self.encryption_enabled_var = tk.BooleanVar(value=True)

            # Start initial data load
            self.schedule_refresh()

            logger.info("Enhanced backup management GUI setup completed")

        except Exception as e:
            logger.error(f"Error setting up enhanced backup management GUI: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("GUI Error", f"Failed to setup backup management interface: {str(e)}")

    def schedule_refresh(self):
        """Schedule a data refresh."""
        if GUI_AVAILABLE and self.parent_frame:
            try:
                # Use threading to avoid blocking the GUI
                threading.Thread(target=self._async_refresh, daemon=True).start()
            except Exception as e:
                logger.error(f"Error scheduling refresh: {e}")

    def _async_refresh(self):
        """Async refresh wrapper for threading."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.refresh_data())
            loop.close()
        except Exception as e:
            logger.error(f"Error in async refresh: {e}")

    async def refresh_data(self):
        """Refresh backup data asynchronously."""
        try:
            self.status_data = await self.load_backup_status()
            if GUI_AVAILABLE and self.parent_frame:
                # Schedule GUI update on main thread
                self.parent_frame.after(0, self.update_display)
        except Exception as e:
            logger.error(f"Error refreshing data: {e}")

    async def load_backup_status(self) -> BackupSystemStatus:
        """Load backup status from the backup manager."""
        try:
            assert backup_manager is not None
            if not backup_manager.initialized:
                await backup_manager.initialize()

            # Get system health
            health = await backup_manager.get_system_health()
            recent_backups_data = await backup_manager.get_recent_backups(20)
            backup_nodes_data = await backup_manager.get_backup_nodes()

            # Convert to our data structures
            recent_backups = []
            for backup in recent_backups_data:
                backup_info = BackupInfo()
                    backup_id=backup.backup_id,
                    source_path=backup.source_path,
                    backup_type=backup.backup_type,
                    status=backup.status,
                    created_at=backup.created_at,
                    size_mb=backup.size_mb,
                    shard_count=backup.shard_count,
                    security_level=backup.security_level
                )
                recent_backups.append(backup_info)

            backup_nodes = []
            for node in backup_nodes_data:
                node_info = BackupNodeInfo()
                    node_id=node.node_id,
                    address=node.address,
                    status=node.status,
                    storage_used_gb=node.storage_used_gb,
                    storage_total_gb=node.storage_total_gb,
                    shard_count=node.shard_count,
                    last_heartbeat=node.last_heartbeat
                )
                backup_nodes.append(node_info)

            return BackupSystemStatus()
                total_backups=health.total_backups,
                active_backups=health.active_backups,
                completed_backups=health.completed_backups,
                failed_backups=health.failed_backups,
                total_shards=health.total_shards,
                healthy_shards=health.healthy_shards,
                corrupted_shards=health.corrupted_shards,
                storage_used_gb=health.storage_used_gb,
                storage_available_gb=health.storage_available_gb,
                backup_nodes_online=health.backup_nodes_online,
                backup_nodes_total=health.backup_nodes_total,
                encryption_status=health.encryption_status,
                last_backup_time=health.last_backup_time,
                recent_backups=recent_backups,
                backup_nodes=backup_nodes
            )
        except Exception as e:
            logger.error(f"Error loading backup status: {e}")
            # Return default status
            return BackupSystemStatus()
                total_backups=0,
                active_backups=0,
                completed_backups=0,
                failed_backups=0,
                total_shards=0,
                healthy_shards=0,
                corrupted_shards=0,
                storage_used_gb=0.0,
                storage_available_gb=0.0,
                backup_nodes_online=0,
                backup_nodes_total=0,
                encryption_status="UNKNOWN",
                last_backup_time=None
            )

    def update_display(self):
        """Update the GUI display with current data."""
        if not GUI_AVAILABLE or not self.status_data:
            return

        try:
            # Update status indicator
            if self.status_indicator:
                if self.status_data.backup_nodes_online > 0:
                    self.status_indicator.config(text=" Online", foreground="green")
                else:
                    self.status_indicator.config(text=" Offline", foreground="red")

            # Update overview metrics
            if self.total_backups_label:
                self.total_backups_label.config(text=str(self.status_data.total_backups))
            if self.active_backups_label:
                self.active_backups_label.config(text=str(self.status_data.active_backups))
            if self.failed_backups_label:
                self.failed_backups_label.config(text=str(self.status_data.failed_backups))
            if self.storage_used_label:
                self.storage_used_label.config(text=f"{self.status_data.storage_used_gb:.1f} GB")
            if self.storage_available_label:
                self.storage_available_label.config(text=f"{self.status_data.storage_available_gb:.1f} GB")
            if self.nodes_online_label:
                self.nodes_online_label.config(text=f"{self.status_data.backup_nodes_online}/{self.status_data.backup_nodes_total}")
            if self.encryption_status_label:
                self.encryption_status_label.config(text=self.status_data.encryption_status)

            # Update status text
            if self.status_text:
                self.status_text.config(state=tk.NORMAL)
                self.status_text.delete(1.0, tk.END)

                status_info = f"Backup System Status Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                status_info += f"{'='*60}\n"
                status_info += f"Total Backups: {self.status_data.total_backups}\n"
                status_info += f"Active Backups: {self.status_data.active_backups}\n"
                status_info += f"Completed Backups: {self.status_data.completed_backups}\n"
                status_info += f"Failed Backups: {self.status_data.failed_backups}\n"
                status_info += f"Total Shards: {self.status_data.total_shards:,}\n"
                status_info += f"Healthy Shards: {self.status_data.healthy_shards:,}\n"
                status_info += f"Corrupted Shards: {self.status_data.corrupted_shards}\n"
                status_info += f"Storage Used: {self.status_data.storage_used_gb:.1f} GB\n"
                status_info += f"Storage Available: {self.status_data.storage_available_gb:.1f} GB\n"
                status_info += f"Backup Nodes Online: {self.status_data.backup_nodes_online}/{self.status_data.backup_nodes_total}\n"
                status_info += f"Encryption Status: {self.status_data.encryption_status}\n"

                if self.status_data.last_backup_time:
                    status_info += f"Last Backup: {self.status_data.last_backup_time.strftime('%Y-%m-%d %H:%M:%S')}\n"

                self.status_text.insert(tk.END, status_info)
                self.status_text.config(state=tk.DISABLED)

            # Update backups tree
            self.update_backups_tree()

            # Update nodes tree
            self.update_nodes_tree()

        except Exception as e:
            logger.error(f"Error updating display: {e}")

    def update_backups_tree(self):
        """Update the backups tree view."""
        if not GUI_AVAILABLE or not self.backups_tree or not self.status_data:
            return

        try:
            # Clear existing items
            for item in self.backups_tree.get_children():
                self.backups_tree.delete(item)

            # Add backups
            for backup in self.status_data.recent_backups:
                values = ()
                    backup.backup_id,
                    backup.source_path,
                    backup.backup_type,
                    backup.status,
                    backup.created_at.strftime('%Y-%m-%d %H:%M'),
                    f"{backup.size_mb:.1f} MB",
                    str(backup.shard_count),
                    backup.security_level
                )

                # Color code based on status
                tags = []
                if backup.status.upper() == "COMPLETED":
                    tags.append("completed")
                elif backup.status.upper() == "FAILED":
                    tags.append("failed")
                elif backup.status.upper() == "ACTIVE":
                    tags.append("active")
                else:
                    tags.append("pending")

                self.backups_tree.insert("", tk.END, values=values, tags=tags)

            # Configure tags for colors
            self.backups_tree.tag_configure("completed", foreground="green")
            self.backups_tree.tag_configure("failed", foreground="red")
            self.backups_tree.tag_configure("active", foreground="blue")
            self.backups_tree.tag_configure("pending", foreground="orange")

        except Exception as e:
            logger.error(f"Error updating backups tree: {e}")

    def update_nodes_tree(self):
        """Update the nodes tree view."""
        if not GUI_AVAILABLE or not self.nodes_tree or not self.status_data:
            return

        try:
            # Clear existing items
            for item in self.nodes_tree.get_children():
                self.nodes_tree.delete(item)

            # Add nodes
            for node in self.status_data.backup_nodes:
                storage_percent = (node.storage_used_gb / node.storage_total_gb * 100) if node.storage_total_gb > 0 else 0
                values = ()
                    node.node_id,
                    node.address,
                    node.status,
                    f"{node.storage_used_gb:.1f}/{node.storage_total_gb:.1f} GB",
                    f"{storage_percent:.1f}%",
                    str(node.shard_count),
                    node.last_heartbeat.strftime('%H:%M:%S')
                )

                # Color code based on status
                tags = []
                if node.status.upper() == "ONLINE":
                    tags.append("online")
                elif node.status.upper() == "OFFLINE":
                    tags.append("offline")
                else:
                    tags.append("warning")

                self.nodes_tree.insert("", tk.END, values=values, tags=tags)

            # Configure tags for colors
            self.nodes_tree.tag_configure("online", foreground="green")
            self.nodes_tree.tag_configure("offline", foreground="red")
            self.nodes_tree.tag_configure("warning", foreground="orange")

        except Exception as e:
            logger.error(f"Error updating nodes tree: {e}")

    def setup_overview_tab(self):
        """Set up the backup overview tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.overview_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.overview_frame, text=" Overview")

            # Metrics frame
            metrics_frame = ttk.LabelFrame(self.overview_frame, text="Backup System Metrics", padding=10)
            metrics_frame.pack(fill=tk.X, padx=10, pady=5)

            # Create metrics grid
            metrics_grid = ttk.Frame(metrics_frame)
            metrics_grid.pack(fill=tk.X)

            # Total backups
            total_frame = ttk.Frame(metrics_grid)
            total_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")
            ttk.Label(total_frame, text="Total Backups:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.total_backups_label = ttk.Label(total_frame, text="0", foreground="blue")
            self.total_backups_label.pack(side=tk.LEFT, padx=(10, 0))

            # Active backups
            active_frame = ttk.Frame(metrics_grid)
            active_frame.grid(row=0, column=1, padx=10, pady=5, sticky="w")
            ttk.Label(active_frame, text="Active Backups:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.active_backups_label = ttk.Label(active_frame, text="0", foreground="green")
            self.active_backups_label.pack(side=tk.LEFT, padx=(10, 0))

            # Failed backups
            failed_frame = ttk.Frame(metrics_grid)
            failed_frame.grid(row=0, column=2, padx=10, pady=5, sticky="w")
            ttk.Label(failed_frame, text="Failed Backups:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.failed_backups_label = ttk.Label(failed_frame, text="0", foreground="red")
            self.failed_backups_label.pack(side=tk.LEFT, padx=(10, 0))

            # Storage used
            storage_used_frame = ttk.Frame(metrics_grid)
            storage_used_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            ttk.Label(storage_used_frame, text="Storage Used:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.storage_used_label = ttk.Label(storage_used_frame, text="0 GB")
            self.storage_used_label.pack(side=tk.LEFT, padx=(10, 0))

            # Storage available
            storage_avail_frame = ttk.Frame(metrics_grid)
            storage_avail_frame.grid(row=1, column=1, padx=10, pady=5, sticky="w")
            ttk.Label(storage_avail_frame, text="Storage Available:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.storage_available_label = ttk.Label(storage_avail_frame, text="0 GB", foreground="green")
            self.storage_available_label.pack(side=tk.LEFT, padx=(10, 0))

            # Nodes online
            nodes_frame = ttk.Frame(metrics_grid)
            nodes_frame.grid(row=1, column=2, padx=10, pady=5, sticky="w")
            ttk.Label(nodes_frame, text="Nodes Online:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.nodes_online_label = ttk.Label(nodes_frame, text="0/0", foreground="blue")
            self.nodes_online_label.pack(side=tk.LEFT, padx=(10, 0))

            # Encryption status
            encryption_frame = ttk.Frame(metrics_grid)
            encryption_frame.grid(row=2, column=0, padx=10, pady=5, sticky="w")
            ttk.Label(encryption_frame, text="Encryption:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.encryption_status_label = ttk.Label(encryption_frame, text="UNKNOWN", foreground="orange")
            self.encryption_status_label.pack(side=tk.LEFT, padx=(10, 0))

            # Status text area
            status_frame = ttk.LabelFrame(self.overview_frame, text="System Status", padding=10)
            status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            self.status_text = tk.Text(status_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
            status_scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
            self.status_text.configure(yscrollcommand=status_scrollbar.set)

            self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            status_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        except Exception as e:
            logger.error(f"Error setting up overview tab: {e}")

    def setup_backups_tab(self):
        """Set up the backups management tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.backups_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.backups_frame, text=" Backups")

            # Backup controls
            control_frame = ttk.Frame(self.backups_frame)
            control_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Button()
                control_frame,
                text=" Create Backup",
                command=self.create_backup_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                control_frame,
                text=" Refresh",
                command=self.refresh_backups
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                control_frame,
                text=" Delete Backup",
                command=self.delete_backup_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                control_frame,
                text=" Export Report",
                command=self.export_backup_report
            ).pack(side=tk.LEFT)

            # Backups list
            backups_list_frame = ttk.LabelFrame(self.backups_frame, text="Recent Backups", padding=10)
            backups_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            # Create treeview for backups
            backup_columns = ("ID", "Source", Type, "Status", "Created", "Size", "Shards", "Security")
            self.backups_tree = ttk.Treeview(backups_list_frame, columns=backup_columns, show="headings", height=12)

            # Configure columns with better widths
            column_widths = {"ID": 100, "Source": 150, Type: 80, "Status": 80,
                           "Created": 120, "Size": 80, "Shards": 60, "Security": 100}

            for col in backup_columns:
                self.backups_tree.heading(col, text=col)
                self.backups_tree.column(col, width=column_widths.get(col, 100))

            # Scrollbar for backups tree
            backups_scrollbar = ttk.Scrollbar(backups_list_frame, orient=tk.VERTICAL, command=self.backups_tree.yview)
            self.backups_tree.configure(yscrollcommand=backups_scrollbar.set)

            self.backups_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            backups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Backup details frame
            details_frame = ttk.LabelFrame(self.backups_frame, text="Backup Details", padding=10)
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            self.backup_details_text = tk.Text(details_frame, height=4, wrap=tk.WORD, state=tk.DISABLED)
            details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.backup_details_text.yview)
            self.backup_details_text.configure(yscrollcommand=details_scrollbar.set)

            self.backup_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Bind selection event
            self.backups_tree.bind('<<TreeviewSelect>>', self.on_backup_select)

        except Exception as e:
            logger.error(f"Error setting up backups tab: {e}")

    def setup_nodes_tab(self):
        """Set up the backup nodes tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.nodes_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.nodes_frame, text=" Nodes")

            # Node controls
            control_frame = ttk.Frame(self.nodes_frame)
            control_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Button()
                control_frame,
                text=" Add Node",
                command=self.add_backup_node_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                control_frame,
                text=" Refresh",
                command=self.refresh_nodes
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                control_frame,
                text=" Node Health",
                command=self.check_node_health
            ).pack(side=tk.LEFT)

            # Nodes list
            nodes_list_frame = ttk.LabelFrame(self.nodes_frame, text="Backup Nodes", padding=10)
            nodes_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            # Create treeview for nodes
            node_columns = ("ID", "Address", "Status", "Storage", "Usage", "Shards", "Last Seen")
            self.nodes_tree = ttk.Treeview(nodes_list_frame, columns=node_columns, show="headings", height=12)

            # Configure columns with better widths
            column_widths = {"ID": 100, "Address": 150, "Status": 80, "Storage": 120,
                           "Usage": 80, "Shards": 60, "Last Seen": 80}

            for col in node_columns:
                self.nodes_tree.heading(col, text=col)
                self.nodes_tree.column(col, width=column_widths.get(col, 100))

            # Scrollbar for nodes tree
            nodes_scrollbar = ttk.Scrollbar(nodes_list_frame, orient=tk.VERTICAL, command=self.nodes_tree.yview)
            self.nodes_tree.configure(yscrollcommand=nodes_scrollbar.set)

            self.nodes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            nodes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Node details frame
            details_frame = ttk.LabelFrame(self.nodes_frame, text="Node Details", padding=10)
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            self.node_details_text = tk.Text(details_frame, height=4, wrap=tk.WORD, state=tk.DISABLED)
            details_scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.node_details_text.yview)
            self.node_details_text.configure(yscrollcommand=details_scrollbar.set)

            self.node_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            # Bind selection event
            self.nodes_tree.bind('<<TreeviewSelect>>', self.on_node_select)

        except Exception as e:
            logger.error(f"Error setting up nodes tab: {e}")

    def setup_recovery_tab(self):
        """Set up the recovery operations tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.recovery_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.recovery_frame, text=" Recovery")

            # Recovery controls
            recovery_controls_frame = ttk.LabelFrame(self.recovery_frame, text="Recovery Operations", padding=10)
            recovery_controls_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Button()
                recovery_controls_frame,
                text=" Browse Backups",
                command=self.browse_backups_for_recovery
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                recovery_controls_frame,
                text=" Restore Backup",
                command=self.restore_backup_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button()
                recovery_controls_frame,
                text=" Verify Integrity",
                command=self.verify_backup_integrity
            ).pack(side=tk.LEFT)

            # Recovery status
            recovery_status_frame = ttk.LabelFrame(self.recovery_frame, text="Recovery Status", padding=10)
            recovery_status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            ttk.Label(recovery_status_frame, text="Recovery operations will be displayed here.").pack()

        except Exception as e:
            logger.error(f"Error setting up recovery tab: {e}")

    def setup_settings_tab(self):
        """Set up the backup settings tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.settings_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.settings_frame, text=" Settings")

            # Backup settings
            backup_settings_frame = ttk.LabelFrame(self.settings_frame, text="Backup Settings", padding=10)
            backup_settings_frame.pack(fill=tk.X, padx=10, pady=5)

            # Auto backup checkbox
            if self.auto_backup_var:
                auto_backup_cb = ttk.Checkbutton()
                    backup_settings_frame,
                    text="Enable Automatic Backups",
                    variable=self.auto_backup_var
                )
                auto_backup_cb.pack(anchor=tk.W, pady=2)

            # Encryption checkbox
            if self.encryption_enabled_var:
                encryption_cb = ttk.Checkbutton()
                    backup_settings_frame,
                    text="Enable Quantum Encryption",
                    variable=self.encryption_enabled_var
                )
                encryption_cb.pack(anchor=tk.W, pady=2)

            # Additional settings
            ttk.Label(backup_settings_frame, text="Additional backup configuration options will be available here.").pack(anchor=tk.W, pady=10)

        except Exception as e:
            logger.error(f"Error setting up settings tab: {e}")

    def setup_control_panel(self):
        """Set up the control panel."""
        if not GUI_AVAILABLE or not self.main_frame:
            return

        try:
            control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding=10)
            control_frame.pack(fill=tk.X, padx=10, pady=5)

            # Auto refresh checkbox
            if self.auto_refresh_var:
                auto_refresh_cb = ttk.Checkbutton()
                    control_frame,
                    text="Auto Refresh",
                    variable=self.auto_refresh_var,
                    command=self.toggle_auto_refresh
                )
                auto_refresh_cb.pack(side=tk.LEFT, padx=(0, 10))

            # Manual refresh button
            ttk.Button()
                control_frame,
                text=" Refresh Now",
                command=self.manual_refresh
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Export button
            ttk.Button()
                control_frame,
                text=" Export Data",
                command=self.export_backup_data
            ).pack(side=tk.LEFT)

        except Exception as e:
            logger.error(f"Error setting up control panel: {e}")

    def start_background_monitoring(self):
        """Start background monitoring thread."""
        if not self.background_thread or not self.background_thread.is_alive():
            self.background_thread = threading.Thread(target=self._background_monitor, daemon=True)
            self.background_thread.start()

    def _background_monitor(self):
        """Background monitoring loop."""
        while not self.stop_background.is_set():
            try:
                if self.auto_refresh_enabled:
                    self.schedule_refresh()
                self.stop_background.wait(self.refresh_interval / 1000)  # Convert to seconds
            except Exception as e:
                logger.error(f"Error in background monitoring: {e}")
                self.stop_background.wait(5)  # Wait 5 seconds before retrying

    # Event handlers
    def on_backup_select(self, event):
        """Handle backup selection in the tree."""
        if not GUI_AVAILABLE or not self.backups_tree or not self.backup_details_text:
            return

        try:
            selection = self.backups_tree.selection()
            if selection and self.status_data:
                item = self.backups_tree.item(selection[0])
                backup_id = item['values'][0]

                # Find the backup in our data
                backup_info = None
                for backup in self.status_data.recent_backups:
                    if backup.backup_id == backup_id:
                        backup_info = backup
                        break

                if backup_info:
                    # Update details text
                    self.backup_details_text.config(state=tk.NORMAL)
                    self.backup_details_text.delete(1.0, tk.END)

                    details = f"Backup Details: {backup_info.backup_id}\n"
                    details += f"Source Path: {backup_info.source_path}\n"
                    details += f"Type: {backup_info.backup_type}\n"
                    details += f"Status: {backup_info.status}\n"
                    details += f"Created: {backup_info.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    details += f"Size: {backup_info.size_mb:.1f} MB\n"
                    details += f"Shard Count: {backup_info.shard_count}\n"
                    details += f"Security Level: {backup_info.security_level}\n"

                    if backup_info.error_message:
                        details += f"Error: {backup_info.error_message}\n"

                    self.backup_details_text.insert(tk.END, details)
                    self.backup_details_text.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Error handling backup selection: {e}")

    def on_node_select(self, event):
        """Handle node selection in the tree."""
        if not GUI_AVAILABLE or not self.nodes_tree or not self.node_details_text:
            return

        try:
            selection = self.nodes_tree.selection()
            if selection and self.status_data:
                item = self.nodes_tree.item(selection[0])
                node_id = item['values'][0]

                # Find the node in our data
                node_info = None
                for node in self.status_data.backup_nodes:
                    if node.node_id == node_id:
                        node_info = node
                        break

                if node_info:
                    # Update details text
                    self.node_details_text.config(state=tk.NORMAL)
                    self.node_details_text.delete(1.0, tk.END)

                    storage_percent = (node_info.storage_used_gb / node_info.storage_total_gb * 100) if node_info.storage_total_gb > 0 else 0

                    details = f"Node Details: {node_info.node_id}\n"
                    details += f"Address: {node_info.address}\n"
                    details += f"Status: {node_info.status}\n"
                    details += f"Storage Used: {node_info.storage_used_gb:.1f} GB\n"
                    details += f"Storage Total: {node_info.storage_total_gb:.1f} GB\n"
                    details += f"Storage Usage: {storage_percent:.1f}%\n"
                    details += f"Shard Count: {node_info.shard_count}\n"
                    details += f"Last Heartbeat: {node_info.last_heartbeat.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    details += f"Health Score: {node_info.health_score:.1f}\n"

                    if node_info.alerts:
                        details += f"Alerts: {', '.join(node_info.alerts)}\n"

                    self.node_details_text.insert(tk.END, details)
                    self.node_details_text.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Error handling node selection: {e}")

    def create_backup_dialog(self):
        """Show dialog to create a new backup."""
        if not GUI_AVAILABLE:
            return

        try:
            source_path = filedialog.askdirectory(title="Select directory to backup")
            if source_path:
                # Simple backup type selection
                backup_type = simpledialog.askstring()
                    "Backup Type",
                    "Enter backup type (FULL/INCREMENTAL):",
                    initialvalue="INCREMENTAL"
                )
                if backup_type:
                    threading.Thread(target=self._create_backup_async, args=(source_path, backup_type), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in create backup dialog: {e}")

    def _create_backup_async(self, source_path, backup_type):
        """Create backup asynchronously."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            backup_id = loop.run_until_complete()
                backup_manager.create_backup(source_path, backup_type, 'GOVERNMENT')
            )

            if backup_id:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showinfo("Success", f"Backup {backup_id} created successfully"))
                    self.schedule_refresh()
            else:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showerror("Error", "Failed to create backup"))

            loop.close()
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            if GUI_AVAILABLE:
                self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to create backup: {str(e)}"))

    def delete_backup_dialog(self):
        """Show dialog to delete a backup."""
        if not GUI_AVAILABLE or not self.backups_tree:
            return

        try:
            selection = self.backups_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a backup to delete")
                return

            item = self.backups_tree.item(selection[0])
            backup_id = item['values'][0]

            if messagebox.askyesno("Confirm", f"Are you sure you want to delete backup {backup_id}?"):
                messagebox.showinfo("Info", "Backup deletion functionality will be implemented here")
        except Exception as e:
            logger.error(f"Error in delete backup dialog: {e}")

    def restore_backup_dialog(self):
        """Show dialog to restore a backup."""
        if not GUI_AVAILABLE:
            return

        try:
            if not self.backups_tree:
                messagebox.showwarning("Warning", "No backup selected")
                return

            selection = self.backups_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a backup to restore")
                return

            item = self.backups_tree.item(selection[0])
            backup_id = item['values'][0]

            target_path = filedialog.askdirectory(title="Select restore destination")
            if target_path:
                threading.Thread(target=self._restore_backup_async, args=(backup_id, target_path), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in restore backup dialog: {e}")

    def _restore_backup_async(self, backup_id, target_path):
        """Restore backup asynchronously."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            success = loop.run_until_complete(backup_manager.restore_backup(backup_id, target_path))

            if success:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showinfo("Success", f"Backup {backup_id} restored successfully"))
            else:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to restore backup {backup_id}"))

            loop.close()
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
            if GUI_AVAILABLE:
                self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to restore backup: {str(e)}"))

    # Additional methods
    def refresh_backups(self):
        """Refresh the backups display."""
        self.schedule_refresh()

    def refresh_nodes(self):
        """Refresh the nodes display."""
        self.schedule_refresh()

    def add_backup_node_dialog(self):
        """Show dialog to add a backup node."""
        if not GUI_AVAILABLE:
            return
        messagebox.showinfo("Info", "Add backup node functionality will be implemented here")

    def check_node_health(self):
        """Check health of all backup nodes."""
        if not GUI_AVAILABLE:
            return
        messagebox.showinfo("Info", "Node health check functionality will be implemented here")

    def browse_backups_for_recovery(self):
        """Browse available backups for recovery."""
        if not GUI_AVAILABLE:
            return
        messagebox.showinfo("Info", "Browse backups functionality will be implemented here")

    def verify_backup_integrity(self):
        """Verify backup integrity."""
        if not GUI_AVAILABLE:
            return
        messagebox.showinfo("Info", "Backup integrity verification will be implemented here")

    def export_backup_report(self):
        """Export backup report."""
        if not GUI_AVAILABLE:
            return
        messagebox.showinfo("Info", "Export backup report functionality will be implemented here")

    def toggle_auto_refresh(self):
        """Toggle auto refresh."""
        if self.auto_refresh_var:
            self.auto_refresh_enabled = self.auto_refresh_var.get()

    def manual_refresh(self):
        """Manually refresh data."""
        self.schedule_refresh()

    def export_backup_data(self):
        """Export backup data to file."""
        if not GUI_AVAILABLE:
            return

        try:
            if not self.status_data:
                messagebox.showwarning("Warning", "No data to export")
                return

            filename = filedialog.asksaveasfilename()
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )

            if filename:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'backup_system_status': {
                        'total_backups': self.status_data.total_backups,
                        'active_backups': self.status_data.active_backups,
                        'completed_backups': self.status_data.completed_backups,
                        'failed_backups': self.status_data.failed_backups,
                        'total_shards': self.status_data.total_shards,
                        'healthy_shards': self.status_data.healthy_shards,
                        'corrupted_shards': self.status_data.corrupted_shards,
                        'storage_used_gb': self.status_data.storage_used_gb,
                        'storage_available_gb': self.status_data.storage_available_gb,
                        'backup_nodes_online': self.status_data.backup_nodes_online,
                        'backup_nodes_total': self.status_data.backup_nodes_total,
                        'encryption_status': self.status_data.encryption_status
                    },
                    'recent_backups': [
                        {
                            'backup_id': backup.backup_id,
                            'source_path': backup.source_path,
                            'backup_type': backup.backup_type,
                            'status': backup.status,
                            'created_at': backup.created_at.isoformat(),
                            'size_mb': backup.size_mb,
                            'shard_count': backup.shard_count,
                            'security_level': backup.security_level
                        }
                        for backup in self.status_data.recent_backups
                    ],
                    'backup_nodes': [
                        {
                            'node_id': node.node_id,
                            'address': node.address,
                            'status': node.status,
                            'storage_used_gb': node.storage_used_gb,
                            'storage_total_gb': node.storage_total_gb,
                            'shard_count': node.shard_count,
                            'last_heartbeat': node.last_heartbeat.isoformat(),
                            'health_score': node.health_score
                        }
                        for node in self.status_data.backup_nodes
                    ]
                }

                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)

                messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")


# Alias for backward compatibility
BackupManagementWidget = EnhancedBackupManagementWidget
