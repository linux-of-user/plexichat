import asyncio
import json
import logging
import threading
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional

from ...features.clustering import AdvancedClusterManager

from datetime import datetime
from datetime import datetime
from datetime import datetime

from datetime import datetime
from datetime import datetime
from datetime import datetime

"""
Enhanced Clustering Management GUI Widget
Comprehensive GUI component for cluster management, load balancing, and failover.

Features:
- Real-time cluster monitoring and visualization
- Advanced node management with health tracking
- Intelligent load balancer configuration
- Failover testing and management
- Performance analytics and optimization
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

# Import clustering system components with fallbacks
CLUSTERING_AVAILABLE = False
cluster_manager = None

try:
    cluster_manager = AdvancedClusterManager()
    CLUSTERING_AVAILABLE = True
except ImportError:
    # Create a mock cluster manager for when clustering is not available
    class MockClusterManager:
        def __init__(self):
            self.initialized = False

        async def initialize(self):
            self.initialized = True

        async def get_cluster_overview(self):
            return type('Overview', (), {
                'total_nodes': 3,
                'active_nodes': 2,
                'cluster_load_percentage': 45.5,
                'performance_improvement_percentage': 150.0,
                'total_failover_events': 2,
                'last_failover_timestamp': from datetime import datetime
datetime = datetime.now() - timedelta(hours=2)
            })()

        async def get_cluster_health(self):
            return type('Health', (), {
                'node_health_status': [
                    type('Node', (), {
                        'node_id': 'node-001',
                        'status': type('Status', (), {'value': 'ONLINE'})(),
                        'health_score': 95.5,
                        'cpu_usage_percentage': 35.2,
                        'memory_usage_percentage': 42.1,
                        'current_connections': 150
                    })(),
                    type('Node', (), {
                        'node_id': 'node-002',
                        'status': type('Status', (), {'value': 'ONLINE'})(),
                        'health_score': 88.3,
                        'cpu_usage_percentage': 52.7,
                        'memory_usage_percentage': 38.9,
                        'current_connections': 203
                    })()
                ]
            })()

        async def get_load_balancer_stats(self):
            return type('Stats', (), {
                'total_requests': 15420,
                'current_rps': 23.5,
                'average_response_time_ms': 145.2,
                'node_request_distribution': {
                    'node-001': 7850,
                    'node-002': 7570
                }
            })()

        async def add_node(self, node_config):
            return True

        async def remove_node(self, node_id):
            return True

    cluster_manager = MockClusterManager()

logger = logging.getLogger(__name__)


@dataclass
class NodeHealthInfo:
    """Individual node health information."""
    node_id: str
    name: str
    status: str
    health_score: float
    cpu_usage: float
    memory_usage: float
    disk_usage: float = 0.0
    network_latency: float = 0.0
    connections: int = 0
    uptime: str = "0:00:00"
    last_heartbeat: Optional[datetime] = None
    maintenance_mode: bool = False
    alerts: List[str] = field(default_factory=list)
    node_type: str = "main"
    address: str = "localhost:8080"


@dataclass
class ClusterSystemStatus:
    """Enhanced cluster system status information."""
    total_nodes: int
    active_nodes: int
    offline_nodes: int = 0
    maintenance_nodes: int = 0
    cluster_load: float = 0.0
    performance_gain: float = 0.0
    failover_events: int = 0
    last_failover: Optional[datetime] = None
    node_health: List[NodeHealthInfo] = field(default_factory=list)
    load_balancer_stats: Dict[str, Any] = field(default_factory=dict)
    security_status: Dict[str, Any] = field(default_factory=dict)
    performance_history: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    cluster_efficiency: float = 0.0
    total_requests_processed: int = 0
    average_response_time: float = 0.0


class EnhancedClusteringManagementWidget:
    """Enhanced GUI widget for comprehensive clustering management."""

    def __init__(self, parent_frame):
        """Initialize enhanced clustering management widget."""
        self.parent_frame = parent_frame
        self.status_data: Optional[ClusterSystemStatus] = None
        self.refresh_interval = 15000  # 15 seconds for more responsive updates
        self.auto_refresh_enabled = True
        self.performance_history = []
        self.max_history_points = 100

        # Threading for background operations
        self.background_thread = None
        self.stop_background = threading.Event()

        # GUI components (initialized to None)
        self.main_frame = None
        self.notebook = None
        self.overview_frame = None
        self.nodes_frame = None
        self.performance_frame = None
        self.loadbalancer_frame = None
        self.failover_frame = None
        self.status_indicator = None

        # Status widgets
        self.total_nodes_label = None
        self.active_nodes_label = None
        self.offline_nodes_label = None
        self.cluster_load_label = None
        self.performance_gain_label = None
        self.efficiency_label = None
        self.response_time_label = None
        self.status_text = None

        # Node widgets
        self.nodes_tree = None
        self.node_details_text = None

        # Control variables
        self.auto_refresh_var = None
        self.monitoring_enabled_var = None
        self.alert_threshold_var = None

        # Configuration
        self.config = {
            'refresh_interval': 15,
            'alert_cpu_threshold': 80,
            'alert_memory_threshold': 85,
            'alert_response_time_threshold': 1000,
            'enable_notifications': True,
            'auto_failover': True,
            'load_balancing_algorithm': 'ai_optimized'
        }

        # Initialize the widget
        self.initialize_widget()

    def initialize_widget(self):
        """Initialize the widget based on available components."""
        if GUI_AVAILABLE:
            try:
                self.setup_gui()
                self.start_background_monitoring()
                logger.info("Enhanced clustering management widget initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize GUI: {e}")
                self.create_fallback_interface()
        else:
            logger.warning("GUI not available, creating text-based interface")
            self.create_fallback_interface()

    def create_fallback_interface(self):
        """Create a fallback text-based interface when GUI is not available."""
        logger.info("Clustering Management Widget initialized in text mode")
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
            title_label = ttk.Label(
                header_frame,
                text=" Enhanced Clustering Management",
                font=("Arial", 18, "bold")
            )
            title_label.pack(side=tk.LEFT)

            # Status indicator
            self.status_indicator = ttk.Label(
                header_frame,
                text=" Connecting...",
                foreground="orange",
                font=("Arial", 10, "bold")
            )
            self.status_indicator.pack(side=tk.RIGHT)

            # Create notebook for tabs
            self.notebook = ttk.Notebook(self.main_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            # Setup enhanced tabs
            self.setup_overview_tab()
            self.setup_nodes_tab()
            self.setup_performance_tab()
            self.setup_loadbalancer_tab()
            self.setup_failover_tab()

            # Control panel at bottom
            self.setup_control_panel()

            # Initialize control variables
            if GUI_AVAILABLE:
                self.auto_refresh_var = tk.BooleanVar(value=True)
                self.monitoring_enabled_var = tk.BooleanVar(value=True)
                self.alert_threshold_var = tk.StringVar(value="80")

            # Start initial data load
            self.schedule_refresh()

            logger.info("Enhanced clustering management GUI setup completed")

        except Exception as e:
            logger.error(f"Error setting up enhanced clustering management GUI: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("GUI Error", f"Failed to setup clustering management interface: {str(e)}")

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
        """Refresh cluster data asynchronously."""
        try:
            self.status_data = await self.load_cluster_status()
            if GUI_AVAILABLE and self.parent_frame:
                # Schedule GUI update on main thread
                self.parent_frame.after(0, self.update_display)
        except Exception as e:
            logger.error(f"Error refreshing data: {e}")

    async def load_cluster_status(self) -> ClusterSystemStatus:
        """Load cluster status from the cluster manager."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            # Get cluster overview
            overview = await cluster_manager.get_cluster_overview()
            health = await cluster_manager.get_cluster_health()
            lb_stats = await cluster_manager.get_load_balancer_stats()

            # Convert to our data structure
            node_health = []
            for node in health.node_health_status:
                node_info = NodeHealthInfo(
                    node_id=node.node_id,
                    name=node.node_id,
                    status=node.status.value,
                    health_score=node.health_score,
                    cpu_usage=node.cpu_usage_percentage,
                    memory_usage=node.memory_usage_percentage,
                    connections=node.current_connections,
                    address=f"{node.node_id}:8080"
                )
                node_health.append(node_info)

            return ClusterSystemStatus(
                total_nodes=overview.total_nodes,
                active_nodes=overview.active_nodes,
                offline_nodes=overview.total_nodes - overview.active_nodes,
                cluster_load=overview.cluster_load_percentage,
                performance_gain=overview.performance_improvement_percentage,
                failover_events=overview.total_failover_events,
                last_failover=overview.last_failover_timestamp,
                node_health=node_health,
                load_balancer_stats={
                    'total_requests': lb_stats.total_requests,
                    'current_rps': lb_stats.current_rps,
                    'average_response_time': lb_stats.average_response_time_ms,
                    'node_distribution': lb_stats.node_request_distribution
                },
                total_requests_processed=lb_stats.total_requests,
                average_response_time=lb_stats.average_response_time_ms
            )
        except Exception as e:
            logger.error(f"Error loading cluster status: {e}")
            # Return default status
            return ClusterSystemStatus(
                total_nodes=0,
                active_nodes=0,
                offline_nodes=0
            )

    def update_display(self):
        """Update the GUI display with current data."""
        if not GUI_AVAILABLE or not self.status_data:
            return

        try:
            # Update status indicator
            if self.status_indicator:
                if self.status_data.active_nodes > 0:
                    self.status_indicator.config(text=" Connected", foreground="green")
                else:
                    self.status_indicator.config(text=" Disconnected", foreground="red")

            # Update overview metrics
            if self.total_nodes_label:
                self.total_nodes_label.config(text=str(self.status_data.total_nodes))
            if self.active_nodes_label:
                self.active_nodes_label.config(text=str(self.status_data.active_nodes))
            if self.offline_nodes_label:
                self.offline_nodes_label.config(text=str(self.status_data.offline_nodes))
            if self.cluster_load_label:
                self.cluster_load_label.config(text=f"{self.status_data.cluster_load:.1f}%")
            if self.performance_gain_label:
                self.performance_gain_label.config(text=f"{self.status_data.performance_gain:.1f}%")

            # Update status text
            if self.status_text:
                self.status_text.config(state=tk.NORMAL)
                self.status_text.delete(1.0, tk.END)

                status_info = f"Cluster Status Report - {from datetime import datetime
datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                status_info += f"{'='*60}\n"
                status_info += f"Total Nodes: {self.status_data.total_nodes}\n"
                status_info += f"Active Nodes: {self.status_data.active_nodes}\n"
                status_info += f"Offline Nodes: {self.status_data.offline_nodes}\n"
                status_info += f"Cluster Load: {self.status_data.cluster_load:.1f}%\n"
                status_info += f"Performance Gain: {self.status_data.performance_gain:.1f}%\n"
                status_info += f"Total Requests: {self.status_data.total_requests_processed:,}\n"
                status_info += f"Average Response Time: {self.status_data.average_response_time:.1f}ms\n"

                if self.status_data.last_failover:
                    status_info += f"Last Failover: {self.status_data.last_failover.strftime('%Y-%m-%d %H:%M:%S')}\n"

                self.status_text.insert(tk.END, status_info)
                self.status_text.config(state=tk.DISABLED)

            # Update nodes tree
            self.update_nodes_tree()

        except Exception as e:
            logger.error(f"Error updating display: {e}")

    def update_nodes_tree(self):
        """Update the nodes tree view."""
        if not GUI_AVAILABLE or not self.nodes_tree or not self.status_data:
            return

        try:
            # Clear existing items
            for item in self.nodes_tree.get_children():
                self.nodes_tree.delete(item)

            # Add nodes
            for node in self.status_data.node_health:
                values = (
                    node.node_id,
                    node.name,
                    node.node_type,
                    node.address,
                    node.status,
                    f"{node.cpu_usage:.1f}%",
                    f"{node.memory_usage:.1f}%",
                    f"{node.health_score:.1f}"
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
        """Set up the cluster overview tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.overview_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.overview_frame, text=" Overview")

            # Metrics frame
            metrics_frame = ttk.LabelFrame(self.overview_frame, text="Cluster Metrics", padding=10)
            metrics_frame.pack(fill=tk.X, padx=10, pady=5)

            # Create metrics grid
            metrics_grid = ttk.Frame(metrics_frame)
            metrics_grid.pack(fill=tk.X)

            # Total nodes
            nodes_frame = ttk.Frame(metrics_grid)
            nodes_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")
            ttk.Label(nodes_frame, text="Total Nodes:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.total_nodes_label = ttk.Label(nodes_frame, text="0", foreground="blue")
            self.total_nodes_label.pack(side=tk.LEFT, padx=(10, 0))

            # Active nodes
            active_frame = ttk.Frame(metrics_grid)
            active_frame.grid(row=0, column=1, padx=10, pady=5, sticky="w")
            ttk.Label(active_frame, text="Active Nodes:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.active_nodes_label = ttk.Label(active_frame, text="0", foreground="green")
            self.active_nodes_label.pack(side=tk.LEFT, padx=(10, 0))

            # Offline nodes
            offline_frame = ttk.Frame(metrics_grid)
            offline_frame.grid(row=0, column=2, padx=10, pady=5, sticky="w")
            ttk.Label(offline_frame, text="Offline Nodes:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.offline_nodes_label = ttk.Label(offline_frame, text="0", foreground="red")
            self.offline_nodes_label.pack(side=tk.LEFT, padx=(10, 0))

            # Cluster load
            load_frame = ttk.Frame(metrics_grid)
            load_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            ttk.Label(load_frame, text="Cluster Load:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.cluster_load_label = ttk.Label(load_frame, text="0%")
            self.cluster_load_label.pack(side=tk.LEFT, padx=(10, 0))

            # Performance gain
            perf_frame = ttk.Frame(metrics_grid)
            perf_frame.grid(row=1, column=1, padx=10, pady=5, sticky="w")
            ttk.Label(perf_frame, text="Performance Gain:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.performance_gain_label = ttk.Label(perf_frame, text="0%", foreground="green")
            self.performance_gain_label.pack(side=tk.LEFT, padx=(10, 0))

            # Efficiency
            eff_frame = ttk.Frame(metrics_grid)
            eff_frame.grid(row=1, column=2, padx=10, pady=5, sticky="w")
            ttk.Label(eff_frame, text="Efficiency:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
            self.efficiency_label = ttk.Label(eff_frame, text="0%", foreground="blue")
            self.efficiency_label.pack(side=tk.LEFT, padx=(10, 0))

            # Status text area
            status_frame = ttk.LabelFrame(self.overview_frame, text="Cluster Status", padding=10)
            status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            self.status_text = tk.Text(status_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
            status_scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
            self.status_text.configure(yscrollcommand=status_scrollbar.set)

            self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            status_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        except Exception as e:
            logger.error(f"Error setting up overview tab: {e}")

    def setup_nodes_tab(self):
        """Set up the cluster nodes tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.nodes_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.nodes_frame, text=" Nodes")

            # Node controls
            control_frame = ttk.Frame(self.nodes_frame)
            control_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Button(
                control_frame,
                text=" Add Node",
                command=self.add_cluster_node_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button(
                control_frame,
                text=" Remove Node",
                command=self.remove_cluster_node_dialog
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button(
                control_frame,
                text=" Refresh",
                command=self.refresh_nodes
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Button(
                control_frame,
                text=" Maintenance",
                command=self.toggle_maintenance_mode
            ).pack(side=tk.LEFT)

            # Nodes list
            nodes_list_frame = ttk.LabelFrame(self.nodes_frame, text="Cluster Nodes", padding=10)
            nodes_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            # Create treeview for nodes
            node_columns = ("ID", "Name", "Type", "Address", "Status", "CPU", "Memory", "Health")
            self.nodes_tree = ttk.Treeview(nodes_list_frame, columns=node_columns, show="headings", height=12)

            # Configure columns with better widths
            column_widths = {"ID": 80, "Name": 100, "Type": 80, "Address": 120,
                           "Status": 80, "CPU": 60, "Memory": 60, "Health": 60}

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

    def setup_performance_tab(self):
        """Set up the performance monitoring tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.performance_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.performance_frame, text=" Performance")

            # Performance metrics
            perf_metrics_frame = ttk.LabelFrame(self.performance_frame, text="Performance Metrics", padding=10)
            perf_metrics_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Label(perf_metrics_frame, text="Performance monitoring and analytics will be displayed here.").pack()

        except Exception as e:
            logger.error(f"Error setting up performance tab: {e}")

    def setup_loadbalancer_tab(self):
        """Set up the load balancer configuration tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.loadbalancer_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.loadbalancer_frame, text=" Load Balancer")

            # Load balancer settings
            lb_settings_frame = ttk.LabelFrame(self.loadbalancer_frame, text="Load Balancer Settings", padding=10)
            lb_settings_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Label(lb_settings_frame, text="Load balancer configuration will be displayed here.").pack()

        except Exception as e:
            logger.error(f"Error setting up load balancer tab: {e}")

    def setup_failover_tab(self):
        """Set up the failover management tab."""
        if not GUI_AVAILABLE or not self.notebook:
            return

        try:
            self.failover_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.failover_frame, text=" Failover")

            # Failover settings
            failover_settings_frame = ttk.LabelFrame(self.failover_frame, text="Failover Management", padding=10)
            failover_settings_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Label(failover_settings_frame, text="Failover management will be displayed here.").pack()

        except Exception as e:
            logger.error(f"Error setting up failover tab: {e}")

    def setup_control_panel(self):
        """Set up the control panel."""
        if not GUI_AVAILABLE or not self.main_frame:
            return

        try:
            control_frame = ttk.LabelFrame(self.main_frame, text="Controls", padding=10)
            control_frame.pack(fill=tk.X, padx=10, pady=5)

            # Auto refresh checkbox
            if self.auto_refresh_var:
                auto_refresh_cb = ttk.Checkbutton(
                    control_frame,
                    text="Auto Refresh",
                    variable=self.auto_refresh_var,
                    command=self.toggle_auto_refresh
                )
                auto_refresh_cb.pack(side=tk.LEFT, padx=(0, 10))

            # Manual refresh button
            ttk.Button(
                control_frame,
                text=" Refresh Now",
                command=self.manual_refresh
            ).pack(side=tk.LEFT, padx=(0, 10))

            # Export button
            ttk.Button(
                control_frame,
                text=" Export Data",
                command=self.export_cluster_data
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
                for node in self.status_data.node_health:
                    if node.node_id == node_id:
                        node_info = node
                        break

                if node_info:
                    # Update details text
                    self.node_details_text.config(state=tk.NORMAL)
                    self.node_details_text.delete(1.0, tk.END)

                    details = f"Node Details: {node_info.node_id}\n"
                    details += f"Name: {node_info.name}\n"
                    details += f"Type: {node_info.node_type}\n"
                    details += f"Address: {node_info.address}\n"
                    details += f"Status: {node_info.status}\n"
                    details += f"Health Score: {node_info.health_score:.1f}\n"
                    details += f"CPU Usage: {node_info.cpu_usage:.1f}%\n"
                    details += f"Memory Usage: {node_info.memory_usage:.1f}%\n"
                    details += f"Connections: {node_info.connections}\n"

                    self.node_details_text.insert(tk.END, details)
                    self.node_details_text.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Error handling node selection: {e}")

    def add_cluster_node_dialog(self):
        """Show dialog to add a new cluster node."""
        if not GUI_AVAILABLE:
            return

        try:
            # Simple dialog for adding a node
            node_address = simpledialog.askstring("Add Node", "Enter node address (host:port):")
            if node_address:
                threading.Thread(target=self._add_node_async, args=(node_address,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in add node dialog: {e}")

    def _add_node_async(self, node_address):
        """Add node asynchronously."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            node_config = {
                'address': node_address,
                'node_type': 'worker',
                'auto_start': True
            }

            success = loop.run_until_complete(cluster_manager.add_node(node_config))

            if success:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showinfo("Success", f"Node {node_address} added successfully"))
                    self.schedule_refresh()
            else:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to add node {node_address}"))

            loop.close()
        except Exception as e:
            logger.error(f"Error adding node: {e}")
            if GUI_AVAILABLE:
                self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to add node: {str(e)}"))

    def remove_cluster_node_dialog(self):
        """Show dialog to remove a cluster node."""
        if not GUI_AVAILABLE or not self.nodes_tree:
            return

        try:
            selection = self.nodes_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a node to remove")
                return

            item = self.nodes_tree.item(selection[0])
            node_id = item['values'][0]

            if messagebox.askyesno("Confirm", f"Are you sure you want to remove node {node_id}?"):
                threading.Thread(target=self._remove_node_async, args=(node_id,), daemon=True).start()
        except Exception as e:
            logger.error(f"Error in remove node dialog: {e}")

    def _remove_node_async(self, node_id):
        """Remove node asynchronously."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            success = loop.run_until_complete(cluster_manager.remove_node(node_id))

            if success:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showinfo("Success", f"Node {node_id} removed successfully"))
                    self.schedule_refresh()
            else:
                if GUI_AVAILABLE:
                    self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to remove node {node_id}"))

            loop.close()
        except Exception as e:
            logger.error(f"Error removing node: {e}")
            if GUI_AVAILABLE:
                self.parent_frame.after(0, lambda: messagebox.showerror("Error", f"Failed to remove node: {str(e)}"))

    def refresh_nodes(self):
        """Refresh the nodes display."""
        self.schedule_refresh()

    def toggle_maintenance_mode(self):
        """Toggle maintenance mode for selected node."""
        if not GUI_AVAILABLE:
            return

        messagebox.showinfo("Info", "Maintenance mode toggle functionality will be implemented here")

    def toggle_auto_refresh(self):
        """Toggle auto refresh."""
        if self.auto_refresh_var:
            self.auto_refresh_enabled = self.auto_refresh_var.get()

    def manual_refresh(self):
        """Manually refresh data."""
        self.schedule_refresh()

    def export_cluster_data(self):
        """Export cluster data to file."""
        if not GUI_AVAILABLE:
            return

        try:
            if not self.status_data:
                messagebox.showwarning("Warning", "No data to export")
                return

            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )

            if filename:
                export_data = {
                    'timestamp': from datetime import datetime
datetime = datetime.now().isoformat(),
                    'cluster_status': {
                        'total_nodes': self.status_data.total_nodes,
                        'active_nodes': self.status_data.active_nodes,
                        'offline_nodes': self.status_data.offline_nodes,
                        'cluster_load': self.status_data.cluster_load,
                        'performance_gain': self.status_data.performance_gain,
                        'total_requests': self.status_data.total_requests_processed,
                        'average_response_time': self.status_data.average_response_time
                    },
                    'nodes': [
                        {
                            'node_id': node.node_id,
                            'name': node.name,
                            'status': node.status,
                            'health_score': node.health_score,
                            'cpu_usage': node.cpu_usage,
                            'memory_usage': node.memory_usage,
                            'connections': node.connections,
                            'address': node.address
                        }
                        for node in self.status_data.node_health
                    ]
                }

                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)

                messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")


# Alias for backward compatibility
ClusteringManagementWidget = EnhancedClusteringManagementWidget
