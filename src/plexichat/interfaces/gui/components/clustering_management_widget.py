"""
Clustering Management GUI Widget
Comprehensive GUI component for cluster management, load balancing, and failover.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
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
    
    class simpledialog:
        @staticmethod
        def askstring(*args, **kwargs): return ""

from ...clustering import cluster_manager
from ...core.exceptions import PlexiChatException

logger = logging.getLogger(__name__)


@dataclass
class ClusterSystemStatus:
    """Cluster system status information."""
    total_nodes: int
    active_nodes: int
    cluster_load: float
    performance_gain: float
    failover_events: int
    last_failover: Optional[datetime]
    node_health: List[Dict[str, Any]]
    load_balancer_stats: Dict[str, Any]


class ClusteringManagementWidget:
    """GUI widget for clustering management."""
    
    def __init__(self, parent_frame: tk.Frame):
        """Initialize clustering management widget."""
        self.parent_frame = parent_frame
        self.status_data: Optional[ClusterSystemStatus] = None
        self.refresh_interval = 30000  # 30 seconds
        self.auto_refresh_enabled = True
        
        # GUI components
        self.main_frame = None
        self.notebook = None
        self.overview_frame = None
        self.nodes_frame = None
        self.performance_frame = None
        self.loadbalancer_frame = None
        self.failover_frame = None
        
        # Status widgets
        self.total_nodes_label = None
        self.active_nodes_label = None
        self.cluster_load_label = None
        self.performance_gain_label = None
        
        # Node widgets
        self.nodes_tree = None
        self.add_node_button = None
        
        # Charts
        self.performance_chart = None
        self.topology_chart = None
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
                text="Clustering Management",
                font=("Arial", 16, "bold")
            )
            title_label.pack(pady=(0, 10))
            
            # Create notebook for tabs
            self.notebook = ttk.Notebook(self.main_frame)
            self.notebook.pack(fill=tk.BOTH, expand=True)
            
            # Setup tabs
            self.setup_overview_tab()
            self.setup_nodes_tab()
            self.setup_performance_tab()
            self.setup_loadbalancer_tab()
            self.setup_failover_tab()
            
            # Control buttons
            self.setup_control_buttons()
            
        except Exception as e:
            logger.error(f"Error setting up clustering management GUI: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("GUI Error", f"Failed to setup clustering management interface: {str(e)}")
    
    def setup_overview_tab(self):
        """Set up the cluster overview tab."""
        self.overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.overview_frame, text="Cluster Overview")
        
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
        
        # Topology visualization frame
        topology_frame = ttk.LabelFrame(self.overview_frame, text="Cluster Topology", padding=10)
        topology_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create topology canvas
        if GUI_AVAILABLE:
            try:
                self.topology_chart = Figure(figsize=(8, 6), dpi=100)
                self.topology_canvas = FigureCanvasTkAgg(self.topology_chart, topology_frame)
                self.topology_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            except Exception as e:
                logger.warning(f"Could not create topology chart: {e}")
                ttk.Label(topology_frame, text="Topology visualization not available").pack()
    
    def setup_nodes_tab(self):
        """Set up the cluster nodes tab."""
        self.nodes_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.nodes_frame, text="Cluster Nodes")
        
        # Node controls
        control_frame = ttk.Frame(self.nodes_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.add_node_button = ttk.Button(
            control_frame,
            text="Add Node",
            command=self.add_cluster_node_dialog
        )
        self.add_node_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Remove Node",
            command=self.remove_cluster_node_dialog
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            control_frame,
            text="Refresh Nodes",
            command=self.refresh_nodes
        ).pack(side=tk.LEFT)
        
        # Nodes list
        nodes_list_frame = ttk.LabelFrame(self.nodes_frame, text="Cluster Nodes", padding=10)
        nodes_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for nodes
        node_columns = ("ID", "Name", "Type", "Address", "Status", "Load", "Performance")
        self.nodes_tree = ttk.Treeview(nodes_list_frame, columns=node_columns, show="headings", height=12)
        
        # Configure columns
        for col in node_columns:
            self.nodes_tree.heading(col, text=col)
            self.nodes_tree.column(col, width=100)
        
        # Scrollbar for nodes tree
        nodes_scrollbar = ttk.Scrollbar(nodes_list_frame, orient=tk.VERTICAL, command=self.nodes_tree.yview)
        self.nodes_tree.configure(yscrollcommand=nodes_scrollbar.set)
        
        self.nodes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        nodes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Node context menu
        self.setup_node_context_menu()
    
    def setup_performance_tab(self):
        """Set up the performance monitoring tab."""
        self.performance_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.performance_frame, text="Performance")
        
        # Performance metrics
        metrics_frame = ttk.LabelFrame(self.performance_frame, text="Real-time Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Performance chart
        chart_frame = ttk.LabelFrame(self.performance_frame, text="Performance History", padding=10)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        if GUI_AVAILABLE:
            try:
                self.performance_chart = Figure(figsize=(10, 6), dpi=100)
                self.chart_canvas = FigureCanvasTkAgg(self.performance_chart, chart_frame)
                self.chart_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            except Exception as e:
                logger.warning(f"Could not create performance chart: {e}")
                ttk.Label(chart_frame, text="Performance chart not available").pack()
    
    def setup_loadbalancer_tab(self):
        """Set up the load balancer tab."""
        self.loadbalancer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.loadbalancer_frame, text="Load Balancer")
        
        # Load balancer configuration
        config_frame = ttk.LabelFrame(self.loadbalancer_frame, text="Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Algorithm selection
        ttk.Label(config_frame, text="Balancing Algorithm:").grid(row=0, column=0, sticky="w", pady=2)
        self.algorithm_combo = ttk.Combobox(config_frame, values=[
            "ai_optimized", "round_robin", "least_connections", "weighted_round_robin", "ip_hash"
        ])
        self.algorithm_combo.set("ai_optimized")
        self.algorithm_combo.grid(row=0, column=1, padx=(10, 0), pady=2)
        
        # Health check interval
        ttk.Label(config_frame, text="Health Check Interval (s):").grid(row=1, column=0, sticky="w", pady=2)
        self.health_check_entry = ttk.Entry(config_frame)
        self.health_check_entry.insert(0, "30")
        self.health_check_entry.grid(row=1, column=1, padx=(10, 0), pady=2)
        
        # Update button
        ttk.Button(
            config_frame,
            text="Update Configuration",
            command=self.update_load_balancer_config
        ).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Load balancer statistics
        stats_frame = ttk.LabelFrame(self.loadbalancer_frame, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=10, wrap=tk.WORD)
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=stats_scrollbar.set)
        
        self.stats_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_failover_tab(self):
        """Set up the failover management tab."""
        self.failover_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.failover_frame, text="Failover")
        
        # Failover configuration
        config_frame = ttk.LabelFrame(self.failover_frame, text="Failover Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Enable failover
        self.failover_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            config_frame,
            text="Enable Automatic Failover",
            variable=self.failover_enabled_var
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=2)
        
        # Failure threshold
        ttk.Label(config_frame, text="Failure Threshold:").grid(row=1, column=0, sticky="w", pady=2)
        self.failure_threshold_entry = ttk.Entry(config_frame)
        self.failure_threshold_entry.insert(0, "3")
        self.failure_threshold_entry.grid(row=1, column=1, padx=(10, 0), pady=2)
        
        # Recovery timeout
        ttk.Label(config_frame, text="Recovery Timeout (s):").grid(row=2, column=0, sticky="w", pady=2)
        self.recovery_timeout_entry = ttk.Entry(config_frame)
        self.recovery_timeout_entry.insert(0, "300")
        self.recovery_timeout_entry.grid(row=2, column=1, padx=(10, 0), pady=2)
        
        # Update button
        ttk.Button(
            config_frame,
            text="Update Failover Settings",
            command=self.update_failover_config
        ).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Failover history
        history_frame = ttk.LabelFrame(self.failover_frame, text="Failover History", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for failover events
        failover_columns = ("Timestamp", "Node", "Event Type", "Reason", "Recovery Time")
        self.failover_tree = ttk.Treeview(history_frame, columns=failover_columns, show="headings", height=10)
        
        # Configure columns
        for col in failover_columns:
            self.failover_tree.heading(col, text=col)
            self.failover_tree.column(col, width=120)
        
        # Scrollbar for failover tree
        failover_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.failover_tree.yview)
        self.failover_tree.configure(yscrollcommand=failover_scrollbar.set)
        
        self.failover_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        failover_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
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
            text="Test Failover",
            command=self.test_failover_dialog
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Hot Update",
            command=self.hot_update_dialog
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            button_frame,
            text="Auto Refresh",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        ).pack(side=tk.RIGHT)
    
    def setup_node_context_menu(self):
        """Set up context menu for nodes."""
        if not GUI_AVAILABLE:
            return
        
        self.node_context_menu = tk.Menu(self.parent_frame, tearoff=0)
        self.node_context_menu.add_command(label="View Details", command=self.view_node_details)
        self.node_context_menu.add_command(label="Enable Maintenance", command=self.toggle_node_maintenance)
        self.node_context_menu.add_separator()
        self.node_context_menu.add_command(label="Remove Node", command=self.remove_selected_node)
        
        def show_context_menu(event):
            try:
                self.node_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.node_context_menu.grab_release()
        
        self.nodes_tree.bind("<Button-3>", show_context_menu)  # Right click
    
    async def load_cluster_status(self) -> Optional[ClusterSystemStatus]:
        """Load cluster system status."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()
            
            overview = await cluster_manager.get_cluster_overview()
            health = await cluster_manager.get_cluster_health()
            lb_stats = await cluster_manager.get_load_balancer_stats()
            
            return ClusterSystemStatus(
                total_nodes=overview.total_nodes,
                active_nodes=overview.active_nodes,
                cluster_load=overview.cluster_load_percentage,
                performance_gain=overview.performance_improvement_percentage,
                failover_events=overview.total_failover_events,
                last_failover=overview.last_failover_timestamp,
                node_health=[
                    {
                        "node_id": node.node_id,
                        "status": node.status.value,
                        "health_score": node.health_score,
                        "cpu_usage": node.cpu_usage_percentage,
                        "memory_usage": node.memory_usage_percentage,
                        "connections": node.current_connections
                    }
                    for node in health.node_health_status
                ],
                load_balancer_stats={
                    "total_requests": lb_stats.total_requests,
                    "requests_per_second": lb_stats.current_rps,
                    "average_response_time": lb_stats.average_response_time_ms,
                    "node_distribution": lb_stats.node_request_distribution
                }
            )
        except Exception as e:
            logger.error(f"Error loading cluster status: {e}")
            return None

    def update_status_display(self):
        """Update the status display with current data."""
        if not self.status_data or not GUI_AVAILABLE:
            return

        try:
            # Update overview labels
            if self.total_nodes_label:
                self.total_nodes_label.config(text=str(self.status_data.total_nodes))

            if self.active_nodes_label:
                self.active_nodes_label.config(text=str(self.status_data.active_nodes))
                color = "green" if self.status_data.active_nodes > 0 else "red"
                self.active_nodes_label.config(foreground=color)

            if self.cluster_load_label:
                self.cluster_load_label.config(text=f"{self.status_data.cluster_load:.1f}%")
                color = "red" if self.status_data.cluster_load > 80 else "orange" if self.status_data.cluster_load > 60 else "green"
                self.cluster_load_label.config(foreground=color)

            if self.performance_gain_label:
                self.performance_gain_label.config(text=f"{self.status_data.performance_gain:.1f}%")

            # Update nodes tree
            if self.nodes_tree:
                # Clear existing items
                for item in self.nodes_tree.get_children():
                    self.nodes_tree.delete(item)

                # Add node health data
                for node in self.status_data.node_health:
                    self.nodes_tree.insert("", tk.END, values=(
                        node["node_id"][:8] + "...",
                        f"Node-{node['node_id'][:4]}",
                        "Main",  # Would be determined from actual node data
                        "192.168.1.100:8080",  # Would be from actual node data
                        node["status"],
                        f"{node.get('cpu_usage', 0):.1f}%",
                        f"{node['health_score']:.1f}"
                    ))

            # Update load balancer stats
            if hasattr(self, 'stats_text') and self.stats_text:
                self.stats_text.delete("1.0", tk.END)
                stats = self.status_data.load_balancer_stats
                stats_text = f"""Load Balancer Statistics:

Total Requests: {stats.get('total_requests', 0):,}
Requests per Second: {stats.get('requests_per_second', 0):.2f}
Average Response Time: {stats.get('average_response_time', 0):.2f} ms

Node Distribution:
"""
                for node_id, count in stats.get('node_distribution', {}).items():
                    stats_text += f"  {node_id}: {count:,} requests\n"

                self.stats_text.insert("1.0", stats_text)

            # Update charts
            self.update_topology_chart()
            self.update_performance_chart()

        except Exception as e:
            logger.error(f"Error updating status display: {e}")

    def update_topology_chart(self):
        """Update the topology visualization chart."""
        if not self.topology_chart or not hasattr(self, 'topology_canvas'):
            return

        try:
            self.topology_chart.clear()
            ax = self.topology_chart.add_subplot(111)

            if self.status_data and self.status_data.node_health:
                # Create a simple network topology visualization
                import numpy as np

                # Position nodes in a circle
                num_nodes = len(self.status_data.node_health)
                angles = np.linspace(0, 2*np.pi, num_nodes, endpoint=False)

                x_positions = np.cos(angles)
                y_positions = np.sin(angles)

                # Color nodes based on status
                colors = []
                for node in self.status_data.node_health:
                    if node["status"] == "ONLINE":
                        colors.append("green")
                    elif node["status"] == "WARNING":
                        colors.append("orange")
                    else:
                        colors.append("red")

                # Plot nodes
                ax.scatter(x_positions, y_positions, c=colors, s=200, alpha=0.7)

                # Add node labels
                for i, node in enumerate(self.status_data.node_health):
                    ax.annotate(f"Node-{node['node_id'][:4]}",
                              (x_positions[i], y_positions[i]),
                              xytext=(5, 5), textcoords='offset points',
                              fontsize=8)

                # Draw connections (simplified - connect all nodes to center)
                center_x, center_y = 0, 0
                for i in range(num_nodes):
                    ax.plot([center_x, x_positions[i]], [center_y, y_positions[i]],
                           'b-', alpha=0.3, linewidth=1)

                ax.set_xlim(-1.5, 1.5)
                ax.set_ylim(-1.5, 1.5)
                ax.set_aspect('equal')
                ax.set_title('Cluster Topology')
                ax.axis('off')

            if hasattr(self, 'topology_canvas'):
                self.topology_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating topology chart: {e}")

    def update_performance_chart(self):
        """Update the performance chart."""
        if not self.performance_chart or not self.chart_canvas:
            return

        try:
            self.performance_chart.clear()
            ax = self.performance_chart.add_subplot(111)

            if self.status_data:
                # Create sample performance data (in real implementation, this would be historical data)
                import numpy as np

                time_points = np.arange(0, 60, 5)  # Last 60 minutes, every 5 minutes
                performance_data = np.random.normal(self.status_data.performance_gain, 5, len(time_points))
                load_data = np.random.normal(self.status_data.cluster_load, 10, len(time_points))

                ax.plot(time_points, performance_data, 'g-', label='Performance Gain (%)', linewidth=2)
                ax.plot(time_points, load_data, 'b-', label='Cluster Load (%)', linewidth=2)

                ax.set_xlabel('Time (minutes ago)')
                ax.set_ylabel('Percentage')
                ax.set_title('Cluster Performance Over Time')
                ax.legend()
                ax.grid(True, alpha=0.3)

            self.chart_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating performance chart: {e}")

    def refresh_all_data(self):
        """Refresh all cluster data."""
        asyncio.create_task(self._refresh_all_data())

    async def _refresh_all_data(self):
        """Async method to refresh all data."""
        try:
            self.status_data = await self.load_cluster_status()
            if GUI_AVAILABLE:
                self.parent_frame.after(0, self.update_status_display)
        except Exception as e:
            logger.error(f"Error refreshing cluster data: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Refresh Error", f"Failed to refresh cluster data: {str(e)}")

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

    # Dialog and action methods
    def add_cluster_node_dialog(self):
        """Show add cluster node dialog."""
        if not GUI_AVAILABLE:
            return

        dialog = tk.Toplevel(self.parent_frame)
        dialog.title("Add Cluster Node")
        dialog.geometry("400x350")
        dialog.transient(self.parent_frame)
        dialog.grab_set()

        # Node name
        ttk.Label(dialog, text="Node Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=40)
        name_entry.pack(pady=5)

        # Node address
        ttk.Label(dialog, text="Node Address (host:port):").pack(pady=5)
        address_entry = ttk.Entry(dialog, width=40)
        address_entry.pack(pady=5)

        # Node type
        ttk.Label(dialog, text="Node Type:").pack(pady=5)
        type_combo = ttk.Combobox(dialog, values=["main", "gateway", "antivirus", "backup"])
        type_combo.set("main")
        type_combo.pack(pady=5)

        # Max connections
        ttk.Label(dialog, text="Max Connections:").pack(pady=5)
        connections_entry = ttk.Entry(dialog, width=40)
        connections_entry.insert(0, "1000")
        connections_entry.pack(pady=5)

        # Options
        encrypt_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Enable Encrypted Communication", variable=encrypt_var).pack(pady=2)

        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)

        def add_node():
            asyncio.create_task(self._add_cluster_node(
                name_entry.get(),
                address_entry.get(),
                type_combo.get(),
                int(connections_entry.get() or 1000),
                encrypt_var.get()
            ))
            dialog.destroy()

        ttk.Button(button_frame, text="Add Node", command=add_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    async def _add_cluster_node(self, name: str, address: str, node_type: str, max_connections: int, encrypt: bool):
        """Add a cluster node."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            from ...clustering.core.cluster_manager import NodeType

            node_type_enum = NodeType(node_type.upper())

            node = await cluster_manager.add_node(
                name=name,
                address=address,
                node_type=node_type_enum,
                encryption_enabled=encrypt,
                max_connections=max_connections
            )

            if GUI_AVAILABLE:
                messagebox.showinfo("Success", f"Node added successfully: {node.node_id}")

            # Refresh data
            await self._refresh_all_data()

        except Exception as e:
            logger.error(f"Error adding cluster node: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to add cluster node: {str(e)}")

    def remove_cluster_node_dialog(self):
        """Show remove cluster node dialog."""
        if not GUI_AVAILABLE:
            return

        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node to remove")
            return

        item = self.nodes_tree.item(selection[0])
        node_id = item['values'][0].replace("...", "")  # Remove truncation

        if messagebox.askyesno("Confirm", f"Are you sure you want to remove node {node_id}?"):
            asyncio.create_task(self._remove_cluster_node(node_id))

    async def _remove_cluster_node(self, node_id: str):
        """Remove a cluster node."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            success = await cluster_manager.remove_node(node_id, force=False)

            if success:
                if GUI_AVAILABLE:
                    messagebox.showinfo("Success", f"Node {node_id} removed successfully")
                await self._refresh_all_data()
            else:
                if GUI_AVAILABLE:
                    messagebox.showerror("Error", f"Failed to remove node {node_id}")

        except Exception as e:
            logger.error(f"Error removing cluster node: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to remove cluster node: {str(e)}")

    def refresh_nodes(self):
        """Refresh nodes list."""
        self.refresh_all_data()

    def update_load_balancer_config(self):
        """Update load balancer configuration."""
        asyncio.create_task(self._update_load_balancer_config())

    async def _update_load_balancer_config(self):
        """Async method to update load balancer configuration."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            from ...clustering.core.load_balancer import LoadBalancingAlgorithm

            algorithm = LoadBalancingAlgorithm(self.algorithm_combo.get().upper())
            health_check_interval = int(self.health_check_entry.get())

            await cluster_manager.update_load_balancer_config(
                algorithm=algorithm,
                health_check_interval=health_check_interval,
                failure_threshold=3,  # Default
                sticky_sessions_enabled=False  # Default
            )

            if GUI_AVAILABLE:
                messagebox.showinfo("Success", "Load balancer configuration updated")

            await self._refresh_all_data()

        except Exception as e:
            logger.error(f"Error updating load balancer config: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to update load balancer config: {str(e)}")

    def update_failover_config(self):
        """Update failover configuration."""
        asyncio.create_task(self._update_failover_config())

    async def _update_failover_config(self):
        """Async method to update failover configuration."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            enabled = self.failover_enabled_var.get()
            failure_threshold = int(self.failure_threshold_entry.get())
            recovery_timeout = int(self.recovery_timeout_entry.get())

            await cluster_manager.update_failover_config(
                enabled=enabled,
                health_check_interval=30,  # Default
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout
            )

            if GUI_AVAILABLE:
                messagebox.showinfo("Success", "Failover configuration updated")

            await self._refresh_all_data()

        except Exception as e:
            logger.error(f"Error updating failover config: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to update failover config: {str(e)}")

    def test_failover_dialog(self):
        """Show test failover dialog."""
        if not GUI_AVAILABLE:
            return

        # Get selected node or ask for node ID
        selection = self.nodes_tree.selection()
        if selection:
            item = self.nodes_tree.item(selection[0])
            node_id = item['values'][0].replace("...", "")
        else:
            node_id = simpledialog.askstring("Test Failover", "Enter node ID to test failover:")
            if not node_id:
                return

        if messagebox.askyesno("Confirm", f"Test failover for node {node_id}?"):
            asyncio.create_task(self._test_failover(node_id))

    async def _test_failover(self, node_id: str):
        """Test failover for a node."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            result = await cluster_manager.test_failover(node_id)

            if GUI_AVAILABLE:
                message = f"Failover test completed for {node_id}\n"
                message += f"Success: {result.success}\n"
                message += f"Failover time: {result.failover_time_ms}ms\n"
                message += f"Recovery time: {result.recovery_time_ms}ms"
                messagebox.showinfo("Failover Test Result", message)

        except Exception as e:
            logger.error(f"Error testing failover: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to test failover: {str(e)}")

    def hot_update_dialog(self):
        """Show hot update dialog."""
        if not GUI_AVAILABLE:
            return

        update_package = simpledialog.askstring("Hot Update", "Enter update package path or URL:")
        if not update_package:
            return

        if messagebox.askyesno("Confirm", f"Perform hot update with package: {update_package}?"):
            asyncio.create_task(self._perform_hot_update(update_package))

    async def _perform_hot_update(self, update_package: str):
        """Perform hot update."""
        try:
            if not cluster_manager.initialized:
                await cluster_manager.initialize()

            result = await cluster_manager.perform_hot_update(
                update_package=update_package,
                target_nodes=None,  # All nodes
                rollback_on_failure=True
            )

            if GUI_AVAILABLE:
                message = f"Hot update initiated\n"
                message += f"Update ID: {result.update_id}\n"
                message += f"Target nodes: {len(result.target_nodes)}\n"
                message += f"Estimated completion: {result.estimated_completion}"
                messagebox.showinfo("Hot Update", message)

        except Exception as e:
            logger.error(f"Error performing hot update: {e}")
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to perform hot update: {str(e)}")

    # Context menu methods
    def view_node_details(self):
        """View details of selected node."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Node details functionality would be implemented here")

    def toggle_node_maintenance(self):
        """Toggle maintenance mode for selected node."""
        if GUI_AVAILABLE:
            messagebox.showinfo("Info", "Node maintenance toggle functionality would be implemented here")

    def remove_selected_node(self):
        """Remove selected node."""
        self.remove_cluster_node_dialog()


def create_clustering_management_widget(parent_frame: tk.Frame) -> ClusteringManagementWidget:
    """Create and return a clustering management widget."""
    return ClusteringManagementWidget(parent_frame)
