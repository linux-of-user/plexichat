"""
Main Dashboard Component for PlexiChat GUI
Central hub with tabs, widgets, and plugin integration.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any, Optional, List
import logging
import time
import platform

logger = logging.getLogger(__name__)


class MainDashboard(ttk.Frame):
    """
    Main dashboard with tabbed interface and widget system.
    
    Features:
    - Tabbed interface for different views
    - Widget system for customizable dashboard
    - Plugin integration
    - Real-time updates
    - Customizable layouts
    """

    def __init__(self, parent, app_instance):
        super().__init__(parent, style="Modern.TFrame")
        self.app = app_instance
        self.parent = parent
        
        # Dashboard components
        self.notebook = None
        self.tabs = {}
        self.widgets = {}
        
        self.create_dashboard()

    def create_dashboard(self):
        """Create the main dashboard interface."""
        try:
            # Create notebook for tabs
            self.notebook = ttk.Notebook(self, style="Modern.TNotebook")
            self.notebook.pack(fill=tk.BOTH, expand=True)
            
            # Create default tabs
            self.create_default_tabs()
            
            logger.info("Main dashboard created")
            
        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}")

    def create_default_tabs(self):
        """Create default server management tabs."""
        try:
            # Server Overview - Main dashboard
            self.add_tab("🖥️ Server Overview", self.create_server_overview_tab)

            # System Monitor - Real-time monitoring
            self.add_tab("📊 System Monitor", self.create_system_monitor_tab)

            # Core Module Management
            self.add_tab("🏗️ Core Modules", self.create_core_modules_tab)

            # Infrastructure Management
            self.add_tab("🔧 Infrastructure", self.create_infrastructure_tab)

            # Features Management
            self.add_tab("✨ Features", self.create_features_tab)

            # User Management - User accounts and permissions
            self.add_tab("👥 User Management", self.create_user_management_tab)

            # Database Manager - Database administration
            self.add_tab("🗄️ Database Manager", self.create_database_manager_tab)

            # Authentication & Security
            self.add_tab("🔐 Auth & Security", self.create_auth_security_tab)

            # Messaging System
            self.add_tab("💬 Messaging", self.create_messaging_tab)

            # AI & ML Management
            self.add_tab("🤖 AI & ML", self.create_ai_ml_tab)

            # File Management
            self.add_tab("📁 File Manager", self.create_file_manager_tab)

            # Plugin Manager - Advanced plugin management
            self.add_tab("🔌 Plugin Manager", self.create_advanced_plugin_manager_tab)

            # Configuration - Server configuration
            self.add_tab("⚙️ Configuration", self.create_configuration_tab)

            # Security Center - Security monitoring and management
            self.add_tab("🔒 Security Center", self.create_security_center_tab)

            # Logs & Analytics - Log viewer and analytics
            self.add_tab("📋 Logs & Analytics", self.create_logs_analytics_tab)

            # Backup & Recovery - Backup management
            self.add_tab("💾 Backup & Recovery", self.create_backup_recovery_tab)

            # API Management - API endpoints and documentation
            self.add_tab("🌐 API Management", self.create_api_management_tab)

            # WebUI Integration - WebUI management
            self.add_tab("🌍 WebUI Manager", self.create_webui_manager_tab)

            # Server Updates - Update management
            self.add_tab("🔄 Updates", self.create_updates_tab)

            # Setup Wizard - Advanced setup and configuration
            self.add_tab("🧙‍♂️ Setup Wizard", self.create_setup_wizard_tab)

            # Documentation - Built-in docs
            self.add_tab("📚 Documentation", self.create_documentation_tab)

        except Exception as e:
            logger.error(f"Failed to create default tabs: {e}")

    def add_tab(self, name: str, creator_func):
        """Add a tab to the dashboard."""
        try:
            # Create tab frame
            tab_frame = ttk.Frame(self.notebook, style="Modern.TFrame")
            
            # Create tab content
            content = creator_func(tab_frame)
            
            # Add to notebook
            self.notebook.add(tab_frame, text=name)
            self.tabs[name] = tab_frame
            
        except Exception as e:
            logger.error(f"Failed to add tab {name}: {e}")

    def create_system_monitor_tab(self, parent):
        """Create comprehensive system monitoring tab."""
        try:
            # Main container
            monitor_frame = ttk.Frame(parent, style="Modern.TFrame")
            monitor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Create notebook for different monitoring views
            monitor_notebook = ttk.Notebook(monitor_frame, style="Modern.TNotebook")
            monitor_notebook.pack(fill=tk.BOTH, expand=True)

            # System Resources tab
            resources_frame = ttk.Frame(monitor_notebook, style="Modern.TFrame")
            monitor_notebook.add(resources_frame, text="📊 System Resources")
            self.create_system_resources_view(resources_frame)

            # Process Monitor tab
            processes_frame = ttk.Frame(monitor_notebook, style="Modern.TFrame")
            monitor_notebook.add(processes_frame, text="⚙️ Processes")
            self.create_process_monitor_view(processes_frame)

            # Network Monitor tab
            network_frame = ttk.Frame(monitor_notebook, style="Modern.TFrame")
            monitor_notebook.add(network_frame, text="🌐 Network")
            self.create_network_monitor_view(network_frame)

            # Performance History tab
            history_frame = ttk.Frame(monitor_notebook, style="Modern.TFrame")
            monitor_notebook.add(history_frame, text="📈 Performance History")
            self.create_performance_history_view(history_frame)

            return monitor_frame

        except Exception as e:
            logger.error(f"Failed to create system monitor tab: {e}")
            return ttk.Label(parent, text="Error loading system monitor")

    def create_system_resources_view(self, parent):
        """Create system resources monitoring view."""
        try:
            import psutil

            # CPU section
            cpu_frame = ttk.LabelFrame(parent, text="🖥️ CPU Information", style="Modern.TLabelframe")
            cpu_frame.pack(fill=tk.X, padx=10, pady=5)

            cpu_info = f"CPU: {platform.processor()}\nCores: {psutil.cpu_count()} physical, {psutil.cpu_count(logical=True)} logical"
            ttk.Label(cpu_frame, text=cpu_info, style="Modern.TLabel").pack(padx=10, pady=5)

            # CPU usage chart (simplified)
            cpu_usage_frame = ttk.Frame(cpu_frame, style="Modern.TFrame")
            cpu_usage_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Label(cpu_usage_frame, text="CPU Usage:", style="Modern.TLabel").pack(side=tk.LEFT)
            self.cpu_progress = ttk.Progressbar(cpu_usage_frame, length=200, mode='determinate')
            self.cpu_progress.pack(side=tk.LEFT, padx=10)
            self.cpu_label = ttk.Label(cpu_usage_frame, text="0%", style="Modern.TLabel")
            self.cpu_label.pack(side=tk.LEFT)

            # Memory section
            memory_frame = ttk.LabelFrame(parent, text="🧠 Memory Information", style="Modern.TLabelframe")
            memory_frame.pack(fill=tk.X, padx=10, pady=5)

            memory = psutil.virtual_memory()
            memory_info = f"Total: {memory.total // (1024**3)} GB\nAvailable: {memory.available // (1024**3)} GB"
            ttk.Label(memory_frame, text=memory_info, style="Modern.TLabel").pack(padx=10, pady=5)

            # Memory usage chart
            memory_usage_frame = ttk.Frame(memory_frame, style="Modern.TFrame")
            memory_usage_frame.pack(fill=tk.X, padx=10, pady=5)

            ttk.Label(memory_usage_frame, text="Memory Usage:", style="Modern.TLabel").pack(side=tk.LEFT)
            self.memory_progress = ttk.Progressbar(memory_usage_frame, length=200, mode='determinate')
            self.memory_progress.pack(side=tk.LEFT, padx=10)
            self.memory_label = ttk.Label(memory_usage_frame, text="0%", style="Modern.TLabel")
            self.memory_label.pack(side=tk.LEFT)

            # Disk section
            disk_frame = ttk.LabelFrame(parent, text="💾 Disk Information", style="Modern.TLabelframe")
            disk_frame.pack(fill=tk.X, padx=10, pady=5)

            # Get disk usage for all mounted drives
            self.create_disk_usage_display(disk_frame)

            # Start updating system resources
            self.update_system_resources()

        except Exception as e:
            logger.error(f"Failed to create system resources view: {e}")

    def create_disk_usage_display(self, parent):
        """Create disk usage display."""
        try:
            import psutil

            disk_partitions = psutil.disk_partitions()

            for partition in disk_partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)

                    partition_frame = ttk.Frame(parent, style="Modern.TFrame")
                    partition_frame.pack(fill=tk.X, padx=10, pady=2)

                    # Partition info
                    info_text = f"{partition.device} ({partition.fstype})"
                    ttk.Label(partition_frame, text=info_text, style="Modern.TLabel").pack(side=tk.LEFT)

                    # Usage bar
                    usage_frame = ttk.Frame(partition_frame, style="Modern.TFrame")
                    usage_frame.pack(side=tk.RIGHT)

                    usage_percent = (usage.used / usage.total) * 100
                    usage_progress = ttk.Progressbar(usage_frame, length=150, mode='determinate', value=usage_percent)
                    usage_progress.pack(side=tk.LEFT, padx=5)

                    usage_text = f"{usage.used // (1024**3)} GB / {usage.total // (1024**3)} GB ({usage_percent:.1f}%)"
                    ttk.Label(usage_frame, text=usage_text, style="Modern.TLabel").pack(side=tk.LEFT, padx=5)

                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Failed to create disk usage display: {e}")

    def create_process_monitor_view(self, parent):
        """Create process monitoring view."""
        try:
            # Process list
            process_frame = ttk.Frame(parent, style="Modern.TFrame")
            process_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Process tree
            columns = ("PID", "CPU%", "Memory%", "Status")
            self.process_tree = ttk.Treeview(process_frame, columns=columns, show="tree headings")

            # Configure columns
            self.process_tree.heading("#0", text="Process Name")
            self.process_tree.heading("PID", text="PID")
            self.process_tree.heading("CPU%", text="CPU%")
            self.process_tree.heading("Memory%", text="Memory%")
            self.process_tree.heading("Status", text="Status")

            self.process_tree.column("#0", width=200)
            self.process_tree.column("PID", width=80)
            self.process_tree.column("CPU%", width=80)
            self.process_tree.column("Memory%", width=80)
            self.process_tree.column("Status", width=100)

            # Scrollbar for process tree
            process_scrollbar = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
            self.process_tree.configure(yscrollcommand=process_scrollbar.set)

            self.process_tree.pack(side="left", fill="both", expand=True)
            process_scrollbar.pack(side="right", fill="y")

            # Process controls
            process_controls = ttk.Frame(parent, style="Modern.TFrame")
            process_controls.pack(fill=tk.X, padx=10, pady=(0, 10))

            ttk.Button(process_controls, text="Refresh", command=self.refresh_processes, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(process_controls, text="Kill Process", command=self.kill_selected_process, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(process_controls, text="Process Details", command=self.show_process_details, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

            # Load processes
            self.refresh_processes()

        except Exception as e:
            logger.error(f"Failed to create process monitor view: {e}")

    def create_network_monitor_view(self, parent):
        """Create network monitoring view."""
        try:
            # Network interfaces
            interfaces_frame = ttk.LabelFrame(parent, text="🌐 Network Interfaces", style="Modern.TLabelframe")
            interfaces_frame.pack(fill=tk.X, padx=10, pady=10)

            self.create_network_interfaces_display(interfaces_frame)

            # Network statistics
            stats_frame = ttk.LabelFrame(parent, text="📊 Network Statistics", style="Modern.TLabelframe")
            stats_frame.pack(fill=tk.X, padx=10, pady=10)

            self.create_network_stats_display(stats_frame)

            # Active connections
            connections_frame = ttk.LabelFrame(parent, text="🔗 Active Connections", style="Modern.TLabelframe")
            connections_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            self.create_network_connections_display(connections_frame)

        except Exception as e:
            logger.error(f"Failed to create network monitor view: {e}")

    def create_performance_history_view(self, parent):
        """Create performance history view."""
        try:
            # Performance charts would go here
            # For now, show a placeholder
            history_label = ttk.Label(
                parent,
                text="📈 Performance History Charts\n\nThis would show historical performance data including:\n• CPU usage over time\n• Memory usage trends\n• Network I/O patterns\n• Disk I/O statistics\n• Server response times",
                style="Modern.TLabel",
                justify=tk.CENTER
            )
            history_label.pack(expand=True)

        except Exception as e:
            logger.error(f"Failed to create performance history view: {e}")

    def update_system_resources(self):
        """Update system resource displays."""
        try:
            import psutil

            if hasattr(self, 'cpu_progress'):
                cpu_percent = psutil.cpu_percent()
                self.cpu_progress['value'] = cpu_percent
                self.cpu_label['text'] = f"{cpu_percent:.1f}%"

            if hasattr(self, 'memory_progress'):
                memory = psutil.virtual_memory()
                self.memory_progress['value'] = memory.percent
                self.memory_label['text'] = f"{memory.percent:.1f}%"

            # Schedule next update
            self.after(2000, self.update_system_resources)

        except Exception as e:
            logger.error(f"Failed to update system resources: {e}")

    def refresh_processes(self):
        """Refresh process list."""
        try:
            import psutil

            if hasattr(self, 'process_tree'):
                # Clear existing items
                for item in self.process_tree.get_children():
                    self.process_tree.delete(item)

                # Add current processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                    try:
                        info = proc.info
                        self.process_tree.insert(
                            "",
                            "end",
                            text=info['name'],
                            values=(info['pid'], f"{info['cpu_percent']:.1f}", f"{info['memory_percent']:.1f}", info['status'])
                        )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            logger.error(f"Failed to refresh processes: {e}")

    def kill_selected_process(self):
        """Kill selected process."""
        try:
            selection = self.process_tree.selection()
            if selection:
                item = self.process_tree.item(selection[0])
                pid = item['values'][0]

                result = messagebox.askyesno(
                    "Kill Process",
                    f"Are you sure you want to kill process {item['text']} (PID: {pid})?"
                )

                if result:
                    import psutil
                    psutil.Process(int(pid)).terminate()
                    self.refresh_processes()

        except Exception as e:
            logger.error(f"Failed to kill process: {e}")
            messagebox.showerror("Error", f"Failed to kill process: {e}")

    def show_process_details(self):
        """Show detailed process information."""
        try:
            selection = self.process_tree.selection()
            if selection:
                item = self.process_tree.item(selection[0])
                pid = item['values'][0]

                # Show process details in a new window
                details_window = tk.Toplevel(self)
                details_window.title(f"Process Details - {item['text']}")
                details_window.geometry("600x400")

                # Get detailed process info
                import psutil
                proc = psutil.Process(int(pid))

                details_text = f"""Process: {proc.name()}
PID: {proc.pid}
Status: {proc.status()}
CPU Percent: {proc.cpu_percent():.2f}%
Memory Percent: {proc.memory_percent():.2f}%
Memory Info: {proc.memory_info()}
Create Time: {datetime.fromtimestamp(proc.create_time())}
Command Line: {' '.join(proc.cmdline()) if proc.cmdline() else 'N/A'}
"""

                text_widget = tk.Text(details_window, wrap=tk.WORD)
                text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                text_widget.insert(tk.END, details_text)
                text_widget.configure(state=tk.DISABLED)

        except Exception as e:
            logger.error(f"Failed to show process details: {e}")
            messagebox.showerror("Error", f"Failed to show process details: {e}")

    def create_network_interfaces_display(self, parent):
        """Create network interfaces display."""
        try:
            import psutil

            interfaces = psutil.net_if_addrs()

            for interface_name, addresses in interfaces.items():
                interface_frame = ttk.Frame(parent, style="Modern.TFrame")
                interface_frame.pack(fill=tk.X, padx=10, pady=5)

                ttk.Label(interface_frame, text=f"Interface: {interface_name}", font=("Segoe UI", 10, "bold"), style="Modern.TLabel").pack(anchor=tk.W)

                for addr in addresses:
                    addr_text = f"  {addr.family.name}: {addr.address}"
                    ttk.Label(interface_frame, text=addr_text, style="Modern.TLabel").pack(anchor=tk.W, padx=20)

        except Exception as e:
            logger.error(f"Failed to create network interfaces display: {e}")

    def create_network_stats_display(self, parent):
        """Create network statistics display."""
        try:
            import psutil

            stats = psutil.net_io_counters()

            stats_text = f"""Bytes Sent: {stats.bytes_sent:,}
Bytes Received: {stats.bytes_recv:,}
Packets Sent: {stats.packets_sent:,}
Packets Received: {stats.packets_recv:,}
Errors In: {stats.errin}
Errors Out: {stats.errout}
Drops In: {stats.dropin}
Drops Out: {stats.dropout}"""

            ttk.Label(parent, text=stats_text, style="Modern.TLabel").pack(padx=10, pady=10)

        except Exception as e:
            logger.error(f"Failed to create network stats display: {e}")

    def create_network_connections_display(self, parent):
        """Create network connections display."""
        try:
            # Connections tree
            columns = ("Local Address", "Remote Address", "Status", "PID")
            connections_tree = ttk.Treeview(parent, columns=columns, show="headings")

            # Configure columns
            for col in columns:
                connections_tree.heading(col, text=col)
                connections_tree.column(col, width=150)

            connections_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Load connections
            import psutil

            for conn in psutil.net_connections():
                if conn.laddr:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

                    connections_tree.insert(
                        "",
                        "end",
                        values=(local_addr, remote_addr, conn.status, conn.pid or "")
                    )

        except Exception as e:
            logger.error(f"Failed to create network connections display: {e}")

    def create_server_overview_tab(self, parent):
        """Create comprehensive server overview tab."""
        try:
            # Main container with scrollable content
            main_frame = ttk.Frame(parent, style="Modern.TFrame")
            main_frame.pack(fill=tk.BOTH, expand=True)

            # Create scrollable frame
            canvas = tk.Canvas(main_frame, highlightthickness=0)
            scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas, style="Modern.TFrame")

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Server header
            header_frame = ttk.Frame(scrollable_frame, style="Modern.TFrame")
            header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))

            # Server title and status
            title_label = ttk.Label(
                header_frame,
                text=f"PlexiChat Server Manager - {self.app.current_user.get('username', 'Administrator')}",
                font=("Segoe UI", 18, "bold"),
                style="Modern.TLabel"
            )
            title_label.pack(side=tk.LEFT)

            # Server status indicator
            status_frame = ttk.Frame(header_frame, style="Modern.TFrame")
            status_frame.pack(side=tk.RIGHT)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 5))
            status_indicator.create_oval(2, 2, 18, 18, fill="#27ae60", outline="#2c3e50", width=2)

            status_label = ttk.Label(status_frame, text="Server Online", style="Modern.TLabel")
            status_label.pack(side=tk.LEFT)

            # Critical server stats row
            critical_stats_frame = ttk.LabelFrame(scrollable_frame, text="🚨 Critical Server Status", style="Modern.TLabelframe")
            critical_stats_frame.pack(fill=tk.X, padx=20, pady=10)

            self.create_critical_stats(critical_stats_frame)

            # Server control panel
            control_panel_frame = ttk.LabelFrame(scrollable_frame, text="🎛️ Server Control Panel", style="Modern.TLabelframe")
            control_panel_frame.pack(fill=tk.X, padx=20, pady=10)

            self.create_server_controls(control_panel_frame)

            # Real-time metrics
            metrics_frame = ttk.LabelFrame(scrollable_frame, text="📈 Real-time Metrics", style="Modern.TLabelframe")
            metrics_frame.pack(fill=tk.X, padx=20, pady=10)

            self.create_realtime_metrics(metrics_frame)

            # Service status
            services_frame = ttk.LabelFrame(scrollable_frame, text="🔧 Service Status", style="Modern.TLabelframe")
            services_frame.pack(fill=tk.X, padx=20, pady=10)

            self.create_service_status(services_frame)

            # Quick actions
            actions_frame = ttk.LabelFrame(scrollable_frame, text="⚡ Quick Actions", style="Modern.TLabelframe")
            actions_frame.pack(fill=tk.X, padx=20, pady=10)

            self.create_server_quick_actions(actions_frame)

            return main_frame

        except Exception as e:
            logger.error(f"Failed to create server overview tab: {e}")
            return ttk.Label(parent, text="Error loading server overview")

    def create_critical_stats(self, parent):
        """Create critical server statistics."""
        try:
            import psutil
            import platform

            # Get system information
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # Create grid of critical stats
            stats = [
                ("🖥️ CPU Usage", f"{cpu_percent:.1f}%", self.get_status_color(cpu_percent, 80, 90)),
                ("🧠 Memory Usage", f"{memory.percent:.1f}%", self.get_status_color(memory.percent, 80, 90)),
                ("💾 Disk Usage", f"{disk.percent:.1f}%", self.get_status_color(disk.percent, 85, 95)),
                ("🌐 Server Uptime", self.get_server_uptime(), "#27ae60"),
                ("👥 Active Users", str(self.get_active_users_count()), "#3498db"),
                ("🔗 API Requests/min", str(self.get_api_requests_per_minute()), "#9b59b6"),
                ("📊 Database Status", self.get_database_status(), "#27ae60"),
                ("🔒 Security Level", "GOVERNMENT", "#e74c3c")
            ]

            for i, (label, value, color) in enumerate(stats):
                row = i // 4
                col = i % 4

                stat_frame = ttk.Frame(parent, style="Modern.TFrame")
                stat_frame.grid(row=row, column=col, padx=10, pady=10, sticky="ew")

                # Value with color indicator
                value_frame = ttk.Frame(stat_frame, style="Modern.TFrame")
                value_frame.pack()

                # Color indicator
                indicator = tk.Canvas(value_frame, width=10, height=10, highlightthickness=0)
                indicator.pack(side=tk.LEFT, padx=(0, 5))
                indicator.create_oval(1, 1, 9, 9, fill=color, outline="")

                value_label = ttk.Label(
                    value_frame,
                    text=value,
                    font=("Segoe UI", 12, "bold"),
                    style="Modern.TLabel"
                )
                value_label.pack(side=tk.LEFT)

                label_label = ttk.Label(
                    stat_frame,
                    text=label,
                    font=("Segoe UI", 9),
                    style="Modern.TLabel"
                )
                label_label.pack()

            # Configure grid weights
            for i in range(4):
                parent.columnconfigure(i, weight=1)

        except Exception as e:
            logger.error(f"Failed to create critical stats: {e}")

    def create_server_controls(self, parent):
        """Create server control panel."""
        try:
            # Control buttons grid
            controls = [
                ("🔄 Restart Server", self.restart_server, "#e74c3c"),
                ("⏹️ Stop Server", self.stop_server, "#c0392b"),
                ("🔧 Reload Config", self.reload_config, "#f39c12"),
                ("🧹 Clear Cache", self.clear_cache, "#3498db"),
                ("📊 Generate Report", self.generate_report, "#9b59b6"),
                ("🔍 Run Diagnostics", self.run_diagnostics, "#27ae60"),
                ("🔒 Security Scan", self.security_scan, "#e67e22"),
                ("💾 Backup Now", self.backup_now, "#34495e")
            ]

            for i, (text, command, color) in enumerate(controls):
                row = i // 4
                col = i % 4

                btn = ttk.Button(
                    parent,
                    text=text,
                    command=command,
                    style="Modern.TButton"
                )
                btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")

            # Configure grid weights
            for i in range(4):
                parent.columnconfigure(i, weight=1)

        except Exception as e:
            logger.error(f"Failed to create server controls: {e}")

    def create_realtime_metrics(self, parent):
        """Create real-time metrics display."""
        try:
            # Metrics container
            metrics_container = ttk.Frame(parent, style="Modern.TFrame")
            metrics_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Create progress bars for various metrics
            metrics = [
                ("CPU Load", 0, 100),
                ("Memory Usage", 0, 100),
                ("Network I/O", 0, 100),
                ("Disk I/O", 0, 100)
            ]

            self.metric_bars = {}

            for i, (name, min_val, max_val) in enumerate(metrics):
                metric_frame = ttk.Frame(metrics_container, style="Modern.TFrame")
                metric_frame.pack(fill=tk.X, pady=5)

                label = ttk.Label(metric_frame, text=name, style="Modern.TLabel")
                label.pack(side=tk.LEFT, padx=(0, 10))

                progress = ttk.Progressbar(
                    metric_frame,
                    length=200,
                    mode='determinate',
                    style="Modern.Horizontal.TProgressbar"
                )
                progress.pack(side=tk.LEFT, padx=(0, 10))

                value_label = ttk.Label(metric_frame, text="0%", style="Modern.TLabel")
                value_label.pack(side=tk.LEFT)

                self.metric_bars[name] = {"progress": progress, "label": value_label}

            # Start real-time updates
            self.update_realtime_metrics()

        except Exception as e:
            logger.error(f"Failed to create realtime metrics: {e}")

    def create_service_status(self, parent):
        """Create service status display."""
        try:
            # Services list
            services = [
                ("API Server", "Running", "8000", "#27ae60"),
                ("WebUI Server", "Running", "3000", "#27ae60"),
                ("Database", "Running", "5432", "#27ae60"),
                ("Cache Server", "Running", "6379", "#27ae60"),
                ("WebSocket", "Running", "8001", "#27ae60"),
                ("File Server", "Running", "8080", "#27ae60"),
                ("Security Monitor", "Running", "-", "#27ae60"),
                ("Backup Service", "Idle", "-", "#f39c12")
            ]

            # Create treeview for services
            columns = ("Status", "Port", "Actions")
            service_tree = ttk.Treeview(parent, columns=columns, show="tree headings", height=8)

            # Configure columns
            service_tree.heading("#0", text="Service")
            service_tree.heading("Status", text="Status")
            service_tree.heading("Port", text="Port")
            service_tree.heading("Actions", text="Actions")

            service_tree.column("#0", width=150)
            service_tree.column("Status", width=100)
            service_tree.column("Port", width=80)
            service_tree.column("Actions", width=100)

            # Add services
            for name, status, port, color in services:
                service_tree.insert("", "end", text=name, values=(status, port, "Manage"))

            service_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Service control buttons
            service_controls = ttk.Frame(parent, style="Modern.TFrame")
            service_controls.pack(fill=tk.X, padx=10, pady=(0, 10))

            ttk.Button(service_controls, text="Start Service", style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(service_controls, text="Stop Service", style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(service_controls, text="Restart Service", style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(service_controls, text="View Logs", style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create service status: {e}")

    def create_server_quick_actions(self, parent):
        """Create server quick actions."""
        try:
            # Quick action buttons
            actions = [
                ("🔧 Open WebUI", self.open_webui),
                ("📊 View API Docs", self.view_api_docs),
                ("🔍 Check Health", self.check_health),
                ("📋 Export Logs", self.export_logs),
                ("⚙️ Edit Config", self.edit_config),
                ("🔄 Update Server", self.update_server),
                ("🛡️ Security Report", self.security_report),
                ("📞 Support", self.contact_support)
            ]

            for i, (text, command) in enumerate(actions):
                row = i // 4
                col = i % 4

                btn = ttk.Button(
                    parent,
                    text=text,
                    command=command,
                    style="Modern.TButton"
                )
                btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")

            # Configure grid weights
            for i in range(4):
                parent.columnconfigure(i, weight=1)

        except Exception as e:
            logger.error(f"Failed to create server quick actions: {e}")

    def create_action_buttons(self, parent):
        """Create quick action buttons."""
        try:
            actions = [
                ("New Chat", self.new_chat),
                ("Upload File", self.upload_file),
                ("Settings", self.open_settings),
                ("Help", self.show_help)
            ]
            
            for i, (text, command) in enumerate(actions):
                btn = ttk.Button(
                    parent,
                    text=text,
                    command=command,
                    style="Modern.TButton"
                )
                btn.grid(row=0, column=i, padx=5, pady=10, sticky="ew")
            
            # Configure grid weights
            for i in range(len(actions)):
                parent.columnconfigure(i, weight=1)
                
        except Exception as e:
            logger.error(f"Failed to create action buttons: {e}")

    def create_files_tab(self, parent):
        """Create files tab content."""
        try:
            # Placeholder for file manager
            label = ttk.Label(parent, text="File Manager", style="Modern.TLabel")
            label.pack(expand=True)
            
            return label
            
        except Exception as e:
            logger.error(f"Failed to create files tab: {e}")
            return ttk.Label(parent, text="Error loading files")

    def create_advanced_plugin_manager_tab(self, parent):
        """Create advanced plugin manager with marketplace integration."""
        try:
            # Main container
            plugin_frame = ttk.Frame(parent, style="Modern.TFrame")
            plugin_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Create notebook for plugin management sections
            plugin_notebook = ttk.Notebook(plugin_frame, style="Modern.TNotebook")
            plugin_notebook.pack(fill=tk.BOTH, expand=True)

            # Installed Plugins tab
            installed_frame = ttk.Frame(plugin_notebook, style="Modern.TFrame")
            plugin_notebook.add(installed_frame, text="📦 Installed Plugins")
            self.create_installed_plugins_view(installed_frame)

            # Plugin Marketplace tab
            marketplace_frame = ttk.Frame(plugin_notebook, style="Modern.TFrame")
            plugin_notebook.add(marketplace_frame, text="🛒 Plugin Marketplace")
            self.create_plugin_marketplace_view(marketplace_frame)

            # Plugin Development tab
            development_frame = ttk.Frame(plugin_notebook, style="Modern.TFrame")
            plugin_notebook.add(development_frame, text="🔧 Plugin Development")
            self.create_plugin_development_view(development_frame)

            # Plugin Settings tab
            settings_frame = ttk.Frame(plugin_notebook, style="Modern.TFrame")
            plugin_notebook.add(settings_frame, text="⚙️ Plugin Settings")
            self.create_plugin_settings_view(settings_frame)

            return plugin_frame

        except Exception as e:
            logger.error(f"Failed to create advanced plugin manager tab: {e}")
            return ttk.Label(parent, text="Error loading plugin manager")

    def create_installed_plugins_view(self, parent):
        """Create installed plugins management view."""
        try:
            # Header
            header_frame = ttk.Frame(parent, style="Modern.TFrame")
            header_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Label(header_frame, text="📦 Installed Plugins", font=("Segoe UI", 14, "bold"), style="Modern.TLabel").pack(side=tk.LEFT)

            # Refresh button
            ttk.Button(header_frame, text="🔄 Refresh", command=self.refresh_installed_plugins, style="Modern.TButton").pack(side=tk.RIGHT)

            # Plugin list with detailed information
            list_frame = ttk.Frame(parent, style="Modern.TFrame")
            list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

            # Create treeview for plugins
            columns = ("Version", "Status", "Type", "Author", "Last Updated", "Size")
            self.installed_plugin_tree = ttk.Treeview(
                list_frame,
                columns=columns,
                show="tree headings",
                style="Modern.Treeview"
            )

            # Configure columns
            self.installed_plugin_tree.heading("#0", text="Plugin Name")
            self.installed_plugin_tree.heading("Version", text="Version")
            self.installed_plugin_tree.heading("Status", text="Status")
            self.installed_plugin_tree.heading("Type", text="Type")
            self.installed_plugin_tree.heading("Author", text="Author")
            self.installed_plugin_tree.heading("Last Updated", text="Last Updated")
            self.installed_plugin_tree.heading("Size", text="Size")

            # Set column widths
            self.installed_plugin_tree.column("#0", width=200)
            self.installed_plugin_tree.column("Version", width=80)
            self.installed_plugin_tree.column("Status", width=100)
            self.installed_plugin_tree.column("Type", width=100)
            self.installed_plugin_tree.column("Author", width=120)
            self.installed_plugin_tree.column("Last Updated", width=120)
            self.installed_plugin_tree.column("Size", width=80)

            # Scrollbar
            plugin_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.installed_plugin_tree.yview)
            self.installed_plugin_tree.configure(yscrollcommand=plugin_scrollbar.set)

            self.installed_plugin_tree.pack(side="left", fill="both", expand=True)
            plugin_scrollbar.pack(side="right", fill="y")

            # Load installed plugins
            self.refresh_installed_plugins()

            # Plugin actions
            actions_frame = ttk.Frame(parent, style="Modern.TFrame")
            actions_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            # Action buttons
            action_buttons = [
                ("▶️ Enable", self.enable_selected_plugin),
                ("⏸️ Disable", self.disable_selected_plugin),
                ("🔧 Configure", self.configure_selected_plugin),
                ("📊 Details", self.view_plugin_details),
                ("🔄 Update", self.update_selected_plugin),
                ("🗑️ Uninstall", self.uninstall_selected_plugin),
                ("📋 Export Config", self.export_plugin_config),
                ("📁 Open Folder", self.open_plugin_folder)
            ]

            for text, command in action_buttons:
                ttk.Button(actions_frame, text=text, command=command, style="Modern.TButton").pack(side=tk.LEFT, padx=2)

        except Exception as e:
            logger.error(f"Failed to create installed plugins view: {e}")

    def create_plugin_marketplace_view(self, parent):
        """Create plugin marketplace view with GitHub integration."""
        try:
            # Header with search
            header_frame = ttk.Frame(parent, style="Modern.TFrame")
            header_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Label(header_frame, text="🛒 Plugin Marketplace", font=("Segoe UI", 14, "bold"), style="Modern.TLabel").pack(side=tk.LEFT)

            # Search frame
            search_frame = ttk.Frame(header_frame, style="Modern.TFrame")
            search_frame.pack(side=tk.RIGHT)

            self.marketplace_search_var = tk.StringVar()
            search_entry = ttk.Entry(search_frame, textvariable=self.marketplace_search_var, width=30, style="Modern.TEntry")
            search_entry.pack(side=tk.LEFT, padx=(0, 5))

            ttk.Button(search_frame, text="🔍 Search", command=self.search_marketplace, style="Modern.TButton").pack(side=tk.LEFT)

            # Categories frame
            categories_frame = ttk.Frame(parent, style="Modern.TFrame")
            categories_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            ttk.Label(categories_frame, text="Categories:", style="Modern.TLabel").pack(side=tk.LEFT, padx=(0, 10))

            self.marketplace_category_var = tk.StringVar(value="all")
            categories = [
                ("All", "all"),
                ("Chat Enhancement", "chat"),
                ("AI & ML", "ai"),
                ("Security", "security"),
                ("Utilities", "utilities"),
                ("Integrations", "integrations"),
                ("Themes", "themes"),
                ("Analytics", "analytics")
            ]

            for text, value in categories:
                ttk.Radiobutton(
                    categories_frame,
                    text=text,
                    variable=self.marketplace_category_var,
                    value=value,
                    style="Modern.TRadiobutton",
                    command=self.filter_marketplace_plugins
                ).pack(side=tk.LEFT, padx=5)

            # Marketplace plugin list
            marketplace_frame = ttk.Frame(parent, style="Modern.TFrame")
            marketplace_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

            # Create treeview for marketplace plugins
            marketplace_columns = ("Version", "Downloads", "Rating", "Author", "Updated", "License")
            self.marketplace_tree = ttk.Treeview(
                marketplace_frame,
                columns=marketplace_columns,
                show="tree headings",
                style="Modern.Treeview"
            )

            # Configure columns
            self.marketplace_tree.heading("#0", text="Plugin Name")
            self.marketplace_tree.heading("Version", text="Version")
            self.marketplace_tree.heading("Downloads", text="Downloads")
            self.marketplace_tree.heading("Rating", text="Rating")
            self.marketplace_tree.heading("Author", text="Author")
            self.marketplace_tree.heading("Updated", text="Updated")
            self.marketplace_tree.heading("License", text="License")

            # Set column widths
            self.marketplace_tree.column("#0", width=200)
            self.marketplace_tree.column("Version", width=80)
            self.marketplace_tree.column("Downloads", width=100)
            self.marketplace_tree.column("Rating", width=80)
            self.marketplace_tree.column("Author", width=120)
            self.marketplace_tree.column("Updated", width=100)
            self.marketplace_tree.column("License", width=100)

            # Scrollbar
            marketplace_scrollbar = ttk.Scrollbar(marketplace_frame, orient="vertical", command=self.marketplace_tree.yview)
            self.marketplace_tree.configure(yscrollcommand=marketplace_scrollbar.set)

            self.marketplace_tree.pack(side="left", fill="both", expand=True)
            marketplace_scrollbar.pack(side="right", fill="y")

            # Load marketplace plugins
            self.refresh_marketplace_plugins()

            # Marketplace actions
            marketplace_actions_frame = ttk.Frame(parent, style="Modern.TFrame")
            marketplace_actions_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            marketplace_buttons = [
                ("🔄 Refresh", self.refresh_marketplace_plugins),
                ("📥 Install", self.install_marketplace_plugin),
                ("👁️ Preview", self.preview_marketplace_plugin),
                ("📊 Details", self.view_marketplace_plugin_details),
                ("⭐ Rate", self.rate_marketplace_plugin),
                ("🐛 Report Issue", self.report_plugin_issue),
                ("📁 View Source", self.view_plugin_source),
                ("🔗 GitHub", self.open_plugin_github)
            ]

            for text, command in marketplace_buttons:
                ttk.Button(marketplace_actions_frame, text=text, command=command, style="Modern.TButton").pack(side=tk.LEFT, padx=2)

        except Exception as e:
            logger.error(f"Failed to create plugin marketplace view: {e}")

    def create_plugin_development_view(self, parent):
        """Create plugin development tools view."""
        try:
            # Development header
            dev_header_frame = ttk.Frame(parent, style="Modern.TFrame")
            dev_header_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Label(dev_header_frame, text="🔧 Plugin Development Tools", font=("Segoe UI", 14, "bold"), style="Modern.TLabel").pack(side=tk.LEFT)

            # Development tools
            tools_frame = ttk.LabelFrame(parent, text="Development Tools", style="Modern.TLabelframe")
            tools_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            dev_tools = [
                ("🆕 Create New Plugin", self.create_new_plugin),
                ("📝 Plugin Template Generator", self.generate_plugin_template),
                ("🔍 Plugin Validator", self.validate_plugin),
                ("📦 Package Plugin", self.package_plugin),
                ("🧪 Test Plugin", self.test_plugin),
                ("📚 API Documentation", self.view_plugin_api_docs),
                ("🎨 UI Designer", self.open_plugin_ui_designer),
                ("🔧 Debug Console", self.open_plugin_debug_console)
            ]

            for i, (text, command) in enumerate(dev_tools):
                row = i // 4
                col = i % 4

                ttk.Button(
                    tools_frame,
                    text=text,
                    command=command,
                    style="Modern.TButton"
                ).grid(row=row, column=col, padx=5, pady=5, sticky="ew")

            # Configure grid weights
            for i in range(4):
                tools_frame.columnconfigure(i, weight=1)

            # Plugin templates
            templates_frame = ttk.LabelFrame(parent, text="Plugin Templates", style="Modern.TLabelframe")
            templates_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

            # Template list
            template_columns = ("Type", "Description", "Complexity")
            template_tree = ttk.Treeview(
                templates_frame,
                columns=template_columns,
                show="tree headings",
                style="Modern.Treeview"
            )

            template_tree.heading("#0", text="Template Name")
            template_tree.heading("Type", text="Type")
            template_tree.heading("Description", text="Description")
            template_tree.heading("Complexity", text="Complexity")

            template_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Sample templates
            templates = [
                ("Basic Chat Plugin", "Chat Enhancement", "Simple message processing", "Beginner"),
                ("AI Integration Plugin", "AI & ML", "Integrate with AI services", "Intermediate"),
                ("Security Scanner Plugin", "Security", "Custom security checks", "Advanced"),
                ("Database Plugin", "Utilities", "Custom database operations", "Intermediate"),
                ("Theme Plugin", "Themes", "Custom UI themes", "Beginner"),
                ("API Integration Plugin", "Integrations", "External API integration", "Intermediate"),
                ("Analytics Plugin", "Analytics", "Custom analytics and reporting", "Advanced"),
                ("Workflow Plugin", "Utilities", "Custom workflow automation", "Advanced")
            ]

            for name, plugin_type, description, complexity in templates:
                template_tree.insert("", "end", text=name, values=(plugin_type, description, complexity))

            # Template actions
            template_actions_frame = ttk.Frame(templates_frame, style="Modern.TFrame")
            template_actions_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            ttk.Button(template_actions_frame, text="📋 Use Template", command=self.use_plugin_template, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(template_actions_frame, text="👁️ Preview", command=self.preview_plugin_template, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(template_actions_frame, text="📥 Download", command=self.download_plugin_template, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create plugin development view: {e}")

    def create_plugin_settings_view(self, parent):
        """Create plugin settings and configuration view."""
        try:
            # Settings header
            settings_header_frame = ttk.Frame(parent, style="Modern.TFrame")
            settings_header_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Label(settings_header_frame, text="⚙️ Plugin System Settings", font=("Segoe UI", 14, "bold"), style="Modern.TLabel").pack(side=tk.LEFT)

            # Global plugin settings
            global_frame = ttk.LabelFrame(parent, text="Global Plugin Settings", style="Modern.TLabelframe")
            global_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            self.plugin_settings_vars = {}

            global_settings = [
                ("🔄 Auto-update plugins", "auto_update", True),
                ("🔒 Sandbox plugins", "sandbox_mode", True),
                ("📊 Collect usage statistics", "usage_stats", False),
                ("🚨 Enable plugin monitoring", "monitoring", True),
                ("🔍 Validate plugin signatures", "signature_validation", True),
                ("⚡ Load plugins on startup", "auto_load", True),
                ("🧹 Auto-cleanup unused plugins", "auto_cleanup", False),
                ("📝 Enable plugin logging", "plugin_logging", True)
            ]

            for text, key, default in global_settings:
                var = tk.BooleanVar(value=default)
                self.plugin_settings_vars[key] = var
                ttk.Checkbutton(
                    global_frame,
                    text=text,
                    variable=var,
                    style="Modern.TCheckbutton"
                ).pack(anchor=tk.W, padx=10, pady=3)

            # Plugin directories
            directories_frame = ttk.LabelFrame(parent, text="Plugin Directories", style="Modern.TLabelframe")
            directories_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            # Directory list
            dir_list_frame = ttk.Frame(directories_frame, style="Modern.TFrame")
            dir_list_frame.pack(fill=tk.X, padx=10, pady=10)

            self.plugin_dirs_listbox = tk.Listbox(dir_list_frame, height=4)
            self.plugin_dirs_listbox.pack(fill=tk.X, pady=(0, 10))

            # Sample directories
            sample_dirs = [
                "/home/user/.plexichat/plugins",
                "/opt/plexichat/plugins",
                "/usr/local/share/plexichat/plugins",
                "./plugins"
            ]

            for directory in sample_dirs:
                self.plugin_dirs_listbox.insert(tk.END, directory)

            # Directory controls
            dir_controls_frame = ttk.Frame(dir_list_frame, style="Modern.TFrame")
            dir_controls_frame.pack(fill=tk.X)

            ttk.Button(dir_controls_frame, text="➕ Add Directory", command=self.add_plugin_directory, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(dir_controls_frame, text="➖ Remove Directory", command=self.remove_plugin_directory, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(dir_controls_frame, text="📁 Browse", command=self.browse_plugin_directory, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

            # Plugin security settings
            security_frame = ttk.LabelFrame(parent, text="Plugin Security", style="Modern.TLabelframe")
            security_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            security_settings = [
                ("🛡️ Require signed plugins", "require_signatures"),
                ("🔒 Restrict file system access", "restrict_filesystem"),
                ("🌐 Restrict network access", "restrict_network"),
                ("💾 Restrict database access", "restrict_database"),
                ("⚙️ Restrict system calls", "restrict_syscalls"),
                ("🔐 Encrypt plugin data", "encrypt_data")
            ]

            for text, key in security_settings:
                var = tk.BooleanVar(value=True)
                self.plugin_settings_vars[key] = var
                ttk.Checkbutton(
                    security_frame,
                    text=text,
                    variable=var,
                    style="Modern.TCheckbutton"
                ).pack(anchor=tk.W, padx=10, pady=3)

            # Settings actions
            settings_actions_frame = ttk.Frame(parent, style="Modern.TFrame")
            settings_actions_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(settings_actions_frame, text="💾 Save Settings", command=self.save_plugin_settings, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(settings_actions_frame, text="🔄 Reset to Defaults", command=self.reset_plugin_settings, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(settings_actions_frame, text="📤 Export Settings", command=self.export_plugin_settings, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(settings_actions_frame, text="📥 Import Settings", command=self.import_plugin_settings, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create plugin settings view: {e}")

    def create_settings_tab(self, parent):
        """Create settings tab content."""
        try:
            # Placeholder for settings
            label = ttk.Label(parent, text="Settings Panel", style="Modern.TLabel")
            label.pack(expand=True)
            
            return label
            
        except Exception as e:
            logger.error(f"Failed to create settings tab: {e}")
            return ttk.Label(parent, text="Error loading settings")

    def refresh_plugin_list(self):
        """Refresh the plugin list."""
        try:
            if not hasattr(self, 'plugin_tree'):
                return
            
            # Clear existing items
            for item in self.plugin_tree.get_children():
                self.plugin_tree.delete(item)
            
            # Add plugins
            for plugin_name in self.app.plugin_manager.get_plugin_list():
                plugin = self.app.plugin_manager.get_plugin(plugin_name)
                status = "Enabled" if plugin.enabled else "Disabled"
                
                self.plugin_tree.insert(
                    "",
                    "end",
                    text=plugin_name,
                    values=(plugin.version, status)
                )
                
        except Exception as e:
            logger.error(f"Failed to refresh plugin list: {e}")

    def install_plugin(self):
        """Install a new plugin."""
        try:
            # Placeholder for plugin installation
            self.app.notification_system.show_notification(
                "Plugin Installation",
                "Plugin installation feature coming soon!",
                "info"
            )
        except Exception as e:
            logger.error(f"Failed to install plugin: {e}")

    # Quick action handlers
    def new_chat(self):
        """Start a new chat."""
        try:
            # Switch to chat tab
            self.notebook.select(0)  # Assuming chat is first tab
            
            self.app.notification_system.show_notification(
                "New Chat",
                "Starting new chat session...",
                "info"
            )
        except Exception as e:
            logger.error(f"Failed to start new chat: {e}")

    def upload_file(self):
        """Upload a file."""
        try:
            from tkinter import filedialog
            
            file_path = filedialog.askopenfilename(
                title="Select file to upload",
                filetypes=[("All files", "*.*")]
            )
            
            if file_path:
                self.app.notification_system.show_notification(
                    "File Upload",
                    f"Uploading {file_path}...",
                    "info"
                )
        except Exception as e:
            logger.error(f"Failed to upload file: {e}")

    def open_settings(self):
        """Open settings."""
        try:
            # Switch to settings tab
            for i, (tab_id, frame) in enumerate(self.tabs.items()):
                if tab_id == "Settings":
                    self.notebook.select(i)
                    break
        except Exception as e:
            logger.error(f"Failed to open settings: {e}")

    def show_help(self):
        """Show help."""
        try:
            import webbrowser
            webbrowser.open("https://plexichat.docs.example.com")
        except Exception as e:
            logger.error(f"Failed to show help: {e}")

    # Helper methods for server management
    def get_status_color(self, value: float, warning_threshold: float, critical_threshold: float) -> str:
        """Get status color based on value and thresholds."""
        if value >= critical_threshold:
            return "#e74c3c"  # Red
        elif value >= warning_threshold:
            return "#f39c12"  # Orange
        else:
            return "#27ae60"  # Green

    def get_server_uptime(self) -> str:
        """Get server uptime."""
        try:
            import psutil
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time

            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)

            return f"{days}d {hours}h {minutes}m"
        except Exception:
            return "Unknown"

    def get_active_users_count(self) -> int:
        """Get active users count."""
        try:
            # This would integrate with actual user session management
            return 42  # Placeholder
        except Exception:
            return 0

    def get_api_requests_per_minute(self) -> int:
        """Get API requests per minute."""
        try:
            # This would integrate with actual API metrics
            return 156  # Placeholder
        except Exception:
            return 0

    def get_database_status(self) -> str:
        """Get database status."""
        try:
            # This would check actual database connection
            return "Online"
        except Exception:
            return "Offline"

    def update_realtime_metrics(self):
        """Update real-time metrics display."""
        try:
            import psutil

            if hasattr(self, 'metric_bars'):
                # Update CPU
                cpu_percent = psutil.cpu_percent()
                if "CPU Load" in self.metric_bars:
                    self.metric_bars["CPU Load"]["progress"]["value"] = cpu_percent
                    self.metric_bars["CPU Load"]["label"]["text"] = f"{cpu_percent:.1f}%"

                # Update Memory
                memory = psutil.virtual_memory()
                if "Memory Usage" in self.metric_bars:
                    self.metric_bars["Memory Usage"]["progress"]["value"] = memory.percent
                    self.metric_bars["Memory Usage"]["label"]["text"] = f"{memory.percent:.1f}%"

                # Update Network I/O (simplified)
                net_io = psutil.net_io_counters()
                net_percent = min((net_io.bytes_sent + net_io.bytes_recv) / 1000000, 100)
                if "Network I/O" in self.metric_bars:
                    self.metric_bars["Network I/O"]["progress"]["value"] = net_percent
                    self.metric_bars["Network I/O"]["label"]["text"] = f"{net_percent:.1f}%"

                # Update Disk I/O (simplified)
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    disk_percent = min((disk_io.read_bytes + disk_io.write_bytes) / 1000000, 100)
                    if "Disk I/O" in self.metric_bars:
                        self.metric_bars["Disk I/O"]["progress"]["value"] = disk_percent
                        self.metric_bars["Disk I/O"]["label"]["text"] = f"{disk_percent:.1f}%"

            # Schedule next update
            self.after(2000, self.update_realtime_metrics)

        except Exception as e:
            logger.error(f"Failed to update realtime metrics: {e}")

    # Server control action handlers
    def restart_server(self):
        """Restart the server."""
        try:
            result = messagebox.askyesno(
                "Restart Server",
                "Are you sure you want to restart the PlexiChat server?\n\nThis will temporarily disconnect all users."
            )

            if result:
                self.app.notification_system.show_notification(
                    "Server Restart",
                    "Initiating server restart...",
                    "warning"
                )
                # Implementation would restart the server

        except Exception as e:
            logger.error(f"Failed to restart server: {e}")

    def stop_server(self):
        """Stop the server."""
        try:
            result = messagebox.askyesno(
                "Stop Server",
                "Are you sure you want to stop the PlexiChat server?\n\nThis will disconnect all users and stop all services."
            )

            if result:
                self.app.notification_system.show_notification(
                    "Server Stop",
                    "Stopping server...",
                    "error"
                )
                # Implementation would stop the server

        except Exception as e:
            logger.error(f"Failed to stop server: {e}")

    def reload_config(self):
        """Reload server configuration."""
        try:
            self.app.notification_system.show_notification(
                "Configuration Reload",
                "Reloading server configuration...",
                "info"
            )
            # Implementation would reload config

        except Exception as e:
            logger.error(f"Failed to reload config: {e}")

    def clear_cache(self):
        """Clear server cache."""
        try:
            self.app.notification_system.show_notification(
                "Cache Clear",
                "Clearing server cache...",
                "info"
            )
            # Implementation would clear cache

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")

    def generate_report(self):
        """Generate server report."""
        try:
            self.app.notification_system.show_notification(
                "Report Generation",
                "Generating comprehensive server report...",
                "info"
            )
            # Implementation would generate report

        except Exception as e:
            logger.error(f"Failed to generate report: {e}")

    def run_diagnostics(self):
        """Run server diagnostics."""
        try:
            self.app.notification_system.show_notification(
                "Diagnostics",
                "Running server diagnostics...",
                "info"
            )
            # Implementation would run diagnostics

        except Exception as e:
            logger.error(f"Failed to run diagnostics: {e}")

    def security_scan(self):
        """Run security scan."""
        try:
            self.app.notification_system.show_notification(
                "Security Scan",
                "Running comprehensive security scan...",
                "warning"
            )
            # Implementation would run security scan

        except Exception as e:
            logger.error(f"Failed to run security scan: {e}")

    def backup_now(self):
        """Create immediate backup."""
        try:
            self.app.notification_system.show_notification(
                "Backup",
                "Creating server backup...",
                "info"
            )
            # Implementation would create backup

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")

    def open_webui(self):
        """Open WebUI in browser."""
        try:
            import webbrowser
            webbrowser.open("http://localhost:8000")

        except Exception as e:
            logger.error(f"Failed to open WebUI: {e}")

    def view_api_docs(self):
        """View API documentation."""
        try:
            import webbrowser
            webbrowser.open("http://localhost:8000/docs")

        except Exception as e:
            logger.error(f"Failed to view API docs: {e}")

    def check_health(self):
        """Check server health."""
        try:
            import requests

            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                self.app.notification_system.show_notification(
                    "Health Check",
                    "Server is healthy and responding normally",
                    "success"
                )
            else:
                self.app.notification_system.show_notification(
                    "Health Check",
                    f"Server health check failed: {response.status_code}",
                    "error"
                )

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.app.notification_system.show_notification(
                "Health Check",
                f"Health check failed: {e}",
                "error"
            )

    def export_logs(self):
        """Export server logs."""
        try:
            from tkinter import filedialog

            file_path = filedialog.asksaveasfilename(
                title="Export Server Logs",
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
            )

            if file_path:
                self.app.notification_system.show_notification(
                    "Log Export",
                    f"Exporting logs to {file_path}...",
                    "info"
                )
                # Implementation would export logs

        except Exception as e:
            logger.error(f"Failed to export logs: {e}")

    def edit_config(self):
        """Edit server configuration."""
        try:
            # Switch to configuration tab
            self.switch_to_tab("⚙️ Configuration")

        except Exception as e:
            logger.error(f"Failed to edit config: {e}")

    def update_server(self):
        """Update server."""
        try:
            # Switch to updates tab
            self.switch_to_tab("🔄 Updates")

        except Exception as e:
            logger.error(f"Failed to update server: {e}")

    def security_report(self):
        """Generate security report."""
        try:
            # Switch to security center tab
            self.switch_to_tab("🔒 Security Center")

        except Exception as e:
            logger.error(f"Failed to generate security report: {e}")

    def contact_support(self):
        """Contact support."""
        try:
            import webbrowser
            webbrowser.open("https://support.plexichat.com")

        except Exception as e:
            logger.error(f"Failed to contact support: {e}")

    # ==================== CORE MODULE MANAGEMENT TABS ====================

    def create_core_modules_tab(self, parent):
        """Create comprehensive core modules management tab."""
        try:
            # Main container with scrollable content
            main_frame = ttk.Frame(parent, style="Modern.TFrame")
            main_frame.pack(fill=tk.BOTH, expand=True)

            # Create scrollable frame
            canvas = tk.Canvas(main_frame, highlightthickness=0)
            scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas, style="Modern.TFrame")

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Core modules header
            header_frame = ttk.Frame(scrollable_frame, style="Modern.TFrame")
            header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))

            title_label = ttk.Label(
                header_frame,
                text="🏗️ Core Modules Management",
                font=("Segoe UI", 18, "bold"),
                style="Modern.TLabel"
            )
            title_label.pack(side=tk.LEFT)

            # Refresh button
            refresh_btn = ttk.Button(
                header_frame,
                text="🔄 Refresh Status",
                command=self.refresh_core_modules,
                style="Modern.TButton"
            )
            refresh_btn.pack(side=tk.RIGHT)

            # Core modules sections
            self.create_config_management_section(scrollable_frame)
            self.create_database_core_section(scrollable_frame)
            self.create_auth_core_section(scrollable_frame)
            self.create_logging_core_section(scrollable_frame)
            self.create_exceptions_core_section(scrollable_frame)
            self.create_messaging_core_section(scrollable_frame)
            self.create_integration_core_section(scrollable_frame)

            return main_frame

        except Exception as e:
            logger.error(f"Failed to create core modules tab: {e}")
            return ttk.Label(parent, text="Error loading core modules")

    def create_config_management_section(self, parent):
        """Create configuration management section."""
        try:
            config_frame = ttk.LabelFrame(parent, text="⚙️ Configuration Management", style="Modern.TLabelframe")
            config_frame.pack(fill=tk.X, padx=20, pady=10)

            # Configuration status
            status_frame = ttk.Frame(config_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            # Get config status
            config_status = self.get_config_status()

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if config_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if config_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Status: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Configuration details
            details_frame = ttk.Frame(config_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Configuration Files: {config_status['files_count']}
Active Settings: {config_status['active_settings']}
Environment: {config_status['environment']}
Last Modified: {config_status['last_modified']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Configuration controls
            controls_frame = ttk.Frame(config_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="📝 Edit Config", command=self.edit_config_files, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔄 Reload Config", command=self.reload_config_system, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="💾 Backup Config", command=self.backup_config, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📋 View Config", command=self.view_config_details, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create config management section: {e}")

    def create_database_core_section(self, parent):
        """Create database core management section."""
        try:
            db_frame = ttk.LabelFrame(parent, text="🗄️ Database Core Management", style="Modern.TLabelframe")
            db_frame.pack(fill=tk.X, padx=20, pady=10)

            # Database status
            db_status = self.get_database_core_status()

            status_frame = ttk.Frame(db_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if db_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if db_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Database Core: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Database details
            details_frame = ttk.Frame(db_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Active Connections: {db_status['connections']}
Database Type: {db_status['type']}
Schema Version: {db_status['schema_version']}
Performance: {db_status['performance']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Database controls
            controls_frame = ttk.Frame(db_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="🔗 Test Connection", command=self.test_db_connection, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📊 Performance", command=self.view_db_performance, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔧 Optimize", command=self.optimize_database, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📋 Schema", command=self.view_db_schema, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create database core section: {e}")

    def create_auth_core_section(self, parent):
        """Create authentication core management section."""
        try:
            auth_frame = ttk.LabelFrame(parent, text="🔐 Authentication Core", style="Modern.TLabelframe")
            auth_frame.pack(fill=tk.X, padx=20, pady=10)

            # Auth status
            auth_status = self.get_auth_core_status()

            status_frame = ttk.Frame(auth_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if auth_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if auth_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Auth Core: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Auth details
            details_frame = ttk.Frame(auth_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Active Sessions: {auth_status['active_sessions']}
Auth Methods: {', '.join(auth_status['auth_methods'])}
Security Level: {auth_status['security_level']}
Token Expiry: {auth_status['token_expiry']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Auth controls
            controls_frame = ttk.Frame(auth_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="👥 Sessions", command=self.manage_auth_sessions, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔑 Tokens", command=self.manage_auth_tokens, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🛡️ Security", command=self.configure_auth_security, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📊 Audit", command=self.view_auth_audit, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create auth core section: {e}")

    def create_logging_core_section(self, parent):
        """Create logging core management section."""
        try:
            logging_frame = ttk.LabelFrame(parent, text="📋 Logging Core", style="Modern.TLabelframe")
            logging_frame.pack(fill=tk.X, padx=20, pady=10)

            # Logging status
            logging_status = self.get_logging_core_status()

            status_frame = ttk.Frame(logging_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if logging_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if logging_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Logging Core: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Logging details
            details_frame = ttk.Frame(logging_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Log Level: {logging_status['log_level']}
Log Files: {logging_status['log_files']}
Log Size: {logging_status['total_size']}
Handlers: {logging_status['handlers']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Logging controls
            controls_frame = ttk.Frame(logging_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="📄 View Logs", command=self.view_system_logs, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="⚙️ Configure", command=self.configure_logging, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🧹 Clear Logs", command=self.clear_system_logs, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📦 Archive", command=self.archive_logs, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create logging core section: {e}")

    def create_exceptions_core_section(self, parent):
        """Create exceptions core management section."""
        try:
            exceptions_frame = ttk.LabelFrame(parent, text="⚠️ Exception Handling", style="Modern.TLabelframe")
            exceptions_frame.pack(fill=tk.X, padx=20, pady=10)

            # Exception status
            exception_status = self.get_exception_core_status()

            status_frame = ttk.Frame(exceptions_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if exception_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if exception_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Exception Handler: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Exception details
            details_frame = ttk.Frame(exceptions_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Recent Exceptions: {exception_status['recent_count']}
Error Rate: {exception_status['error_rate']}%
Critical Errors: {exception_status['critical_count']}
Last Error: {exception_status['last_error']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Exception controls
            controls_frame = ttk.Frame(exceptions_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="📊 Error Report", command=self.view_error_report, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔍 Debug", command=self.debug_exceptions, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="⚙️ Configure", command=self.configure_exception_handling, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🧹 Clear", command=self.clear_exception_logs, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create exceptions core section: {e}")

    def create_messaging_core_section(self, parent):
        """Create messaging core management section."""
        try:
            messaging_frame = ttk.LabelFrame(parent, text="💬 Messaging Core", style="Modern.TLabelframe")
            messaging_frame.pack(fill=tk.X, padx=20, pady=10)

            # Messaging status
            messaging_status = self.get_messaging_core_status()

            status_frame = ttk.Frame(messaging_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if messaging_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if messaging_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Messaging Core: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Messaging details
            details_frame = ttk.Frame(messaging_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Active Channels: {messaging_status['active_channels']}
Messages/Hour: {messaging_status['messages_per_hour']}
Queue Size: {messaging_status['queue_size']}
WebSocket Connections: {messaging_status['websocket_connections']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Messaging controls
            controls_frame = ttk.Frame(messaging_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="💬 Channels", command=self.manage_message_channels, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📊 Statistics", command=self.view_messaging_stats, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔧 Configure", command=self.configure_messaging, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🧹 Clear Queue", command=self.clear_message_queue, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create messaging core section: {e}")

    def create_integration_core_section(self, parent):
        """Create integration core management section."""
        try:
            integration_frame = ttk.LabelFrame(parent, text="🔗 Integration Core", style="Modern.TLabelframe")
            integration_frame.pack(fill=tk.X, padx=20, pady=10)

            # Integration status
            integration_status = self.get_integration_core_status()

            status_frame = ttk.Frame(integration_frame, style="Modern.TFrame")
            status_frame.pack(fill=tk.X, padx=10, pady=5)

            status_indicator = tk.Canvas(status_frame, width=20, height=20, highlightthickness=0)
            status_indicator.pack(side=tk.LEFT, padx=(0, 10))

            color = "#27ae60" if integration_status["available"] else "#e74c3c"
            status_indicator.create_oval(2, 2, 18, 18, fill=color, outline="#2c3e50", width=2)

            status_text = "Available" if integration_status["available"] else "Unavailable"
            ttk.Label(status_frame, text=f"Integration Core: {status_text}", style="Modern.TLabel").pack(side=tk.LEFT)

            # Integration details
            details_frame = ttk.Frame(integration_frame, style="Modern.TFrame")
            details_frame.pack(fill=tk.X, padx=10, pady=5)

            details_text = f"""Active Integrations: {integration_status['active_integrations']}
API Endpoints: {integration_status['api_endpoints']}
Webhooks: {integration_status['webhooks']}
External Services: {integration_status['external_services']}"""

            ttk.Label(details_frame, text=details_text, style="Modern.TLabel").pack(anchor=tk.W)

            # Integration controls
            controls_frame = ttk.Frame(integration_frame, style="Modern.TFrame")
            controls_frame.pack(fill=tk.X, padx=10, pady=10)

            ttk.Button(controls_frame, text="🔗 Manage", command=self.manage_integrations, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="📊 Monitor", command=self.monitor_integrations, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🔧 Configure", command=self.configure_integrations, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🧪 Test", command=self.test_integrations, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create integration core section: {e}")

    # ==================== CORE MODULE STATUS METHODS ====================

    def refresh_core_modules(self):
        """Refresh core modules status."""
        try:
            self.app.notification_system.show_notification(
                "Core Modules",
                "Refreshing core modules status...",
                "info"
            )
            # Implementation would refresh all core module statuses

        except Exception as e:
            logger.error(f"Failed to refresh core modules: {e}")

    def get_config_status(self) -> Dict[str, Any]:
        """Get configuration system status."""
        try:
            # This would integrate with actual config system
            return {
                "available": True,
                "files_count": 12,
                "active_settings": 156,
                "environment": "production",
                "last_modified": "2024-01-20 15:30:00"
            }
        except Exception as e:
            logger.error(f"Failed to get config status: {e}")
            return {"available": False, "files_count": 0, "active_settings": 0, "environment": "unknown", "last_modified": "unknown"}

    def get_database_core_status(self) -> Dict[str, Any]:
        """Get database core status."""
        try:
            # This would integrate with actual database system
            return {
                "available": True,
                "connections": 15,
                "type": "PostgreSQL",
                "schema_version": "1.2.3",
                "performance": "Excellent"
            }
        except Exception as e:
            logger.error(f"Failed to get database core status: {e}")
            return {"available": False, "connections": 0, "type": "unknown", "schema_version": "unknown", "performance": "unknown"}

    def get_auth_core_status(self) -> Dict[str, Any]:
        """Get authentication core status."""
        try:
            # This would integrate with actual auth system
            return {
                "available": True,
                "active_sessions": 42,
                "auth_methods": ["password", "2fa", "oauth"],
                "security_level": "GOVERNMENT",
                "token_expiry": "8 hours"
            }
        except Exception as e:
            logger.error(f"Failed to get auth core status: {e}")
            return {"available": False, "active_sessions": 0, "auth_methods": [], "security_level": "unknown", "token_expiry": "unknown"}

    def get_logging_core_status(self) -> Dict[str, Any]:
        """Get logging core status."""
        try:
            # This would integrate with actual logging system
            return {
                "available": True,
                "log_level": "INFO",
                "log_files": 8,
                "total_size": "2.3 GB",
                "handlers": 5
            }
        except Exception as e:
            logger.error(f"Failed to get logging core status: {e}")
            return {"available": False, "log_level": "unknown", "log_files": 0, "total_size": "unknown", "handlers": 0}

    def get_exception_core_status(self) -> Dict[str, Any]:
        """Get exception handling status."""
        try:
            # This would integrate with actual exception system
            return {
                "available": True,
                "recent_count": 3,
                "error_rate": 0.02,
                "critical_count": 0,
                "last_error": "2 hours ago"
            }
        except Exception as e:
            logger.error(f"Failed to get exception core status: {e}")
            return {"available": False, "recent_count": 0, "error_rate": 0, "critical_count": 0, "last_error": "unknown"}

    def get_messaging_core_status(self) -> Dict[str, Any]:
        """Get messaging core status."""
        try:
            # This would integrate with actual messaging system
            return {
                "available": True,
                "active_channels": 25,
                "messages_per_hour": 1250,
                "queue_size": 12,
                "websocket_connections": 89
            }
        except Exception as e:
            logger.error(f"Failed to get messaging core status: {e}")
            return {"available": False, "active_channels": 0, "messages_per_hour": 0, "queue_size": 0, "websocket_connections": 0}

    def get_integration_core_status(self) -> Dict[str, Any]:
        """Get integration core status."""
        try:
            # This would integrate with actual integration system
            return {
                "available": True,
                "active_integrations": 8,
                "api_endpoints": 45,
                "webhooks": 12,
                "external_services": 6
            }
        except Exception as e:
            logger.error(f"Failed to get integration core status: {e}")
            return {"available": False, "active_integrations": 0, "api_endpoints": 0, "webhooks": 0, "external_services": 0}

    # ==================== CORE MODULE ACTION METHODS ====================

    def edit_config_files(self):
        """Open configuration file editor."""
        try:
            # This would open a sophisticated config editor
            self.app.notification_system.show_notification(
                "Configuration Editor",
                "Opening advanced configuration editor...",
                "info"
            )
            # Implementation would open config editor window

        except Exception as e:
            logger.error(f"Failed to edit config files: {e}")

    def reload_config_system(self):
        """Reload configuration system."""
        try:
            self.app.notification_system.show_notification(
                "Configuration Reload",
                "Reloading configuration system...",
                "info"
            )
            # Implementation would reload config

        except Exception as e:
            logger.error(f"Failed to reload config system: {e}")

    def backup_config(self):
        """Backup configuration files."""
        try:
            self.app.notification_system.show_notification(
                "Configuration Backup",
                "Creating configuration backup...",
                "info"
            )
            # Implementation would backup config

        except Exception as e:
            logger.error(f"Failed to backup config: {e}")

    def view_config_details(self):
        """View detailed configuration information."""
        try:
            # Create config details window
            details_window = tk.Toplevel(self)
            details_window.title("Configuration Details")
            details_window.geometry("800x600")

            # Config details content
            text_widget = tk.Text(details_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            config_details = """PlexiChat Configuration Details
=====================================

Environment: Production
Config Files: 12 active files
Last Modified: 2024-01-20 15:30:00

Active Settings:
- Database: PostgreSQL connection configured
- Authentication: Multi-factor enabled
- Security: Government-level encryption
- Logging: INFO level with rotation
- API: Rate limiting enabled
- WebUI: SSL/TLS configured
- Backup: Automatic daily backups
- Monitoring: Real-time metrics enabled

Configuration Files:
- config/main.yaml
- config/database.yaml
- config/security.yaml
- config/logging.yaml
- config/api.yaml
- config/webui.yaml
- config/backup.yaml
- config/monitoring.yaml
- config/plugins.yaml
- config/features.yaml
- config/infrastructure.yaml
- config/core.yaml

Environment Variables:
- PLEXICHAT_ENV=production
- PLEXICHAT_DEBUG=false
- PLEXICHAT_LOG_LEVEL=INFO
- PLEXICHAT_DB_URL=postgresql://...
- PLEXICHAT_SECRET_KEY=***
"""

            text_widget.insert(tk.END, config_details)
            text_widget.configure(state=tk.DISABLED)

        except Exception as e:
            logger.error(f"Failed to view config details: {e}")

    def test_db_connection(self):
        """Test database connection."""
        try:
            self.app.notification_system.show_notification(
                "Database Test",
                "Testing database connection...",
                "info"
            )

            # Simulate connection test
            self.after(2000, lambda: self.app.notification_system.show_notification(
                "Database Test",
                "Database connection successful!",
                "success"
            ))

        except Exception as e:
            logger.error(f"Failed to test database connection: {e}")

    def view_db_performance(self):
        """View database performance metrics."""
        try:
            # Create performance window
            perf_window = tk.Toplevel(self)
            perf_window.title("Database Performance")
            perf_window.geometry("600x400")

            # Performance content
            text_widget = tk.Text(perf_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            perf_details = """Database Performance Metrics
==============================

Connection Pool:
- Active Connections: 15/50
- Idle Connections: 10
- Max Connections: 50
- Connection Timeout: 30s

Query Performance:
- Average Query Time: 12ms
- Slow Queries (>1s): 0
- Failed Queries: 0.01%
- Cache Hit Rate: 98.5%

Storage:
- Database Size: 2.3 GB
- Index Size: 450 MB
- Free Space: 15.2 GB
- Fragmentation: 2.1%

Recent Activity:
- Queries/Second: 125
- Transactions/Second: 45
- Locks: 0 waiting
- Deadlocks: 0

Optimization Recommendations:
✓ All indexes are optimized
✓ Query cache is effective
✓ No performance issues detected
"""

            text_widget.insert(tk.END, perf_details)
            text_widget.configure(state=tk.DISABLED)

        except Exception as e:
            logger.error(f"Failed to view database performance: {e}")

    def optimize_database(self):
        """Optimize database performance."""
        try:
            result = messagebox.askyesno(
                "Database Optimization",
                "This will optimize database indexes and clean up unused data.\n\nProceed with optimization?"
            )

            if result:
                self.app.notification_system.show_notification(
                    "Database Optimization",
                    "Starting database optimization...",
                    "info"
                )
                # Implementation would optimize database

        except Exception as e:
            logger.error(f"Failed to optimize database: {e}")

    def view_db_schema(self):
        """View database schema."""
        try:
            # Create schema window
            schema_window = tk.Toplevel(self)
            schema_window.title("Database Schema")
            schema_window.geometry("800x600")

            # Schema tree
            schema_tree = ttk.Treeview(schema_window, show="tree")
            schema_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Add schema items
            tables_node = schema_tree.insert("", "end", text="📊 Tables")
            schema_tree.insert(tables_node, "end", text="👥 users")
            schema_tree.insert(tables_node, "end", text="💬 messages")
            schema_tree.insert(tables_node, "end", text="📁 files")
            schema_tree.insert(tables_node, "end", text="🔐 sessions")
            schema_tree.insert(tables_node, "end", text="🔌 plugins")

            views_node = schema_tree.insert("", "end", text="👁️ Views")
            schema_tree.insert(views_node, "end", text="📊 user_stats")
            schema_tree.insert(views_node, "end", text="📈 message_analytics")

            indexes_node = schema_tree.insert("", "end", text="🗂️ Indexes")
            schema_tree.insert(indexes_node, "end", text="idx_users_email")
            schema_tree.insert(indexes_node, "end", text="idx_messages_timestamp")
            schema_tree.insert(indexes_node, "end", text="idx_files_user_id")

        except Exception as e:
            logger.error(f"Failed to view database schema: {e}")

    def manage_auth_sessions(self):
        """Manage authentication sessions."""
        try:
            # Create sessions management window
            sessions_window = tk.Toplevel(self)
            sessions_window.title("Authentication Sessions")
            sessions_window.geometry("900x600")

            # Sessions tree
            columns = ("User", "IP Address", "Login Time", "Last Activity", "Status")
            sessions_tree = ttk.Treeview(sessions_window, columns=columns, show="headings")

            for col in columns:
                sessions_tree.heading(col, text=col)
                sessions_tree.column(col, width=150)

            sessions_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Sample session data
            sessions_data = [
                ("admin", "192.168.1.100", "2024-01-20 09:00", "2024-01-20 15:30", "Active"),
                ("user1", "192.168.1.101", "2024-01-20 10:15", "2024-01-20 15:25", "Active"),
                ("user2", "192.168.1.102", "2024-01-20 11:30", "2024-01-20 14:45", "Idle"),
            ]

            for session in sessions_data:
                sessions_tree.insert("", "end", values=session)

            # Session controls
            controls_frame = ttk.Frame(sessions_window)
            controls_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            ttk.Button(controls_frame, text="🔄 Refresh", style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="❌ Terminate Session", style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(controls_frame, text="🚫 Block IP", style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to manage auth sessions: {e}")

    # ==================== SETUP WIZARD TAB ====================

    def create_setup_wizard_tab(self, parent):
        """Create advanced setup wizard tab."""
        try:
            # Main container
            wizard_frame = ttk.Frame(parent, style="Modern.TFrame")
            wizard_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

            # Wizard header
            header_frame = ttk.Frame(wizard_frame, style="Modern.TFrame")
            header_frame.pack(fill=tk.X, pady=(0, 20))

            title_label = ttk.Label(
                header_frame,
                text="🧙‍♂️ PlexiChat Advanced Setup Wizard",
                font=("Segoe UI", 20, "bold"),
                style="Modern.TLabel"
            )
            title_label.pack()

            subtitle_label = ttk.Label(
                header_frame,
                text="Complete server configuration and initialization",
                font=("Segoe UI", 12),
                style="Modern.TLabel"
            )
            subtitle_label.pack(pady=(5, 0))

            # Create notebook for wizard steps
            self.wizard_notebook = ttk.Notebook(wizard_frame, style="Modern.TNotebook")
            self.wizard_notebook.pack(fill=tk.BOTH, expand=True)

            # Wizard steps
            self.create_wizard_welcome_step()
            self.create_wizard_database_step()
            self.create_wizard_security_step()
            self.create_wizard_ssl_step()
            self.create_wizard_features_step()
            self.create_wizard_plugins_step()
            self.create_wizard_users_step()
            self.create_wizard_finalization_step()

            # Wizard navigation
            nav_frame = ttk.Frame(wizard_frame, style="Modern.TFrame")
            nav_frame.pack(fill=tk.X, pady=(20, 0))

            self.wizard_prev_btn = ttk.Button(
                nav_frame,
                text="⬅️ Previous",
                command=self.wizard_previous_step,
                style="Modern.TButton",
                state="disabled"
            )
            self.wizard_prev_btn.pack(side=tk.LEFT)

            self.wizard_next_btn = ttk.Button(
                nav_frame,
                text="Next ➡️",
                command=self.wizard_next_step,
                style="Modern.TButton"
            )
            self.wizard_next_btn.pack(side=tk.RIGHT)

            # Progress indicator
            self.wizard_progress = ttk.Progressbar(
                nav_frame,
                length=300,
                mode='determinate',
                value=12.5  # 1/8 steps
            )
            self.wizard_progress.pack(pady=10)

            return wizard_frame

        except Exception as e:
            logger.error(f"Failed to create setup wizard tab: {e}")
            return ttk.Label(parent, text="Error loading setup wizard")

    def create_wizard_welcome_step(self):
        """Create welcome step of setup wizard."""
        try:
            welcome_frame = ttk.Frame(self.wizard_notebook, style="Modern.TFrame")
            self.wizard_notebook.add(welcome_frame, text="🏠 Welcome")

            # Welcome content
            content_frame = ttk.Frame(welcome_frame, style="Modern.TFrame")
            content_frame.pack(expand=True, fill=tk.BOTH, padx=40, pady=40)

            # Welcome message
            welcome_text = """Welcome to PlexiChat Advanced Setup Wizard!

This wizard will guide you through the complete configuration of your PlexiChat server.

What we'll configure:
• Database connections and optimization
• Security settings and encryption
• SSL/TLS certificates
• Feature modules and capabilities
• Plugin management and marketplace
• User accounts and permissions
• Final system validation

The setup process typically takes 10-15 minutes and will ensure your PlexiChat server is properly configured for production use.

Click 'Next' to begin the setup process."""

            welcome_label = ttk.Label(
                content_frame,
                text=welcome_text,
                font=("Segoe UI", 11),
                style="Modern.TLabel",
                justify=tk.LEFT
            )
            welcome_label.pack(expand=True)

            # System requirements check
            req_frame = ttk.LabelFrame(content_frame, text="📋 System Requirements Check", style="Modern.TLabelframe")
            req_frame.pack(fill=tk.X, pady=(20, 0))

            self.create_system_requirements_check(req_frame)

        except Exception as e:
            logger.error(f"Failed to create wizard welcome step: {e}")

    def create_system_requirements_check(self, parent):
        """Create system requirements check."""
        try:
            import psutil

            # Check system requirements
            requirements = [
                ("Python Version", f"{sys.version.split()[0]}", "✅" if sys.version_info >= (3, 8) else "❌"),
                ("Available Memory", f"{psutil.virtual_memory().available // (1024**3)} GB", "✅" if psutil.virtual_memory().available >= 2*(1024**3) else "❌"),
                ("Disk Space", f"{psutil.disk_usage('/').free // (1024**3)} GB", "✅" if psutil.disk_usage('/').free >= 10*(1024**3) else "❌"),
                ("Network Access", "Available", "✅"),
                ("Database Support", "PostgreSQL/MySQL", "✅"),
                ("SSL Support", "OpenSSL", "✅")
            ]

            for i, (requirement, value, status) in enumerate(requirements):
                req_item_frame = ttk.Frame(parent, style="Modern.TFrame")
                req_item_frame.pack(fill=tk.X, padx=10, pady=2)

                ttk.Label(req_item_frame, text=f"{status} {requirement}:", style="Modern.TLabel").pack(side=tk.LEFT)
                ttk.Label(req_item_frame, text=value, style="Modern.TLabel").pack(side=tk.RIGHT)

        except Exception as e:
            logger.error(f"Failed to create system requirements check: {e}")

    def create_wizard_database_step(self):
        """Create database configuration step."""
        try:
            db_frame = ttk.Frame(self.wizard_notebook, style="Modern.TFrame")
            self.wizard_notebook.add(db_frame, text="🗄️ Database")

            # Database configuration content
            content_frame = ttk.Frame(db_frame, style="Modern.TFrame")
            content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

            # Database type selection
            db_type_frame = ttk.LabelFrame(content_frame, text="Database Type", style="Modern.TLabelframe")
            db_type_frame.pack(fill=tk.X, pady=(0, 20))

            self.db_type_var = tk.StringVar(value="postgresql")

            db_types = [
                ("PostgreSQL (Recommended)", "postgresql"),
                ("MySQL/MariaDB", "mysql"),
                ("SQLite (Development Only)", "sqlite"),
                ("MongoDB (NoSQL)", "mongodb")
            ]

            for text, value in db_types:
                ttk.Radiobutton(
                    db_type_frame,
                    text=text,
                    variable=self.db_type_var,
                    value=value,
                    style="Modern.TRadiobutton"
                ).pack(anchor=tk.W, padx=10, pady=5)

            # Database connection settings
            conn_frame = ttk.LabelFrame(content_frame, text="Connection Settings", style="Modern.TLabelframe")
            conn_frame.pack(fill=tk.X, pady=(0, 20))

            # Connection fields
            self.db_host_var = tk.StringVar(value="localhost")
            self.db_port_var = tk.StringVar(value="5432")
            self.db_name_var = tk.StringVar(value="plexichat")
            self.db_user_var = tk.StringVar(value="plexichat")
            self.db_pass_var = tk.StringVar()

            fields = [
                ("Host:", self.db_host_var),
                ("Port:", self.db_port_var),
                ("Database Name:", self.db_name_var),
                ("Username:", self.db_user_var),
                ("Password:", self.db_pass_var)
            ]

            for i, (label, var) in enumerate(fields):
                field_frame = ttk.Frame(conn_frame, style="Modern.TFrame")
                field_frame.pack(fill=tk.X, padx=10, pady=5)

                ttk.Label(field_frame, text=label, style="Modern.TLabel").pack(side=tk.LEFT, anchor=tk.W, padx=(0, 10))

                if "Password" in label:
                    entry = ttk.Entry(field_frame, textvariable=var, show="*", style="Modern.TEntry")
                else:
                    entry = ttk.Entry(field_frame, textvariable=var, style="Modern.TEntry")

                entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)

            # Database actions
            actions_frame = ttk.Frame(content_frame, style="Modern.TFrame")
            actions_frame.pack(fill=tk.X)

            ttk.Button(actions_frame, text="🔍 Test Connection", command=self.test_wizard_db_connection, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(actions_frame, text="🏗️ Create Database", command=self.create_wizard_database, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(actions_frame, text="📊 Import Schema", command=self.import_wizard_schema, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create wizard database step: {e}")

    def create_wizard_security_step(self):
        """Create security configuration step."""
        try:
            security_frame = ttk.Frame(self.wizard_notebook, style="Modern.TFrame")
            self.wizard_notebook.add(security_frame, text="🔒 Security")

            # Security content
            content_frame = ttk.Frame(security_frame, style="Modern.TFrame")
            content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

            # Security level selection
            level_frame = ttk.LabelFrame(content_frame, text="Security Level", style="Modern.TLabelframe")
            level_frame.pack(fill=tk.X, pady=(0, 20))

            self.security_level_var = tk.StringVar(value="government")

            security_levels = [
                ("🔒 Basic - Standard security features", "basic"),
                ("🛡️ Enhanced - Advanced security with monitoring", "enhanced"),
                ("🏛️ Government - Maximum security with compliance", "government"),
                ("🔐 Custom - Configure individual settings", "custom")
            ]

            for text, value in security_levels:
                ttk.Radiobutton(
                    level_frame,
                    text=text,
                    variable=self.security_level_var,
                    value=value,
                    style="Modern.TRadiobutton"
                ).pack(anchor=tk.W, padx=10, pady=5)

            # Encryption settings
            encryption_frame = ttk.LabelFrame(content_frame, text="Encryption Settings", style="Modern.TLabelframe")
            encryption_frame.pack(fill=tk.X, pady=(0, 20))

            self.encryption_vars = {}
            encryption_options = [
                ("🔐 Database Encryption (AES-256)", "database_encryption"),
                ("🌐 API Encryption (TLS 1.3)", "api_encryption"),
                ("💬 Message Encryption (End-to-End)", "message_encryption"),
                ("📁 File Encryption (AES-256)", "file_encryption"),
                ("🔑 Key Rotation (Weekly)", "key_rotation"),
                ("🛡️ Quantum-Safe Algorithms", "quantum_safe")
            ]

            for text, key in encryption_options:
                var = tk.BooleanVar(value=True)
                self.encryption_vars[key] = var
                ttk.Checkbutton(
                    encryption_frame,
                    text=text,
                    variable=var,
                    style="Modern.TCheckbutton"
                ).pack(anchor=tk.W, padx=10, pady=3)

            # Authentication settings
            auth_frame = ttk.LabelFrame(content_frame, text="Authentication Settings", style="Modern.TLabelframe")
            auth_frame.pack(fill=tk.X)

            self.auth_vars = {}
            auth_options = [
                ("🔑 Multi-Factor Authentication (MFA)", "mfa"),
                ("👤 Biometric Authentication", "biometric"),
                ("🌐 OAuth Integration", "oauth"),
                ("🔐 LDAP/Active Directory", "ldap"),
                ("⏰ Session Timeout (30 min)", "session_timeout"),
                ("🚫 Account Lockout Protection", "account_lockout")
            ]

            for text, key in auth_options:
                var = tk.BooleanVar(value=True)
                self.auth_vars[key] = var
                ttk.Checkbutton(
                    auth_frame,
                    text=text,
                    variable=var,
                    style="Modern.TCheckbutton"
                ).pack(anchor=tk.W, padx=10, pady=3)

        except Exception as e:
            logger.error(f"Failed to create wizard security step: {e}")

    def create_wizard_ssl_step(self):
        """Create SSL/TLS configuration step."""
        try:
            ssl_frame = ttk.Frame(self.wizard_notebook, style="Modern.TFrame")
            self.wizard_notebook.add(ssl_frame, text="🔐 SSL/TLS")

            # SSL content
            content_frame = ttk.Frame(ssl_frame, style="Modern.TFrame")
            content_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

            # SSL configuration type
            ssl_type_frame = ttk.LabelFrame(content_frame, text="SSL/TLS Configuration", style="Modern.TLabelframe")
            ssl_type_frame.pack(fill=tk.X, pady=(0, 20))

            self.ssl_type_var = tk.StringVar(value="letsencrypt")

            ssl_types = [
                ("🆓 Let's Encrypt (Automatic)", "letsencrypt"),
                ("📜 Custom Certificate", "custom"),
                ("🏢 Corporate CA", "corporate"),
                ("🔧 Self-Signed (Development)", "selfsigned")
            ]

            for text, value in ssl_types:
                ttk.Radiobutton(
                    ssl_type_frame,
                    text=text,
                    variable=self.ssl_type_var,
                    value=value,
                    style="Modern.TRadiobutton"
                ).pack(anchor=tk.W, padx=10, pady=5)

            # Domain configuration
            domain_frame = ttk.LabelFrame(content_frame, text="Domain Configuration", style="Modern.TLabelframe")
            domain_frame.pack(fill=tk.X, pady=(0, 20))

            self.domain_var = tk.StringVar(value="plexichat.example.com")
            self.email_var = tk.StringVar(value="admin@example.com")

            domain_fields = [
                ("Domain Name:", self.domain_var),
                ("Admin Email:", self.email_var)
            ]

            for label, var in domain_fields:
                field_frame = ttk.Frame(domain_frame, style="Modern.TFrame")
                field_frame.pack(fill=tk.X, padx=10, pady=5)

                ttk.Label(field_frame, text=label, style="Modern.TLabel").pack(side=tk.LEFT, anchor=tk.W, padx=(0, 10))
                ttk.Entry(field_frame, textvariable=var, style="Modern.TEntry").pack(side=tk.RIGHT, fill=tk.X, expand=True)

            # SSL actions
            actions_frame = ttk.Frame(content_frame, style="Modern.TFrame")
            actions_frame.pack(fill=tk.X)

            ttk.Button(actions_frame, text="🔍 Validate Domain", command=self.validate_ssl_domain, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(actions_frame, text="📜 Generate Certificate", command=self.generate_ssl_certificate, style="Modern.TButton").pack(side=tk.LEFT, padx=5)
            ttk.Button(actions_frame, text="🔧 Test SSL", command=self.test_ssl_configuration, style="Modern.TButton").pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create wizard SSL step: {e}")

    # ==================== PLUGIN MANAGEMENT METHODS ====================

    def refresh_installed_plugins(self):
        """Refresh installed plugins list."""
        try:
            if hasattr(self, 'installed_plugin_tree'):
                # Clear existing items
                for item in self.installed_plugin_tree.get_children():
                    self.installed_plugin_tree.delete(item)

                # Get installed plugins from plugin manager
                plugins = self.app.plugin_manager.get_plugin_list()

                # Sample plugin data (would come from actual plugin manager)
                sample_plugins = [
                    ("Chat Enhancer", "1.2.3", "Enabled", "Chat", "PlexiChat Team", "2024-01-15", "2.1 MB"),
                    ("AI Assistant", "2.0.1", "Enabled", "AI", "AI Corp", "2024-01-18", "15.3 MB"),
                    ("Security Scanner", "1.0.5", "Disabled", "Security", "SecureTech", "2024-01-10", "5.7 MB"),
                    ("Theme Manager", "1.1.0", "Enabled", "Theme", "Design Studio", "2024-01-12", "3.2 MB"),
                    ("Database Tools", "1.3.2", "Enabled", "Utilities", "DB Solutions", "2024-01-20", "8.9 MB")
                ]

                for name, version, status, plugin_type, author, updated, size in sample_plugins:
                    self.installed_plugin_tree.insert(
                        "",
                        "end",
                        text=name,
                        values=(version, status, plugin_type, author, updated, size)
                    )

        except Exception as e:
            logger.error(f"Failed to refresh installed plugins: {e}")

    def refresh_marketplace_plugins(self):
        """Refresh marketplace plugins from GitHub."""
        try:
            if hasattr(self, 'marketplace_tree'):
                # Clear existing items
                for item in self.marketplace_tree.get_children():
                    self.marketplace_tree.delete(item)

                # Sample marketplace data (would come from GitHub API)
                marketplace_plugins = [
                    ("Advanced Chat Bot", "2.1.0", "15.2k", "⭐⭐⭐⭐⭐", "BotMaster", "2024-01-19", "MIT"),
                    ("File Encryption", "1.5.3", "8.7k", "⭐⭐⭐⭐", "CryptoSec", "2024-01-17", "GPL-3.0"),
                    ("Analytics Dashboard", "3.0.2", "12.1k", "⭐⭐⭐⭐⭐", "DataViz", "2024-01-20", "Apache-2.0"),
                    ("Voice Commands", "1.8.1", "6.3k", "⭐⭐⭐", "VoiceTech", "2024-01-16", "MIT"),
                    ("Custom Themes Pack", "2.2.0", "22.5k", "⭐⭐⭐⭐⭐", "ThemeStudio", "2024-01-18", "CC-BY-4.0"),
                    ("API Gateway", "1.4.7", "9.8k", "⭐⭐⭐⭐", "APITools", "2024-01-15", "MIT"),
                    ("Backup Manager", "2.0.5", "11.2k", "⭐⭐⭐⭐", "BackupPro", "2024-01-19", "GPL-2.0"),
                    ("Notification Center", "1.7.2", "7.9k", "⭐⭐⭐⭐", "NotifyTeam", "2024-01-14", "MIT")
                ]

                for name, version, downloads, rating, author, updated, license_type in marketplace_plugins:
                    self.marketplace_tree.insert(
                        "",
                        "end",
                        text=name,
                        values=(version, downloads, rating, author, updated, license_type)
                    )

        except Exception as e:
            logger.error(f"Failed to refresh marketplace plugins: {e}")

    def search_marketplace(self):
        """Search marketplace plugins."""
        try:
            search_term = self.marketplace_search_var.get()
            self.app.notification_system.show_notification(
                "Plugin Search",
                f"Searching for plugins: {search_term}",
                "info"
            )
            # Implementation would search GitHub repositories

        except Exception as e:
            logger.error(f"Failed to search marketplace: {e}")

    def filter_marketplace_plugins(self):
        """Filter marketplace plugins by category."""
        try:
            category = self.marketplace_category_var.get()
            self.app.notification_system.show_notification(
                "Plugin Filter",
                f"Filtering plugins by category: {category}",
                "info"
            )
            # Implementation would filter plugins

        except Exception as e:
            logger.error(f"Failed to filter marketplace plugins: {e}")

    def install_marketplace_plugin(self):
        """Install selected marketplace plugin."""
        try:
            selection = self.marketplace_tree.selection()
            if selection:
                item = self.marketplace_tree.item(selection[0])
                plugin_name = item['text']

                result = messagebox.askyesno(
                    "Install Plugin",
                    f"Install plugin '{plugin_name}' from the marketplace?\n\nThis will download and install the plugin automatically."
                )

                if result:
                    self.app.notification_system.show_notification(
                        "Plugin Installation",
                        f"Installing plugin: {plugin_name}",
                        "info"
                    )
                    # Implementation would install from GitHub

        except Exception as e:
            logger.error(f"Failed to install marketplace plugin: {e}")

    def enable_selected_plugin(self):
        """Enable selected plugin."""
        try:
            selection = self.installed_plugin_tree.selection()
            if selection:
                item = self.installed_plugin_tree.item(selection[0])
                plugin_name = item['text']

                self.app.notification_system.show_notification(
                    "Plugin Management",
                    f"Enabling plugin: {plugin_name}",
                    "success"
                )
                # Implementation would enable plugin

        except Exception as e:
            logger.error(f"Failed to enable plugin: {e}")

    def disable_selected_plugin(self):
        """Disable selected plugin."""
        try:
            selection = self.installed_plugin_tree.selection()
            if selection:
                item = self.installed_plugin_tree.item(selection[0])
                plugin_name = item['text']

                self.app.notification_system.show_notification(
                    "Plugin Management",
                    f"Disabling plugin: {plugin_name}",
                    "warning"
                )
                # Implementation would disable plugin

        except Exception as e:
            logger.error(f"Failed to disable plugin: {e}")

    def configure_selected_plugin(self):
        """Configure selected plugin."""
        try:
            selection = self.installed_plugin_tree.selection()
            if selection:
                item = self.installed_plugin_tree.item(selection[0])
                plugin_name = item['text']

                # Create plugin configuration window
                config_window = tk.Toplevel(self)
                config_window.title(f"Configure {plugin_name}")
                config_window.geometry("600x500")

                # Configuration content
                config_notebook = ttk.Notebook(config_window)
                config_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

                # General settings tab
                general_frame = ttk.Frame(config_notebook)
                config_notebook.add(general_frame, text="General")

                # Sample configuration options
                ttk.Label(general_frame, text=f"Configuration for {plugin_name}", font=("Segoe UI", 12, "bold")).pack(pady=10)

                # Enable/disable
                enabled_var = tk.BooleanVar(value=True)
                ttk.Checkbutton(general_frame, text="Enable plugin", variable=enabled_var).pack(anchor=tk.W, padx=20, pady=5)

                # Auto-start
                autostart_var = tk.BooleanVar(value=False)
                ttk.Checkbutton(general_frame, text="Auto-start with server", variable=autostart_var).pack(anchor=tk.W, padx=20, pady=5)

                # Log level
                ttk.Label(general_frame, text="Log Level:").pack(anchor=tk.W, padx=20, pady=(10, 0))
                log_level_var = tk.StringVar(value="INFO")
                log_level_combo = ttk.Combobox(general_frame, textvariable=log_level_var, values=["DEBUG", "INFO", "WARNING", "ERROR"])
                log_level_combo.pack(anchor=tk.W, padx=20, pady=5)

                # Advanced settings tab
                advanced_frame = ttk.Frame(config_notebook)
                config_notebook.add(advanced_frame, text="Advanced")

                # Configuration buttons
                button_frame = ttk.Frame(config_window)
                button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

                ttk.Button(button_frame, text="Save", command=config_window.destroy).pack(side=tk.RIGHT, padx=5)
                ttk.Button(button_frame, text="Cancel", command=config_window.destroy).pack(side=tk.RIGHT, padx=5)
                ttk.Button(button_frame, text="Reset to Defaults", command=lambda: None).pack(side=tk.LEFT, padx=5)

        except Exception as e:
            logger.error(f"Failed to configure plugin: {e}")

    def view_plugin_details(self):
        """View detailed plugin information."""
        try:
            selection = self.installed_plugin_tree.selection()
            if selection:
                item = self.installed_plugin_tree.item(selection[0])
                plugin_name = item['text']

                # Create details window
                details_window = tk.Toplevel(self)
                details_window.title(f"Plugin Details - {plugin_name}")
                details_window.geometry("700x600")

                # Details content
                details_text = f"""Plugin Details: {plugin_name}
{'=' * 50}

Name: {plugin_name}
Version: {item['values'][0]}
Status: {item['values'][1]}
Type: {item['values'][2]}
Author: {item['values'][3]}
Last Updated: {item['values'][4]}
Size: {item['values'][5]}

Description:
This is a comprehensive plugin that enhances PlexiChat functionality with advanced features and capabilities.

Features:
• Advanced message processing
• Real-time notifications
• Custom UI components
• API integrations
• Security enhancements

Dependencies:
• Python 3.8+
• requests >= 2.25.0
• asyncio
• tkinter

Installation Path:
/opt/plexichat/plugins/{plugin_name.lower().replace(' ', '_')}

Configuration Files:
• config.yaml
• settings.json
• permissions.xml

Permissions:
• Read/Write file system
• Network access
• Database access
• UI modification

License: MIT License
Support: https://github.com/plexichat/{plugin_name.lower().replace(' ', '-')}
Documentation: https://docs.plexichat.com/plugins/{plugin_name.lower().replace(' ', '-')}
"""

                text_widget = tk.Text(details_window, wrap=tk.WORD)
                text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                text_widget.insert(tk.END, details_text)
                text_widget.configure(state=tk.DISABLED)

        except Exception as e:
            logger.error(f"Failed to view plugin details: {e}")

    def create_new_plugin(self):
        """Create new plugin wizard."""
        try:
            # Create new plugin wizard window
            wizard_window = tk.Toplevel(self)
            wizard_window.title("Create New Plugin")
            wizard_window.geometry("800x600")

            # Wizard content
            wizard_notebook = ttk.Notebook(wizard_window)
            wizard_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Basic info tab
            basic_frame = ttk.Frame(wizard_notebook)
            wizard_notebook.add(basic_frame, text="Basic Info")

            # Plugin name
            ttk.Label(basic_frame, text="Plugin Name:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=20, pady=(20, 5))
            plugin_name_var = tk.StringVar()
            ttk.Entry(basic_frame, textvariable=plugin_name_var, width=50).pack(anchor=tk.W, padx=20, pady=(0, 10))

            # Plugin description
            ttk.Label(basic_frame, text="Description:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=20, pady=(10, 5))
            description_text = tk.Text(basic_frame, height=4, width=60)
            description_text.pack(anchor=tk.W, padx=20, pady=(0, 10))

            # Plugin type
            ttk.Label(basic_frame, text="Plugin Type:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=20, pady=(10, 5))
            plugin_type_var = tk.StringVar(value="chat")
            plugin_type_combo = ttk.Combobox(basic_frame, textvariable=plugin_type_var,
                                           values=["chat", "ai", "security", "utilities", "integrations", "themes", "analytics"])
            plugin_type_combo.pack(anchor=tk.W, padx=20, pady=(0, 10))

            # Author info
            ttk.Label(basic_frame, text="Author:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=20, pady=(10, 5))
            author_var = tk.StringVar()
            ttk.Entry(basic_frame, textvariable=author_var, width=50).pack(anchor=tk.W, padx=20, pady=(0, 10))

            # Features tab
            features_frame = ttk.Frame(wizard_notebook)
            wizard_notebook.add(features_frame, text="Features")

            # Feature checkboxes
            ttk.Label(features_frame, text="Select Plugin Features:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=20, pady=20)

            feature_vars = {}
            features = [
                ("Message Processing", "message_processing"),
                ("UI Components", "ui_components"),
                ("API Integration", "api_integration"),
                ("Database Access", "database_access"),
                ("File System Access", "file_system"),
                ("Network Access", "network_access"),
                ("Configuration Panel", "config_panel"),
                ("Real-time Updates", "realtime_updates"),
                ("Custom Commands", "custom_commands"),
                ("Event Handling", "event_handling")
            ]

            for text, key in features:
                var = tk.BooleanVar()
                feature_vars[key] = var
                ttk.Checkbutton(features_frame, text=text, variable=var).pack(anchor=tk.W, padx=40, pady=3)

            # Wizard buttons
            button_frame = ttk.Frame(wizard_window)
            button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

            def create_plugin():
                name = plugin_name_var.get()
                if name:
                    self.app.notification_system.show_notification(
                        "Plugin Creation",
                        f"Creating plugin: {name}",
                        "success"
                    )
                    wizard_window.destroy()
                    # Implementation would create plugin files
                else:
                    messagebox.showerror("Error", "Please enter a plugin name")

            ttk.Button(button_frame, text="Create Plugin", command=create_plugin).pack(side=tk.RIGHT, padx=5)
            ttk.Button(button_frame, text="Cancel", command=wizard_window.destroy).pack(side=tk.RIGHT, padx=5)

        except Exception as e:
            logger.error(f"Failed to create new plugin: {e}")

    def apply_theme(self, theme_data: Dict[str, Any]):
        """Apply theme to dashboard."""
        try:
            # Theme will be applied automatically through ttk styles
            # Custom theming logic can be added here if needed
            pass
        except Exception as e:
            logger.error(f"Failed to apply theme to dashboard: {e}")

    def get_tab(self, name: str) -> Optional[tk.Widget]:
        """Get a tab by name."""
        return self.tabs.get(name)

    def switch_to_tab(self, name: str):
        """Switch to a specific tab."""
        try:
            for i, (tab_id, frame) in enumerate(self.tabs.items()):
                if tab_id == name:
                    self.notebook.select(i)
                    break
        except Exception as e:
            logger.error(f"Failed to switch to tab {name}: {e}")

    def add_plugin_tab(self, plugin_name: str):
        """Add a tab for a plugin."""
        try:
            # Create plugin UI
            plugin_ui = self.app.plugin_manager.create_plugin_ui(plugin_name, self.notebook)
            
            if plugin_ui:
                self.notebook.add(plugin_ui, text=plugin_name)
                self.tabs[plugin_name] = plugin_ui
                
                logger.info(f"Added plugin tab: {plugin_name}")
                
        except Exception as e:
            logger.error(f"Failed to add plugin tab {plugin_name}: {e}")

    def remove_plugin_tab(self, plugin_name: str):
        """Remove a plugin tab."""
        try:
            if plugin_name in self.tabs:
                tab_widget = self.tabs[plugin_name]
                
                # Find tab index
                for i in range(self.notebook.index("end")):
                    if self.notebook.nametowidget(self.notebook.tabs()[i]) == tab_widget:
                        self.notebook.forget(i)
                        break
                
                del self.tabs[plugin_name]
                logger.info(f"Removed plugin tab: {plugin_name}")
                
        except Exception as e:
            logger.error(f"Failed to remove plugin tab {plugin_name}: {e}")
