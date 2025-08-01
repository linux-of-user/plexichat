"""
Performance Monitor Plugin

Advanced system monitoring with real-time metrics, alerts, and performance optimization suggestions.
"""

import asyncio
import json
import logging
import psutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Fallback definitions for plugin interface
class PluginInterface:
    def get_metadata(self) -> Dict[str, Any]:
        return {}

class PluginMetadata:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class PluginType:
    MONITORING = "monitoring"

class ModulePermissions:
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

class ModuleCapability:
    SYSTEM_MONITORING = "system_monitoring"

logger = logging.getLogger(__name__)


class SystemMetrics(BaseModel):
    """System metrics model."""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    disk_usage: Dict[str, float]
    network_io: Dict[str, int]
    process_count: int
    uptime: float


class PerformanceMonitorCore:
    """Core performance monitoring functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.monitoring_interval = config.get('monitoring_interval', 5)
        self.alert_thresholds = config.get('alert_thresholds', {})
        self.data_retention_days = config.get('data_retention_days', 30)
        self.metrics_history = []
        self.alerts = []
        self.monitoring_active = False
        
    async def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": (usage.used / usage.total) * 100
                    }
                except PermissionError:
                    continue
            
            # Network metrics
            network_io = psutil.net_io_counters()
            network_stats = {
                "bytes_sent": network_io.bytes_sent,
                "bytes_recv": network_io.bytes_recv,
                "packets_sent": network_io.packets_sent,
                "packets_recv": network_io.packets_recv
            }
            
            # Process metrics
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            top_processes = sorted(processes, key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]
            
            # System uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq._asdict() if cpu_freq else None
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                },
                "swap": {
                    "total": swap.total,
                    "used": swap.used,
                    "free": swap.free,
                    "percent": swap.percent
                },
                "disk": disk_usage,
                "network": network_stats,
                "processes": {
                    "total": len(processes),
                    "top_cpu": [
                        {
                            "pid": p.info['pid'],
                            "name": p.info['name'],
                            "cpu_percent": p.info['cpu_percent'],
                            "memory_percent": p.info['memory_percent']
                        }
                        for p in top_processes[:5]
                    ]
                },
                "uptime": uptime
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            raise
    
    async def check_alerts(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for alert conditions."""
        alerts = []
        
        try:
            # CPU alert
            cpu_threshold = self.alert_thresholds.get('cpu_usage', 80)
            if metrics['cpu']['percent'] > cpu_threshold:
                alerts.append({
                    "type": "cpu_high",
                    "severity": "warning",
                    "message": f"High CPU usage: {metrics['cpu']['percent']:.1f}%",
                    "value": metrics['cpu']['percent'],
                    "threshold": cpu_threshold,
                    "timestamp": metrics['timestamp']
                })
            
            # Memory alert
            memory_threshold = self.alert_thresholds.get('memory_usage', 85)
            if metrics['memory']['percent'] > memory_threshold:
                alerts.append({
                    "type": "memory_high",
                    "severity": "warning",
                    "message": f"High memory usage: {metrics['memory']['percent']:.1f}%",
                    "value": metrics['memory']['percent'],
                    "threshold": memory_threshold,
                    "timestamp": metrics['timestamp']
                })
            
            # Disk alerts
            disk_threshold = self.alert_thresholds.get('disk_usage', 90)
            for mount, usage in metrics['disk'].items():
                if usage['percent'] > disk_threshold:
                    alerts.append({
                        "type": "disk_high",
                        "severity": "critical",
                        "message": f"High disk usage on {mount}: {usage['percent']:.1f}%",
                        "value": usage['percent'],
                        "threshold": disk_threshold,
                        "mount": mount,
                        "timestamp": metrics['timestamp']
                    })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
            return []
    
    async def get_optimization_suggestions(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate performance optimization suggestions."""
        suggestions = []
        
        try:
            # High CPU suggestions
            if metrics['cpu']['percent'] > 70:
                suggestions.append({
                    "category": "cpu",
                    "priority": "high",
                    "title": "High CPU Usage Detected",
                    "description": "Consider closing unnecessary applications or upgrading hardware",
                    "actions": [
                        "Check top CPU-consuming processes",
                        "Close unnecessary applications",
                        "Consider CPU upgrade if consistently high"
                    ]
                })
            
            # High memory suggestions
            if metrics['memory']['percent'] > 80:
                suggestions.append({
                    "category": "memory",
                    "priority": "high",
                    "title": "High Memory Usage",
                    "description": "System is running low on available memory",
                    "actions": [
                        "Close memory-intensive applications",
                        "Clear browser cache and tabs",
                        "Consider adding more RAM"
                    ]
                })
            
            # Disk space suggestions
            for mount, usage in metrics['disk'].items():
                if usage['percent'] > 85:
                    suggestions.append({
                        "category": "disk",
                        "priority": "critical",
                        "title": f"Low Disk Space on {mount}",
                        "description": f"Disk usage is at {usage['percent']:.1f}%",
                        "actions": [
                            "Delete unnecessary files",
                            "Clear temporary files and cache",
                            "Move large files to external storage",
                            "Uninstall unused applications"
                        ]
                    })
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error generating optimization suggestions: {e}")
            return []
    
    async def start_monitoring(self):
        """Start continuous monitoring."""
        self.monitoring_active = True
        
        while self.monitoring_active:
            try:
                # Collect metrics
                metrics = await self.get_current_metrics()
                
                # Store in history
                self.metrics_history.append(metrics)
                
                # Cleanup old data
                cutoff_time = datetime.now() - timedelta(days=self.data_retention_days)
                self.metrics_history = [
                    m for m in self.metrics_history 
                    if datetime.fromisoformat(m['timestamp']) > cutoff_time
                ]
                
                # Check for alerts
                new_alerts = await self.check_alerts(metrics)
                self.alerts.extend(new_alerts)
                
                # Cleanup old alerts
                self.alerts = [
                    a for a in self.alerts 
                    if datetime.fromisoformat(a['timestamp']) > cutoff_time
                ]
                
                await asyncio.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def stop_monitoring(self):
        """Stop continuous monitoring."""
        self.monitoring_active = False
    
    async def get_historical_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical metrics data."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            historical_data = [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m['timestamp']) > cutoff_time
            ]
            
            return historical_data
            
        except Exception as e:
            logger.error(f"Error getting historical data: {e}")
            return []


class PerformanceMonitorPlugin(PluginInterface):
    """Performance Monitor Plugin."""
    
    def __init__(self):
        super().__init__()
        self.name = "performance_monitor"
        self.version = "1.0.0"
        self.router = APIRouter()
        self.monitor = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.monitoring_task = None
        
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": "performance_monitor",
            "version": "1.0.0",
            "description": "Advanced system monitoring with real-time metrics, alerts, and performance optimization suggestions",
            "plugin_type": "monitoring"
        }
    
    def get_required_permissions(self) -> Dict[str, Any]:
        """Get required permissions."""
        return {
            "capabilities": [
                "system",
                "network",
                "file_system",
                "web_ui"
            ],
            "network_access": True,
            "file_system_access": True,
            "database_access": False
        }

def run_cpu_benchmark():
    """Run the CPU benchmark from the performance_monitor plugin."""
    # Assuming there is a function or class in this file that runs the CPU test
    # If not, implement a simple CPU benchmark here
    import time
    print("Running CPU benchmark...")
    start = time.time()
    total = 0
    for i in range(10**7):
        total += i % 7
    duration = time.time() - start
    print(f"CPU benchmark completed in {duration:.2f} seconds. Result: {total}")
    return duration, total
