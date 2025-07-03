"""
Automatic Configuration Detection and Improvement System
Intelligently detects system capabilities and optimizes configuration.
"""

import asyncio
import os
import platform
import psutil
import socket
import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

from app.core.config.settings import settings
from app.logger_config import logger

@dataclass
class SystemCapabilities:
    """Detected system capabilities."""
    cpu_cores: int
    memory_gb: float
    disk_space_gb: float
    network_interfaces: List[str]
    python_version: str
    platform: str
    architecture: str
    available_ports: List[int]
    database_engines: List[str]
    cache_systems: List[str]
    web_servers: List[str]
    container_systems: List[str]
    monitoring_tools: List[str]

@dataclass
class ConfigurationRecommendation:
    """Configuration recommendation."""
    setting: str
    current_value: Any
    recommended_value: Any
    reason: str
    priority: str  # high, medium, low
    category: str  # performance, security, reliability, etc.

class AutoConfigurationSystem:
    """Automatic configuration detection and optimization system."""
    
    def __init__(self):
        self.capabilities: Optional[SystemCapabilities] = None
        self.recommendations: List[ConfigurationRecommendation] = []
        self.config_file = Path(getattr(settings, 'CONFIG_FILE', '.env'))
        self.current_config: Dict[str, Any] = {}
        
    async def detect_system_capabilities(self) -> SystemCapabilities:
        """Detect system capabilities and available services."""
        logger.info("Detecting system capabilities...")
        
        # Basic system info
        cpu_cores = psutil.cpu_count(logical=True)
        memory_gb = psutil.virtual_memory().total / (1024**3)
        disk_space_gb = psutil.disk_usage('/').free / (1024**3)
        
        # Network interfaces
        network_interfaces = list(psutil.net_if_addrs().keys())
        
        # Python and platform info
        python_version = platform.python_version()
        platform_name = platform.system()
        architecture = platform.machine()
        
        # Available ports
        available_ports = await self._scan_available_ports()
        
        # Available software
        database_engines = await self._detect_database_engines()
        cache_systems = await self._detect_cache_systems()
        web_servers = await self._detect_web_servers()
        container_systems = await self._detect_container_systems()
        monitoring_tools = await self._detect_monitoring_tools()
        
        self.capabilities = SystemCapabilities(
            cpu_cores=cpu_cores,
            memory_gb=memory_gb,
            disk_space_gb=disk_space_gb,
            network_interfaces=network_interfaces,
            python_version=python_version,
            platform=platform_name,
            architecture=architecture,
            available_ports=available_ports,
            database_engines=database_engines,
            cache_systems=cache_systems,
            web_servers=web_servers,
            container_systems=container_systems,
            monitoring_tools=monitoring_tools
        )
        
        logger.info(f"System capabilities detected: {cpu_cores} cores, {memory_gb:.1f}GB RAM, {disk_space_gb:.1f}GB free")
        return self.capabilities
    
    async def _scan_available_ports(self, start_port: int = 8000, end_port: int = 8100) -> List[int]:
        """Scan for available ports."""
        available_ports = []
        
        for port in range(start_port, end_port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.1)
                    result = sock.connect_ex(('localhost', port))
                    if result != 0:  # Port is available
                        available_ports.append(port)
                        if len(available_ports) >= 10:  # Limit to first 10 available
                            break
            except Exception:
                continue
        
        return available_ports
    
    async def _detect_database_engines(self) -> List[str]:
        """Detect available database engines."""
        engines = []
        
        # Check for common database commands
        db_commands = {
            'postgresql': ['psql', 'pg_config'],
            'mysql': ['mysql', 'mysqld'],
            'mongodb': ['mongo', 'mongod'],
            'redis': ['redis-server', 'redis-cli'],
            'sqlite': ['sqlite3']
        }
        
        for engine, commands in db_commands.items():
            for cmd in commands:
                if shutil.which(cmd):
                    engines.append(engine)
                    break
        
        # Always include SQLite as it's built into Python
        if 'sqlite' not in engines:
            engines.append('sqlite')
        
        return engines
    
    async def _detect_cache_systems(self) -> List[str]:
        """Detect available caching systems."""
        cache_systems = []
        
        cache_commands = {
            'redis': ['redis-server', 'redis-cli'],
            'memcached': ['memcached'],
            'hazelcast': ['hazelcast']
        }
        
        for cache, commands in cache_commands.items():
            for cmd in commands:
                if shutil.which(cmd):
                    cache_systems.append(cache)
                    break
        
        return cache_systems
    
    async def _detect_web_servers(self) -> List[str]:
        """Detect available web servers."""
        web_servers = []
        
        server_commands = {
            'nginx': ['nginx'],
            'apache': ['apache2', 'httpd'],
            'caddy': ['caddy'],
            'traefik': ['traefik']
        }
        
        for server, commands in server_commands.items():
            for cmd in commands:
                if shutil.which(cmd):
                    web_servers.append(server)
                    break
        
        return web_servers
    
    async def _detect_container_systems(self) -> List[str]:
        """Detect available container systems."""
        container_systems = []
        
        container_commands = {
            'docker': ['docker'],
            'podman': ['podman'],
            'kubernetes': ['kubectl'],
            'docker-compose': ['docker-compose']
        }
        
        for system, commands in container_commands.items():
            for cmd in commands:
                if shutil.which(cmd):
                    container_systems.append(system)
                    break
        
        return container_systems
    
    async def _detect_monitoring_tools(self) -> List[str]:
        """Detect available monitoring tools."""
        monitoring_tools = []
        
        monitoring_commands = {
            'prometheus': ['prometheus'],
            'grafana': ['grafana-server'],
            'elasticsearch': ['elasticsearch'],
            'logstash': ['logstash'],
            'kibana': ['kibana']
        }
        
        for tool, commands in monitoring_commands.items():
            for cmd in commands:
                if shutil.which(cmd):
                    monitoring_tools.append(tool)
                    break
        
        return monitoring_tools
    
    async def load_current_config(self) -> Dict[str, Any]:
        """Load current configuration."""
        config = {}
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip()
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        self.current_config = config
        return config
    
    async def generate_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate configuration recommendations based on system capabilities."""
        if not self.capabilities:
            await self.detect_system_capabilities()
        
        await self.load_current_config()
        recommendations = []
        
        # Performance recommendations
        recommendations.extend(await self._performance_recommendations())
        
        # Security recommendations
        recommendations.extend(await self._security_recommendations())
        
        # Reliability recommendations
        recommendations.extend(await self._reliability_recommendations())
        
        # Database recommendations
        recommendations.extend(await self._database_recommendations())
        
        # Monitoring recommendations
        recommendations.extend(await self._monitoring_recommendations())
        
        self.recommendations = recommendations
        return recommendations
    
    async def _performance_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate performance-related recommendations."""
        recommendations = []
        
        # Worker count optimization
        current_workers = int(self.current_config.get('WORKERS', 4))
        optimal_workers = min(self.capabilities.cpu_cores * 2 + 1, 16)
        
        if current_workers != optimal_workers:
            recommendations.append(ConfigurationRecommendation(
                setting='WORKERS',
                current_value=current_workers,
                recommended_value=optimal_workers,
                reason=f'Optimize for {self.capabilities.cpu_cores} CPU cores',
                priority='high',
                category='performance'
            ))
        
        # Memory-based recommendations
        if self.capabilities.memory_gb < 2:
            recommendations.append(ConfigurationRecommendation(
                setting='LOG_LEVEL',
                current_value=self.current_config.get('LOG_LEVEL', 'INFO'),
                recommended_value='WARNING',
                reason='Reduce memory usage on low-memory system',
                priority='medium',
                category='performance'
            ))
        
        # Port optimization
        current_port = int(self.current_config.get('PORT', 8000))
        if current_port not in self.capabilities.available_ports:
            recommended_port = self.capabilities.available_ports[0] if self.capabilities.available_ports else 8080
            recommendations.append(ConfigurationRecommendation(
                setting='PORT',
                current_value=current_port,
                recommended_value=recommended_port,
                reason=f'Port {current_port} may be in use, {recommended_port} is available',
                priority='medium',
                category='performance'
            ))
        
        return recommendations
    
    async def _security_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate security-related recommendations."""
        recommendations = []
        
        # HTTPS recommendation
        if self.current_config.get('USE_HTTPS', 'false').lower() != 'true':
            recommendations.append(ConfigurationRecommendation(
                setting='USE_HTTPS',
                current_value='false',
                recommended_value='true',
                reason='Enable HTTPS for secure communication',
                priority='high',
                category='security'
            ))
        
        # Secret key check
        secret_key = self.current_config.get('SECRET_KEY', '')
        if len(secret_key) < 32:
            recommendations.append(ConfigurationRecommendation(
                setting='SECRET_KEY',
                current_value='<short_key>',
                recommended_value='<generate_new_key>',
                reason='Use a longer, more secure secret key',
                priority='high',
                category='security'
            ))
        
        return recommendations
    
    async def _reliability_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate reliability-related recommendations."""
        recommendations = []
        
        # Backup recommendations
        if self.current_config.get('BACKUP_AUTO_DISTRIBUTE', 'false').lower() != 'true':
            recommendations.append(ConfigurationRecommendation(
                setting='BACKUP_AUTO_DISTRIBUTE',
                current_value='false',
                recommended_value='true',
                reason='Enable automatic backup distribution for data safety',
                priority='high',
                category='reliability'
            ))
        
        # Health check interval
        current_interval = int(self.current_config.get('HEALTH_CHECK_INTERVAL', 30))
        if current_interval > 60:
            recommendations.append(ConfigurationRecommendation(
                setting='HEALTH_CHECK_INTERVAL',
                current_value=current_interval,
                recommended_value=30,
                reason='More frequent health checks for better monitoring',
                priority='medium',
                category='reliability'
            ))
        
        return recommendations
    
    async def _database_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate database-related recommendations."""
        recommendations = []
        
        current_db = self.current_config.get('DATABASE_URL', 'sqlite:///./data/chatapi.db')
        
        # Recommend PostgreSQL if available and using SQLite
        if 'sqlite' in current_db.lower() and 'postgresql' in self.capabilities.database_engines:
            recommendations.append(ConfigurationRecommendation(
                setting='DATABASE_URL',
                current_value=current_db,
                recommended_value='postgresql://user:pass@localhost/chatapi',
                reason='PostgreSQL offers better performance and features than SQLite',
                priority='medium',
                category='database'
            ))
        
        # Redis cache recommendation
        if 'redis' in self.capabilities.cache_systems and not self.current_config.get('REDIS_URL'):
            recommendations.append(ConfigurationRecommendation(
                setting='REDIS_URL',
                current_value='',
                recommended_value='redis://localhost:6379/0',
                reason='Enable Redis caching for better performance',
                priority='medium',
                category='database'
            ))
        
        return recommendations
    
    async def _monitoring_recommendations(self) -> List[ConfigurationRecommendation]:
        """Generate monitoring-related recommendations."""
        recommendations = []
        
        # Enable metrics if not enabled
        if self.current_config.get('METRICS_ENABLED', 'false').lower() != 'true':
            recommendations.append(ConfigurationRecommendation(
                setting='METRICS_ENABLED',
                current_value='false',
                recommended_value='true',
                reason='Enable metrics collection for monitoring',
                priority='medium',
                category='monitoring'
            ))
        
        return recommendations
    
    async def apply_recommendations(self, selected_recommendations: List[str]) -> Dict[str, Any]:
        """Apply selected recommendations to configuration."""
        applied = []
        failed = []
        
        for rec_setting in selected_recommendations:
            recommendation = next((r for r in self.recommendations if r.setting == rec_setting), None)
            if not recommendation:
                failed.append(f"Recommendation not found: {rec_setting}")
                continue
            
            try:
                await self._apply_single_recommendation(recommendation)
                applied.append(recommendation.setting)
                logger.info(f"Applied recommendation: {recommendation.setting} = {recommendation.recommended_value}")
            except Exception as e:
                failed.append(f"Failed to apply {recommendation.setting}: {e}")
                logger.error(f"Failed to apply recommendation {recommendation.setting}: {e}")
        
        # Save updated configuration
        await self._save_configuration()
        
        return {
            'applied': applied,
            'failed': failed,
            'total_recommendations': len(selected_recommendations)
        }
    
    async def _apply_single_recommendation(self, recommendation: ConfigurationRecommendation):
        """Apply a single recommendation."""
        if recommendation.setting == 'SECRET_KEY' and recommendation.recommended_value == '<generate_new_key>':
            # Generate a new secret key
            import secrets
            self.current_config[recommendation.setting] = secrets.token_urlsafe(32)
        else:
            self.current_config[recommendation.setting] = str(recommendation.recommended_value)
    
    async def _save_configuration(self):
        """Save configuration to file."""
        try:
            # Backup existing config
            if self.config_file.exists():
                backup_file = self.config_file.with_suffix('.env.backup')
                shutil.copy2(self.config_file, backup_file)
            
            # Write new configuration
            with open(self.config_file, 'w') as f:
                f.write(f"# Enhanced Chat API Configuration\n")
                f.write(f"# Auto-updated on {datetime.now().isoformat()}\n\n")
                
                for key, value in self.current_config.items():
                    f.write(f"{key}={value}\n")
            
            logger.info(f"Configuration saved to {self.config_file}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
    
    async def get_optimization_report(self) -> Dict[str, Any]:
        """Get a comprehensive optimization report."""
        if not self.capabilities:
            await self.detect_system_capabilities()
        
        if not self.recommendations:
            await self.generate_recommendations()
        
        # Categorize recommendations
        by_category = {}
        by_priority = {'high': [], 'medium': [], 'low': []}
        
        for rec in self.recommendations:
            if rec.category not in by_category:
                by_category[rec.category] = []
            by_category[rec.category].append(rec)
            by_priority[rec.priority].append(rec)
        
        return {
            'system_capabilities': {
                'cpu_cores': self.capabilities.cpu_cores,
                'memory_gb': self.capabilities.memory_gb,
                'disk_space_gb': self.capabilities.disk_space_gb,
                'platform': self.capabilities.platform,
                'available_services': {
                    'databases': self.capabilities.database_engines,
                    'cache_systems': self.capabilities.cache_systems,
                    'web_servers': self.capabilities.web_servers,
                    'containers': self.capabilities.container_systems,
                    'monitoring': self.capabilities.monitoring_tools
                }
            },
            'recommendations': {
                'total': len(self.recommendations),
                'by_priority': {
                    priority: len(recs) for priority, recs in by_priority.items()
                },
                'by_category': {
                    category: len(recs) for category, recs in by_category.items()
                },
                'details': [
                    {
                        'setting': rec.setting,
                        'current': rec.current_value,
                        'recommended': rec.recommended_value,
                        'reason': rec.reason,
                        'priority': rec.priority,
                        'category': rec.category
                    }
                    for rec in self.recommendations
                ]
            },
            'optimization_score': self._calculate_optimization_score()
        }
    
    def _calculate_optimization_score(self) -> float:
        """Calculate optimization score (0-100)."""
        if not self.recommendations:
            return 100.0  # No recommendations means fully optimized
        
        # Weight recommendations by priority
        total_weight = 0
        applied_weight = 0
        
        for rec in self.recommendations:
            weight = {'high': 3, 'medium': 2, 'low': 1}[rec.priority]
            total_weight += weight
            
            # Check if recommendation is already applied
            current_value = str(self.current_config.get(rec.setting, ''))
            recommended_value = str(rec.recommended_value)
            
            if current_value == recommended_value:
                applied_weight += weight
        
        return (applied_weight / total_weight * 100) if total_weight > 0 else 100.0

# Global auto-configuration instance
auto_config = AutoConfigurationSystem()
