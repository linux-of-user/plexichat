"""
PlexiChat Container Orchestration System

Manages Docker containers and Kubernetes deployments for the PlexiChat platform.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


class ContainerStatus(Enum):
    """Container status enumeration."""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    RESTARTING = "restarting"
    UNKNOWN = "unknown"


class OrchestrationPlatform(Enum):
    """Supported orchestration platforms."""
    DOCKER_COMPOSE = "docker_compose"
    KUBERNETES = "kubernetes"
    DOCKER_SWARM = "docker_swarm"
    NOMAD = "nomad"


@dataclass
class ContainerConfig:
    """Container configuration."""
    name: str
    image: str
    ports: Dict[str, str] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    restart_policy: str = "unless-stopped"
    memory_limit: Optional[str] = None
    cpu_limit: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class ContainerInfo:
    """Container runtime information."""
    id: str
    name: str
    status: ContainerStatus
    image: str
    created: datetime
    ports: Dict[str, str] = field(default_factory=dict)
    networks: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)


class ContainerOrchestrator:
    """Container orchestration manager."""
    
    def __init__(self, platform: OrchestrationPlatform = OrchestrationPlatform.DOCKER_COMPOSE):
        self.platform = platform
        self.containers: Dict[str, ContainerInfo] = {}
        self.configs: Dict[str, ContainerConfig] = {}
        
    async def initialize(self):
        """Initialize the orchestrator."""
        try:
            await self._check_platform_availability()
            await self._load_existing_containers()
            logger.info(f"Container orchestrator initialized with {self.platform.value}")
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            raise
    
    async def _check_platform_availability(self):
        """Check if the orchestration platform is available."""
        if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
            await self._check_docker()
        elif self.platform == OrchestrationPlatform.KUBERNETES:
            await self._check_kubernetes()
        elif self.platform == OrchestrationPlatform.DOCKER_SWARM:
            await self._check_docker_swarm()
    
    async def _check_docker(self):
        """Check Docker availability."""
        try:
            result = await asyncio.create_subprocess_exec(
                'docker', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            if result.returncode != 0:
                raise RuntimeError("Docker is not available")
        except FileNotFoundError:
            raise RuntimeError("Docker is not installed")
    
    async def _check_kubernetes(self):
        """Check Kubernetes availability."""
        try:
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'version', '--client',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            if result.returncode != 0:
                raise RuntimeError("kubectl is not available")
        except FileNotFoundError:
            raise RuntimeError("kubectl is not installed")
    
    async def _check_docker_swarm(self):
        """Check Docker Swarm availability."""
        await self._check_docker()
        try:
            result = await asyncio.create_subprocess_exec(
                'docker', 'info', '--format', '{{.Swarm.LocalNodeState}}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            if stdout.decode().strip() != 'active':
                raise RuntimeError("Docker Swarm is not active")
        except Exception as e:
            raise RuntimeError(f"Docker Swarm check failed: {e}")
    
    async def _load_existing_containers(self):
        """Load information about existing containers."""
        if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
            await self._load_docker_containers()
        elif self.platform == OrchestrationPlatform.KUBERNETES:
            await self._load_kubernetes_pods()
    
    async def _load_docker_containers(self):
        """Load Docker containers."""
        try:
            result = await asyncio.create_subprocess_exec(
                'docker', 'ps', '-a', '--format', 'json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        container_data = json.loads(line)
                        container_info = self._parse_docker_container(container_data)
                        self.containers[container_info.name] = container_info
        except Exception as e:
            logger.warning(f"Failed to load Docker containers: {e}")
    
    def _parse_docker_container(self, data: Dict[str, Any]) -> ContainerInfo:
        """Parse Docker container data."""
        status_map = {
            'running': ContainerStatus.RUNNING,
            'exited': ContainerStatus.STOPPED,
            'created': ContainerStatus.CREATING,
            'restarting': ContainerStatus.RESTARTING,
            'dead': ContainerStatus.FAILED,
        }
        
        status_str = data.get('State', 'unknown').lower()
        status = status_map.get(status_str, ContainerStatus.UNKNOWN)
        
        return ContainerInfo(
            id=data.get('ID', ''),
            name=data.get('Names', '').lstrip('/'),
            status=status,
            image=data.get('Image', ''),
            created=datetime.now(timezone.utc),  # Simplified
            ports={},  # Would need to parse ports
            networks=[],  # Would need to parse networks
            labels={}  # Would need to parse labels
        )
    
    async def _load_kubernetes_pods(self):
        """Load Kubernetes pods."""
        try:
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'get', 'pods', '-o', 'json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                pods_data = json.loads(stdout.decode())
                for pod in pods_data.get('items', []):
                    container_info = self._parse_kubernetes_pod(pod)
                    self.containers[container_info.name] = container_info
        except Exception as e:
            logger.warning(f"Failed to load Kubernetes pods: {e}")
    
    def _parse_kubernetes_pod(self, pod_data: Dict[str, Any]) -> ContainerInfo:
        """Parse Kubernetes pod data."""
        metadata = pod_data.get('metadata', {})
        status = pod_data.get('status', {})
        
        phase = status.get('phase', 'Unknown').lower()
        status_map = {
            'running': ContainerStatus.RUNNING,
            'pending': ContainerStatus.CREATING,
            'succeeded': ContainerStatus.STOPPED,
            'failed': ContainerStatus.FAILED,
        }
        
        container_status = status_map.get(phase, ContainerStatus.UNKNOWN)
        
        return ContainerInfo(
            id=metadata.get('uid', ''),
            name=metadata.get('name', ''),
            status=container_status,
            image='',  # Would need to extract from containers
            created=datetime.now(timezone.utc),  # Simplified
            ports={},
            networks=[],
            labels=metadata.get('labels', {})
        )
    
    async def deploy_container(self, config: ContainerConfig) -> bool:
        """Deploy a container."""
        try:
            self.configs[config.name] = config
            
            if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
                return await self._deploy_docker_container(config)
            elif self.platform == OrchestrationPlatform.KUBERNETES:
                return await self._deploy_kubernetes_pod(config)
            else:
                logger.error(f"Deployment not implemented for {self.platform.value}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to deploy container {config.name}: {e}")
            return False
    
    async def _deploy_docker_container(self, config: ContainerConfig) -> bool:
        """Deploy container using Docker."""
        cmd = ['docker', 'run', '-d', '--name', config.name]
        
        # Add ports
        for host_port, container_port in config.ports.items():
            cmd.extend(['-p', f"{host_port}:{container_port}"])
        
        # Add environment variables
        for key, value in config.environment.items():
            cmd.extend(['-e', f"{key}={value}"])
        
        # Add volumes
        for volume in config.volumes:
            cmd.extend(['-v', volume])
        
        # Add restart policy
        cmd.extend(['--restart', config.restart_policy])
        
        # Add resource limits
        if config.memory_limit:
            cmd.extend(['--memory', config.memory_limit])
        if config.cpu_limit:
            cmd.extend(['--cpus', config.cpu_limit])
        
        # Add labels
        for key, value in config.labels.items():
            cmd.extend(['--label', f"{key}={value}"])
        
        cmd.append(config.image)
        
        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                container_id = stdout.decode().strip()
                logger.info(f"Container {config.name} deployed with ID: {container_id}")
                await self._load_existing_containers()  # Refresh container list
                return True
            else:
                logger.error(f"Failed to deploy container: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error deploying Docker container: {e}")
            return False
    
    async def _deploy_kubernetes_pod(self, config: ContainerConfig) -> bool:
        """Deploy pod using Kubernetes."""
        # Create a simple pod manifest
        pod_manifest = {
            'apiVersion': 'v1',
            'kind': 'Pod',
            'metadata': {
                'name': config.name,
                'labels': config.labels
            },
            'spec': {
                'containers': [{
                    'name': config.name,
                    'image': config.image,
                    'env': [{'name': k, 'value': v} for k, v in config.environment.items()],
                    'ports': [{'containerPort': int(port)} for port in config.ports.values()]
                }],
                'restartPolicy': 'Always'
            }
        }
        
        # Add resource limits if specified
        if config.memory_limit or config.cpu_limit:
            resources = {}
            if config.memory_limit:
                resources['memory'] = config.memory_limit
            if config.cpu_limit:
                resources['cpu'] = config.cpu_limit
            pod_manifest['spec']['containers'][0]['resources'] = {'limits': resources}
        
        try:
            # Write manifest to temporary file
            manifest_yaml = yaml.dump(pod_manifest)
            
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'apply', '-f', '-',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate(input=manifest_yaml.encode())
            
            if result.returncode == 0:
                logger.info(f"Pod {config.name} deployed successfully")
                await self._load_existing_containers()  # Refresh pod list
                return True
            else:
                logger.error(f"Failed to deploy pod: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error deploying Kubernetes pod: {e}")
            return False
    
    async def stop_container(self, name: str) -> bool:
        """Stop a container."""
        try:
            if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
                return await self._stop_docker_container(name)
            elif self.platform == OrchestrationPlatform.KUBERNETES:
                return await self._stop_kubernetes_pod(name)
            else:
                logger.error(f"Stop not implemented for {self.platform.value}")
                return False
        except Exception as e:
            logger.error(f"Failed to stop container {name}: {e}")
            return False
    
    async def _stop_docker_container(self, name: str) -> bool:
        """Stop Docker container."""
        try:
            result = await asyncio.create_subprocess_exec(
                'docker', 'stop', name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error stopping Docker container: {e}")
            return False
    
    async def _stop_kubernetes_pod(self, name: str) -> bool:
        """Stop Kubernetes pod."""
        try:
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'delete', 'pod', name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error stopping Kubernetes pod: {e}")
            return False
    
    def get_container_status(self, name: str) -> Optional[ContainerStatus]:
        """Get container status."""
        container = self.containers.get(name)
        return container.status if container else None
    
    def list_containers(self) -> List[ContainerInfo]:
        """List all containers."""
        return list(self.containers.values())
    
    async def get_container_logs(self, name: str, lines: int = 100) -> str:
        """Get container logs."""
        try:
            if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
                result = await asyncio.create_subprocess_exec(
                    'docker', 'logs', '--tail', str(lines), name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            elif self.platform == OrchestrationPlatform.KUBERNETES:
                result = await asyncio.create_subprocess_exec(
                    'kubectl', 'logs', '--tail', str(lines), name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                return "Logs not supported for this platform"
            
            stdout, stderr = await result.communicate()
            return stdout.decode() + stderr.decode()
            
        except Exception as e:
            logger.error(f"Failed to get logs for {name}: {e}")
            return f"Error getting logs: {e}"


# Global orchestrator instance
orchestrator = ContainerOrchestrator()
