"""
PlexiChat Container Orchestration System
Manages Docker containers and Kubernetes deployments
"""

import asyncio
import logging
import json
import yaml
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import subprocess

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
    tag: str = "latest"
    ports: Dict[int, int] = field(default_factory=dict)  # container_port: host_port
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)  # host_path: container_path
    networks: List[str] = field(default_factory=list)
    restart_policy: str = "unless-stopped"
    resource_limits: Dict[str, str] = field(default_factory=dict)
    health_check: Optional[Dict[str, Any]] = None
    dependencies: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    
    @property
    def full_image(self) -> str:
        """Get full image name with tag."""
        return f"{self.image}:{self.tag}"


@dataclass
class DeploymentSpec:
    """Kubernetes deployment specification."""
    name: str
    namespace: str = "default"
    replicas: int = 1
    containers: List[ContainerConfig] = field(default_factory=list)
    service_type: str = "ClusterIP"
    ingress_enabled: bool = False
    ingress_host: Optional[str] = None
    config_maps: Dict[str, Dict[str, str]] = field(default_factory=dict)
    secrets: Dict[str, Dict[str, str]] = field(default_factory=dict)
    persistent_volumes: List[Dict[str, Any]] = field(default_factory=list)


class ContainerOrchestrator:
    """
    Container Orchestration Manager.
    
    Features:
    - Docker and Kubernetes support
    - Automatic container health monitoring
    - Rolling updates and rollbacks
    - Service discovery integration
    - Resource management and scaling
    - Configuration management
    - Persistent volume management
    - Network policy enforcement
    """
    
    def __init__(self, platform: OrchestrationPlatform = OrchestrationPlatform.DOCKER_COMPOSE):
        self.platform = platform
        self.containers: Dict[str, ContainerConfig] = {}
        self.deployments: Dict[str, DeploymentSpec] = {}
        self.running_containers: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.docker_compose_file = "docker-compose.yml"
        self.kubernetes_namespace = "plexichat"
        self.base_image_registry = "plexichat"
        
        # Statistics
        self.stats = {
            "total_containers": 0,
            "running_containers": 0,
            "failed_containers": 0,
            "deployments": 0,
            "last_deployment": None
        }
        
        self._initialize_default_containers()
    
    def _initialize_default_containers(self):
        """Initialize default container configurations."""
        
        # Main PlexiChat application
        self.containers["plexichat-app"] = ContainerConfig(
            name="plexichat-app",
            image=f"{self.base_image_registry}/plexichat",
            tag="latest",
            ports={8000: 8000},
            environment={
                "PLEXICHAT_ENV": "production",
                "REDIS_URL": "redis://redis:6379",
                "DATABASE_URL": "postgresql://postgres:password@postgres:5432/plexichat"
            },
            volumes={
                "./data": "/app/data",
                "./logs": "/app/logs",
                "./config": "/app/config"
            },
            networks=["plexichat-network"],
            dependencies=["postgres", "redis"],
            health_check={
                "test": ["CMD", "curl", "-f", "http://localhost:8000/health"],
                "interval": "30s",
                "timeout": "10s",
                "retries": 3
            },
            resource_limits={
                "memory": "2g",
                "cpus": "1.0"
            }
        )
        
        # PostgreSQL database
        self.containers["postgres"] = ContainerConfig(
            name="postgres",
            image="postgres",
            tag="14",
            ports={5432: 5432},
            environment={
                "POSTGRES_DB": "plexichat",
                "POSTGRES_USER": "postgres",
                "POSTGRES_PASSWORD": "password"
            },
            volumes={
                "postgres_data": "/var/lib/postgresql/data"
            },
            networks=["plexichat-network"],
            health_check={
                "test": ["CMD-SHELL", "pg_isready -U postgres"],
                "interval": "10s",
                "timeout": "5s",
                "retries": 5
            }
        )
        
        # Redis cache
        self.containers["redis"] = ContainerConfig(
            name="redis",
            image="redis",
            tag="7-alpine",
            ports={6379: 6379},
            volumes={
                "redis_data": "/data"
            },
            networks=["plexichat-network"],
            health_check={
                "test": ["CMD", "redis-cli", "ping"],
                "interval": "10s",
                "timeout": "3s",
                "retries": 3
            }
        )
        
        # Nginx reverse proxy
        self.containers["nginx"] = ContainerConfig(
            name="nginx",
            image="nginx",
            tag="alpine",
            ports={80: 80, 443: 443},
            volumes={
                "./nginx.conf": "/etc/nginx/nginx.conf",
                "./ssl": "/etc/ssl/certs"
            },
            networks=["plexichat-network"],
            dependencies=["plexichat-app"]
        )
    
    async def generate_docker_compose(self) -> str:
        """Generate Docker Compose configuration."""
        compose_config = {
            "version": "3.8",
            "services": {},
            "networks": {
                "plexichat-network": {
                    "driver": "bridge"
                }
            },
            "volumes": {}
        }
        
        # Add services
        for container_name, config in self.containers.items():
            service_config = {
                "image": config.full_image,
                "container_name": config.name,
                "restart": config.restart_policy,
                "networks": config.networks
            }
            
            # Add ports
            if config.ports:
                service_config["ports"] = [f"{host}:{container}" for container, host in config.ports.items()]
            
            # Add environment variables
            if config.environment:
                service_config["environment"] = config.environment
            
            # Add volumes
            if config.volumes:
                service_config["volumes"] = [f"{host}:{container}" for host, container in config.volumes.items()]
            
            # Add health check
            if config.health_check:
                service_config["healthcheck"] = config.health_check
            
            # Add resource limits
            if config.resource_limits:
                service_config["deploy"] = {
                    "resources": {
                        "limits": config.resource_limits
                    }
                }
            
            # Add dependencies
            if config.dependencies:
                service_config["depends_on"] = config.dependencies
            
            compose_config["services"][container_name] = service_config
        
        # Add named volumes
        named_volumes = set()
        for config in self.containers.values():
            for host_path, _ in config.volumes.items():
                if not host_path.startswith("./") and not host_path.startswith("/"):
                    named_volumes.add(host_path)
        
        for volume in named_volumes:
            compose_config["volumes"][volume] = {}
        
        return yaml.dump(compose_config, default_flow_style=False)
    
    async def generate_kubernetes_manifests(self) -> Dict[str, str]:
        """Generate Kubernetes manifests."""
        manifests = {}
        
        for container_name, config in self.containers.items():
            # Deployment manifest
            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": config.name,
                    "namespace": self.kubernetes_namespace,
                    "labels": {
                        "app": config.name,
                        "component": "plexichat"
                    }
                },
                "spec": {
                    "replicas": 1,
                    "selector": {
                        "matchLabels": {
                            "app": config.name
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": {
                                "app": config.name
                            }
                        },
                        "spec": {
                            "containers": [{
                                "name": config.name,
                                "image": config.full_image,
                                "ports": [{"containerPort": port} for port in config.ports.keys()],
                                "env": [{"name": k, "value": v} for k, v in config.environment.items()],
                                "resources": {
                                    "limits": config.resource_limits
                                } if config.resource_limits else {}
                            }]
                        }
                    }
                }
            }
            
            # Add health check
            if config.health_check:
                container_spec = deployment["spec"]["template"]["spec"]["containers"][0]
                if "test" in config.health_check:
                    container_spec["livenessProbe"] = {
                        "exec": {"command": config.health_check["test"]},
                        "initialDelaySeconds": 30,
                        "periodSeconds": 30
                    }
            
            manifests[f"{config.name}-deployment.yaml"] = yaml.dump(deployment, default_flow_style=False)
            
            # Service manifest (if ports are exposed)
            if config.ports:
                service = {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {
                        "name": f"{config.name}-service",
                        "namespace": self.kubernetes_namespace
                    },
                    "spec": {
                        "selector": {
                            "app": config.name
                        },
                        "ports": [
                            {
                                "port": host_port,
                                "targetPort": container_port,
                                "protocol": "TCP"
                            }
                            for container_port, host_port in config.ports.items()
                        ],
                        "type": "ClusterIP"
                    }
                }
                
                manifests[f"{config.name}-service.yaml"] = yaml.dump(service, default_flow_style=False)
        
        return manifests
    
    async def deploy_with_docker_compose(self) -> bool:
        """Deploy using Docker Compose."""
        try:
            # Generate docker-compose.yml
            compose_content = await self.generate_docker_compose()
            
            # Write to file
            with open(self.docker_compose_file, 'w') as f:
                f.write(compose_content)
            
            # Deploy with docker-compose
            result = await self._run_command([
                "docker-compose", "-f", self.docker_compose_file, "up", "-d"
            ])
            
            if result["returncode"] == 0:
                logger.info("✅ Docker Compose deployment successful")
                self.stats["deployments"] += 1
                self.stats["last_deployment"] = datetime.now(timezone.utc)
                return True
            else:
                logger.error(f"❌ Docker Compose deployment failed: {result['stderr']}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Docker Compose deployment error: {e}")
            return False
    
    async def deploy_with_kubernetes(self) -> bool:
        """Deploy using Kubernetes."""
        try:
            # Create namespace if it doesn't exist
            await self._run_command([
                "kubectl", "create", "namespace", self.kubernetes_namespace, "--dry-run=client", "-o", "yaml"
            ])
            await self._run_command([
                "kubectl", "apply", "-f", "-"
            ], input_data=f"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {self.kubernetes_namespace}")
            
            # Generate and apply manifests
            manifests = await self.generate_kubernetes_manifests()
            
            for filename, content in manifests.items():
                # Apply manifest
                result = await self._run_command([
                    "kubectl", "apply", "-f", "-"
                ], input_data=content)
                
                if result["returncode"] != 0:
                    logger.error(f"❌ Failed to apply {filename}: {result['stderr']}")
                    return False
            
            logger.info("✅ Kubernetes deployment successful")
            self.stats["deployments"] += 1
            self.stats["last_deployment"] = datetime.now(timezone.utc)
            return True
            
        except Exception as e:
            logger.error(f"❌ Kubernetes deployment error: {e}")
            return False
    
    async def scale_service(self, service_name: str, replicas: int) -> bool:
        """Scale a service to the specified number of replicas."""
        try:
            if self.platform == OrchestrationPlatform.KUBERNETES:
                result = await self._run_command([
                    "kubectl", "scale", "deployment", service_name,
                    f"--replicas={replicas}",
                    "-n", self.kubernetes_namespace
                ])
                
                if result["returncode"] == 0:
                    logger.info(f"✅ Scaled {service_name} to {replicas} replicas")
                    return True
                else:
                    logger.error(f"❌ Failed to scale {service_name}: {result['stderr']}")
                    return False
            
            elif self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
                result = await self._run_command([
                    "docker-compose", "-f", self.docker_compose_file,
                    "up", "-d", "--scale", f"{service_name}={replicas}"
                ])
                
                if result["returncode"] == 0:
                    logger.info(f"✅ Scaled {service_name} to {replicas} replicas")
                    return True
                else:
                    logger.error(f"❌ Failed to scale {service_name}: {result['stderr']}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Scaling error for {service_name}: {e}")
            return False
    
    async def get_container_status(self) -> Dict[str, Any]:
        """Get status of all containers."""
        container_statuses = {}
        
        try:
            if self.platform == OrchestrationPlatform.DOCKER_COMPOSE:
                result = await self._run_command([
                    "docker-compose", "-f", self.docker_compose_file, "ps", "--format", "json"
                ])
                
                if result["returncode"] == 0:
                    containers_data = json.loads(result["stdout"]) if result["stdout"] else []
                    for container in containers_data:
                        container_statuses[container["Name"]] = {
                            "status": container["State"],
                            "ports": container.get("Ports", ""),
                            "image": container.get("Image", "")
                        }
            
            elif self.platform == OrchestrationPlatform.KUBERNETES:
                result = await self._run_command([
                    "kubectl", "get", "pods", "-n", self.kubernetes_namespace, "-o", "json"
                ])
                
                if result["returncode"] == 0:
                    pods_data = json.loads(result["stdout"])
                    for pod in pods_data.get("items", []):
                        pod_name = pod["metadata"]["name"]
                        container_statuses[pod_name] = {
                            "status": pod["status"]["phase"],
                            "ready": pod["status"].get("containerStatuses", [{}])[0].get("ready", False),
                            "restart_count": pod["status"].get("containerStatuses", [{}])[0].get("restartCount", 0)
                        }
        
        except Exception as e:
            logger.error(f"❌ Error getting container status: {e}")
        
        return container_statuses
    
    async def _run_command(self, cmd: List[str], input_data: str = None) -> Dict[str, Any]:
        """Run a shell command asynchronously."""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate(
                input=input_data.encode() if input_data else None
            )
            
            return {
                "returncode": process.returncode,
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else ""
            }
            
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e)
            }
    
    def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get orchestrator status and statistics."""
        return {
            "platform": self.platform.value,
            "total_containers": len(self.containers),
            "statistics": self.stats,
            "containers": list(self.containers.keys()),
            "kubernetes_namespace": self.kubernetes_namespace,
            "docker_compose_file": self.docker_compose_file
        }


# Global container orchestrator
container_orchestrator = ContainerOrchestrator()
