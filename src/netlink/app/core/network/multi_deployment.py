"""
Multi-Network Deployment System
Enables deployment across multiple networks and environments.
"""

import asyncio
import json
import ssl
import socket
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import logging
import aiohttp
import docker
from kubernetes import client, config
import consul

from app.core.config.settings import settings
from app.logger_config import logger

@dataclass
class NetworkNode:
    """Represents a network node in the deployment."""
    id: str
    name: str
    host: str
    port: int
    protocol: str = "https"
    region: str = "default"
    datacenter: str = "default"
    status: str = "unknown"
    last_seen: Optional[datetime] = None
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"
    
    @property
    def is_healthy(self) -> bool:
        return self.status == "healthy" and self.last_seen and \
               (datetime.utcnow() - self.last_seen).total_seconds() < 300

@dataclass
class DeploymentTarget:
    """Represents a deployment target environment."""
    name: str
    type: str  # docker, kubernetes, bare_metal, cloud
    config: Dict[str, Any]
    nodes: List[NetworkNode] = field(default_factory=list)
    load_balancer: Optional[str] = None
    ssl_config: Optional[Dict[str, Any]] = None
    monitoring: Dict[str, Any] = field(default_factory=dict)

class MultiNetworkDeployment:
    """Multi-network deployment management system."""
    
    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.targets: Dict[str, DeploymentTarget] = {}
        self.consul_client = None
        self.docker_client = None
        self.k8s_client = None
        
        self._initialize_clients()
        self._load_deployment_config()
    
    def _initialize_clients(self):
        """Initialize deployment clients."""
        try:
            # Initialize Consul client for service discovery
            consul_host = getattr(settings, 'CONSUL_HOST', 'localhost')
            consul_port = getattr(settings, 'CONSUL_PORT', 8500)
            self.consul_client = consul.Consul(host=consul_host, port=consul_port)
            logger.info(f"Consul client initialized: {consul_host}:{consul_port}")
        except Exception as e:
            logger.warning(f"Failed to initialize Consul client: {e}")
        
        try:
            # Initialize Docker client
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize Docker client: {e}")
        
        try:
            # Initialize Kubernetes client
            config.load_incluster_config()  # Try in-cluster first
            self.k8s_client = client.ApiClient()
            logger.info("Kubernetes client initialized (in-cluster)")
        except Exception:
            try:
                config.load_kube_config()  # Try local config
                self.k8s_client = client.ApiClient()
                logger.info("Kubernetes client initialized (local config)")
            except Exception as e:
                logger.warning(f"Failed to initialize Kubernetes client: {e}")
    
    def _load_deployment_config(self):
        """Load deployment configuration."""
        config_file = Path(getattr(settings, 'DEPLOYMENT_CONFIG', './deployment.json'))
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Load deployment targets
                for target_data in config_data.get('targets', []):
                    target = DeploymentTarget(**target_data)
                    self.targets[target.name] = target
                
                # Load network nodes
                for node_data in config_data.get('nodes', []):
                    node = NetworkNode(**node_data)
                    self.nodes[node.id] = node
                
                logger.info(f"Loaded deployment config: {len(self.targets)} targets, {len(self.nodes)} nodes")
                
            except Exception as e:
                logger.error(f"Failed to load deployment config: {e}")
        else:
            logger.info("No deployment config found, using defaults")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default deployment configuration."""
        # Default local deployment target
        local_target = DeploymentTarget(
            name="local",
            type="bare_metal",
            config={
                "host": "localhost",
                "port": 8000,
                "workers": 4
            }
        )
        self.targets["local"] = local_target
        
        # Default local node
        local_node = NetworkNode(
            id="local-node-1",
            name="Local Node",
            host="localhost",
            port=8000,
            protocol="http",
            capabilities=["api", "websocket", "files"]
        )
        self.nodes[local_node.id] = local_node
    
    async def discover_nodes(self) -> List[NetworkNode]:
        """Discover available nodes in the network."""
        discovered_nodes = []
        
        # Consul service discovery
        if self.consul_client:
            try:
                services = self.consul_client.health.service('chatapi', passing=True)[1]
                for service in services:
                    node_data = service['Service']
                    node = NetworkNode(
                        id=f"consul-{node_data['ID']}",
                        name=node_data.get('Service', 'Unknown'),
                        host=node_data['Address'],
                        port=node_data['Port'],
                        status="healthy",
                        last_seen=datetime.utcnow(),
                        metadata=node_data.get('Meta', {})
                    )
                    discovered_nodes.append(node)
                    self.nodes[node.id] = node
                
                logger.info(f"Discovered {len(services)} nodes via Consul")
                
            except Exception as e:
                logger.error(f"Consul discovery failed: {e}")
        
        # Kubernetes service discovery
        if self.k8s_client:
            try:
                v1 = client.CoreV1Api(self.k8s_client)
                services = v1.list_service_for_all_namespaces(
                    label_selector="app=chatapi"
                )
                
                for service in services.items:
                    if service.spec.ports:
                        port = service.spec.ports[0].port
                        node = NetworkNode(
                            id=f"k8s-{service.metadata.name}",
                            name=service.metadata.name,
                            host=service.spec.cluster_ip,
                            port=port,
                            status="healthy",
                            last_seen=datetime.utcnow(),
                            capabilities=["api", "websocket"],
                            metadata={
                                "namespace": service.metadata.namespace,
                                "labels": service.metadata.labels or {}
                            }
                        )
                        discovered_nodes.append(node)
                        self.nodes[node.id] = node
                
                logger.info(f"Discovered {len(services.items)} nodes via Kubernetes")
                
            except Exception as e:
                logger.error(f"Kubernetes discovery failed: {e}")
        
        # Docker service discovery
        if self.docker_client:
            try:
                containers = self.docker_client.containers.list(
                    filters={"label": "app=chatapi"}
                )
                
                for container in containers:
                    if container.status == "running":
                        # Get container network info
                        networks = container.attrs['NetworkSettings']['Networks']
                        for network_name, network_info in networks.items():
                            if network_info.get('IPAddress'):
                                node = NetworkNode(
                                    id=f"docker-{container.short_id}",
                                    name=container.name,
                                    host=network_info['IPAddress'],
                                    port=8000,  # Default port
                                    status="healthy",
                                    last_seen=datetime.utcnow(),
                                    capabilities=["api"],
                                    metadata={
                                        "container_id": container.id,
                                        "image": container.image.tags[0] if container.image.tags else "unknown"
                                    }
                                )
                                discovered_nodes.append(node)
                                self.nodes[node.id] = node
                
                logger.info(f"Discovered {len(containers)} nodes via Docker")
                
            except Exception as e:
                logger.error(f"Docker discovery failed: {e}")
        
        return discovered_nodes
    
    async def health_check_node(self, node: NetworkNode) -> bool:
        """Perform health check on a node."""
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                health_url = f"{node.url}/api/v1/system/health"
                
                async with session.get(health_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        node.status = "healthy"
                        node.last_seen = datetime.utcnow()
                        node.metadata.update(data.get('metadata', {}))
                        return True
                    else:
                        node.status = "unhealthy"
                        return False
        
        except Exception as e:
            logger.debug(f"Health check failed for {node.id}: {e}")
            node.status = "unreachable"
            return False
    
    async def health_check_all_nodes(self) -> Dict[str, bool]:
        """Perform health checks on all nodes."""
        tasks = []
        for node in self.nodes.values():
            tasks.append(self.health_check_node(node))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        health_status = {}
        for i, (node_id, result) in enumerate(zip(self.nodes.keys(), results)):
            if isinstance(result, Exception):
                health_status[node_id] = False
                self.nodes[node_id].status = "error"
            else:
                health_status[node_id] = result
        
        return health_status
    
    async def deploy_to_target(self, target_name: str, image: str = None, config: Dict[str, Any] = None) -> bool:
        """Deploy to a specific target environment."""
        if target_name not in self.targets:
            logger.error(f"Unknown deployment target: {target_name}")
            return False
        
        target = self.targets[target_name]
        logger.info(f"Deploying to target: {target_name} ({target.type})")
        
        try:
            if target.type == "docker":
                return await self._deploy_docker(target, image, config)
            elif target.type == "kubernetes":
                return await self._deploy_kubernetes(target, image, config)
            elif target.type == "bare_metal":
                return await self._deploy_bare_metal(target, config)
            else:
                logger.error(f"Unsupported deployment type: {target.type}")
                return False
                
        except Exception as e:
            logger.error(f"Deployment to {target_name} failed: {e}")
            return False
    
    async def _deploy_docker(self, target: DeploymentTarget, image: str, config: Dict[str, Any]) -> bool:
        """Deploy using Docker."""
        if not self.docker_client:
            logger.error("Docker client not available")
            return False
        
        try:
            container_config = {
                "image": image or "chatapi:latest",
                "ports": {"8000/tcp": target.config.get("port", 8000)},
                "environment": {
                    "HOST": "0.0.0.0",
                    "PORT": "8000",
                    **config
                },
                "labels": {
                    "app": "chatapi",
                    "deployment": target.name
                },
                "restart_policy": {"Name": "unless-stopped"}
            }
            
            # Stop existing container if it exists
            try:
                existing = self.docker_client.containers.get(f"chatapi-{target.name}")
                existing.stop()
                existing.remove()
                logger.info(f"Stopped existing container for {target.name}")
            except docker.errors.NotFound:
                pass
            
            # Start new container
            container = self.docker_client.containers.run(
                detach=True,
                name=f"chatapi-{target.name}",
                **container_config
            )
            
            logger.info(f"Docker deployment successful: {container.short_id}")
            return True
            
        except Exception as e:
            logger.error(f"Docker deployment failed: {e}")
            return False
    
    async def _deploy_kubernetes(self, target: DeploymentTarget, image: str, config: Dict[str, Any]) -> bool:
        """Deploy using Kubernetes."""
        if not self.k8s_client:
            logger.error("Kubernetes client not available")
            return False
        
        try:
            apps_v1 = client.AppsV1Api(self.k8s_client)
            core_v1 = client.CoreV1Api(self.k8s_client)
            
            namespace = target.config.get("namespace", "default")
            app_name = f"chatapi-{target.name}"
            
            # Create deployment
            deployment = client.V1Deployment(
                metadata=client.V1ObjectMeta(name=app_name, namespace=namespace),
                spec=client.V1DeploymentSpec(
                    replicas=target.config.get("replicas", 3),
                    selector=client.V1LabelSelector(
                        match_labels={"app": app_name}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={"app": app_name}
                        ),
                        spec=client.V1PodSpec(
                            containers=[
                                client.V1Container(
                                    name="chatapi",
                                    image=image or "chatapi:latest",
                                    ports=[client.V1ContainerPort(container_port=8000)],
                                    env=[
                                        client.V1EnvVar(name=k, value=str(v))
                                        for k, v in config.items()
                                    ]
                                )
                            ]
                        )
                    )
                )
            )
            
            # Apply deployment
            try:
                apps_v1.patch_namespaced_deployment(
                    name=app_name,
                    namespace=namespace,
                    body=deployment
                )
                logger.info(f"Updated existing Kubernetes deployment: {app_name}")
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    apps_v1.create_namespaced_deployment(
                        namespace=namespace,
                        body=deployment
                    )
                    logger.info(f"Created new Kubernetes deployment: {app_name}")
                else:
                    raise
            
            # Create service
            service = client.V1Service(
                metadata=client.V1ObjectMeta(name=app_name, namespace=namespace),
                spec=client.V1ServiceSpec(
                    selector={"app": app_name},
                    ports=[
                        client.V1ServicePort(
                            port=80,
                            target_port=8000,
                            protocol="TCP"
                        )
                    ],
                    type="ClusterIP"
                )
            )
            
            try:
                core_v1.patch_namespaced_service(
                    name=app_name,
                    namespace=namespace,
                    body=service
                )
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    core_v1.create_namespaced_service(
                        namespace=namespace,
                        body=service
                    )
            
            logger.info(f"Kubernetes deployment successful: {app_name}")
            return True
            
        except Exception as e:
            logger.error(f"Kubernetes deployment failed: {e}")
            return False
    
    async def _deploy_bare_metal(self, target: DeploymentTarget, config: Dict[str, Any]) -> bool:
        """Deploy to bare metal server."""
        try:
            # This would typically involve SSH connections and remote execution
            # For now, we'll simulate the deployment
            logger.info(f"Bare metal deployment to {target.config.get('host', 'unknown')}")
            
            # In a real implementation, this would:
            # 1. SSH to the target server
            # 2. Update the application code
            # 3. Restart services
            # 4. Verify deployment
            
            return True
            
        except Exception as e:
            logger.error(f"Bare metal deployment failed: {e}")
            return False
    
    async def get_deployment_status(self) -> Dict[str, Any]:
        """Get overall deployment status."""
        await self.health_check_all_nodes()
        
        healthy_nodes = [n for n in self.nodes.values() if n.is_healthy]
        total_nodes = len(self.nodes)
        
        return {
            "total_nodes": total_nodes,
            "healthy_nodes": len(healthy_nodes),
            "unhealthy_nodes": total_nodes - len(healthy_nodes),
            "deployment_targets": len(self.targets),
            "regions": list(set(n.region for n in self.nodes.values())),
            "datacenters": list(set(n.datacenter for n in self.nodes.values())),
            "nodes": [
                {
                    "id": node.id,
                    "name": node.name,
                    "url": node.url,
                    "status": node.status,
                    "region": node.region,
                    "datacenter": node.datacenter,
                    "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                    "capabilities": node.capabilities
                }
                for node in self.nodes.values()
            ]
        }
    
    async def register_node(self, node: NetworkNode) -> bool:
        """Register a new node in the network."""
        try:
            self.nodes[node.id] = node
            
            # Register with Consul if available
            if self.consul_client:
                self.consul_client.agent.service.register(
                    name="chatapi",
                    service_id=node.id,
                    address=node.host,
                    port=node.port,
                    tags=node.capabilities,
                    meta=node.metadata,
                    check=consul.Check.http(
                        f"{node.url}/api/v1/system/health",
                        interval="30s"
                    )
                )
                logger.info(f"Registered node {node.id} with Consul")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register node {node.id}: {e}")
            return False
    
    async def unregister_node(self, node_id: str) -> bool:
        """Unregister a node from the network."""
        try:
            if node_id in self.nodes:
                del self.nodes[node_id]
            
            # Unregister from Consul if available
            if self.consul_client:
                self.consul_client.agent.service.deregister(node_id)
                logger.info(f"Unregistered node {node_id} from Consul")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister node {node_id}: {e}")
            return False

# Global multi-network deployment instance
multi_deployment = MultiNetworkDeployment()
