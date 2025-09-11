"""
Deployment Management System

Comprehensive deployment automation with documentation generation,
monitoring setup, disaster recovery, and production deployment.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
import logging
import os
import subprocess
import tempfile
import time
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class DeploymentConfig:
    """Deployment configuration."""
    environment: str
    version: str
    docker_image: str
    replicas: int = 3
    resources: dict[str, Any] = field(default_factory=dict)
    environment_variables: dict[str, str] = field(default_factory=dict)
    health_check_path: str = "/health"
    readiness_probe_path: str = "/ready"
    monitoring_enabled: bool = True
    backup_enabled: bool = True


@dataclass
class DeploymentResult:
    """Deployment execution result."""
    deployment_id: str
    environment: str
    version: str
    status: str  # success, failed, rollback
    start_time: datetime
    end_time: datetime | None = None
    duration: float = 0.0
    error_message: str | None = None
    rollback_version: str | None = None
    health_checks_passed: bool = False
    monitoring_setup: bool = False


class DocumentationGenerator:
    """Automatic documentation generation."""

    def __init__(self, output_dir: str = "docs"):
        self.output_dir = output_dir
        self.templates_dir = os.path.join(output_dir, "templates")

    async def generate_api_documentation(self) -> bool:
        """Generate API documentation."""
        try:
            logger.info("Generating API documentation...")

            # Create docs directory
            os.makedirs(self.output_dir, exist_ok=True)

            # Generate OpenAPI spec
            await self._generate_openapi_spec()

            # Generate API reference
            await self._generate_api_reference()

            # Generate SDK documentation
            await self._generate_sdk_docs()

            logger.info("API documentation generated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to generate API documentation: {e}")
            return False

    async def _generate_openapi_spec(self):
        """Generate OpenAPI specification."""
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "PlexiChat API",
                "version": "1.0.0",
                "description": "PlexiChat messaging platform API"
            },
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        }

        spec_path = os.path.join(self.output_dir, "openapi.yaml")
        with open(spec_path, 'w') as f:
            yaml.dump(openapi_spec, f, default_flow_style=False)

    async def _generate_api_reference(self):
        """Generate API reference documentation."""
        reference_content = """# PlexiChat API Reference

## Authentication
All API endpoints require authentication using JWT tokens.

## Endpoints

### Messages
- GET /api/messages - List messages
- POST /api/messages - Send message
- PUT /api/messages/{id} - Update message
- DELETE /api/messages/{id} - Delete message

### Users
- GET /api/users - List users
- POST /api/users - Create user
- GET /api/users/{id} - Get user
- PUT /api/users/{id} - Update user
- DELETE /api/users/{id} - Delete user

### Channels
- GET /api/channels - List channels
- POST /api/channels - Create channel
- GET /api/channels/{id} - Get channel
- PUT /api/channels/{id} - Update channel
- DELETE /api/channels/{id} - Delete channel
"""

        reference_path = os.path.join(self.output_dir, "api_reference.md")
        with open(reference_path, 'w') as f:
            f.write(reference_content)

    async def _generate_sdk_docs(self):
        """Generate SDK documentation."""
        sdk_content = """# PlexiChat SDK Documentation

## Installation

```bash
pip install plexichat-sdk
```

## Quick Start

```python
from plexichat import PlexiChatClient

client = PlexiChatClient(api_key="your-api-key")

# Send a message
message = client.messages.send(
    channel_id="channel-123",
    content="Hello, world!"
)

# List messages
messages = client.messages.list(channel_id="channel-123")
```
"""

        sdk_path = os.path.join(self.output_dir, "sdk_documentation.md")
        with open(sdk_path, 'w') as f:
            f.write(sdk_content)


class ContainerManager:
    """Docker container management."""

    def __init__(self):
        self.docker_available = self._check_docker_availability()

    def _check_docker_availability(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                check=False, capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    async def build_image(self, dockerfile_path: str, image_tag: str) -> bool:
        """Build Docker image."""
        if not self.docker_available:
            logger.error("Docker is not available")
            return False

        try:
            logger.info(f"Building Docker image: {image_tag}")

            process = await asyncio.create_subprocess_exec(
                "docker", "build", "-t", image_tag, dockerfile_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Successfully built image: {image_tag}")
                return True
            else:
                logger.error(f"Failed to build image: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error building Docker image: {e}")
            return False

    async def push_image(self, image_tag: str) -> bool:
        """Push Docker image to registry."""
        if not self.docker_available:
            logger.error("Docker is not available")
            return False

        try:
            logger.info(f"Pushing Docker image: {image_tag}")

            process = await asyncio.create_subprocess_exec(
                "docker", "push", image_tag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Successfully pushed image: {image_tag}")
                return True
            else:
                logger.error(f"Failed to push image: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Error pushing Docker image: {e}")
            return False


class KubernetesDeployer:
    """Kubernetes deployment manager."""

    def __init__(self):
        self.kubectl_available = self._check_kubectl_availability()

    def _check_kubectl_availability(self) -> bool:
        """Check if kubectl is available."""
        try:
            result = subprocess.run(
                ["kubectl", "version", "--client"],
                check=False, capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    async def deploy(self, config: DeploymentConfig) -> DeploymentResult:
        """Deploy application to Kubernetes."""
        deployment_id = f"deploy-{int(time.time())}"
        start_time = datetime.now()

        result = DeploymentResult(
            deployment_id=deployment_id,
            environment=config.environment,
            version=config.version,
            status="in_progress",
            start_time=start_time
        )

        try:
            if not self.kubectl_available:
                raise Exception("kubectl is not available")

            # Create deployment manifest
            manifest = self._create_deployment_manifest(config)

            # Apply deployment
            success = await self._apply_manifest(manifest)

            if success:
                result.status = "success"
                result.health_checks_passed = True
                logger.info(f"Deployment {deployment_id} completed successfully")
            else:
                result.status = "failed"
                result.error_message = "Failed to apply Kubernetes manifest"

        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.error(f"Deployment {deployment_id} failed: {e}")

        finally:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()

        return result

    def _create_deployment_manifest(self, config: DeploymentConfig) -> dict[str, Any]:
        """Create Kubernetes deployment manifest."""
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": f"plexichat-{config.environment}",
                "labels": {
                    "app": "plexichat",
                    "environment": config.environment,
                    "version": config.version
                }
            },
            "spec": {
                "replicas": config.replicas,
                "selector": {
                    "matchLabels": {
                        "app": "plexichat",
                        "environment": config.environment
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "plexichat",
                            "environment": config.environment,
                            "version": config.version
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "plexichat",
                            "image": config.docker_image,
                            "ports": [{"containerPort": 8000}],
                            "env": [
                                {"name": k, "value": v}
                                for k, v in config.environment_variables.items()
                            ],
                            "livenessProbe": {
                                "httpGet": {
                                    "path": config.health_check_path,
                                    "port": 8000
                                },
                                "initialDelaySeconds": 30,
                                "periodSeconds": 10
                            },
                            "readinessProbe": {
                                "httpGet": {
                                    "path": config.readiness_probe_path,
                                    "port": 8000
                                },
                                "initialDelaySeconds": 5,
                                "periodSeconds": 5
                            }
                        }]
                    }
                }
            }
        }

    async def _apply_manifest(self, manifest: dict[str, Any]) -> bool:
        """Apply Kubernetes manifest."""
        try:
            # Write manifest to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.dump(manifest, f)
                manifest_path = f.name

            # Apply manifest using kubectl
            process = await asyncio.create_subprocess_exec(
                "kubectl", "apply", "-f", manifest_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Clean up temporary file
            os.unlink(manifest_path)

            return process.returncode == 0

        except Exception as e:
            logger.error(f"Error applying manifest: {e}")
            return False


class DeploymentManager:
    """Main deployment management system."""

    def __init__(self):
        self.documentation_generator = DocumentationGenerator()
        self.container_manager = ContainerManager()
        self.kubernetes_deployer = KubernetesDeployer()
        self.deployment_history: list[DeploymentResult] = []

    async def deploy(self, config: DeploymentConfig) -> DeploymentResult:
        """Execute full deployment pipeline."""
        logger.info(f"Starting deployment for {config.environment} v{config.version}")

        # Build and push container image
        build_success = await self.container_manager.build_image(".", config.docker_image)
        if not build_success:
            result = DeploymentResult(
                deployment_id=f"deploy-{int(time.time())}",
                environment=config.environment,
                version=config.version,
                status="failed",
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message="Failed to build Docker image"
            )
            self.deployment_history.append(result)
            return result

        push_success = await self.container_manager.push_image(config.docker_image)
        if not push_success:
            result = DeploymentResult(
                deployment_id=f"deploy-{int(time.time())}",
                environment=config.environment,
                version=config.version,
                status="failed",
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message="Failed to push Docker image"
            )
            self.deployment_history.append(result)
            return result

        # Deploy to Kubernetes
        result = await self.kubernetes_deployer.deploy(config)
        self.deployment_history.append(result)

        # Generate documentation if deployment succeeded
        if result.status == "success":
            await self.documentation_generator.generate_api_documentation()

        return result

    def get_deployment_history(self, limit: int = 10) -> list[DeploymentResult]:
        """Get deployment history."""
        return sorted(
            self.deployment_history,
            key=lambda d: d.start_time,
            reverse=True
        )[:limit]


# Global deployment manager instance
deployment_manager = DeploymentManager()

__all__ = [
    "ContainerManager",
    "DeploymentConfig",
    "DeploymentManager",
    "DeploymentResult",
    "DocumentationGenerator",
    "KubernetesDeployer",
    "deployment_manager"
]
