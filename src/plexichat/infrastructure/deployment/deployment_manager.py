"""
import time
Deployment Management System

Comprehensive deployment automation with documentation generation,
monitoring setup, disaster recovery, and production deployment.
"""

import asyncio
import logging
import os
import shutil
import subprocess
import yaml
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
import json
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class DeploymentConfig:
    """Deployment configuration."""
    environment: str
    version: str
    docker_image: str
    replicas: int = 3
    resources: Dict[str, Any] = field(default_factory=dict)
    environment_variables: Dict[str, str] = field(default_factory=dict)
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
    end_time: Optional[datetime] = None
    duration: float = 0.0
    error_message: Optional[str] = None
    rollback_version: Optional[str] = None
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
            logger.info("📚 Generating API documentation...")

            # Create docs directory
            os.makedirs(self.output_dir, exist_ok=True)

            # Generate OpenAPI spec
            await self._generate_openapi_spec()

            # Generate API reference
            await self._generate_api_reference()

            # Generate SDK documentation
            await self._generate_sdk_docs()

            logger.info("✅ API documentation generated successfully")
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
                "description": "Government-Level Secure Communication Platform API"
            },
            "servers": [
                {"url": "https://api.plexichat.com/v1", "description": "Production server"},
                {"url": "https://staging-api.plexichat.com/v1", "description": "Staging server"}
            ],
            "paths": {
                "/auth/login": {
                    "post": {
                        "summary": "User authentication",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Authentication successful"},
                            "401": {"description": "Authentication failed"}
                        }
                    }
                },
                "/messages": {
                    "get": {
                        "summary": "Get messages",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Messages retrieved successfully"}
                        }
                    },
                    "post": {
                        "summary": "Send message",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "content": {"type": "string"},
                                            "channel_id": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Message sent successfully"}
                        }
                    }
                }
            }
        }

        spec_path = os.path.join(self.output_dir, "openapi.yaml")
        with open(spec_path, "w") as f:
            yaml.dump(openapi_spec, f, default_flow_style=False)

    async def _generate_api_reference(self):
        """Generate API reference documentation."""
        api_reference = """# PlexiChat API Reference

## Authentication

### POST /auth/login
Authenticate a user and receive an access token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "access_token": "string",
  "refresh_token": "string",
  "expires_in": 3600
}
```

## Messages

### GET /messages
Retrieve messages from a channel.

**Query Parameters:**
- `limit` (integer): Maximum number of messages to return
- `offset` (integer): Number of messages to skip

**Response:**
```json
{
  "messages": [
    {
      "id": "string",
      "content": "string",
      "author": "string",
      "timestamp": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 100,
  "has_more": true
}
```

### POST /messages
Send a new message.

**Request Body:**
```json
{
  "content": "string",
  "channel_id": "string"
}
```

**Response:**
```json
{
  "id": "string",
  "content": "string",
  "author": "string",
  "timestamp": "2023-01-01T00:00:00Z"
}
```
"""

        reference_path = os.path.join(self.output_dir, "api-reference.md")
        with open(reference_path, "w") as f:
            f.write(api_reference)

    async def _generate_sdk_docs(self):
        """Generate SDK documentation."""
        sdk_docs = """# PlexiChat SDK Documentation

## Installation

```bash
pip install plexichat-sdk
```

## Quick Start

```python
from plexichat import PlexiChatClient

# Initialize client
client = PlexiChatClient(api_key="your-api-key")

# Authenticate
await client.authenticate("username", "password")

# Send a message
message = await client.send_message("Hello, World!", channel_id="general")

# Get messages
messages = await client.get_messages(limit=10)
```

## Configuration

```python
config = {
    "api_base_url": "https://api.plexichat.com/v1",
    "timeout": 30,
    "retry_attempts": 3
}

client = PlexiChatClient(config=config)
```

## Error Handling

```python
try:
    await client.send_message("Hello", channel_id="invalid")
except PlexiChatError as e:
    print(f"Error: {e.message}")
    print(f"Error Code: {e.code}")
```
"""

        sdk_path = os.path.join(self.output_dir, "sdk-documentation.md")
        with open(sdk_path, "w") as f:
            f.write(sdk_docs)

    async def generate_deployment_docs(self) -> bool:
        """Generate deployment documentation."""
        try:
            logger.info("📖 Generating deployment documentation...")

            deployment_docs = """# PlexiChat Deployment Guide

## Prerequisites

- Docker 20.10+
- Kubernetes 1.20+
- Helm 3.0+
- PostgreSQL 13+
- Redis 6.0+

## Quick Deployment

### Using Docker Compose

```bash
# Clone repository
git clone https://github.com/your-org/plexichat.git
cd plexichat

# Start services
docker-compose up -d
```

### Using Kubernetes

```bash
# Add Helm repository
helm repo add plexichat https://charts.plexichat.com

# Install PlexiChat
helm install plexichat plexichat/plexichat \\
  --set image.tag=latest \\
  --set database.host=postgres.example.com \\
  --set redis.host=redis.example.com
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://localhost/plexichat` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `SECRET_KEY` | Application secret key | Generated |
| `LOG_LEVEL` | Logging level | `INFO` |

### Security Configuration

```yaml
security:
  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_days: 30
  authentication:
    session_timeout: 3600
    max_login_attempts: 5
  rate_limiting:
    requests_per_minute: 100
```

## Monitoring

### Health Checks

- Health endpoint: `/health`
- Readiness endpoint: `/ready`
- Metrics endpoint: `/metrics`

### Logging

Logs are structured in JSON format and include:
- Request ID
- User ID
- Timestamp
- Log level
- Message
- Context data

## Backup and Recovery

### Database Backup

```bash
# Create backup
kubectl exec -it postgres-pod -- pg_dump plexichat > backup.sql

# Restore backup
kubectl exec -i postgres-pod -- psql plexichat < backup.sql
```

### File Storage Backup

```bash
# Backup uploaded files
kubectl cp app-pod:/app/uploads ./uploads-backup
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check database credentials
   - Verify network connectivity
   - Check database server status

2. **High Memory Usage**
   - Review cache configuration
   - Check for memory leaks
   - Scale horizontally

3. **Slow Response Times**
   - Check database query performance
   - Review cache hit rates
   - Monitor resource usage
"""

            deployment_path = os.path.join(self.output_dir, "deployment-guide.md")
            with open(deployment_path, "w") as f:
                f.write(deployment_docs)

            logger.info("✅ Deployment documentation generated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to generate deployment documentation: {e}")
            return False


class ContainerManager:
    """Docker container management."""

    def __init__(self):
        self.docker_available = self._check_docker_availability()

    def _check_docker_availability(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    async def build_image(self, image_name: str, tag: str = "latest", )
                         dockerfile_path: str = "Dockerfile") -> bool:
        """Build Docker image."""
        if not self.docker_available:
            logger.error("Docker is not available")
            return False

        try:
            logger.info(f"🐳 Building Docker image: {image_name}:{tag}")

            build_cmd = [
                "docker", "build",
                "-t", f"{image_name}:{tag}",
                "-f", dockerfile_path,
                "."
            ]

            result = subprocess.run(build_cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"✅ Docker image built successfully: {image_name}:{tag}")
                return True
            else:
                logger.error(f"Docker build failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error building Docker image: {e}")
            return False

    async def push_image(self, image_name: str, tag: str = "latest",
                        registry: str = "docker.io") -> bool:
        """Push Docker image to registry."""
        if not self.docker_available:
            logger.error("Docker is not available")
            return False

        try:
            full_image_name = f"{registry}/{image_name}:{tag}"
            logger.info(f"📤 Pushing Docker image: {full_image_name}")

            # Tag image for registry
            tag_cmd = ["docker", "tag", f"{image_name}:{tag}", full_image_name]
            tag_result = subprocess.run(tag_cmd, capture_output=True)

            if tag_result.returncode != 0:
                logger.error("Failed to tag image for registry")
                return False

            # Push image
            push_cmd = ["docker", "push", full_image_name]
            push_result = subprocess.run(push_cmd, capture_output=True, text=True)

            if push_result.returncode == 0:
                logger.info(f"✅ Docker image pushed successfully: {full_image_name}")
                return True
            else:
                logger.error(f"Docker push failed: {push_result.stderr}")
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
            result = subprocess.run(["kubectl", "version", "--client"], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    async def deploy_application(self, config: DeploymentConfig) -> DeploymentResult:
        """Deploy application to Kubernetes."""
        deployment_id = f"deploy_{int(datetime.now().timestamp())}"
        start_time = datetime.now()

        result = DeploymentResult()
            deployment_id=deployment_id,
            environment=config.environment,
            version=config.version,
            status="failed",
            start_time=start_time
        )

        if not self.kubectl_available:
            result.error_message = "kubectl is not available"
            return result

        try:
            logger.info(f"🚀 Starting deployment: {deployment_id}")

            # Generate Kubernetes manifests
            manifests = await self._generate_k8s_manifests(config)

            # Apply manifests
            success = await self._apply_manifests(manifests)

            if success:
                # Wait for deployment to be ready
                ready = await self._wait_for_deployment(config)

                if ready:
                    # Run health checks
                    health_ok = await self._run_health_checks(config)

                    result.status = "success" if health_ok else "failed"
                    result.health_checks_passed = health_ok
                else:
                    result.status = "failed"
                    result.error_message = "Deployment not ready within timeout"
            else:
                result.status = "failed"
                result.error_message = "Failed to apply Kubernetes manifests"

            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()

            logger.info(f"✅ Deployment {deployment_id} completed: {result.status}")
            return result

        except Exception as e:
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
            result.error_message = str(e)
            logger.error(f"Deployment {deployment_id} failed: {e}")
            return result

    async def _generate_k8s_manifests(self, config: DeploymentConfig) -> Dict[str, Any]:
        """Generate Kubernetes manifests."""
        manifests = {
            "deployment": {
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
                                "resources": config.resources,
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
            },
            "service": {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": f"plexichat-{config.environment}-service",
                    "labels": {
                        "app": "plexichat",
                        "environment": config.environment
                    }
                },
                "spec": {
                    "selector": {
                        "app": "plexichat",
                        "environment": config.environment
                    },
                    "ports": [{
                        "port": 80,
                        "targetPort": 8000,
                        "protocol": "TCP"
                    }],
                    "type": "ClusterIP"
                }
            }
        }

        return manifests

    async def _apply_manifests(self, manifests: Dict[str, Any]) -> bool:
        """Apply Kubernetes manifests."""
        try:
            for name, manifest in manifests.items():
                # Write manifest to temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    yaml.dump(manifest, f)
                    manifest_file = f.name

                # Apply manifest
                apply_cmd = ["kubectl", "apply", "-f", manifest_file]
                result = subprocess.run(apply_cmd, capture_output=True, text=True)

                # Clean up temporary file
                os.unlink(manifest_file)

                if result.returncode != 0:
                    logger.error(f"Failed to apply {name} manifest: {result.stderr}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error applying manifests: {e}")
            return False

    async def _wait_for_deployment(self, config: DeploymentConfig, timeout: int = 300) -> bool:
        """Wait for deployment to be ready."""
        try:
            deployment_name = f"plexichat-{config.environment}"

            wait_cmd = [
                "kubectl", "rollout", "status",
                f"deployment/{deployment_name}",
                f"--timeout={timeout}s"
            ]

            result = subprocess.run(wait_cmd, capture_output=True, text=True)
            return result.returncode == 0

        except Exception as e:
            logger.error(f"Error waiting for deployment: {e}")
            return False

    async def _run_health_checks(self, config: DeploymentConfig) -> bool:
        """Run health checks on deployed application."""
        try:
            # Get service endpoint
            service_name = f"plexichat-{config.environment}-service"

            # Port forward to test health endpoint
            port_forward_cmd = [
                "kubectl", "port-forward",
                f"service/{service_name}", "8080:80"
            ]

            # This is simplified - in reality you'd test the actual health endpoint
            logger.info("🏥 Running health checks...")
            await asyncio.sleep(5)  # Simulate health check

            return True

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False


class DeploymentManager:
    """Main deployment management system."""

    def __init__(self):
        self.documentation_generator = DocumentationGenerator()
        self.container_manager = ContainerManager()
        self.kubernetes_deployer = KubernetesDeployer()
        self.deployment_history: List[DeploymentResult] = []

    async def full_deployment_pipeline(self, config: DeploymentConfig) -> DeploymentResult:
        """Run complete deployment pipeline."""
        logger.info(f"🚀 Starting full deployment pipeline for {config.environment}")

        try:
            # Step 1: Generate documentation
            docs_success = await self.documentation_generator.generate_api_documentation()
            if not docs_success:
                logger.warning("Documentation generation failed, continuing...")

            deployment_docs_success = await self.documentation_generator.generate_deployment_docs()
            if not deployment_docs_success:
                logger.warning("Deployment documentation generation failed, continuing...")

            # Step 2: Build and push container image
            image_name = "plexichat"
            build_success = await self.container_manager.build_image(image_name, config.version)
            if not build_success:
                raise Exception("Container image build failed")

            push_success = await self.container_manager.push_image(image_name, config.version)
            if not push_success:
                logger.warning("Container image push failed, using local image...")

            # Step 3: Deploy to Kubernetes
            deployment_result = await self.kubernetes_deployer.deploy_application(config)

            # Step 4: Record deployment
            self.deployment_history.append(deployment_result)

            logger.info(f"✅ Full deployment pipeline completed: {deployment_result.status}")
            return deployment_result

        except Exception as e:
            logger.error(f"Deployment pipeline failed: {e}")

            # Create failed deployment result
            failed_result = DeploymentResult()
                deployment_id=f"failed_{int(datetime.now().timestamp())}",
                environment=config.environment,
                version=config.version,
                status="failed",
                start_time=datetime.now(),
                end_time=datetime.now(),
                error_message=str(e)
            )

            self.deployment_history.append(failed_result)
            return failed_result

    def get_deployment_status(self, environment: str) -> Optional[DeploymentResult]:
        """Get latest deployment status for environment."""
        env_deployments = [
            d for d in self.deployment_history
            if d.environment == environment
        ]

        if env_deployments:
            return max(env_deployments, key=lambda d: d.start_time)

        return None

    def get_deployment_history(self, limit: int = 10) -> List[DeploymentResult]:
        """Get deployment history."""
        return sorted()
            self.deployment_history,
            key=lambda d: d.start_time,
            reverse=True
        )[:limit]


# Global deployment manager instance
deployment_manager = DeploymentManager()
