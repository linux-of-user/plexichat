# PlexiChat Deployment Guide

Comprehensive guide for deploying PlexiChat in production environments with high availability, security, and scalability.

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Cloud Deployments](#cloud-deployments)
6. [Load Balancing](#load-balancing)
7. [Database Setup](#database-setup)
8. [Security Configuration](#security-configuration)
9. [Monitoring & Logging](#monitoring--logging)
10. [Backup & Recovery](#backup--recovery)
11. [Performance Optimization](#performance-optimization)
12. [Troubleshooting](#troubleshooting)

## Deployment Overview

PlexiChat supports multiple deployment architectures:

### Deployment Types

1. **Single Node**: Simple deployment for small teams
2. **Multi-Node Cluster**: High availability with load balancing
3. **Microservices**: Distributed architecture for large scale
4. **Cloud Native**: Kubernetes-based cloud deployment
5. **Hybrid**: On-premises with cloud integration

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer                            │
│                   (HAProxy/Nginx)                           │
└─────────────────┬───────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐     ┌───▼───┐     ┌───▼───┐
│Node 1 │     │Node 2 │     │Node 3 │
│       │     │       │     │       │
│App    │     │App    │     │App    │
│Redis  │     │Redis  │     │Redis  │
└───┬───┘     └───┬───┘     └───┬───┘
    │             │             │
    └─────────────┼─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │      Database Cluster     │
    │     (PostgreSQL HA)       │
    └───────────────────────────┘
```

## Infrastructure Requirements

### Minimum Production Requirements

#### Single Node
- **CPU**: 4 cores (8 recommended)
- **RAM**: 8GB (16GB recommended)
- **Storage**: 100GB SSD (500GB recommended)
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04 LTS, CentOS 8, or RHEL 8

#### Multi-Node Cluster (per node)
- **CPU**: 8 cores (16 recommended)
- **RAM**: 16GB (32GB recommended)
- **Storage**: 200GB SSD (1TB recommended)
- **Network**: 10Gbps connection
- **OS**: Ubuntu 20.04 LTS, CentOS 8, or RHEL 8

### Software Dependencies

#### Required
- **Docker**: 20.10+ or Podman 3.0+
- **Docker Compose**: 2.0+
- **PostgreSQL**: 12+ (or compatible cloud service)
- **Redis**: 6.0+ (or compatible cloud service)

#### Optional
- **Kubernetes**: 1.20+ (for K8s deployment)
- **Helm**: 3.0+ (for K8s package management)
- **Nginx/HAProxy**: Load balancing
- **Prometheus**: Monitoring
- **Grafana**: Visualization

## Docker Deployment

PlexiChat uses a multi-stage Dockerfile with Cython/Numba compilation support for optimized performance. The deployment supports both development and production environments with consistent tooling.

### Local Development Setup

#### Prerequisites
- Docker Desktop 20.10+ (Windows/macOS/Linux)
- Docker Compose 2.0+
- Makefile (included in repository)
- PostgreSQL 15+ (via docker-compose)

#### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/plexichat.git
cd plexichat

# Install development dependencies (host)
pip install -e ".[dev]"

# Build Cython extensions (host)
make cythonize
```

#### 2. Environment Configuration

Create `.env` file in project root:

```bash
# .env
POSTGRES_URL=postgresql://postgres:password@localhost:5432/plexichat
POSTGRES_DB=plexichat
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
PLEXICHAT_SECRET_KEY=your-super-secret-key-change-in-production
PLEXICHAT_ENCRYPTION_KEY=your-32-byte-encryption-key-base64-encoded
JWT_SECRET=your-jwt-secret-key
DEBUG=True
```

#### 3. Development with Docker Compose

The `docker-compose.yml` provides a complete development stack:

```yaml
# docker-compose.yml (excerpt)
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: dev
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - .:/app
      - /app/.venv
      - /app/build
    depends_on:
      - postgres
    environment:
      - POSTGRES_URL=postgresql://postgres:password@postgres:5432/plexichat
    command: uvicorn plexichat.main:app --reload --host 0.0.0.0 --port 8000

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: plexichat
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

#### 4. Development Commands (Makefile)

```bash
# Build development Docker image (multi-platform)
make docker-build

# Run Cython compilation in container
make docker-cythonize

# Run tests in Docker with coverage
make docker-test

# Start development server in Docker
make docker-serve

# Interactive development shell
make docker-dev

# Full development workflow
make docker-dev  # Starts bash in container with volumes mounted
# Inside container: uvicorn plexichat.main:app --reload
```

### Production Deployment

#### 1. Build Production Image

The multi-stage Dockerfile creates an optimized production image:

```dockerfile
# Dockerfile (excerpt - production stage)
FROM base as prod

# Install minimal runtime dependencies
COPY requirements-minimal.txt .
RUN pip install --no-cache-dir -r requirements-minimal.txt

# Copy application code and compiled extensions
COPY src/ ./src/
COPY --from=dev /app/build/ ./build/

# Security: non-root user
RUN useradd --uid 1000 --create-home app
USER app

EXPOSE 8000

CMD ["uvicorn", "plexichat.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build production image:

```bash
# Build for specific platform
docker build --target prod -t plexichat-prod:latest .

# Multi-platform build (for ARM/x86)
docker buildx build --platform linux/amd64,linux/arm64 \
  --target prod -t your-registry/plexichat:latest \
  --push .
```

#### 2. Production Docker Compose

For production, create `docker-compose.prod.yml`:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    image: plexichat-prod:latest
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - PLEXICHAT_ENV=production
      - POSTGRES_URL=postgresql://plexichat:${POSTGRES_PASSWORD}@postgres:5432/plexichat
    env_file:
      - .env.prod
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - plexichat-prod
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: plexichat
      POSTGRES_USER: plexichat
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init:/docker-entrypoint-initdb.d
    networks:
      - plexichat-prod
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U plexichat"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:

networks:
  plexichat-prod:
    driver: bridge
```

#### 3. Deploy Production

```bash
# Production environment
cp .env.example .env.prod
# Edit .env.prod with production values

# Pull latest image or build locally
docker pull your-registry/plexichat:latest
# OR
docker build --target prod -t plexichat-prod:latest .

# Start production stack
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose -f docker-compose.prod.yml ps
docker-compose -f docker-compose.prod.yml logs app

# Run database migrations
docker-compose -f docker-compose.prod.yml exec app python -m plexichat db upgrade

# Health check
curl http://localhost:8000/health
```

### CI/CD Integration

The `.github/workflows/docker.yml` provides automated Docker builds and tests:

```yaml
# .github/workflows/docker.yml (excerpt)
name: Docker Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build and push multi-platform image
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: ${{ github.event_name != 'pull_request' }}
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  test:
    needs: build-and-push
    steps:
      - name: Run containerized tests
        run: |
          docker run --rm -v ${{ github.workspace }}:/app \
            ghcr.io/${{ github.repository }}:latest make docker-test
```

### Security and Best Practices

#### Dockerfile Security
- Multi-stage builds minimize attack surface
- Non-root user (UID 1000) for production
- No unnecessary system packages
- Health checks for container monitoring
- `.dockerignore` excludes sensitive files

#### Volume Management
```bash
# Persistent volumes for production
docker volume create plexichat_data
docker volume create plexichat_logs
docker volume create postgres_data

# Backup strategy
docker run --rm -v plexichat_data:/data -v backups:/backup \
  alpine tar czf /backup/plexichat_data_$(date +%Y%m%d).tar.gz -C /data .
```

#### Performance Optimization
- Cython/Numba compilation in build stage
- Minimal production dependencies
- Multi-platform builds for cloud flexibility
- Layer caching for faster builds

### Validation and Testing

#### Local Validation
```bash
# Test build time (<5 minutes target)
time make docker-build

# Verify Cython compilation
make docker-cythonize
ls -la build/  # Should show .so/.pyd files

# Run full test suite
make docker-test  # Should show 80%+ coverage

# Benchmark consistency
pytest tests/test_compilation.py::TestCythonBenchmark \
  --benchmark-compare=baseline --benchmark-save=host
```

#### Container vs Host Comparison
```bash
# Host benchmarks
pytest tests/test_compilation.py --benchmark-save=host

# Container benchmarks
make docker-test  # Includes benchmark save to 'container'

# Compare (add to CI)
pytest-benchmark compare host container
```

### Troubleshooting

#### Common Issues

1. **Cython Build Fails**
   ```bash
   # Ensure build-essential in Dockerfile
   docker build --no-cache --target dev .
   
   # Check for missing headers
   docker run --rm plexichat-dev:latest gcc --version
   ```

2. **Database Connection Issues**
   ```bash
   # Verify network connectivity
   docker-compose exec app ping postgres
   
   # Check PostgreSQL logs
   docker-compose logs postgres
   
   # Test connection
   docker-compose exec app psql $POSTGRES_URL -c "SELECT 1;"
   ```

3. **Port Conflicts**
   ```bash
   # Check running containers
   docker ps
   
   # Stop conflicting services
   docker-compose down
   
   # Use different ports
   # Edit docker-compose.yml: "8001:8000"
   ```

4. **Volume Mount Issues (Windows)**
   ```bash
   # Use WSL2 backend for Docker Desktop
   # Or use named volumes instead of bind mounts
   
   # Alternative: named volume for development
   volumes:
     - plexichat_dev:/app
   ```

#### Monitoring Deployment Health
```bash
# Container resource usage
docker stats

# Application logs
docker-compose logs -f app

# Database health
docker-compose exec postgres pg_isready

# Performance metrics
docker-compose exec app python -c "
from plexichat.core import metrics
print(metrics.get_system_stats())
"
```

### Multi-Platform Support

The Dockerfile supports both AMD64 and ARM64 architectures:

```bash
# Build for specific architecture
docker buildx build --platform linux/amd64 --target prod -t plexichat-amd64 .

# Build multi-platform
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  --target prod -t your-registry/plexichat:latest --push .
```

This enables deployment on AWS Graviton, Apple M1/M2, and standard x86 servers.

## Kubernetes Deployment

**Note**: For Kubernetes deployments, build the production Docker image first, then use standard Kubernetes manifests or Helm charts. The multi-stage Dockerfile ensures compatibility with container orchestrators.

### 1. Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: plexichat
---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: plexichat-config
  namespace: plexichat
data:
  PLEXICHAT_ENV: "production"
  PLEXICHAT_DATABASE_URL: "postgresql://plexichat:password@postgres:5432/plexichat"
  PLEXICHAT_REDIS_URL: "redis://redis:6379/0"
```

### 2. Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: plexichat-secrets
  namespace: plexichat
type: Opaque
data:
  secret-key: <base64-encoded-secret>
  encryption-key: <base64-encoded-encryption-key>
  jwt-secret: <base64-encoded-jwt-secret>
  postgres-password: <base64-encoded-password>
  redis-password: <base64-encoded-password>
```

### 3. Database Deployment

```yaml
# postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: plexichat
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:14-alpine
        env:
        - name: POSTGRES_DB
          value: plexichat
        - name: POSTGRES_USER
          value: plexichat
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: plexichat-secrets
              key: postgres-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1"
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: plexichat
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

### 4. Application Deployment

```yaml
# plexichat.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: plexichat
  namespace: plexichat
spec:
  replicas: 3
  selector:
    matchLabels:
      app: plexichat
  template:
    metadata:
      labels:
        app: plexichat
    spec:
      containers:
      - name: plexichat
        image: plexichat/plexichat:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: plexichat-config
        env:
        - name: PLEXICHAT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: plexichat-secrets
              key: secret-key
        - name: PLEXICHAT_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: plexichat-secrets
              key: encryption-key
        - name: PLEXICHAT_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: plexichat-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: data-storage
          mountPath: /app/data
        - name: logs-storage
          mountPath: /app/logs
      volumes:
      - name: data-storage
        persistentVolumeClaim:
          claimName: plexichat-data
      - name: logs-storage
        persistentVolumeClaim:
          claimName: plexichat-logs
---
apiVersion: v1
kind: Service
metadata:
  name: plexichat
  namespace: plexichat
spec:
  selector:
    app: plexichat
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
```

### 5. Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: plexichat-ingress
  namespace: plexichat
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
spec:
  tls:
  - hosts:
    - plexichat.example.com
    secretName: plexichat-tls
  rules:
  - host: plexichat.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: plexichat
            port:
              number: 8000
```

### 6. Deploy to Kubernetes

```bash
# Apply configurations
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml
kubectl apply -f postgres.yaml
kubectl apply -f redis.yaml
kubectl apply -f plexichat.yaml
kubectl apply -f ingress.yaml

# Check deployment
kubectl get pods -n plexichat
kubectl get services -n plexichat
kubectl get ingress -n plexichat

# View logs
kubectl logs -f deployment/plexichat -n plexichat

# Scale deployment
kubectl scale deployment plexichat --replicas=5 -n plexichat
```

## Cloud Deployments

### AWS Deployment

#### Using ECS Fargate

```yaml
# ecs-task-definition.json
{
  "family": "plexichat",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "plexichat",
      "image": "plexichat/plexichat:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "PLEXICHAT_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "PLEXICHAT_SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:plexichat/secret-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/plexichat",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### Using EKS

```bash
# Create EKS cluster
eksctl create cluster --name plexichat-cluster --region us-west-2 --nodes 3

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name plexichat-cluster

# Deploy PlexiChat
kubectl apply -f k8s/
```

### Google Cloud Platform

#### Using Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: plexichat
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containerConcurrency: 100
      containers:
      - image: gcr.io/project-id/plexichat:latest
        ports:
        - containerPort: 8000
        env:
        - name: PLEXICHAT_ENV
          value: production
        - name: PLEXICHAT_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: plexichat-secrets
              key: database-url
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
```

#### Using GKE

```bash
# Create GKE cluster
gcloud container clusters create plexichat-cluster \
  --num-nodes=3 \
  --machine-type=e2-standard-4 \
  --zone=us-central1-a

# Get credentials
gcloud container clusters get-credentials plexichat-cluster --zone=us-central1-a

# Deploy PlexiChat
kubectl apply -f k8s/
```

### Azure Deployment

#### Using Container Instances

```yaml
# azure-container-group.yaml
apiVersion: 2019-12-01
location: eastus
name: plexichat-group
properties:
  containers:
  - name: plexichat
    properties:
      image: plexichat/plexichat:latest
      ports:
      - port: 8000
        protocol: TCP
      environmentVariables:
      - name: PLEXICHAT_ENV
        value: production
      resources:
        requests:
          cpu: 2
          memoryInGB: 4
  osType: Linux
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8000
  restartPolicy: Always
```

#### Using AKS

```bash
# Create AKS cluster
az aks create \
  --resource-group plexichat-rg \
  --name plexichat-cluster \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --enable-addons monitoring

# Get credentials
az aks get-credentials --resource-group plexichat-rg --name plexichat-cluster

# Deploy PlexiChat
kubectl apply -f k8s/
```