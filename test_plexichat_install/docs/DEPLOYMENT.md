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

### Single Node Docker Deployment

#### 1. Prepare Environment

```bash
# Create deployment directory
mkdir plexichat-production
cd plexichat-production

# Download production configuration
curl -O https://raw.githubusercontent.com/linux-of-user/plexichat/main/docker-compose.prod.yml
curl -O https://raw.githubusercontent.com/linux-of-user/plexichat/main/.env.production
```

#### 2. Configure Environment

```bash
# Edit environment variables
cp .env.production .env
nano .env

# Required variables
PLEXICHAT_ENV=production
PLEXICHAT_SECRET_KEY=your-super-secret-key-here
PLEXICHAT_DATABASE_URL=postgresql://plexichat:password@postgres:5432/plexichat
PLEXICHAT_REDIS_URL=redis://redis:6379/0
PLEXICHAT_ENCRYPTION_KEY=your-256-bit-encryption-key
PLEXICHAT_JWT_SECRET=your-jwt-secret-key

# SSL Configuration
PLEXICHAT_SSL_CERT_PATH=/certs/fullchain.pem
PLEXICHAT_SSL_KEY_PATH=/certs/privkey.pem

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# AI Configuration (optional)
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
```

#### 3. Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  plexichat:
    image: plexichat/plexichat:latest
    restart: unless-stopped
    ports:
      - "80:8000"
      - "443:8443"
    environment:
      - PLEXICHAT_ENV=production
    env_file:
      - .env
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./certs:/certs:ro
      - ./config:/app/config
    depends_on:
      - postgres
      - redis
    networks:
      - plexichat-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:14-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: plexichat
      POSTGRES_USER: plexichat
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - plexichat-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U plexichat"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - plexichat-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - plexichat
    networks:
      - plexichat-network

volumes:
  postgres_data:
  redis_data:

networks:
  plexichat-network:
    driver: bridge
```

#### 4. Deploy

```bash
# Start services
docker-compose -f docker-compose.prod.yml up -d

# Check status
docker-compose -f docker-compose.prod.yml ps

# View logs
docker-compose -f docker-compose.prod.yml logs -f plexichat

# Initialize database
docker-compose -f docker-compose.prod.yml exec plexichat python -m plexichat db init

# Create admin user
docker-compose -f docker-compose.prod.yml exec plexichat python -m plexichat user create admin \
  --email admin@example.com --password admin123 --role admin
```

### Multi-Node Docker Swarm

#### 1. Initialize Swarm

```bash
# On manager node
docker swarm init --advertise-addr <MANAGER-IP>

# On worker nodes
docker swarm join --token <TOKEN> <MANAGER-IP>:2377
```

#### 2. Deploy Stack

```yaml
# docker-stack.yml
version: '3.8'

services:
  plexichat:
    image: plexichat/plexichat:latest
    deploy:
      replicas: 3
      placement:
        constraints:
          - node.role == worker
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
    environment:
      - PLEXICHAT_ENV=production
    env_file:
      - .env
    volumes:
      - plexichat_data:/app/data
      - plexichat_logs:/app/logs
    networks:
      - plexichat-overlay
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:14-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.labels.postgres == true
    environment:
      POSTGRES_DB: plexichat
      POSTGRES_USER: plexichat
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - plexichat-overlay

  redis:
    image: redis:7-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.labels.redis == true
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - plexichat-overlay

  nginx:
    image: nginx:alpine
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.role == manager
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    networks:
      - plexichat-overlay
    depends_on:
      - plexichat

volumes:
  plexichat_data:
  plexichat_logs:
  postgres_data:
  redis_data:

networks:
  plexichat-overlay:
    driver: overlay
    attachable: true
```

```bash
# Deploy stack
docker stack deploy -c docker-stack.yml plexichat

# Check services
docker service ls

# Scale services
docker service scale plexichat_plexichat=5
```

## Kubernetes Deployment

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