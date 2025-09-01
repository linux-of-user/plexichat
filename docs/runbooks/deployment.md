# Deployment Runbook

## Overview
This runbook provides procedures for deploying PlexiChat to various environments.

## Prerequisites
- Docker and Docker Compose installed
- Kubernetes cluster access (for production)
- AWS CLI configured (for cloud deployments)
- Git repository access

## Environments
- **Development**: Local deployment for testing
- **Staging**: Pre-production environment
- **Production**: Live environment

## Deployment Procedures

### Local Development Deployment
```bash
# Clone repository
git clone https://github.com/plexichat/plexichat.git
cd plexichat

# Install dependencies
pip install -e .[dev]

# Set environment variables
cp .env.example .env
# Edit .env with local configuration

# Run database migrations
alembic upgrade head

# Start services
docker-compose up -d redis postgres
python run.py
```

### Staging Deployment
```bash
# Build Docker image
docker build -t plexichat/staging:latest .

# Deploy to staging
kubectl apply -f k8s/staging/

# Run migrations
kubectl exec -it deployment/plexichat-staging -- alembic upgrade head

# Verify deployment
curl https://staging.plexichat.com/health
```

### Production Deployment
```bash
# Tag release
git tag v1.0.0
git push origin v1.0.0

# Build and push Docker image
docker build -t plexichat/production:latest .
docker push plexichat/production:latest

# Deploy to production
kubectl apply -f k8s/production/

# Run zero-downtime migration
kubectl exec -it deployment/plexichat-prod -- alembic upgrade head

# Verify deployment
curl https://api.plexichat.com/health
```

## Rollback Procedures

### Quick Rollback
```bash
# Rollback to previous version
kubectl rollout undo deployment/plexichat-prod

# Verify rollback
kubectl get pods
```

### Database Rollback
```bash
# Downgrade migration
kubectl exec -it deployment/plexichat-prod -- alembic downgrade -1

# Restore from backup if needed
# See backup runbook for procedures
```

## Monitoring Post-Deployment
- Check application logs
- Monitor error rates
- Verify database connections
- Test critical user flows

## Troubleshooting
- **Service not starting**: Check environment variables
- **Database connection failed**: Verify credentials and network
- **High memory usage**: Check for memory leaks
- **Slow response times**: Review performance metrics

## Contacts
- **DevOps Team**: devops@plexichat.com
- **On-call Engineer**: +1-555-0123
- **Security Team**: security@plexichat.com