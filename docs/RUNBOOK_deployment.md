# Deployment Runbook

## Overview

This runbook outlines the deployment procedures for PlexiChat across different environments, ensuring reliable and secure software delivery.

## Environments

### Development Environment
- **Purpose**: Feature development and testing
- **Branch**: `develop`
- **Auto-deployment**: On push to develop
- **URL**: dev.plexichat.com
- **Database**: Development database
- **Monitoring**: Basic logging

### Staging Environment
- **Purpose**: Pre-production testing
- **Branch**: `main`
- **Auto-deployment**: On merge to main
- **URL**: staging.plexichat.com
- **Database**: Staging database (production-like)
- **Monitoring**: Full monitoring stack

### Production Environment
- **Purpose**: Live production system
- **Branch**: `main`
- **Deployment**: Manual approval required
- **URL**: app.plexichat.com
- **Database**: Production database
- **Monitoring**: Full monitoring with alerts

## Deployment Process

### Automated Deployment (Dev/Staging)

1. **Code Changes**
   - Develop features on feature branches
   - Create pull request to `develop` or `main`
   - Ensure all CI checks pass

2. **Merge and Deploy**
   - Merge PR after approval
   - CI pipeline triggers automatically
   - Deployment starts after successful build

3. **Post-Deployment**
   - Run smoke tests
   - Monitor application health
   - Notify team of deployment status

### Manual Deployment (Production)

1. **Preparation**
   - Review release notes
   - Check staging environment
   - Prepare rollback plan
   - Schedule deployment window

2. **Pre-Deployment Checks**
   ```bash
   # Check system resources
   kubectl get nodes
   kubectl get pods

   # Verify database connectivity
   # Check backup status
   # Review monitoring dashboards
   ```

3. **Deployment Execution**
   ```bash
   # Update deployment
   kubectl set image deployment/plexichat app=plexichat:v1.2.3

   # Monitor rollout
   kubectl rollout status deployment/plexichat

   # Check pod health
   kubectl get pods -l app=plexichat
   ```

4. **Post-Deployment Verification**
   - Run health checks
   - Execute smoke tests
   - Monitor error rates
   - Verify data integrity

## Infrastructure Setup

### Containerization
- **Base Image**: Python 3.11 slim
- **Multi-stage Build**: Optimized for production
- **Security**: Non-root user, minimal attack surface

### Orchestration
- **Platform**: Kubernetes
- **Service Mesh**: Istio for traffic management
- **Ingress**: NGINX Ingress Controller
- **Load Balancing**: AWS ALB or similar

### Database
- **Primary**: PostgreSQL
- **Backup**: Automated daily backups
- **Replication**: Read replicas for performance
- **Migration**: Alembic for schema changes

### Caching
- **Primary**: Redis cluster
- **Session Store**: Redis
- **Cache Strategy**: Write-through with TTL

## Deployment Strategies

### Blue-Green Deployment
- Maintain two identical environments
- Route traffic to new version after testing
- Quick rollback by switching traffic
- Zero downtime deployment

### Canary Deployment
- Deploy to subset of users first
- Gradually increase traffic to new version
- Monitor metrics and rollback if needed
- A/B testing capabilities

### Rolling Update
- Update pods incrementally
- Maintain service availability
- Automatic rollback on failure
- Kubernetes native deployment

## Rollback Procedures

### Automated Rollback
```bash
# Immediate rollback to previous version
kubectl rollout undo deployment/plexichat

# Rollback to specific revision
kubectl rollout undo deployment/plexichat --to-revision=2
```

### Manual Rollback
1. **Identify Issue**
   - Monitor alerts and dashboards
   - Check application logs
   - Review error rates and performance

2. **Execute Rollback**
   ```bash
   # Scale down new deployment
   kubectl scale deployment new-plexichat --replicas=0

   # Scale up old deployment
   kubectl scale deployment plexichat --replicas=3

   # Update service selector if needed
   kubectl patch service plexichat -p '{"spec":{"selector":{"version":"v1.1.0"}}}'
   ```

3. **Post-Rollback**
   - Verify application functionality
   - Check data consistency
   - Notify stakeholders
   - Investigate root cause

## Monitoring and Alerting

### Application Monitoring
- **APM**: New Relic or DataDog
- **Logs**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **Metrics**: Prometheus + Grafana
- **Tracing**: Jaeger or Zipkin

### Infrastructure Monitoring
- **Kubernetes**: Prometheus Operator
- **Nodes**: Node Exporter
- **Services**: Blackbox Exporter
- **Alerts**: AlertManager

### Key Metrics to Monitor
- Response time < 500ms
- Error rate < 1%
- CPU usage < 80%
- Memory usage < 85%
- Database connection pool utilization
- Cache hit rate > 90%

### Alert Thresholds
- Critical: Error rate > 5%
- Warning: Response time > 1s
- Info: CPU > 90% for 5 minutes

## Security in Deployment

### Secrets Management
- **Tool**: HashiCorp Vault or AWS Secrets Manager
- **Rotation**: Automatic rotation every 30 days
- **Access**: Least privilege principle
- **Encryption**: TLS 1.3 for all communications

### Network Security
- **Firewall**: Web Application Firewall (WAF)
- **Network Policies**: Kubernetes network policies
- **TLS**: End-to-end encryption
- **VPN**: For administrative access

### Compliance
- **SBOM**: Generated on every release
- **Vulnerability Scanning**: Automated in CI/CD
- **Audit Logs**: All deployment activities logged
- **Access Reviews**: Quarterly access reviews

## Backup and Recovery

### Database Backups
- **Frequency**: Daily full backups
- **Retention**: 30 days for daily, 1 year for monthly
- **Storage**: Encrypted S3 buckets
- **Testing**: Monthly restore tests

### Application Backups
- **Configuration**: Version controlled
- **User Data**: Regular snapshots
- **Logs**: Archived for 90 days
- **Artifacts**: Stored in artifact repository

### Disaster Recovery
- **RTO**: 4 hours
- **RPO**: 1 hour
- **Multi-region**: Active-passive setup
- **Testing**: Quarterly DR drills

## Performance Optimization

### Application Performance
- **Caching**: Redis for session and data caching
- **CDN**: CloudFront for static assets
- **Database**: Query optimization and indexing
- **Async Processing**: Background job queues

### Infrastructure Performance
- **Auto-scaling**: Horizontal Pod Autoscaler
- **Resource Limits**: CPU and memory limits per pod
- **Load Balancing**: Intelligent traffic distribution
- **CDN Integration**: Edge caching for global users

## Troubleshooting

### Common Deployment Issues

#### Pod Startup Failures
```bash
# Check pod status
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name> --previous

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp
```

#### Database Connection Issues
- Verify connection strings
- Check network policies
- Review database credentials
- Monitor connection pool

#### High Resource Usage
- Check application metrics
- Review resource limits
- Optimize queries
- Scale horizontally

### Debug Commands
```bash
# Enter pod for debugging
kubectl exec -it <pod-name> -- /bin/bash

# Port forward for local testing
kubectl port-forward <pod-name> 8080:8080

# Check service endpoints
kubectl get endpoints

# View cluster events
kubectl get events --watch
```

## Maintenance Procedures

### Regular Maintenance
- **Weekly**: Review logs and metrics
- **Monthly**: Update dependencies and security patches
- **Quarterly**: Performance optimization
- **Annually**: Infrastructure review and upgrades

### Patch Management
- **Security Patches**: Apply within 30 days
- **Bug Fixes**: Test in staging before production
- **Feature Updates**: Follow deployment process
- **Emergency Patches**: Fast-track for critical issues

## Contact Information

- **DevOps Team**: devops@plexichat.com
- **Platform Team**: platform@plexichat.com
- **Security Team**: security@plexichat.com
- **Development Team**: dev@plexichat.com

## Emergency Contacts

- **On-call Engineer**: +1-555-0100 (PagerDuty)
- **Management**: +1-555-0200
- **Vendor Support**: As per vendor agreements

## Version History

- v1.0: Initial deployment procedures
- v1.1: Added blue-green deployment
- v1.2: Enhanced monitoring and alerting
- v1.3: Improved security measures