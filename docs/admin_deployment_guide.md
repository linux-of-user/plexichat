# PlexiChat Admin Deployment Guide

## 🚀 How to Push Updates to Users

This guide explains how to create releases, deploy updates, and manage the PlexiChat update system as an administrator.

## 📋 Prerequisites

- Admin access to the PlexiChat GitHub repository: `github.com/linux-of-user/plexichat`
- Git configured with appropriate permissions
- Understanding of PlexiChat's version format: `XaY`, `XbY`, `XrY` (where X=major, a/b/r=alpha/beta/release, Y=minor)

## 🔄 Version Format

PlexiChat uses a specific version format: `letter.major.minor-build`
- **Alpha**: `a.1.1-1`, `a.1.1-2`, `a.1.2-1`, etc. (Development/testing)
- **Beta**: `b.1.1-1`, `b.1.1-2`, `b.1.2-1`, etc. (Pre-release testing)
- **Release**: `r.1.1-1`, `r.1.1-2`, `r.1.2-1`, etc. (Stable production)

### Version Progression Examples:
```
a.1.1-1 → a.1.1-2 → a.1.2-1 → b.1.2-1 → b.1.2-2 → r.1.2-1 → r.1.2-2 → a.1.3-1 → a.2.0-1
```

## 📦 Creating and Deploying Updates

### Step 1: Prepare Your Code

1. **Make your changes** in the development branch
2. **Test thoroughly** using the built-in test system:
   ```bash
   plexichat test run
   plexichat test health
   plexichat test security
   ```
3. **Update version.json** if needed:
   ```json
   {
     "current_version": "a.1.2-1",
     "last_updated": "2025-07-09T12:00:00Z",
     "history": []
   }
   ```

### Step 2: Create a Git Tag

1. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: Add new collaboration features for v1a2"
   ```

2. **Create and push a tag**:
   ```bash
   # For alpha release
   git tag a.1.2-1
   git push origin a.1.2-1

   # For beta release
   git tag b.1.2-1
   git push origin b.1.2-1

   # For stable release
   git tag r.1.2-1
   git push origin r.1.2-1
   ```

### Step 3: Create GitHub Release

1. **Go to GitHub**: Navigate to `https://github.com/linux-of-user/plexichat/releases`

2. **Click "Create a new release"**

3. **Fill in the release information**:
   - **Tag version**: Select the tag you just created (e.g., `a.1.2-1`)
   - **Release title**: Use format like "PlexiChat va.1.2-1 - Enhanced Collaboration"
   - **Description**: Include detailed release notes (see template below)
   - **Pre-release**: Check this for alpha/beta versions, uncheck for stable releases

4. **Release Notes Template**:
   ```markdown
   # PlexiChat va.1.2-1 - Enhanced Collaboration
   
   ## 🆕 New Features
   - Real-time collaboration with presence indicators
   - Enhanced message endpoints with advanced filtering
   - Seamless zero-downtime updates
   - Improved API versioning (/api, /api/v1, /api/beta)
   
   ## 🔧 Improvements
   - Better rate limiting integration
   - Enhanced security monitoring
   - Optimized database queries
   - Improved error handling
   
   ## 🐛 Bug Fixes
   - Fixed message pagination issues
   - Resolved WebSocket connection stability
   - Fixed authentication token refresh
   
   ## 🔒 Security Updates
   - Enhanced input validation
   - Improved rate limiting
   - Better DDoS protection
   
   ## 📋 Breaking Changes
   - None in this release
   
   ## 🔄 Update Instructions
   Users can update using:
   ```bash
   plexichat version update --channel alpha
   ```
   
   Or via the WebUI: Settings → Updates → Check for Updates
   ```

5. **Attach files** (optional):
   - You can attach pre-built packages if needed
   - PlexiChat will automatically use the source code zipball

6. **Publish the release**

## 🎯 Update Channels

PlexiChat supports three update channels:

### Alpha Channel (`/api/beta`)
- **Purpose**: Development and testing
- **Audience**: Developers and early testers
- **Frequency**: Multiple releases per week
- **Stability**: Experimental features, may have bugs

### Beta Channel (`/api/v1`)
- **Purpose**: Pre-release testing
- **Audience**: Beta testers and advanced users
- **Frequency**: Weekly releases
- **Stability**: Feature-complete, minor bugs possible

### Stable Channel (`/api`)
- **Purpose**: Production use
- **Audience**: All users
- **Frequency**: Monthly releases
- **Stability**: Thoroughly tested, production-ready

## 🔧 Managing Updates

### Check Update Status
```bash
# Via CLI
plexichat version update --check-only

# Via API
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/updates/check"
```

### Configure Auto-Updates
```bash
# Enable auto-updates for stable channel
plexichat version update --auto --channel stable

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auto_download": true, "update_channel": "stable"}' \
  "http://localhost:8000/api/v1/updates/config"
```

### Monitor Update History
```bash
# Via CLI
plexichat version history

# Via API
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/updates/history"
```

## 🚨 Emergency Updates

For critical security updates:

1. **Create hotfix branch**:
   ```bash
   git checkout -b hotfix/security-patch
   ```

2. **Apply the fix and test**

3. **Create emergency release**:
   ```bash
   git tag 1r2-security
   git push origin 1r2-security
   ```

4. **Mark as security update** in release notes:
   ```markdown
   ## 🔒 SECURITY UPDATE
   This release contains critical security fixes. Update immediately.
   
   ### CVE Fixes
   - CVE-2025-XXXX: Fixed SQL injection vulnerability
   ```

5. **Notify users** through all channels

## 📊 Monitoring Deployments

### Update Analytics
- Monitor update adoption rates
- Track failed updates
- Analyze rollback frequency

### Health Monitoring
```bash
# Check system health after updates
plexichat test health

# Monitor logs
tail -f logs/plexichat.log | grep -i update
```

## 🔄 Rollback Procedures

### Automatic Rollback
PlexiChat automatically rolls back failed updates. Monitor logs:
```bash
tail -f logs/update.log
```

### Manual Rollback
```bash
# Via CLI
plexichat version rollback --to 1r1

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"target_version": "1r1"}' \
  "http://localhost:8000/api/v1/updates/rollback"
```

## 📋 Best Practices

### 1. Testing Strategy
- **Alpha**: Internal testing, automated tests
- **Beta**: Community testing, feedback collection
- **Stable**: Production deployment after beta validation

### 2. Release Timing
- **Alpha**: Continuous (as features are ready)
- **Beta**: Weekly (Fridays)
- **Stable**: Monthly (first Tuesday of month)

### 3. Communication
- **Release notes**: Always include comprehensive notes
- **Breaking changes**: Clearly document and provide migration guides
- **Security updates**: Immediate notification through all channels

### 4. Monitoring
- **Update success rates**: Track deployment success
- **Performance impact**: Monitor system performance post-update
- **User feedback**: Collect and respond to user reports

## 🛠️ Troubleshooting

### Common Issues

1. **Update fails to download**:
   - Check GitHub API rate limits
   - Verify network connectivity
   - Check GitHub token permissions

2. **Update fails to install**:
   - Check disk space
   - Verify file permissions
   - Review backup creation

3. **Service doesn't restart**:
   - Check for port conflicts
   - Verify configuration files
   - Review dependency installation

### Debug Commands
```bash
# Check update system status
plexichat version update --check-only --verbose

# Test update system
plexichat test run --suite updates

# View detailed logs
tail -f logs/github_updater.log
```

## 📞 Support

For deployment issues:
1. Check the troubleshooting section above
2. Review logs in `logs/` directory
3. Test with `plexichat test run`
4. Contact development team with logs and error details

---

**Remember**: Always test updates in a staging environment before deploying to production!
