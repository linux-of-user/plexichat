# CI/CD Operations Runbook

## Overview

This runbook provides operational guidance for the PlexiChat CI/CD pipeline, which automates code quality checks, testing, security scanning, and deployment processes.

## Pipeline Structure

The CI/CD pipeline consists of the following jobs:

### 1. Lint Job
- **Purpose**: Code quality and style enforcement
- **Tools**:
  - Ruff: Fast Python linter
  - Black: Code formatter
  - isort: Import sorter
  - MyPy: Static type checker
- **Triggers**: All pushes and PRs
- **Failure Action**: Block merge if any linter fails

### 2. Test Job
- **Purpose**: Automated testing with coverage reporting
- **Test Types**:
  - Unit tests (`tests/unit/`)
  - Integration tests (`tests/integration/`)
  - Simulation tests (marked with `simulation` keyword)
- **Coverage**: Minimum 80% code coverage required
- **Reports**: Coverage uploaded to Codecov
- **Triggers**: All pushes and PRs

### 3. Security Job
- **Purpose**: Automated security vulnerability scanning
- **Tools**:
  - Bandit: Python security linter
  - Semgrep: Semantic code analysis
  - pip-audit: Dependency vulnerability scanning
- **Reports**: JSON reports uploaded as artifacts
- **Triggers**: All pushes and PRs

### 4. Secret Scan Job
- **Purpose**: Detect hardcoded secrets and credentials
- **Tool**: TruffleHog
- **Triggers**: All pushes and PRs
- **Failure Action**: Block merge if secrets detected

### 5. Coverage Check Job
- **Purpose**: Enforce minimum code coverage
- **Threshold**: 80% minimum coverage
- **Triggers**: After successful test job

### 6. SBOM Generation Job
- **Purpose**: Generate Software Bill of Materials for releases
- **Tool**: CycloneDX
- **Format**: JSON
- **Triggers**: Release publication only

## Quality Gates

### Branch Protection Rules
- Require status checks to pass before merging
- Require up-to-date branches
- Require code reviews for PRs

### Required Checks
All of the following must pass:
- Lint (ruff, black, isort, mypy)
- Test (unit, integration, simulation)
- Security (bandit, semgrep, pip-audit)
- Secret Scan (trufflehog)
- Coverage Check (80% minimum)

## Triggering Builds

### Automatic Triggers
- Push to `main` or `develop` branches
- Pull requests targeting `main` or `develop`
- Release publication

### Manual Triggers
- Push commits to trigger pipeline
- Create/update pull requests
- Publish releases on GitHub

## Monitoring and Troubleshooting

### Viewing Pipeline Status
1. Navigate to GitHub Actions tab
2. Select the workflow run
3. Review job logs and artifacts

### Common Issues and Solutions

#### Linter Failures
- **Issue**: Code style violations
- **Solution**:
  ```bash
  # Fix formatting
  black .
  isort .

  # Fix linting issues
  ruff check . --fix
  ```

#### Test Failures
- **Issue**: Test suite failures
- **Solution**:
  - Check test logs for specific errors
  - Run tests locally: `pytest tests/ -v`
  - Debug with: `pytest tests/ -s --pdb`

#### Coverage Below Threshold
- **Issue**: Code coverage < 80%
- **Solution**:
  - Run coverage locally: `pytest --cov=plexichat --cov-report=html`
  - Add tests for uncovered lines
  - Review coverage report in `htmlcov/index.html`

#### Security Scan Failures
- **Issue**: Security vulnerabilities detected
- **Solution**:
  - Review security reports in artifacts
  - Fix vulnerabilities or add suppressions
  - Update dependencies if needed

#### Secret Detection
- **Issue**: Hardcoded secrets found
- **Solution**:
  - Remove hardcoded secrets
  - Use environment variables or secret management
  - Add false positives to `.trufflehogignore`

### Debugging Locally

#### Run Full Pipeline Locally
```bash
# Install all dependencies
pip install -r requirements.txt
pip install ruff black isort mypy pytest pytest-cov bandit semgrep pip-audit

# Run linters
ruff check .
black --check .
isort --check-only .
mypy .

# Run tests with coverage
pytest --cov=plexichat --cov-report=term-missing

# Run security scans
bandit -r plexichat/
semgrep --config auto
pip-audit
```

## Security Considerations

### Secrets Management
- Never commit secrets to code
- Use GitHub Secrets for CI/CD variables
- Rotate secrets regularly
- Monitor for secret leaks

### Dependency Security
- Regular dependency updates
- Automated vulnerability scanning
- SBOM generation for compliance
- Review third-party licenses

### Access Control
- Branch protection rules enforced
- Required code reviews
- Limited write access to main branch
- Automated security scanning

## Best Practices

### Code Quality
- Write tests for new features
- Maintain code coverage above 80%
- Follow PEP 8 style guidelines
- Use type hints for better code quality

### Commit Practices
- Use descriptive commit messages
- Keep commits focused and atomic
- Test locally before pushing
- Use feature branches for development

### Pull Request Process
- Create PRs from feature branches
- Ensure all checks pass
- Request code reviews
- Squash commits before merging

### Release Process
- Use semantic versioning
- Generate SBOM on release
- Tag releases appropriately
- Document breaking changes

## Emergency Procedures

### Pipeline Failure
1. Check GitHub Actions logs
2. Identify failing job
3. Review error messages
4. Fix issues locally
5. Push fixes or create hotfix PR

### Security Incident
1. Immediately notify security team
2. Quarantine affected branches
3. Audit recent changes
4. Apply security patches
5. Update security policies

### Rollback Procedure
1. Identify last stable commit
2. Create rollback branch
3. Test rollback changes
4. Merge rollback to main
5. Monitor system stability

## Maintenance

### Regular Tasks
- Weekly: Review pipeline performance
- Monthly: Update dependencies
- Quarterly: Review security policies
- Annually: Audit access controls

### Tool Updates
- Monitor tool release notes
- Test tool updates in development
- Update pipeline configuration
- Document changes in this runbook

## Contact Information

- DevOps Team: devops@plexichat.com
- Security Team: security@plexichat.com
- Development Team: dev@plexichat.com

## Version History

- v1.0: Initial CI/CD pipeline implementation
- v1.1: Added SBOM generation
- v1.2: Enhanced security scanning